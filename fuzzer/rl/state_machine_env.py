#!/usr/bin/env python3
"""
State Machine Confusion Environment for DICOM fuzzing.

This environment tests the server's DICOM state machine by:
  1. Sending PDUs in unexpected order
  2. Sending server-side PDUs from the client
  3. Interleaving valid and invalid PDUs
  4. Testing double-association and re-association scenarios

Attack vectors:
  - PDATA before association
  - Double A-ASSOCIATE-RQ
  - A-ASSOCIATE-AC from client (server-side PDU)
  - RELEASE during data transfer
  - ABORT then continue
  - Mixed valid/invalid sequences
"""

import os
import sys
import random
import struct
import socket
import time
import logging

import numpy as np

try:
    import gymnasium as gym
    from gymnasium import spaces
except ImportError:
    import gym
    from gym import spaces

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from fuzzer.common.pcap_utils import wrap_tcp_ip

from fuzzer.rl.reward import RewardComputer
from fuzzer.rl.server_monitor import ServerMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# PDU Builders
# ============================================================================

def build_assoc_rq(called_ae="ORTHANC", calling_ae="FUZZER"):
    """Build a valid A-ASSOCIATE-RQ PDU."""
    called = called_ae.ljust(16).encode('ascii')[:16]
    calling = calling_ae.ljust(16).encode('ascii')[:16]

    # Application Context
    app_ctx_uid = b'1.2.840.10008.3.1.1.1'
    app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

    # Presentation Context: Verification SOP
    abstract_uid = b'1.2.840.10008.1.1'
    abstract = struct.pack('>BBH', 0x30, 0, len(abstract_uid)) + abstract_uid
    transfer_uid = b'1.2.840.10008.1.2'
    transfer = struct.pack('>BBH', 0x40, 0, len(transfer_uid)) + transfer_uid
    pres_ctx_data = struct.pack('>BBBB', 1, 0, 0, 0) + abstract + transfer
    pres_ctx = struct.pack('>BBH', 0x20, 0, len(pres_ctx_data)) + pres_ctx_data

    # User Info
    max_pdu = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', 16382)
    impl_uid = b'1.2.826.0.1.3680043.9.3811.2.0.2'
    impl_item = struct.pack('>BBH', 0x52, 0, len(impl_uid)) + impl_uid
    user_info = struct.pack('>BBH', 0x50, 0, len(max_pdu) + len(impl_item)) + max_pdu + impl_item

    variable = app_ctx + pres_ctx + user_info
    reserved32 = b'\x00' * 32
    pdu_data = struct.pack('>H', 1) + b'\x00\x00' + called + calling + reserved32 + variable
    return struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data


def build_assoc_ac(called_ae="ORTHANC", calling_ae="FUZZER"):
    """Build an A-ASSOCIATE-AC PDU (server-side, shouldn't come from client)."""
    called = called_ae.ljust(16).encode('ascii')[:16]
    calling = calling_ae.ljust(16).encode('ascii')[:16]

    app_ctx_uid = b'1.2.840.10008.3.1.1.1'
    app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

    # Accepted presentation context
    transfer_uid = b'1.2.840.10008.1.2'
    transfer = struct.pack('>BBH', 0x40, 0, len(transfer_uid)) + transfer_uid
    pres_ctx_data = struct.pack('>BBBB', 1, 0, 0, 0) + transfer  # result=0 (accepted)
    pres_ctx = struct.pack('>BBH', 0x21, 0, len(pres_ctx_data)) + pres_ctx_data

    max_pdu = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', 16382)
    impl_uid = b'1.2.826.0.1.3680043.9.3811.2.0.2'
    impl_item = struct.pack('>BBH', 0x52, 0, len(impl_uid)) + impl_uid
    user_info = struct.pack('>BBH', 0x50, 0, len(max_pdu) + len(impl_item)) + max_pdu + impl_item

    variable = app_ctx + pres_ctx + user_info
    reserved32 = b'\x00' * 32
    pdu_data = struct.pack('>H', 1) + b'\x00\x00' + called + calling + reserved32 + variable
    return struct.pack('>BBi', 0x02, 0, len(pdu_data)) + pdu_data


def build_assoc_rj(result=1, source=1, reason=1):
    """Build an A-ASSOCIATE-RJ PDU (server-side)."""
    return struct.pack('>BBi BBBB', 0x03, 0, 4, 0, result, source, reason)


def build_pdata_cecho():
    """Build a C-ECHO-RQ PDATA PDU."""
    uid = b'1.2.840.10008.1.1'
    if len(uid) % 2: uid += b'\x00'
    elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid
    elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)  # C-ECHO-RQ
    elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, 1)  # Message ID
    elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0101)  # No dataset
    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0800
    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set
    pdv_data = struct.pack('>BB', 1, 0x03) + command_set
    pdv_item = struct.pack('>I', len(pdv_data)) + pdv_data
    return struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item


def build_release_rq():
    """Build an A-RELEASE-RQ PDU."""
    return struct.pack('>BBi', 0x05, 0, 4) + b'\x00' * 4


def build_release_rp():
    """Build an A-RELEASE-RP PDU (server-side)."""
    return struct.pack('>BBi', 0x06, 0, 4) + b'\x00' * 4


def build_abort(source=0, reason=0):
    """Build an A-ABORT PDU."""
    return struct.pack('>BBi BB BB', 0x07, 0, 4, 0, 0, source, reason)


def build_invalid_pdu(pdu_type):
    """Build a PDU with invalid/unknown type."""
    return struct.pack('>BBi', pdu_type, 0, 4) + b'\x00' * 4


# ============================================================================
# Attack Sequences
# ============================================================================

# Pre-defined attack sequences
ATTACK_SEQUENCES = [
    # 0: Normal sequence (baseline)
    ("normal", ["assoc_rq", "pdata", "release_rq"]),

    # 1: PDATA before association
    ("pdata_first", ["pdata", "assoc_rq"]),

    # 2: Double association request
    ("double_assoc", ["assoc_rq", "assoc_rq"]),

    # 3: Client sends server-side PDU (ASSOC_AC)
    ("client_sends_ac", ["assoc_ac"]),

    # 4: Client sends server-side PDU (ASSOC_RJ)
    ("client_sends_rj", ["assoc_rj"]),

    # 5: Client sends server-side PDU (RELEASE_RP)
    ("client_sends_release_rp", ["release_rp"]),

    # 6: Abort then continue
    ("abort_continue", ["assoc_rq", "abort", "pdata"]),

    # 7: Release then data
    ("release_then_data", ["assoc_rq", "release_rq", "pdata"]),

    # 8: Multiple PDATs without association
    ("pdata_flood_no_assoc", ["pdata", "pdata", "pdata"]),

    # 9: Valid association then server-side PDU
    ("assoc_then_ac", ["assoc_rq", "assoc_ac"]),

    # 10: Interleaved valid/invalid
    ("interleaved", ["assoc_rq", "invalid_0x08", "pdata"]),

    # 11: Unknown PDU types
    ("unknown_pdu", ["invalid_0x00", "invalid_0x08", "invalid_0x09", "invalid_0xFF"]),

    # 12: Re-association attempt
    ("reassoc", ["assoc_rq", "pdata", "assoc_rq"]),

    # 13: Abort flood
    ("abort_flood", ["abort", "abort", "abort"]),

    # 14: Release without association
    ("release_no_assoc", ["release_rq"]),

    # 15: Mixed server PDUs
    ("server_pdu_mix", ["assoc_ac", "assoc_rj", "release_rp"]),
]


# ============================================================================
# State Machine Environment
# ============================================================================

class DicomStateMachineEnv(gym.Env):
    """
    Environment for testing DICOM server state machine handling.

    Action space: Select which attack sequence to execute (discrete)
    Observation: One-hot encoding of last response + sequence index

    This tests protocol-level vulnerabilities rather than byte-level mutations.
    """

    metadata = {"render_modes": ["human"]}

    def __init__(self, target_host=None, target_port=4242, called_ae="ORTHANC",
                 max_steps=10):
        super().__init__()

        self.target_host = target_host
        self.target_port = target_port
        self.called_ae = called_ae
        self.max_steps = max_steps

        # Action: choose an attack sequence
        self.n_sequences = len(ATTACK_SEQUENCES)
        self.action_space = spaces.Discrete(self.n_sequences)

        # Observation: [sequence_idx (one-hot), last_response_type, step_count]
        # Response types: 0=none, 1=accept, 2=reject, 3=abort, 4=release, 5=pdata,
        #                 6=reset, 7=timeout, 8=closed, 9=error
        self.observation_space = spaces.Box(
            low=0, high=1,
            shape=(self.n_sequences + 10 + 1,),  # one-hot seq + response + step
            dtype=np.float32,
        )

        # Server monitor
        self.server_monitor = None
        if target_host:
            self.server_monitor = ServerMonitor(
                target_host=target_host,
                target_port=target_port,
                called_ae=called_ae,
            )

        # State
        self.step_count = 0
        self.last_response = 0
        self.last_sequence = 0
        self.episode_reward = 0
        self.responses_seen = set()
        self.sequences_tried = set()

    def _get_pdu(self, pdu_name):
        """Get PDU bytes by name."""
        if pdu_name == "assoc_rq":
            return build_assoc_rq(called_ae=self.called_ae)
        elif pdu_name == "assoc_ac":
            return build_assoc_ac(called_ae=self.called_ae)
        elif pdu_name == "assoc_rj":
            return build_assoc_rj()
        elif pdu_name == "pdata":
            return build_pdata_cecho()
        elif pdu_name == "release_rq":
            return build_release_rq()
        elif pdu_name == "release_rp":
            return build_release_rp()
        elif pdu_name == "abort":
            return build_abort()
        elif pdu_name.startswith("invalid_"):
            pdu_type = int(pdu_name.split("_")[1], 16)
            return build_invalid_pdu(pdu_type)
        else:
            return build_pdata_cecho()

    def _send_sequence(self, sequence_name, pdu_names):
        """Send a sequence of PDUs and return response info."""
        info = {
            "sequence": sequence_name,
            "pdus_sent": pdu_names,
            "responses": [],
            "final_response": "none",
            "crash": False,
            "response_time_ms": 0,
        }
        reward = 0.0

        if not self.target_host:
            return reward, info

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((self.target_host, self.target_port))

            for i, pdu_name in enumerate(pdu_names):
                pdu_bytes = self._get_pdu(pdu_name)
                t_start = time.monotonic()

                try:
                    sock.sendall(pdu_bytes)
                    sock.settimeout(2.0)

                    try:
                        response = sock.recv(4096)
                        t_end = time.monotonic()
                        response_ms = (t_end - t_start) * 1000.0

                        if not response:
                            resp_type = "closed"
                        elif response[0] == 0x02:
                            resp_type = "accept"
                        elif response[0] == 0x03:
                            resp_type = "reject"
                        elif response[0] == 0x04:
                            resp_type = "pdata"
                        elif response[0] == 0x06:
                            resp_type = "release"
                        elif response[0] == 0x07:
                            resp_type = "abort"
                        else:
                            resp_type = f"type_0x{response[0]:02x}"

                        info["responses"].append({
                            "pdu": pdu_name,
                            "response": resp_type,
                            "time_ms": round(response_ms, 1)
                        })
                        info["final_response"] = resp_type
                        info["response_time_ms"] = round(response_ms, 1)

                    except socket.timeout:
                        info["responses"].append({
                            "pdu": pdu_name,
                            "response": "timeout",
                            "time_ms": 2000.0
                        })
                        info["final_response"] = "timeout"
                        reward += 10.0  # per-PDU timeout: mild bonus

                except (ConnectionResetError, BrokenPipeError):
                    info["responses"].append({
                        "pdu": pdu_name,
                        "response": "reset",
                        "time_ms": 0
                    })
                    info["final_response"] = "reset"
                    break

            sock.close()

        except ConnectionRefusedError:
            info["final_response"] = "refused"
            # Check if server crashed
            time.sleep(0.5)
            try:
                check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                check.settimeout(2.0)
                check.connect((self.target_host, self.target_port))
                check.close()
            except Exception:
                info["crash"] = True
                reward += 100.0

        except socket.timeout:
            info["final_response"] = "connect_timeout"
            reward += 20.0

        except Exception as e:
            info["final_response"] = f"error:{e}"

        # Compute reward based on response — abort > hang > accept hierarchy
        response = info["final_response"]
        if response == "abort":
            reward += 50.0  # primary security signal: server hit error-handling code
        elif response == "timeout":
            reward += 20.0  # DoS potential, less exploitable than crash/abort
        elif response == "accept":
            # Unexpected accept is interesting for some sequences
            if sequence_name not in ["normal"]:
                reward += 15.0
        elif response == "reject":
            reward += 5.0
        elif response == "reset":
            reward += 2.0
        elif response == "closed":
            reward += 3.0
        elif response.startswith("type_"):
            reward += 20.0  # Unknown PDU type from server

        # Novelty bonus for new sequence
        if sequence_name not in self.sequences_tried:
            self.sequences_tried.add(sequence_name)
            reward += 10.0

        # Response novelty
        if response not in self.responses_seen:
            self.responses_seen.add(response)
            reward += 5.0

        return reward, info

    def _get_obs(self):
        """Build observation vector."""
        obs = np.zeros(self.n_sequences + 10 + 1, dtype=np.float32)
        # One-hot sequence
        obs[self.last_sequence] = 1.0
        # Response type encoding
        response_map = {
            "none": 0, "accept": 1, "reject": 2, "abort": 3, "release": 4,
            "pdata": 5, "reset": 6, "timeout": 7, "closed": 8, "error": 9
        }
        resp_idx = response_map.get(self.last_response, 9)
        obs[self.n_sequences + resp_idx] = 1.0
        # Step count (normalized)
        obs[-1] = self.step_count / self.max_steps
        return obs

    def reset(self, seed=None, options=None):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        self.step_count = 0
        self.last_response = "none"
        self.last_sequence = 0
        self.episode_reward = 0
        self.responses_seen = set()
        # Don't reset sequences_tried - track across episodes for novelty

        return self._get_obs(), {}

    def step(self, action):
        """Execute an attack sequence."""
        sequence_name, pdu_names = ATTACK_SEQUENCES[action]
        self.last_sequence = action

        reward, info = self._send_sequence(sequence_name, pdu_names)
        self.last_response = info["final_response"]
        self.step_count += 1

        self.episode_reward += reward
        info["episode_reward"] = self.episode_reward

        truncated = self.step_count >= self.max_steps
        terminated = info.get("crash", False)

        return self._get_obs(), reward, terminated, truncated, info

    def render(self, mode="human"):
        seq_name = ATTACK_SEQUENCES[self.last_sequence][0]
        print(f"Step {self.step_count} | sequence={seq_name} | "
              f"response={self.last_response}")
