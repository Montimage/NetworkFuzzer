#!/usr/bin/env python3
"""
DICOM Semantic-Aware Fuzzing Environment.

Unlike random byte mutations, this environment:
1. Respects DICOM protocol constraints
2. Mutates specific fields with semantically valid/boundary values
3. Passes initial validation to reach deeper code paths
4. Targets known vulnerability patterns

Key insight: Random mutations get rejected early. Semantic mutations
exploit edge cases within the protocol specification.
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

from fuzzer.rl.dicom_semantics import (
    build_smart_cecho_pdata,
    build_smart_assoc_rq,
    mutate_message_id_smart,
    mutate_command_field_smart,
    mutate_data_set_type_smart,
    mutate_context_id_smart,
    mutate_pdv_flags_smart,
    mutate_status_smart,
    mutate_max_pdu_length_smart,
    MESSAGE_ID_MUTATIONS,
    COMMAND_FIELD_MUTATIONS,
    DATA_SET_TYPE_MUTATIONS,
    CONTEXT_ID_MUTATIONS,
    PDV_FLAGS_MUTATIONS,
    SEMANTIC_MUTATION_STRATEGIES,
)
from fuzzer.rl.server_monitor import ServerMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# Semantic Mutation Actions
# ============================================================================

# Action space: which field to mutate and with what strategy
FIELD_ACTIONS = [
    # (field_name, mutation_values, description)
    ("message_id", MESSAGE_ID_MUTATIONS, "Message ID mutations"),
    ("command_field", COMMAND_FIELD_MUTATIONS, "Command field mutations"),
    ("data_set_type", DATA_SET_TYPE_MUTATIONS, "Data set type mutations"),
    ("context_id", CONTEXT_ID_MUTATIONS, "Context ID mutations"),
    ("msg_control", PDV_FLAGS_MUTATIONS, "PDV flags mutations"),
]

# Combined action space: field_index * len(mutations for that field)
# But simpler: just index into all possible (field, value) combinations
ALL_MUTATIONS = []
for field_name, values, desc in FIELD_ACTIONS:
    for val in values:
        ALL_MUTATIONS.append((field_name, val, desc))


class DicomSemanticEnv(gym.Env):
    """
    Semantic-aware DICOM fuzzing environment.

    Action space: Choose which field to mutate and to what value
    Observation: Current field values + server response history

    This environment sends PDATA within a valid association, mutating
    specific DIMSE fields with semantically meaningful values.
    """

    metadata = {"render_modes": ["human"]}

    def __init__(self, target_host=None, target_port=4242, called_ae="ORTHANC",
                 max_steps=30):
        super().__init__()

        self.target_host = target_host
        self.target_port = target_port
        self.called_ae = called_ae.encode() if isinstance(called_ae, str) else called_ae
        self.max_steps = max_steps

        # Action space: index into ALL_MUTATIONS
        self.n_actions = len(ALL_MUTATIONS)
        self.action_space = spaces.Discrete(self.n_actions)

        # Observation: current field values + response history
        # [message_id(norm), command_field(norm), data_set_type(norm),
        #  context_id(norm), msg_control(norm), step_frac,
        #  last_response_type, response_time_norm, hang_count, accept_count]
        self.observation_space = spaces.Box(
            low=0, high=1,
            shape=(15,),
            dtype=np.float32,
        )

        # Server monitor
        self.server_monitor = None
        if target_host:
            self.server_monitor = ServerMonitor(
                target_host=target_host,
                target_port=target_port,
                called_ae=called_ae if isinstance(called_ae, str) else called_ae.decode(),
            )

        # Current field values
        self.current_fields = {}
        self.reset_fields()

        # Episode state
        self.step_count = 0
        self.episode_reward = 0
        self.response_history = []
        self.hang_count = 0
        self.accept_count = 0
        self.abort_count = 0

    def reset_fields(self):
        """Reset fields to valid defaults."""
        self.current_fields = {
            "message_id": 1,
            "command_field": 0x0030,  # C-ECHO-RQ
            "data_set_type": 0x0101,  # No dataset
            "context_id": 1,
            "msg_control": 0x03,  # Last fragment, command
        }

    def _get_obs(self):
        """Build observation vector."""
        obs = np.zeros(15, dtype=np.float32)

        # Normalize current field values
        obs[0] = self.current_fields["message_id"] / 65535.0
        obs[1] = self.current_fields["command_field"] / 65535.0
        obs[2] = self.current_fields["data_set_type"] / 65535.0
        obs[3] = self.current_fields["context_id"] / 255.0
        obs[4] = self.current_fields["msg_control"] / 255.0

        # Step progress
        obs[5] = self.step_count / self.max_steps

        # Response history (last 5 responses encoded)
        response_map = {"none": 0, "accept": 0.2, "reject": 0.4, "abort": 0.6,
                        "timeout": 0.8, "reset": 0.3, "pdata": 0.9}
        for i, resp in enumerate(self.response_history[-5:]):
            if i < 5:
                obs[6 + i] = response_map.get(resp, 0.5)

        # Counters
        obs[11] = min(self.hang_count / 10.0, 1.0)
        obs[12] = min(self.accept_count / 10.0, 1.0)
        obs[13] = min(self.abort_count / 10.0, 1.0)
        obs[14] = len(self.response_history) / 100.0

        return obs

    def _build_pdata(self):
        """Build PDATA PDU with current field values."""
        return build_smart_cecho_pdata(
            context_id=self.current_fields["context_id"],
            msg_control=self.current_fields["msg_control"],
            command_field=self.current_fields["command_field"],
            message_id=self.current_fields["message_id"],
            data_set_type=self.current_fields["data_set_type"],
        )

    def _send_session(self):
        """Send association + PDATA and return response info."""
        info = {
            "response": "none",
            "response_time_ms": 0,
            "crash": False,
            "hang": False,
            "assoc_accepted": False,
        }
        reward = 0.0

        if not self.target_host:
            return reward, info

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(5.0)
            sock.connect((self.target_host, self.target_port))

            # Send association request
            assoc_rq = build_smart_assoc_rq(called_ae=self.called_ae)
            sock.sendall(assoc_rq)
            sock.settimeout(3.0)

            try:
                assoc_resp = sock.recv(4096)
                if assoc_resp and assoc_resp[0] == 0x02:
                    info["assoc_accepted"] = True
                    self.accept_count += 1

                    # Send PDATA with mutated fields
                    pdata = self._build_pdata()
                    t_start = time.monotonic()
                    sock.sendall(pdata)
                    sock.settimeout(2.0)

                    try:
                        data_resp = sock.recv(4096)
                        t_end = time.monotonic()
                        info["response_time_ms"] = (t_end - t_start) * 1000

                        if not data_resp:
                            info["response"] = "closed"
                            reward = 5.0
                        elif data_resp[0] == 0x04:
                            info["response"] = "pdata"
                            reward = 20.0  # Server processed our PDATA!
                        elif data_resp[0] == 0x07:
                            info["response"] = "abort"
                            self.abort_count += 1
                            reward = 50.0  # Abort: server hit error-handling path
                        elif data_resp[0] == 0x06:
                            info["response"] = "release"
                            reward = 8.0
                        else:
                            info["response"] = f"type_{data_resp[0]:02x}"
                            reward = 15.0  # Unknown response

                        # Time bonus
                        if info["response_time_ms"] > 100:
                            reward += 15.0
                        elif info["response_time_ms"] > 50:
                            reward += 8.0

                    except socket.timeout:
                        info["response"] = "timeout"
                        info["hang"] = True
                        self.hang_count += 1
                        reward = 20.0  # Hang: resource exhaustion potential

                elif assoc_resp and assoc_resp[0] == 0x03:
                    info["response"] = "reject"
                    reward = 3.0
                elif assoc_resp and assoc_resp[0] == 0x07:
                    info["response"] = "abort"
                    self.abort_count += 1
                    reward = 50.0  # Abort on association: error path triggered
                else:
                    info["response"] = "unknown_assoc"
                    reward = 5.0

            except socket.timeout:
                info["response"] = "assoc_timeout"
                info["hang"] = True
                self.hang_count += 1
                reward = 15.0  # Hang on association

            sock.close()

        except ConnectionResetError:
            info["response"] = "reset"
            reward = 3.0
        except ConnectionRefusedError:
            info["response"] = "refused"
            # Check if crash
            time.sleep(0.5)
            try:
                check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                check.settimeout(2.0)
                check.connect((self.target_host, self.target_port))
                check.close()
            except:
                info["crash"] = True
                reward = 100.0
        except Exception as e:
            info["response"] = f"error"
            reward = 2.0

        self.response_history.append(info["response"])
        return reward, info

    def reset(self, seed=None, options=None):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        self.reset_fields()
        self.step_count = 0
        self.episode_reward = 0
        self.response_history = []
        # Don't reset counters - track across episodes

        return self._get_obs(), {}

    def step(self, action):
        """Apply a semantic mutation and test."""
        # Decode action
        field_name, value, desc = ALL_MUTATIONS[action]

        # Apply mutation
        self.current_fields[field_name] = value

        # Send and evaluate
        reward, info = self._send_session()

        self.step_count += 1
        self.episode_reward += reward

        info["field_mutated"] = field_name
        info["new_value"] = value
        info["current_fields"] = dict(self.current_fields)
        info["episode_reward"] = self.episode_reward

        truncated = self.step_count >= self.max_steps
        terminated = info.get("crash", False)

        return self._get_obs(), reward, terminated, truncated, info

    def render(self, mode="human"):
        print(f"Step {self.step_count} | Fields: {self.current_fields}")
        print(f"  Hangs: {self.hang_count}, Accepts: {self.accept_count}, Aborts: {self.abort_count}")


# ============================================================================
# Training with Progress Callback
# ============================================================================

class TrainingProgressCallback:
    """Callback to show training progress."""

    def __init__(self, log_interval=100):
        self.log_interval = log_interval
        self.episode_count = 0
        self.total_reward = 0
        self.hangs = 0
        self.crashes = 0

    def __call__(self, locals_, globals_):
        """Called after each step."""
        if 'infos' in locals_:
            for info in locals_['infos']:
                if info.get('hang'):
                    self.hangs += 1
                if info.get('crash'):
                    self.crashes += 1

        if locals_.get('num_timesteps', 0) % self.log_interval == 0:
            timesteps = locals_.get('num_timesteps', 0)
            logger.info(f"Timesteps: {timesteps} | Hangs: {self.hangs} | Crashes: {self.crashes}")

        return True
