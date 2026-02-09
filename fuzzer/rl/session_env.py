#!/usr/bin/env python3
"""
Multi-PDU session fuzzer environment.

Instead of fuzzing a single ASSOC_RQ, this environment:
  1. Sends a VALID association request (accepted by Orthanc)
  2. Then sends FUZZED PDATA PDUs (actual DICOM commands/data)
  3. Reward comes from how the server processes the data-level PDUs

This reaches deeper parser code paths where mmt-security rules fire
(command_field, message_id, status, data_set_type, etc.)

v2: DICOM-aware mutations for PDATA PDUs:
  - Length field corruption (PDU length, PDV length)
  - DIMSE command field targeting
  - Message control header manipulation
"""

import os
import sys
import random
import struct
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

from fuzzer.rl.reward import RewardComputer, CRITICAL_FIELDS_PDATA
from fuzzer.rl.server_monitor import ServerMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# v2: Enhanced Mutation Types (same as environment.py)
# ============================================================================

# Basic mutations
MUT_FLIP = 0           # Flip random bit in byte
MUT_REPLACE = 1        # Replace with random byte
MUT_INCREMENT = 2      # Increment byte (mod 256)
MUT_ZERO = 3           # Set to 0x00
MUT_MAX = 4            # Set to 0xFF

# DICOM-aware mutations
MUT_DECREMENT = 5      # Decrement byte (mod 256)
MUT_BOUNDARY = 6       # Set to boundary value
MUT_LENGTH_ZERO = 7    # Set length field to 0
MUT_LENGTH_MAX = 8     # Set length field to max
MUT_LENGTH_OFF1 = 9    # Length field off by +1
MUT_LENGTH_OFF_NEG = 10  # Length field off by -1
MUT_NULL_INJECT = 11   # Insert null byte
MUT_SWAP_BYTES = 12    # Swap with adjacent byte
MUT_REPEAT_BYTE = 13   # Repeat byte value

N_MUTATION_TYPES = 14

# Boundary values
BOUNDARY_VALUES = [
    0x00, 0x01, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF,
    0x20, 0x09, 0x0A, 0x0D,
    0x00, 0x2F, 0x3A, 0x40, 0x5B, 0x60, 0x7B,
]

# ============================================================================
# v2: PDATA PDU Structure Definitions
# ============================================================================

# PDATA PDU structure
PDATA_STRUCTURE = {
    "pdu_type": (0, 1, False),          # 0x04 for PDATA
    "reserved": (1, 2, False),          # Should be 0x00
    "pdu_length": (2, 6, True),         # 4-byte big-endian PDU length
    "pdv_length": (6, 10, True),        # 4-byte PDV item length
    "context_id": (10, 11, False),      # Presentation context ID
    "msg_control": (11, 12, False),     # Message control header
    # DIMSE command set starts at offset 12 (implicit VR LE)
    "cmd_group_len_tag": (12, 16, False),  # (0000,0000) tag
    "cmd_group_len_val": (16, 20, True),   # Command group length
    "affected_sop_tag": (20, 24, False),   # (0000,0002) tag
    "affected_sop_len": (24, 28, True),    # UID length
}

# Length field offsets for PDATA
LENGTH_FIELDS_PDATA = [
    (2, 6, "pdu_length"),       # 4-byte big-endian
    (6, 10, "pdv_length"),      # 4-byte big-endian
    (16, 20, "cmd_group_len"),  # 4-byte little-endian (DIMSE)
    (24, 28, "affected_sop_len"),  # 4-byte little-endian (DIMSE)
]

# v2: DIMSE Command Field values for targeted mutations
DIMSE_COMMAND_FIELDS = {
    0x0001: "C-STORE-RQ",
    0x8001: "C-STORE-RSP",
    0x0020: "C-FIND-RQ",
    0x8020: "C-FIND-RSP",
    0x0010: "C-GET-RQ",
    0x8010: "C-GET-RSP",
    0x0021: "C-MOVE-RQ",
    0x8021: "C-MOVE-RSP",
    0x0030: "C-ECHO-RQ",
    0x8030: "C-ECHO-RSP",
    0x0100: "N-EVENT-REPORT-RQ",
    0x0110: "N-GET-RQ",
    0x0120: "N-SET-RQ",
    0x0130: "N-ACTION-RQ",
    0x0140: "N-CREATE-RQ",
    0x0150: "N-DELETE-RQ",
    0xFFFF: "INVALID",
}

# v2: High-priority mutation targets for PDATA
# (offset, size, name, mutation_weight)
PDATA_HOTSPOTS = [
    (2, 4, "pdu_length", 3.0),      # PDU length - buffer overflow potential
    (6, 4, "pdv_length", 3.0),      # PDV length - buffer overflow potential
    (10, 1, "context_id", 2.0),     # Context ID - may cause lookup failure
    (11, 1, "msg_control", 2.5),    # Message control - fragmentation confusion
    (16, 4, "cmd_group_len", 2.5),  # Command length - parsing issues
]

# PDATA PDU max observable length
# v2: Reduced from 512 to 256 for faster training (most PDATA commands are < 200 bytes)
MAX_PDATA_LEN = 256

# v2: Timeout settings (reduced for faster iteration)
SEND_TIMEOUT = 1.5  # Was 3.0 - server should respond quickly if it will
CONNECT_TIMEOUT = 3.0


def build_valid_assoc_rq(called_ae="ORTHANC", calling_ae="FUZZER"):
    """Build a valid ASSOC_RQ that Orthanc will accept."""
    import struct

    called = called_ae.ljust(16).encode('ascii')[:16]
    calling = calling_ae.ljust(16).encode('ascii')[:16]

    # Application Context: 1.2.840.10008.3.1.1.1
    app_ctx_uid = b'1.2.840.10008.3.1.1.1'
    app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

    # Presentation Context: Verification SOP + Implicit VR Little Endian
    abstract_uid = b'1.2.840.10008.1.1'  # Verification SOP Class
    abstract = struct.pack('>BBH', 0x30, 0, len(abstract_uid)) + abstract_uid

    transfer_uid = b'1.2.840.10008.1.2'  # Implicit VR Little Endian
    transfer = struct.pack('>BBH', 0x40, 0, len(transfer_uid)) + transfer_uid

    pres_ctx_data = struct.pack('>BBBB', 1, 0, 0, 0) + abstract + transfer
    pres_ctx = struct.pack('>BBH', 0x20, 0, len(pres_ctx_data)) + pres_ctx_data

    # User Information
    max_pdu = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', 16382)
    impl_uid_data = b'1.2.826.0.1.3680043.9.3811.2.0.2'
    impl_uid = struct.pack('>BBH', 0x52, 0, len(impl_uid_data)) + impl_uid_data
    impl_name_data = b'NETWORKFUZZER'
    impl_name = struct.pack('>BBH', 0x55, 0, len(impl_name_data)) + impl_name_data
    user_info_data = max_pdu + impl_uid + impl_name
    user_info = struct.pack('>BBH', 0x50, 0, len(user_info_data)) + user_info_data

    # Variable items
    variable = app_ctx + pres_ctx + user_info

    # PDU header
    reserved32 = b'\x00' * 32
    pdu_data = struct.pack('>H', 1) + b'\x00\x00' + called + calling + reserved32 + variable
    pdu = struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data

    return pdu


def build_cecho_pdata():
    """Build a valid C-ECHO-RQ PDATA PDU."""
    # DIMSE C-ECHO-RQ command set (as implicit VR LE dataset)
    # (0000,0002) Affected SOP Class UID = 1.2.840.10008.1.1
    uid = b'1.2.840.10008.1.1'
    if len(uid) % 2: uid += b'\x00'
    elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid

    # (0000,0100) Command Field = 0x0030 (C-ECHO-RQ)
    elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)

    # (0000,0110) Message ID = 1
    elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, 1)

    # (0000,0800) Data Set Type = 0x0101 (no dataset)
    elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0101)

    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0800

    # (0000,0000) Command Group Length
    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set

    # PDV Item: context_id=1, message_control_header=0x03 (command, last fragment)
    pdv_data = struct.pack('>B', 1) + struct.pack('>B', 0x03) + command_set
    pdv_item = struct.pack('>I', len(pdv_data)) + pdv_data

    # PDATA PDU
    pdata_data = pdv_item
    pdata = struct.pack('>BBi', 0x04, 0, len(pdata_data)) + pdata_data

    return pdata


class DicomSessionEnv(gym.Env):
    """
    Multi-PDU DICOM session fuzzing environment (v2).

    Episode flow:
      1. Start from a valid PDATA seed (C-ECHO, C-STORE, C-FIND command)
      2. Agent applies mutations to the PDATA PDU
      3. At episode end: send valid ASSOC_RQ, then mutated PDATA, observe response

    This reaches DICOM command-level parsing where mmt-security rules check
    command_field, message_id, status, data_set_type, etc.

    v2: DICOM-aware mutations targeting:
      - PDU/PDV length fields
      - Message control header
      - DIMSE command fields
    """

    metadata = {"render_modes": ["human"]}

    def __init__(self, seed_pdus=None, target_host=None, target_port=4242,
                 called_ae="ORTHANC", max_steps=30, max_pdu_len=MAX_PDATA_LEN):
        super().__init__()

        self.max_pdu_len = max_pdu_len
        self.max_steps = max_steps
        self.called_ae = called_ae

        # Valid ASSOC_RQ for session setup
        self.valid_assoc_rq = build_valid_assoc_rq(called_ae=called_ae)

        # Seed PDATA PDUs
        self.seed_pdus = []
        self.seed_lengths = []
        if seed_pdus:
            for p in seed_pdus:
                raw = list(p) if isinstance(p, (bytes, bytearray)) else list(p)
                actual_len = min(len(raw), max_pdu_len)
                self.seed_lengths.append(actual_len)
                self.seed_pdus.append(self._pad_pdu(raw))
        else:
            default = build_cecho_pdata()
            self.seed_lengths.append(min(len(default), max_pdu_len))
            self.seed_pdus.append(self._pad_pdu(list(default)))

        # v2: Expanded action space with new mutation types
        self.action_space = spaces.Discrete(max_pdu_len * N_MUTATION_TYPES)
        self.observation_space = spaces.Box(
            low=0, high=255,
            shape=(max_pdu_len + 2,),
            dtype=np.float32,
        )

        # Server health monitor
        self.server_monitor = None
        if target_host:
            self.server_monitor = ServerMonitor(
                target_host=target_host,
                target_port=target_port,
                called_ae=called_ae,
            )

        # v2: Use pdu_type="pdata" for PDATA-specific field bonuses
        self.reward_computer = RewardComputer(
            target_host=target_host,
            target_port=target_port,
            called_ae=called_ae,
            server_monitor=self.server_monitor,
            pdu_type="pdata",
        )

        self.current_pdu = None
        self.seed_pdu = None
        self.seed_length = 0
        self.step_count = 0
        self.episode_reward = 0
        self.last_reward = 0
        self.mutated_positions = set()
        self.critical_field_hits = {}  # v2: Track critical field hits
        self.episode_count = 0  # v2: Track episodes for periodic health checks
        self.health_check_interval = 5  # v2: Only full health check every N episodes

    def _pad_pdu(self, pdu):
        if len(pdu) > self.max_pdu_len:
            return pdu[:self.max_pdu_len]
        return pdu + [0] * (self.max_pdu_len - len(pdu))

    def get_priority_actions(self, top_k=20):
        """
        v2: Get high-priority actions for exploration boosting.
        Returns list of (action_idx, weight) for hotspot mutations.
        """
        priority_actions = []
        for offset, size, name, weight in PDATA_HOTSPOTS:
            if offset < self.seed_length:
                # Add actions for each mutation type on this hotspot
                for mut_type in [MUT_LENGTH_ZERO, MUT_LENGTH_MAX, MUT_LENGTH_OFF1,
                                 MUT_LENGTH_OFF_NEG, MUT_BOUNDARY]:
                    action_idx = offset * N_MUTATION_TYPES + mut_type
                    if action_idx < self.action_space.n:
                        priority_actions.append((action_idx, weight))
        return sorted(priority_actions, key=lambda x: -x[1])[:top_k]

    def _get_obs(self):
        step_frac = self.step_count / self.max_steps * 255.0
        div_frac = len(self.mutated_positions) / max(self.seed_length, 1) * 255.0
        return np.array(self.current_pdu + [step_frac, min(div_frac, 255.0)],
                        dtype=np.float32)

    def _decode_action(self, action):
        return action // N_MUTATION_TYPES, action % N_MUTATION_TYPES

    def _is_length_field_start(self, offset):
        """Check if offset is the start of a known length field."""
        for start, end, name in LENGTH_FIELDS_PDATA:
            if offset == start:
                return (start, end, name)
        return None

    def _is_critical_field(self, offset):
        """Check if offset is within a critical PDATA field."""
        for (start, end), (field_name, bonus) in CRITICAL_FIELDS_PDATA.items():
            if start <= offset < end:
                return (field_name, bonus)
        return None

    def _apply_mutation(self, offset, mutation_type):
        """
        Apply mutation to PDATA PDU.

        v2: Extended mutations including DICOM-aware mutations for PDATA:
          - PDU/PDV length corruption
          - DIMSE command field targeting
          - Message control header manipulation
        """
        if offset >= len(self.current_pdu):
            return
        original = self.current_pdu[offset]

        # Basic mutations
        if mutation_type == MUT_FLIP:
            self.current_pdu[offset] = original ^ (1 << random.randint(0, 7))
        elif mutation_type == MUT_REPLACE:
            self.current_pdu[offset] = random.randint(0, 255)
        elif mutation_type == MUT_INCREMENT:
            self.current_pdu[offset] = (original + 1) % 256
        elif mutation_type == MUT_ZERO:
            self.current_pdu[offset] = 0x00
        elif mutation_type == MUT_MAX:
            self.current_pdu[offset] = 0xFF

        # v2: DICOM-aware mutations
        elif mutation_type == MUT_DECREMENT:
            self.current_pdu[offset] = (original - 1) % 256

        elif mutation_type == MUT_BOUNDARY:
            self.current_pdu[offset] = random.choice(BOUNDARY_VALUES)

        elif mutation_type == MUT_LENGTH_ZERO:
            length_field = self._is_length_field_start(offset)
            if length_field:
                start, end, name = length_field
                for i in range(start, min(end, len(self.current_pdu))):
                    self.current_pdu[i] = 0x00
                    if self.current_pdu[i] != self.seed_pdu[i]:
                        self.mutated_positions.add(i)
            else:
                self.current_pdu[offset] = 0x00

        elif mutation_type == MUT_LENGTH_MAX:
            length_field = self._is_length_field_start(offset)
            if length_field:
                start, end, name = length_field
                for i in range(start, min(end, len(self.current_pdu))):
                    self.current_pdu[i] = 0xFF
                    if self.current_pdu[i] != self.seed_pdu[i]:
                        self.mutated_positions.add(i)
            else:
                self.current_pdu[offset] = 0xFF

        elif mutation_type == MUT_LENGTH_OFF1:
            length_field = self._is_length_field_start(offset)
            if length_field:
                start, end, name = length_field
                field_len = end - start
                # PDATA uses big-endian for PDU/PDV lengths, but DIMSE uses little-endian
                is_dimse = offset >= 12
                if field_len == 4 and end <= len(self.current_pdu):
                    if is_dimse:
                        val = struct.unpack('<I', bytes(self.current_pdu[start:end]))[0]
                        val = min(val + 1, 0xFFFFFFFF)
                        new_bytes = struct.pack('<I', val)
                    else:
                        val = struct.unpack('>I', bytes(self.current_pdu[start:end]))[0]
                        val = min(val + 1, 0xFFFFFFFF)
                        new_bytes = struct.pack('>I', val)
                    for i, b in enumerate(new_bytes):
                        self.current_pdu[start + i] = b
                        if self.current_pdu[start + i] != self.seed_pdu[start + i]:
                            self.mutated_positions.add(start + i)
            else:
                self.current_pdu[offset] = (original + 1) % 256

        elif mutation_type == MUT_LENGTH_OFF_NEG:
            length_field = self._is_length_field_start(offset)
            if length_field:
                start, end, name = length_field
                field_len = end - start
                is_dimse = offset >= 12
                if field_len == 4 and end <= len(self.current_pdu):
                    if is_dimse:
                        val = struct.unpack('<I', bytes(self.current_pdu[start:end]))[0]
                        val = max(val - 1, 0)
                        new_bytes = struct.pack('<I', val)
                    else:
                        val = struct.unpack('>I', bytes(self.current_pdu[start:end]))[0]
                        val = max(val - 1, 0)
                        new_bytes = struct.pack('>I', val)
                    for i, b in enumerate(new_bytes):
                        self.current_pdu[start + i] = b
                        if self.current_pdu[start + i] != self.seed_pdu[start + i]:
                            self.mutated_positions.add(start + i)
            else:
                self.current_pdu[offset] = (original - 1) % 256

        elif mutation_type == MUT_NULL_INJECT:
            self.current_pdu[offset] = 0x00

        elif mutation_type == MUT_SWAP_BYTES:
            if offset + 1 < len(self.current_pdu):
                next_byte = self.current_pdu[offset + 1]
                self.current_pdu[offset + 1] = original
                self.current_pdu[offset] = next_byte
                if self.current_pdu[offset + 1] != self.seed_pdu[offset + 1]:
                    self.mutated_positions.add(offset + 1)
                elif offset + 1 in self.mutated_positions:
                    self.mutated_positions.discard(offset + 1)

        elif mutation_type == MUT_REPEAT_BYTE:
            repeat_count = random.randint(2, 4)
            for i in range(repeat_count):
                pos = offset + i
                if pos < len(self.current_pdu):
                    self.current_pdu[pos] = original
                    if self.current_pdu[pos] != self.seed_pdu[pos]:
                        self.mutated_positions.add(pos)
                    elif pos in self.mutated_positions:
                        self.mutated_positions.discard(pos)

        # Track mutation
        if self.current_pdu[offset] != self.seed_pdu[offset]:
            self.mutated_positions.add(offset)
        elif offset in self.mutated_positions:
            self.mutated_positions.discard(offset)

        # v2: Track critical field hits
        for (start, end), (field_name, _) in CRITICAL_FIELDS_PDATA.items():
            if start <= offset < end:
                self.critical_field_hits[field_name] = \
                    self.critical_field_hits.get(field_name, 0) + 1
                break

    def _build_session_packets(self):
        """Build a full DICOM session: valid ASSOC_RQ + mutated PDATA."""
        effective_len = self.seed_length
        if self.mutated_positions:
            effective_len = max(effective_len, max(self.mutated_positions) + 1)
        effective_len = min(effective_len, self.max_pdu_len)

        pdata_bytes = bytes(self.current_pdu[:effective_len])

        # Build release PDUs
        release_rq = struct.pack('>BBi', 0x05, 0, 4) + b'\x00' * 4
        release_rp = struct.pack('>BBi', 0x06, 0, 4) + b'\x00' * 4

        session = [self.valid_assoc_rq, pdata_bytes, release_rq, release_rp]
        return wrap_tcp_ip(session)

    def _compute_divergence(self):
        diffs = sum(1 for i in range(self.seed_length)
                    if self.current_pdu[i] != self.seed_pdu[i])
        return diffs / max(self.seed_length, 1)

    def _evaluate_final(self):
        """Send the full session to the target and evaluate with server metrics."""
        self.episode_count += 1  # v2: Track episode number

        try:
            packets = self._build_session_packets()
            effective_len = self.seed_length
            if self.mutated_positions:
                effective_len = max(effective_len, max(self.mutated_positions) + 1)
            effective_len = min(effective_len, self.max_pdu_len)
            pdu_bytes = bytes(self.current_pdu[:effective_len])

            # mmt-security analysis on session PCAP (ASSOC_RQ + PDATA)
            mmt_reward = 0.0
            mmt_info = {"mmt_alerts": 0, "new_rules": 0, "field_bonus": 0, "field_hits": {}}
            if self.reward_computer._mmt_available and packets:
                mmt_reward, mmt_info = self.reward_computer._mmt_reward(packets)

            # v2: Compute field bonus for critical field mutations
            field_bonus, field_hits = self.reward_computer.compute_field_bonus(
                self.mutated_positions)
            mmt_info["field_bonus"] = round(field_bonus, 1)
            mmt_info["field_hits"] = field_hits

            # v2: Only do full health check periodically to speed up training
            do_health_check = (self.episode_count % self.health_check_interval == 0)

            # Pre-fuzz health check
            health_before = None
            if self.server_monitor and do_health_check:
                try:
                    health_before = self.server_monitor.check_health(full=False)  # v2: Quick check
                except Exception as e:
                    logger.debug(f"Pre-fuzz health check failed: {e}")

            # Live testing: send valid ASSOC_RQ then fuzzed PDATA
            live_reward = 0.0
            live_info = {"live_response": "none", "crash": False,
                         "response_time_ms": 0, "parser_depth": 0}
            if self.reward_computer.target_host:
                live_reward, live_info = self._send_session_live(pdu_bytes)

            # Post-fuzz health check (v2: only when we did pre-check)
            degradation_info = {}
            if self.server_monitor and health_before and do_health_check:
                try:
                    import time as _time
                    _time.sleep(0.1)  # v2: Reduced from 0.3
                    health_after = self.server_monitor.check_health(full=False)  # v2: Quick check
                    degradation_info = self.server_monitor.compute_degradation(
                        health_before, health_after)
                    live_info.update(degradation_info)
                except Exception as e:
                    logger.debug(f"Post-fuzz health check failed: {e}")

            reward = mmt_reward + live_reward
            info = {**live_info, "mmt_alerts": mmt_info.get("alerts", 0),
                    "new_rules": mmt_info.get("new_rules", 0)}
        except Exception as e:
            reward = 0.0
            info = {"error": str(e)}
            degradation_info = {}

        reward += 1.0  # Undo step penalty

        divergence = self._compute_divergence()
        info["divergence"] = divergence
        info["mutated_positions"] = len(self.mutated_positions)

        response = info.get("live_response", "none")
        parser_depth = info.get("parser_depth", 0)
        response_ms = info.get("response_time_ms", 0)

        resp_score = max(parser_depth * 3.0, 1.0)

        if response == "accept" and divergence > 0.15:
            resp_score = 25.0
        elif response == "accept" and divergence > 0.05:
            resp_score = 10.0
        elif response == "accept" and divergence <= 0.05:
            resp_score = 1.0

        if info.get("crash", False):
            resp_score = 100.0

        time_bonus = 10.0 if response_ms > 100 else (3.0 if response_ms > 20 else (1.0 if response_ms > 10 else 0.0))
        novelty_bonus = 5.0 if info.get("response_novelty", False) else 0.0
        div_bonus = 1.0 + min(divergence * 5.0, 3.0)
        mmt_bonus = info.get("mmt_alerts", 0) * 5.0 + info.get("new_rules", 0) * 10.0

        # Server health degradation bonus
        impact_score = degradation_info.get("impact_score", 0)
        health_bonus = 0.0
        if impact_score > 50:
            health_bonus = 30.0
        elif impact_score > 20:
            health_bonus = 15.0
        elif impact_score > 5:
            health_bonus = 5.0

        if degradation_info.get("echo_lost", False):
            health_bonus += 20.0
        if degradation_info.get("assoc_lost", False):
            health_bonus += 15.0
        if degradation_info.get("connections_lost", 0) > 0:
            health_bonus += degradation_info["connections_lost"] * 5.0

        echo_delta = degradation_info.get("echo_latency_delta_ms", 0)
        if echo_delta > 500:
            health_bonus += 15.0
        elif echo_delta > 100:
            health_bonus += 8.0
        elif echo_delta > 20:
            health_bonus += 3.0

        # v2: Include field bonus in final reward
        field_bonus = mmt_info.get("field_bonus", 0)
        final_reward = resp_score * div_bonus + time_bonus + novelty_bonus + mmt_bonus + health_bonus + field_bonus
        info.update({"final_reward": final_reward, "resp_score": resp_score,
                     "div_bonus": div_bonus, "time_bonus": time_bonus,
                     "novelty_bonus": novelty_bonus, "mmt_bonus": mmt_bonus,
                     "health_bonus": health_bonus, "field_bonus": field_bonus,
                     "field_hits": mmt_info.get("field_hits", {})})

        return final_reward, info

    def _send_session_live(self, pdu_bytes):
        """
        Send valid ASSOC_RQ then fuzzed PDATA to live target.

        v2 Optimizations:
          - Reduced timeouts for faster iteration
          - TCP_NODELAY for lower latency
          - Better error differentiation
        """
        import socket
        import time

        info = {"live_response": "none", "crash": False,
                "response_time_ms": 0, "reject_source": "", "reject_reason": "",
                "parser_depth": 0, "response_novelty": False}
        reward = 0.0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # v2: Reduce latency
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect((self.reward_computer.target_host,
                          self.reward_computer.target_port))

            # Step 1: Send valid ASSOC_RQ
            sock.sendall(self.valid_assoc_rq)
            sock.settimeout(2.0)  # Association should be fast
            assoc_resp = sock.recv(4096)

            if not assoc_resp or assoc_resp[0] != 0x02:
                # Association not accepted — can't test PDATA
                info["live_response"] = "assoc_rejected"
                info["parser_depth"] = 0
                sock.close()
                return 2.0, info

            # Step 2: Association accepted! Now send fuzzed PDATA
            t_start = time.monotonic()
            sock.sendall(pdu_bytes)
            sock.settimeout(SEND_TIMEOUT)  # v2: Reduced from 3.0

            try:
                data_resp = sock.recv(4096)
                t_end = time.monotonic()
                response_ms = (t_end - t_start) * 1000.0
                info["response_time_ms"] = round(response_ms, 1)

                if not data_resp:
                    info["live_response"] = "session_closed"
                    info["parser_depth"] = 3.0
                    reward = 8.0
                elif data_resp[0] == 0x04:
                    # PDATA response — server processed our command!
                    info["live_response"] = "pdata_response"
                    info["parser_depth"] = 5.0
                    reward = 20.0
                    # v2: Check if response indicates error status
                    if len(data_resp) > 20:
                        # Could parse DIMSE status here for more reward signal
                        pass
                elif data_resp[0] == 0x07:
                    info["live_response"] = "session_abort"
                    info["parser_depth"] = 4.0
                    reward = 15.0
                    # v2: Parse abort source/reason
                    if len(data_resp) >= 10:
                        info["reject_source"] = f"abort-source-{data_resp[8]}"
                        info["reject_reason"] = f"abort-reason-{data_resp[9]}"
                elif data_resp[0] == 0x06:
                    info["live_response"] = "release"
                    info["parser_depth"] = 3.5
                    reward = 10.0
                else:
                    info["live_response"] = f"data_0x{data_resp[0]:02x}"
                    info["parser_depth"] = 3.0
                    reward = 12.0  # v2: Unknown response is interesting

                # v2: More aggressive time bonus
                if response_ms > 500:
                    reward += 20.0  # Server really struggled
                elif response_ms > 100:
                    reward += 10.0
                elif response_ms > 50:
                    reward += 5.0
                elif response_ms > 20:
                    reward += 3.0

            except socket.timeout:
                t_end = time.monotonic()
                info["response_time_ms"] = round((t_end - t_start) * 1000.0, 1)
                info["live_response"] = "pdata_timeout"
                info["parser_depth"] = 5.0
                reward = 50.0

                # v2: Quick crash check with shorter timeout
                try:
                    check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    check.settimeout(1.0)
                    check.connect((self.reward_computer.target_host,
                                   self.reward_computer.target_port))
                    check.close()
                except Exception:
                    info["crash"] = True
                    reward += 50.0

            sock.close()

        except ConnectionResetError:
            info["live_response"] = "session_reset"
            info["parser_depth"] = 1.0
            reward = 3.0

        except BrokenPipeError:
            info["live_response"] = "broken_pipe"
            info["parser_depth"] = 1.0
            reward = 5.0

        except Exception as e:
            info["live_response"] = f"error:{e}"
            reward = 2.0

        return reward, info

    def reset(self, seed=None, options=None):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        idx = random.randint(0, len(self.seed_pdus) - 1)
        self.current_pdu = list(self.seed_pdus[idx])
        self.seed_pdu = list(self.seed_pdus[idx])
        self.seed_length = self.seed_lengths[idx]
        self.step_count = 0
        self.episode_reward = 0
        self.last_reward = 0
        self.mutated_positions = set()
        self.critical_field_hits = {}  # v2: Reset critical field tracking
        self.reward_computer.reset_episode()

        return self._get_obs(), {}

    def step(self, action):
        """
        Apply mutation to PDATA PDU.

        v2: Enhanced per-step rewards with critical field bonuses.
        """
        offset, mutation_type = self._decode_action(action)
        in_pdu = offset < self.seed_length
        already_mutated = offset in self.mutated_positions

        # Check if targeting critical field BEFORE mutation
        critical_field = self._is_critical_field(offset)

        self._apply_mutation(offset, mutation_type)
        self.step_count += 1

        if not in_pdu:
            step_reward = -0.3
        elif not already_mutated and offset in self.mutated_positions:
            step_reward = 0.5
            # v2: Bonus for critical field targeting
            if critical_field:
                field_name, bonus = critical_field
                hit_count = self.critical_field_hits.get(field_name, 0)
                if hit_count == 1:
                    step_reward += bonus * 0.3
                else:
                    step_reward += bonus * 0.1
        elif already_mutated and offset not in self.mutated_positions:
            step_reward = -0.3
        else:
            step_reward = 0.0

        # v2: Bonus for using DICOM-aware mutation types
        if mutation_type >= MUT_DECREMENT:
            step_reward += 0.1

        truncated = self.step_count >= self.max_steps
        terminated = False
        info = {"step": self.step_count, "mutations": len(self.mutated_positions),
                "critical_hits": dict(self.critical_field_hits)}

        if truncated:
            final_reward, eval_info = self._evaluate_final()
            step_reward += final_reward
            info.update(eval_info)
            terminated = eval_info.get("crash", False)

        self.last_reward = step_reward
        self.episode_reward += step_reward
        info["episode_reward"] = self.episode_reward

        return self._get_obs(), step_reward, terminated, truncated, info

    def render(self, mode="human"):
        pdu = bytes(self.current_pdu[:20])
        hex_str = ' '.join(f'{b:02x}' for b in pdu)
        print(f"Step {self.step_count} | mutations={len(self.mutated_positions)} | "
              f"first20=[{hex_str}]")
