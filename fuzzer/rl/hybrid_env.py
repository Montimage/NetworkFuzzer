#!/usr/bin/env python3
"""
Hybrid DICOM Fuzzing Environment.

Combines multiple fuzzing strategies:
1. SEMANTIC: DICOM-aware field mutations (pass initial validation)
2. AGGRESSIVE: Payload injection (format strings, path traversal, overflow)
3. STATE: Protocol state confusion (out-of-order PDUs, invalid sequences)

The RL agent learns to combine these strategies for maximum impact.
"""

import os
import sys
import math
import random
import struct
import socket
import time
import glob
import logging
import threading

import numpy as np

from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import gymnasium as gym
    from gymnasium import spaces
except ImportError:
    import gym
    from gym import spaces

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fuzzer.rl.dicom_semantics import (
    MESSAGE_ID_MUTATIONS,
    COMMAND_FIELD_MUTATIONS,
    DATA_SET_TYPE_MUTATIONS,
    CONTEXT_ID_MUTATIONS,
    PDV_FLAGS_MUTATIONS,
    MAX_PDU_LENGTH_MUTATIONS,
    build_smart_assoc_rq,
    build_multi_context_assoc_rq,
    build_smart_cecho_pdata,
    build_malformed_dimse_pdata,
    MALFORMED_DIMSE_ATTACKS,
    STORAGE_SOP_CLASSES,
    TRANSFER_SYNTAXES,
)
from fuzzer.rl.server_monitor import ServerMonitor, ProcessMonitor, AsanMonitor, CoverageMonitor
from fuzzer.rl.log_monitor import ServerLogMonitor, create_log_monitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# Attack Payloads (from aggressive mode)
# ============================================================================

FORMAT_STRING_PAYLOADS = [
    b'%s%s%s%s%s%s%s%s',
    b'%n%n%n%n%n%n',
    b'%x' * 50,
    b'%08x.' * 20,
    b'AAAA%08x.%08x.%08x.%08x.%n',
]

PATH_TRAVERSAL_PAYLOADS = [
    b'../../../etc/passwd',
    b'....//....//....//etc/passwd',
    b'..\\..\\..\\windows\\system32\\config\\sam',
    b'/etc/passwd%00.dcm',
    b'....//....//....//etc/shadow',
]

BUFFER_OVERFLOW_PAYLOADS = [
    b'A' * 16,      # AE title boundary
    b'A' * 17,      # Just over AE title
    b'A' * 64,      # UID boundary
    b'A' * 65,      # Just over UID
    b'A' * 256,     # Larger overflow
    b'A' * 1024,    # 1KB
    b'A' * 4096,    # 4KB
]

NULL_INJECTION_PAYLOADS = [
    b'\x00' * 8,
    b'VALID\x00HIDDEN',
    b'\x00\x00\x00\x00',
    b'A' * 10 + b'\x00' + b'B' * 10,
]

SPECIAL_CHAR_PAYLOADS = [
    b'\xff\xfe',           # BOM
    b'\x00\x00\x00\x00',   # Nulls
    b'\r\n\r\n',           # CRLF injection
    b"'; DROP TABLE;--",   # SQL-like
    b'<script>alert(1)</script>',  # XSS-like
]

# ============================================================================
# CVE-Inspired Attack Payloads
# ============================================================================

# Integer overflow payloads (CVE-2024-28130 type conversion issues)
INTEGER_OVERFLOW_PAYLOADS = [
    b'\xff\xff\xff\xff',           # 0xFFFFFFFF - max uint32
    b'\x7f\xff\xff\xff',           # 0x7FFFFFFF - max int32
    b'\x80\x00\x00\x00',           # 0x80000000 - min int32 (negative)
    b'\xff\xff\xff\x7f',           # Little-endian max int32
    b'\x00\x00\x00\x80',           # Little-endian min int32
    b'\xff\xff',                   # 0xFFFF - max uint16
    b'\xff\x7f',                   # 0x7FFF - max int16 LE
    b'\x00\x80',                   # 0x8000 - overflow to negative
]

# Path traversal UIDs (CVE-2022-2119/2120)
PATH_TRAVERSAL_UID_PAYLOADS = [
    b'1.2.3/../../../etc/passwd',
    b'1.2.3/..\\..\\..\\windows\\system32\\config\\sam',
    b'../../../orthanc.json',
    b'1.2.3/%2e%2e/%2e%2e/etc/passwd',  # URL encoded
    b'1.2.3/....//....//etc/shadow',
    b'1.2.3\x00/../../../etc/passwd',   # Null byte injection
]

# Large allocation attacks (trigger OOM, heap issues)
LARGE_ALLOC_PAYLOADS = [
    b'A' * 65536,          # 64KB
    b'A' * 262144,         # 256KB
    b'\x00' * 65536,       # 64KB nulls
    b'\xff' * 32768,       # 32KB 0xFF bytes
]

# RLE-style compressed data attacks (CVE in DcmRLEDecoder)
RLE_ATTACK_PAYLOADS = [
    b'\x00\x00\x00\x01' + b'\xff' * 100,  # Malformed RLE header
    b'\x01\x00\x00\x00' + b'\x80' * 50,   # Invalid segment
    b'\xff\xff\xff\xff' + b'A' * 20,     # Overflow count
]

# Nested/recursive structure attacks
NESTED_SEQUENCE_PAYLOADS = [
    # Deeply nested sequence (can cause stack overflow)
    b'\xfe\xff\x00\xe0' * 100,  # Many SQ delimiters
    b'\xfe\xff\x0d\xe0' * 50,   # Many item delimiters
]

# Type confusion attacks (mixing VRs)
TYPE_CONFUSION_PAYLOADS = [
    b'PN' + b'\xff\xff\xff\xff',  # Person Name with huge length
    b'SQ' + b'\x00\x00\x00\x00',  # Sequence with zero length
    b'OB' + b'\xff\xff\xff\xff',  # Other Byte with max length
    b'UN' + struct.pack('<I', 0xFFFFFFFF),  # Unknown VR max length
]

# ============================================================================
# Byte-Level Mutation Constants
# ============================================================================

BOUNDARY_BYTE_VALUES = [0x00, 0x01, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF]

# Critical offsets in PDATA PDUs for hotspot byte mutations
PDATA_HOTSPOT_OFFSETS = [
    (2, 6, "pdu_length", 3.0),       # 4-byte PDU length
    (6, 10, "pdv_length", 3.0),      # 4-byte PDV item length
    (10, 11, "context_id", 2.0),     # Presentation context ID
    (11, 12, "msg_control", 2.5),    # Message control header
    (16, 20, "cmd_group_len", 2.5),  # Command group length
]

SPECIAL_ATTACKS_LIST = [
    "byte_flip", "byte_length", "byte_hotspot", "byte_boundary",
    "seed_mutate", "slowloris", "fragment", "concurrent",
    "rapid_reconnect", "memory_exhaust",
    "seed_assoc", "seed_pdata", "seed_crossover",
]

# ============================================================================
# Protocol State Sequences
# ============================================================================

STATE_SEQUENCES = [
    # (name, sequence of PDU types to send)

    # === Normal baseline ===
    ("normal", ["assoc_rq", "pdata", "release_rq"]),
    ("no_release", ["assoc_rq", "pdata"]),

    # === Out-of-order attacks (send before association) ===
    ("pdata_first", ["pdata"]),                          # PDATA without association
    ("release_first", ["release_rq"]),                   # Release without association
    ("abort_first", ["abort"]),                          # Abort without association
    ("pdata_release_first", ["pdata", "release_rq"]),    # PDATA then release, no assoc

    # === Duplication attacks ===
    ("double_assoc", ["assoc_rq", "assoc_rq"]),          # Duplicate ASSOC_RQ
    ("triple_assoc", ["assoc_rq", "assoc_rq", "assoc_rq"]),
    ("double_pdata", ["assoc_rq", "pdata", "pdata"]),    # Duplicate PDATA
    ("double_release", ["assoc_rq", "pdata", "release_rq", "release_rq"]),
    ("double_abort", ["assoc_rq", "abort", "abort"]),    # Duplicate abort
    ("pdata_flood_5", ["assoc_rq", "pdata", "pdata", "pdata", "pdata", "pdata"]),
    ("pdata_flood_10", ["assoc_rq"] + ["pdata"] * 10),   # 10 duplicate PDATAs

    # === Reordering attacks ===
    ("release_before_pdata", ["assoc_rq", "release_rq", "pdata"]),  # Release then data
    ("abort_before_pdata", ["assoc_rq", "abort", "pdata"]),         # Abort then data
    ("pdata_then_assoc", ["assoc_rq", "pdata", "assoc_rq"]),        # Re-associate mid-session
    ("release_then_assoc", ["assoc_rq", "release_rq", "assoc_rq"]), # Release then re-assoc

    # === Role reversal (client sends server messages) ===
    ("client_sends_ac", ["assoc_ac"]),                   # Client sends ASSOC-AC
    ("client_sends_rj", ["assoc_rj"]),                   # Client sends ASSOC-RJ
    ("client_sends_release_rp", ["release_rp"]),         # Client sends release response
    ("ac_then_pdata", ["assoc_ac", "pdata"]),            # AC then PDATA (wrong role)

    # === Interleaved/mixed attacks ===
    ("pdata_abort_pdata", ["assoc_rq", "pdata", "abort", "pdata"]),
    ("assoc_pdata_assoc_pdata", ["assoc_rq", "pdata", "assoc_rq", "pdata"]),
    ("rapid_state_changes", ["assoc_rq", "pdata", "abort", "assoc_rq", "pdata"]),

    # === Immediate termination ===
    ("immediate_abort", ["assoc_rq", "abort"]),
    ("immediate_release", ["assoc_rq", "release_rq"]),

    # === Partial/incomplete ===
    ("assoc_only", ["assoc_rq"]),                        # Just association, nothing else
    ("empty_session", []),                               # Connect but send nothing
    ("partial_pdu", ["assoc_rq", "partial_pdu"]),        # Truncated PDU
    ("garbage_after_assoc", ["assoc_rq", "garbage"]),    # Random bytes after assoc

    # === C-STORE attacks ===
    ("cstore_normal", ["assoc_rq", "cstore_pdata", "release_rq"]),
    ("cstore_no_release", ["assoc_rq", "cstore_pdata"]),
    ("cstore_double", ["assoc_rq", "cstore_pdata", "cstore_pdata"]),
    ("cstore_then_echo", ["assoc_rq", "cstore_pdata", "pdata"]),

    # === C-FIND attacks ===
    ("cfind_normal", ["assoc_rq", "cfind_pdata", "release_rq"]),
    ("cfind_flood", ["assoc_rq", "cfind_pdata", "cfind_pdata", "cfind_pdata"]),

    # === C-MOVE attacks ===
    ("cmove_normal", ["assoc_rq", "cmove_pdata", "release_rq"]),
    ("cmove_no_release", ["assoc_rq", "cmove_pdata"]),
    ("cmove_flood", ["assoc_rq", "cmove_pdata", "cmove_pdata", "cmove_pdata"]),
    ("cmove_then_echo", ["assoc_rq", "cmove_pdata", "pdata"]),

    # === C-GET attacks ===
    ("cget_normal", ["assoc_rq", "cget_pdata", "release_rq"]),
    ("cget_no_release", ["assoc_rq", "cget_pdata"]),
    ("cget_flood", ["assoc_rq", "cget_pdata", "cget_pdata", "cget_pdata"]),
    ("cget_then_store", ["assoc_rq", "cget_pdata", "cstore_pdata"]),

    # === Cross-command attacks ===
    ("find_then_move", ["assoc_rq", "cfind_pdata", "cmove_pdata", "release_rq"]),
    ("find_then_get", ["assoc_rq", "cfind_pdata", "cget_pdata", "release_rq"]),
    ("store_then_move", ["assoc_rq", "cstore_pdata", "cmove_pdata"]),
    ("all_commands", ["assoc_rq", "pdata", "cstore_pdata", "cfind_pdata", "cmove_pdata", "cget_pdata"]),

    # === Mixed command attacks ===
    ("echo_store_find", ["assoc_rq", "pdata", "cstore_pdata", "cfind_pdata"]),
    ("store_abort_store", ["assoc_rq", "cstore_pdata", "abort", "cstore_pdata"]),

    # === Rich C-STORE sequences (multi-context ASSOC + full dataset) ===
    ("cstore_rich", ["assoc_rq_ct", "cstore_rich_pdata", "release_rq"]),
    ("cstore_mr", ["assoc_rq_mr", "cstore_mr_pdata", "release_rq"]),
    ("cstore_us", ["assoc_rq_us", "cstore_us_pdata", "release_rq"]),
    ("cstore_sc", ["assoc_rq_sc", "cstore_sc_pdata", "release_rq"]),
    ("cstore_explicit", ["assoc_rq_ct_explicit", "cstore_explicit_pdata", "release_rq"]),
]

# ============================================================================
# Hybrid Action Space
# ============================================================================

# Semantic field mutations
SEMANTIC_FIELDS = [
    ("message_id", MESSAGE_ID_MUTATIONS),
    ("command_field", COMMAND_FIELD_MUTATIONS),
    ("data_set_type", DATA_SET_TYPE_MUTATIONS),
    ("context_id", CONTEXT_ID_MUTATIONS),
    ("msg_control", PDV_FLAGS_MUTATIONS),
    ("max_pdu_length", MAX_PDU_LENGTH_MUTATIONS),
]

# Payload injection targets
INJECTION_TARGETS = [
    "called_ae",        # Called AE title in ASSOC_RQ
    "calling_ae",       # Calling AE title in ASSOC_RQ
    "abstract_syntax",  # SOP Class UID
    "transfer_syntax",  # Transfer Syntax UID
    "impl_uid",         # Implementation UID
]

# Payload types
PAYLOAD_TYPES = [
    ("format_string", FORMAT_STRING_PAYLOADS),
    ("path_traversal", PATH_TRAVERSAL_PAYLOADS),
    ("buffer_overflow", BUFFER_OVERFLOW_PAYLOADS),
    ("null_injection", NULL_INJECTION_PAYLOADS),
    ("special_chars", SPECIAL_CHAR_PAYLOADS),
    # CVE-inspired payloads
    ("integer_overflow", INTEGER_OVERFLOW_PAYLOADS),
    ("path_uid", PATH_TRAVERSAL_UID_PAYLOADS),
    ("large_alloc", LARGE_ALLOC_PAYLOADS),
    ("rle_attack", RLE_ATTACK_PAYLOADS),
    ("nested_seq", NESTED_SEQUENCE_PAYLOADS),
    ("type_confusion", TYPE_CONFUSION_PAYLOADS),
]


class HybridFuzzEnv(gym.Env):
    """
    Hybrid fuzzing environment combining semantic, aggressive, and state attacks.

    Action space is MultiDiscrete:
    - semantic_field: which DIMSE field to mutate (0 = none)
    - semantic_value: index into mutation values for that field
    - payload_type: which payload category (0 = none)
    - injection_target: where to inject payload (0 = none)
    - state_sequence: which protocol state sequence to use
    - intensity: attack intensity level (affects payload size, timing)
    """

    metadata = {"render_modes": ["human"]}

    def __init__(self, target_host=None, target_port=4242, called_ae="ORTHANC",
                 max_steps=30, log_path=None, docker_container=None,
                 server_type="orthanc"):
        super().__init__()

        self.target_host = target_host
        self.target_port = target_port
        self.called_ae = called_ae.encode() if isinstance(called_ae, str) else called_ae
        self.max_steps = max_steps

        # Build action dimensions
        self.n_semantic_fields = len(SEMANTIC_FIELDS) + 1  # +1 for "none"
        self.max_semantic_values = max(len(vals) for _, vals in SEMANTIC_FIELDS)
        self.n_payload_types = len(PAYLOAD_TYPES) + 1  # +1 for "none"
        self.n_injection_targets = len(INJECTION_TARGETS) + 1  # +1 for "none"
        self.n_state_sequences = len(STATE_SEQUENCES)
        self.n_intensities = 3  # low, medium, high

        # MultiDiscrete action space
        self.action_space = spaces.MultiDiscrete([
            self.n_semantic_fields,      # Which semantic field to mutate
            self.max_semantic_values,    # Value index for that field
            self.n_payload_types,        # Which payload type
            self.n_injection_targets,    # Where to inject
            self.n_state_sequences,      # Protocol state sequence
            self.n_intensities,          # Intensity level
        ])

        # Observation space
        # [semantic_fields(6), last_5_responses(5), counters(4), step_frac(1),
        #  log_features(5): new_errors, new_warnings, new_messages, new_locations, depth,
        #  asan/cov(5): asan_critical, asan_total, cov_new_lines, cov_new_funcs, cov_absolute]
        self.observation_space = spaces.Box(
            low=0, high=1,
            shape=(30,),
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

        # Log monitor for depth-based rewards
        self.log_monitor = None
        if log_path or docker_container:
            self.log_monitor = create_log_monitor(
                server_type=server_type,
                log_path=log_path,
                docker_container=docker_container,
            )
            logger.info(f"Log monitoring enabled: {log_path or docker_container}")

        # Current state
        self.current_fields = {}
        self.current_payloads = {}
        self.reset_state()

        # Episode tracking
        self.step_count = 0
        self.episode_reward = 0
        self.response_history = []
        self.hang_count = 0
        self.slow_count = 0
        self.crash_count = 0
        self.accept_count = 0
        self.pdata_response_count = 0

        # Log monitoring counters
        self.new_error_count = 0
        self.new_warning_count = 0
        self.new_message_count = 0
        self.new_location_count = 0
        self.depth_score = 0.0

        # Track effective combinations
        self.effective_combos = {}

    def reset_state(self):
        """Reset to valid defaults."""
        self.current_fields = {
            "message_id": 1,
            "command_field": 0x0030,  # C-ECHO-RQ
            "data_set_type": 0x0101,  # No dataset
            "context_id": 1,
            "msg_control": 0x03,      # Last fragment, command
            "max_pdu_length": 16384,
        }
        self.current_payloads = {
            "called_ae": None,
            "calling_ae": None,
            "abstract_syntax": None,
            "transfer_syntax": None,
            "impl_uid": None,
        }

    def _get_obs(self):
        """Build observation vector."""
        obs = np.zeros(30, dtype=np.float32)

        # Normalized semantic field values
        obs[0] = self.current_fields["message_id"] / 65535.0
        obs[1] = self.current_fields["command_field"] / 65535.0
        obs[2] = self.current_fields["data_set_type"] / 65535.0
        obs[3] = self.current_fields["context_id"] / 255.0
        obs[4] = self.current_fields["msg_control"] / 255.0
        obs[5] = min(self.current_fields["max_pdu_length"] / 65536.0, 1.0)

        # Response history (last 5)
        response_map = {
            "none": 0, "accept": 0.2, "reject": 0.3, "abort": 0.5,
            "timeout": 0.8, "reset": 0.4, "pdata": 0.9, "closed": 0.6,
            "refused": 0.7, "crash": 1.0
        }
        for i, resp in enumerate(self.response_history[-5:]):
            obs[6 + i] = response_map.get(resp, 0.5)

        # Counters
        obs[11] = min(self.hang_count / 10.0, 1.0)
        obs[12] = min(self.crash_count / 5.0, 1.0)
        obs[13] = min(self.accept_count / 20.0, 1.0)
        obs[14] = min(self.pdata_response_count / 10.0, 1.0)

        # Current attack state
        obs[15] = 1.0 if any(self.current_payloads.values()) else 0.0  # Has payload
        obs[16] = self.step_count / self.max_steps

        # Log-based features (for depth exploration)
        obs[17] = min(self.new_error_count / 20.0, 1.0)
        obs[18] = min(self.new_warning_count / 50.0, 1.0)
        obs[19] = min(self.new_message_count / 30.0, 1.0)
        obs[20] = min(self.new_location_count / 30.0, 1.0)
        obs[21] = min(self.depth_score / 100.0, 1.0)

        # Padding (formerly obs[22-24])
        obs[22] = 0
        obs[23] = 0
        obs[24] = 0

        # ASAN/Coverage features (25-29)
        # obs[25-29] are left as 0 for HybridFuzzEnv (no monitor integration here)

        return obs

    def _build_assoc_rq(self, intensity):
        """Build ASSOC_RQ with current payloads."""
        # Determine called/calling AE
        called = self.current_payloads.get("called_ae") or self.called_ae
        calling = self.current_payloads.get("calling_ae") or b"FUZZER"

        # Determine UIDs
        abstract = self.current_payloads.get("abstract_syntax")
        transfer = self.current_payloads.get("transfer_syntax")

        # Max PDU length from semantic mutations
        max_pdu = self.current_fields.get("max_pdu_length", 16384)

        return build_smart_assoc_rq(
            called_ae=called,
            calling_ae=calling,
            max_pdu_length=max_pdu,
            abstract_syntax=abstract,
            transfer_syntax=transfer,
        )

    def _build_pdata(self):
        """Build PDATA with current semantic field values."""
        return build_smart_cecho_pdata(
            context_id=self.current_fields["context_id"],
            msg_control=self.current_fields["msg_control"],
            command_field=self.current_fields["command_field"],
            message_id=self.current_fields["message_id"],
            data_set_type=self.current_fields["data_set_type"],
        )

    def _build_pdu(self, pdu_type, intensity):
        """Build a PDU of the specified type."""
        if pdu_type == "assoc_rq":
            return self._build_assoc_rq(intensity)
        elif pdu_type == "pdata":
            return self._build_pdata()
        elif pdu_type == "release_rq":
            return struct.pack('>BBi', 0x05, 0, 4) + b'\x00\x00\x00\x00'
        elif pdu_type == "abort":
            return struct.pack('>BBi', 0x07, 0, 4) + b'\x00\x00\x00\x00'
        elif pdu_type == "assoc_ac":
            # Client shouldn't send this - test server handling
            return struct.pack('>BBi', 0x02, 0, 4) + b'\x00\x00\x00\x00'
        elif pdu_type == "assoc_rj":
            # Client shouldn't send this either
            return struct.pack('>BBi', 0x03, 0, 4) + b'\x00\x01\x01\x01'
        else:
            return self._build_pdata()

    def _send_sequence(self, sequence_name, intensity):
        """Send a sequence of PDUs and return response info."""
        info = {
            "response": "none",
            "responses": [],
            "response_time_ms": 0,
            "crash": False,
            "hang": False,
            "slow": False,
            "assoc_accepted": False,
            "sequence": sequence_name,
        }
        total_reward = 0.0

        if not self.target_host:
            return total_reward, info

        # Find sequence
        sequence = None
        for name, seq in STATE_SEQUENCES:
            if name == sequence_name:
                sequence = seq
                break
        if not sequence:
            sequence = ["assoc_rq", "pdata", "release_rq"]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(5.0)
            sock.connect((self.target_host, self.target_port))

            # Adjust timeout based on intensity
            base_timeout = [3.0, 2.0, 1.5][intensity]

            for pdu_type in sequence:
                pdu = self._build_pdu(pdu_type, intensity)
                t_start = time.monotonic()

                try:
                    sock.sendall(pdu)
                    sock.settimeout(base_timeout)

                    resp_data = sock.recv(4096)
                    t_end = time.monotonic()
                    resp_time = (t_end - t_start) * 1000

                    if not resp_data:
                        resp_type = "closed"
                        reward = 8.0
                    elif resp_data[0] == 0x02:
                        resp_type = "accept"
                        info["assoc_accepted"] = True
                        self.accept_count += 1
                        reward = 5.0
                    elif resp_data[0] == 0x03:
                        resp_type = "reject"
                        reward = 3.0
                    elif resp_data[0] == 0x04:
                        resp_type = "pdata"
                        self.pdata_response_count += 1
                        reward = 25.0  # Server processed our data!
                    elif resp_data[0] == 0x05:
                        resp_type = "release_rq"
                        reward = 10.0
                    elif resp_data[0] == 0x06:
                        resp_type = "release_rp"
                        reward = 8.0
                    elif resp_data[0] == 0x07:
                        resp_type = "abort"
                        reward = 50.0  # Abort: server hit error-handling path
                    else:
                        resp_type = f"type_{resp_data[0]:02x}"
                        reward = 20.0  # Unknown is interesting

                    # Time bonus
                    if resp_time > 100:
                        reward += 20.0
                    elif resp_time > 50:
                        reward += 10.0

                    info["responses"].append({
                        "pdu": pdu_type,
                        "response": resp_type,
                        "time_ms": resp_time,
                    })
                    info["response"] = resp_type
                    info["response_time_ms"] = resp_time
                    total_reward += reward

                except socket.timeout:
                    # Distinguish slow (server busy) vs hang (server unresponsive)
                    # Retry with longer timeout to confirm true hang
                    is_hang = False
                    try:
                        sock.settimeout(5.0)
                        retry_data = sock.recv(4096)
                        if not retry_data:
                            is_hang = True  # Connection dead
                    except socket.timeout:
                        is_hang = True  # Still no response after 5s retry
                    except Exception:
                        is_hang = True  # Connection broken

                    total_elapsed = (time.monotonic() - t_start) * 1000
                    info["responses"].append({
                        "pdu": pdu_type,
                        "response": "timeout",
                        "time_ms": total_elapsed,
                    })
                    info["response"] = "timeout"

                    if is_hang:
                        info["hang"] = True
                        self.hang_count += 1
                        total_reward += 50.0  # True hang is very interesting
                    else:
                        info["slow"] = True
                        self.slow_count += 1
                        total_reward += 15.0  # Slow response, server was busy
                    break

            sock.close()

        except ConnectionResetError:
            info["response"] = "reset"
            total_reward += 5.0
        except ConnectionRefusedError:
            info["response"] = "refused"
            # Check if crash
            time.sleep(0.3)
            try:
                check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                check.settimeout(2.0)
                check.connect((self.target_host, self.target_port))
                check.close()
            except:
                info["crash"] = True
                self.crash_count += 1
                total_reward += 150.0  # Crash is extremely interesting
        except Exception as e:
            info["response"] = "error"
            info["error"] = str(e)
            total_reward += 3.0

        self.response_history.append(info["response"])
        return total_reward, info

    def reset(self, seed=None, options=None):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        self.reset_state()
        self.step_count = 0
        self.episode_reward = 0
        self.response_history = []

        return self._get_obs(), {}

    def step(self, action):
        """Execute hybrid attack based on action."""
        # Decode action
        semantic_field_idx = action[0]
        semantic_value_idx = action[1]
        payload_type_idx = action[2]
        injection_target_idx = action[3]
        state_seq_idx = action[4]
        intensity = action[5]

        info = {
            "semantic_mutation": None,
            "payload_injection": None,
            "state_sequence": None,
            "intensity": intensity,
        }

        # Apply semantic mutation
        if semantic_field_idx > 0:
            field_idx = semantic_field_idx - 1
            if field_idx < len(SEMANTIC_FIELDS):
                field_name, values = SEMANTIC_FIELDS[field_idx]
                value_idx = semantic_value_idx % len(values)
                value = values[value_idx]
                self.current_fields[field_name] = value
                info["semantic_mutation"] = f"{field_name}={value}"

        # Apply payload injection
        if payload_type_idx > 0 and injection_target_idx > 0:
            payload_idx = payload_type_idx - 1
            target_idx = injection_target_idx - 1
            if payload_idx < len(PAYLOAD_TYPES) and target_idx < len(INJECTION_TARGETS):
                payload_name, payloads = PAYLOAD_TYPES[payload_idx]
                target_name = INJECTION_TARGETS[target_idx]

                # Select payload based on intensity
                payload_options = payloads[:intensity + 1] if intensity < len(payloads) else payloads
                payload = random.choice(payload_options)

                self.current_payloads[target_name] = payload
                info["payload_injection"] = f"{payload_name}->{target_name}"

        # Select state sequence
        seq_name, _ = STATE_SEQUENCES[state_seq_idx % len(STATE_SEQUENCES)]
        info["state_sequence"] = seq_name

        # Execute attack
        reward, exec_info = self._send_sequence(seq_name, intensity)
        info.update(exec_info)

        # Track effective combinations
        combo_key = (info.get("semantic_mutation"), info.get("payload_injection"), seq_name)
        if combo_key not in self.effective_combos:
            self.effective_combos[combo_key] = {"count": 0, "total_reward": 0}
        self.effective_combos[combo_key]["count"] += 1
        self.effective_combos[combo_key]["total_reward"] += reward

        # Bonus for discovering crashes/hangs/slow
        if info.get("crash"):
            reward += 100.0
            logger.warning(f"CRASH detected! Combo: {combo_key}")
            self._save_corpus_entry("crash", info)
        if info.get("hang"):
            reward += 30.0
            self._save_corpus_entry("hang", info)
        if info.get("slow"):
            reward += 5.0

        self.step_count += 1
        self.episode_reward += reward
        info["episode_reward"] = self.episode_reward
        info["current_fields"] = dict(self.current_fields)

        truncated = self.step_count >= self.max_steps
        terminated = info.get("crash", False)

        return self._get_obs(), reward, terminated, truncated, info

    def _save_corpus_entry(self, kind, info):
        """Save a crash or hang input to corpus_dir for later triage/replay."""
        if not self.corpus_dir:
            return
        import json
        subdir = os.path.join(self.corpus_dir, f"{kind}s")
        os.makedirs(subdir, exist_ok=True)
        ts = int(time.time())
        idx = getattr(self, "_corpus_idx", 0)
        self._corpus_idx = idx + 1
        stem = f"{kind}_{idx:04d}_{ts}"
        sent_pdus = info.get("sent_pdus", [])
        raw = b"".join(pdu for _, pdu in sent_pdus) if sent_pdus else b""
        if raw:
            bin_path = os.path.join(subdir, f"{stem}.bin")
            with open(bin_path, "wb") as f:
                f.write(raw)
        meta = {
            "kind": kind, "index": idx, "timestamp": ts,
            "response": info.get("response"), "episode_reward": info.get("episode_reward"),
            "fields": dict(getattr(self, "current_fields", {})),
            "sent_pdu_types": [pt for pt, _ in sent_pdus],
            "sent_pdu_sizes": [len(p) for _, p in sent_pdus],
        }
        json_path = os.path.join(subdir, f"{stem}.json")
        with open(json_path, "w") as f:
            json.dump(meta, f, indent=2, default=str)
        logger.warning(f"[CORPUS] Saved {kind} input → {json_path}")

    def render(self, mode="human"):
        print(f"Step {self.step_count}")
        print(f"  Fields: {self.current_fields}")
        print(f"  Payloads: {self.current_payloads}")
        print(f"  Hangs: {self.hang_count}, Crashes: {self.crash_count}")

    def get_effective_combos(self, top_n=10):
        """Return top effective attack combinations."""
        sorted_combos = sorted(
            self.effective_combos.items(),
            key=lambda x: x[1]["total_reward"] / max(x[1]["count"], 1),
            reverse=True
        )
        return sorted_combos[:top_n]


# ============================================================================
# Thompson Sampling Bandit for Category-Level Exploration
# ============================================================================

class ThompsonBandit:
    """Thompson Sampling multi-armed bandit for attack category selection.

    Sits above the DQN: selects which CATEGORY of attack to explore,
    then the DQN (or random) picks a specific action within that category.
    Uses Beta(alpha, beta) conjugate prior for Bernoulli rewards.
    """

    def __init__(self, categories):
        self.categories = list(categories)
        self.alpha = {c: 1.0 for c in self.categories}  # Beta prior successes
        self.beta = {c: 1.0 for c in self.categories}   # Beta prior failures

    def sample(self):
        """Sample from posterior and return best category."""
        samples = {c: np.random.beta(self.alpha[c], self.beta[c]) for c in self.categories}
        return max(samples, key=samples.get)

    def update(self, category, reward, threshold=5.0):
        """Update posterior. Reward > threshold = success."""
        if category not in self.alpha:
            return
        if reward > threshold:
            self.alpha[category] = min(self.alpha[category] + 1, 100)
        else:
            self.beta[category] = min(self.beta[category] + 1, 100)

    def boost_exploration(self):
        """Reset the worst-performing category to give it a second chance."""
        if not self.categories:
            return
        # Category with highest beta (most failures) relative to alpha
        worst = max(self.categories, key=lambda c: self.beta[c] / (self.alpha[c] + 1e-6))
        self.alpha[worst] = 1.0
        self.beta[worst] = 1.0

    def get_stats(self):
        """Return alpha/beta ratios for logging."""
        stats = {}
        for c in self.categories:
            ratio = self.alpha[c] / (self.alpha[c] + self.beta[c])
            stats[c] = {"alpha": self.alpha[c], "beta": self.beta[c], "ratio": ratio}
        return stats


class SimplifiedHybridEnv(gym.Env):
    """
    Simplified hybrid environment with Discrete action space.

    Combines pre-defined attack combinations for easier RL training.
    """

    metadata = {"render_modes": ["human"]}

    # Pre-defined attack combinations
    # Format: (name, semantic_field, semantic_value, payload_type, target, sequence)
    ATTACK_COMBOS = [
        # === PDATA/DIMSE fuzzing (within valid association) ===
        # These pass ASSOC validation and fuzz the DIMSE layer
        ("pdata_msgid_zero", "message_id", 0, None, None, "normal"),
        ("pdata_msgid_max", "message_id", 65535, None, None, "normal"),
        ("pdata_msgid_boundary", "message_id", 32767, None, None, "normal"),
        ("pdata_cmd_invalid", "command_field", 0x0002, None, None, "normal"),
        ("pdata_cmd_response", "command_field", 0x8030, None, None, "normal"),
        ("pdata_cmd_naction", "command_field", 0x0130, None, None, "normal"),
        ("pdata_cmd_cancel", "command_field", 0x0FFF, None, None, "normal"),
        ("pdata_ctx_zero", "context_id", 0, None, None, "normal"),
        ("pdata_ctx_even", "context_id", 2, None, None, "normal"),
        ("pdata_ctx_max_even", "context_id", 254, None, None, "normal"),
        ("pdata_dataset_mismatch", "data_set_type", 0x0102, None, None, "normal"),
        ("pdata_dataset_zero", "data_set_type", 0x0000, None, None, "normal"),
        ("pdata_msgctrl_invalid", "msg_control", 0x80, None, None, "normal"),
        ("pdata_msgctrl_fragment", "msg_control", 0x00, None, None, "normal"),

        # === Multiple PDATA attacks (flood the DIMSE parser) ===
        ("pdata_flood_msgid", "message_id", 1, None, None, "pdata_flood"),
        ("pdata_flood_ctx_invalid", "context_id", 0, None, None, "pdata_flood"),
        ("pdata_flood_cmd_invalid", "command_field", 0xFFFF, None, None, "pdata_flood"),

        # === PDATA with payload injection in DIMSE ===
        # Note: These inject into ASSOC but then send semantic PDATA
        ("pdata_after_fmt", "message_id", 1, "format_string", "called_ae", "normal"),
        ("pdata_after_overflow", "context_id", 1, "buffer_overflow", "abstract_syntax", "normal"),

        # === State machine attacks ===
        ("state_pdata_first", None, None, None, None, "pdata_first"),
        ("state_double_assoc", None, None, None, None, "double_assoc"),
        ("state_pdata_flood", None, None, None, None, "pdata_flood"),
        ("state_abort_continue", None, None, None, None, "abort_continue"),
        ("state_release_continue", None, None, None, None, "release_continue"),
        ("state_client_ac", None, None, None, None, "client_sends_ac"),
        ("state_immediate_abort", None, None, None, None, "immediate_abort"),

        # === ASSOC payload injections (what's triggering current errors) ===
        ("inject_fmt_called", "message_id", 1, "format_string", "called_ae", "normal"),
        ("inject_fmt_calling", "message_id", 1, "format_string", "calling_ae", "normal"),
        ("inject_path_abstract", "message_id", 1, "path_traversal", "abstract_syntax", "normal"),
        ("inject_overflow_called", "message_id", 1, "buffer_overflow", "called_ae", "normal"),
        ("inject_overflow_uid", "message_id", 1, "buffer_overflow", "abstract_syntax", "normal"),
        ("inject_null_called", "message_id", 1, "null_injection", "called_ae", "normal"),

        # === Combined: PDATA semantic + state attacks ===
        ("combo_pdata_invalid_state", "context_id", 0, None, None, "pdata_first"),
        ("combo_msgid_double", "message_id", 65535, None, None, "double_assoc"),
        ("combo_cmd_abort", "command_field", 0x8030, None, None, "abort_continue"),

        # === Malformed DIMSE attacks (bypass DUL, target DIMSE parser) ===
        # Format: (name, None, None, None, None, "normal", dimse_attack_type)
        ("dimse_truncated_cmd", None, None, None, None, "normal", "truncated_cmd"),
        ("dimse_wrong_length", None, None, None, None, "normal", "wrong_length"),
        ("dimse_negative_length", None, None, None, None, "normal", "negative_length"),
        ("dimse_zero_uid", None, None, None, None, "normal", "zero_length_uid"),
        ("dimse_duplicate_elem", None, None, None, None, "normal", "duplicate_elements"),
        ("dimse_out_of_order", None, None, None, None, "normal", "out_of_order"),
        ("dimse_invalid_group", None, None, None, None, "normal", "invalid_group"),
        ("dimse_oversized_grplen", None, None, None, None, "normal", "oversized_group_length"),
        ("dimse_cstore_nodataset", None, None, None, None, "normal", "cstore_no_dataset"),
        ("dimse_empty_pdata", None, None, None, None, "normal", "empty_pdata"),
        ("dimse_pdv_zero", None, None, None, None, "normal", "pdv_length_zero"),

        # === Duplication attacks ===
        ("dup_double_assoc", None, None, None, None, "double_assoc"),
        ("dup_triple_assoc", None, None, None, None, "triple_assoc"),
        ("dup_double_pdata", None, None, None, None, "double_pdata"),
        ("dup_double_release", None, None, None, None, "double_release"),
        ("dup_double_abort", None, None, None, None, "double_abort"),
        ("dup_pdata_flood_5", None, None, None, None, "pdata_flood_5"),
        ("dup_pdata_flood_10", None, None, None, None, "pdata_flood_10"),

        # === Reordering attacks ===
        ("reorder_release_before", None, None, None, None, "release_before_pdata"),
        ("reorder_abort_before", None, None, None, None, "abort_before_pdata"),
        ("reorder_pdata_then_assoc", None, None, None, None, "pdata_then_assoc"),
        ("reorder_release_then_assoc", None, None, None, None, "release_then_assoc"),
        ("reorder_pdata_first", None, None, None, None, "pdata_first"),
        ("reorder_release_first", None, None, None, None, "release_first"),
        ("reorder_abort_first", None, None, None, None, "abort_first"),

        # === Role reversal attacks ===
        ("role_client_ac", None, None, None, None, "client_sends_ac"),
        ("role_client_rj", None, None, None, None, "client_sends_rj"),
        ("role_client_release_rp", None, None, None, None, "client_sends_release_rp"),
        ("role_ac_then_pdata", None, None, None, None, "ac_then_pdata"),

        # === Interleaved/mixed attacks ===
        ("mixed_pdata_abort_pdata", None, None, None, None, "pdata_abort_pdata"),
        ("mixed_assoc_pdata_assoc", None, None, None, None, "assoc_pdata_assoc_pdata"),
        ("mixed_rapid_state", None, None, None, None, "rapid_state_changes"),

        # === Partial/garbage attacks ===
        ("partial_truncated", None, None, None, None, "partial_pdu"),
        ("partial_garbage", None, None, None, None, "garbage_after_assoc"),
        ("partial_empty", None, None, None, None, "empty_session"),
        ("partial_assoc_only", None, None, None, None, "assoc_only"),

        # === C-STORE attacks (with dataset) ===
        ("cstore_normal", None, None, None, None, "cstore_normal"),
        ("cstore_no_release", None, None, None, None, "cstore_no_release"),
        ("cstore_duplicate", None, None, None, None, "cstore_double"),
        ("cstore_then_echo", None, None, None, None, "cstore_then_echo"),
        ("cstore_with_fmt", "message_id", 1, "format_string", "called_ae", "cstore_normal"),
        ("cstore_with_overflow", "message_id", 1, "buffer_overflow", "calling_ae", "cstore_normal"),

        # === C-FIND attacks (query) ===
        ("cfind_normal", None, None, None, None, "cfind_normal"),
        ("cfind_flood", None, None, None, None, "cfind_flood"),
        ("cfind_with_path", "message_id", 1, "path_traversal", "calling_ae", "cfind_normal"),

        # === Mixed command attacks ===
        ("mixed_echo_store_find", None, None, None, None, "echo_store_find"),
        ("mixed_store_abort_store", None, None, None, None, "store_abort_store"),

        # === C-MOVE attacks (query/retrieve) ===
        ("cmove_normal", None, None, None, None, "cmove_normal"),
        ("cmove_no_release", None, None, None, None, "cmove_no_release"),
        ("cmove_flood", None, None, None, None, "cmove_flood"),
        ("cmove_then_echo", None, None, None, None, "cmove_then_echo"),
        ("cmove_with_fmt", "message_id", 1, "format_string", "called_ae", "cmove_normal"),
        ("cmove_with_overflow", "message_id", 1, "buffer_overflow", "calling_ae", "cmove_normal"),
        ("cmove_with_path", "message_id", 1, "path_traversal", "calling_ae", "cmove_normal"),

        # === C-GET attacks (query/retrieve) ===
        ("cget_normal", None, None, None, None, "cget_normal"),
        ("cget_no_release", None, None, None, None, "cget_no_release"),
        ("cget_flood", None, None, None, None, "cget_flood"),
        ("cget_then_store", None, None, None, None, "cget_then_store"),
        ("cget_with_fmt", "message_id", 1, "format_string", "called_ae", "cget_normal"),
        ("cget_with_overflow", "message_id", 1, "buffer_overflow", "calling_ae", "cget_normal"),

        # === Cross-command attacks ===
        ("cross_find_move", None, None, None, None, "find_then_move"),
        ("cross_find_get", None, None, None, None, "find_then_get"),
        ("cross_store_move", None, None, None, None, "store_then_move"),
        ("cross_all_commands", None, None, None, None, "all_commands"),

        # === CVE-style on C-MOVE/C-GET ===
        ("cve_pathuid_cmove", None, None, "path_uid", "abstract_syntax", "cmove_normal"),
        ("cve_pathuid_cget", None, None, "path_uid", "abstract_syntax", "cget_normal"),
        ("cve_largealloc_cmove", None, None, "large_alloc", "calling_ae", "cmove_normal"),
        ("cve_largealloc_cget", None, None, "large_alloc", "calling_ae", "cget_normal"),
        ("cve_intoverflow_cmove", "max_pdu_length", 0xFFFFFFFF, None, None, "cmove_normal"),
        ("cve_nested_cmove", None, None, "nested_seq", "abstract_syntax", "cmove_normal"),
        ("cve_rle_cget", None, None, "rle_attack", "abstract_syntax", "cget_normal"),

        # === Semantic + Duplication combos ===
        ("combo_msgid_zero_dup", "message_id", 0, None, None, "double_pdata"),
        ("combo_ctx_zero_dup", "context_id", 0, None, None, "pdata_flood_5"),
        ("combo_cmd_invalid_dup", "command_field", 0xFFFF, None, None, "double_pdata"),

        # === Payload + State combos ===
        ("combo_fmt_pdata_first", None, None, "format_string", "called_ae", "pdata_first"),
        ("combo_overflow_reorder", None, None, "buffer_overflow", "calling_ae", "release_before_pdata"),
        ("combo_path_cstore", None, None, "path_traversal", "abstract_syntax", "cstore_normal"),

        # === CVE-Inspired Attacks ===
        # Integer overflow attacks (CVE-2024-28130 style)
        ("cve_intoverflow_called", None, None, "integer_overflow", "called_ae", "normal"),
        ("cve_intoverflow_uid", None, None, "integer_overflow", "abstract_syntax", "normal"),
        ("cve_intoverflow_pdu", "max_pdu_length", 0xFFFFFFFF, None, None, "normal"),
        ("cve_intoverflow_pdu_neg", "max_pdu_length", 0x80000000, None, None, "normal"),

        # Path traversal UID attacks (CVE-2022-2119/2120)
        ("cve_pathuid_abstract", None, None, "path_uid", "abstract_syntax", "normal"),
        ("cve_pathuid_transfer", None, None, "path_uid", "transfer_syntax", "normal"),
        ("cve_pathuid_impl", None, None, "path_uid", "impl_uid", "cstore_normal"),
        ("cve_pathuid_cstore", None, None, "path_uid", "abstract_syntax", "cstore_normal"),

        # Large allocation / heap attacks
        ("cve_largealloc_called", None, None, "large_alloc", "called_ae", "normal"),
        ("cve_largealloc_uid", None, None, "large_alloc", "abstract_syntax", "normal"),
        ("cve_largealloc_flood", None, None, "large_alloc", "calling_ae", "pdata_flood_5"),

        # RLE decoder attacks (DCMTK CVE)
        ("cve_rle_cstore", None, None, "rle_attack", "abstract_syntax", "cstore_normal"),

        # Type confusion attacks
        ("cve_typeconf_uid", None, None, "type_confusion", "abstract_syntax", "normal"),
        ("cve_typeconf_cstore", None, None, "type_confusion", "transfer_syntax", "cstore_normal"),

        # Nested sequence attacks (stack overflow)
        ("cve_nested_pdata", None, None, "nested_seq", "abstract_syntax", "normal"),

        # Combined CVE-style attacks
        ("cve_combo_intpath", "max_pdu_length", 0x7FFFFFFF, "path_uid", "abstract_syntax", "normal"),
        ("cve_combo_largestate", None, None, "large_alloc", "called_ae", "rapid_state_changes"),
        ("cve_combo_pathflood", None, None, "path_uid", "impl_uid", "pdata_flood_10"),

        # === Byte-level mutation attacks ===
        ("byte_flip_normal", None, None, None, None, "normal", None, "byte_flip"),
        ("byte_flip_cstore", None, None, None, None, "cstore_normal", None, "byte_flip"),
        ("byte_length_normal", None, None, None, None, "normal", None, "byte_length"),
        ("byte_length_cstore", None, None, None, None, "cstore_normal", None, "byte_length"),
        ("byte_hotspot_normal", None, None, None, None, "normal", None, "byte_hotspot"),
        ("byte_hotspot_cfind", None, None, None, None, "cfind_normal", None, "byte_hotspot"),
        ("byte_boundary_normal", None, None, None, None, "normal", None, "byte_boundary"),
        ("byte_boundary_flood", None, None, None, None, "pdata_flood_5", None, "byte_boundary"),

        # === Seed mutation (byte corrupt built PDUs) ===
        ("seed_mutate_normal", None, None, None, None, "normal", None, "seed_mutate"),
        ("seed_mutate_cstore", None, None, None, None, "cstore_normal", None, "seed_mutate"),
        ("seed_mutate_cmove", None, None, None, None, "cmove_normal", None, "seed_mutate"),
        ("seed_mutate_with_fmt", None, None, "format_string", "called_ae", "normal", None, "seed_mutate"),
        ("seed_mutate_with_overflow", None, None, "buffer_overflow", "calling_ae", "cstore_normal", None, "seed_mutate"),

        # === Timing attacks ===
        ("slowloris_normal", None, None, None, None, "normal", None, "slowloris"),
        ("slowloris_with_fmt", None, None, "format_string", "called_ae", "normal", None, "slowloris"),
        ("fragment_normal", None, None, None, None, "normal", None, "fragment"),
        ("fragment_cstore", None, None, None, None, "cstore_normal", None, "fragment"),
        ("fragment_with_overflow", None, None, "buffer_overflow", "calling_ae", "normal", None, "fragment"),

        # === Concurrent attacks ===
        ("concurrent_normal", None, None, None, None, "normal", None, "concurrent"),
        ("concurrent_with_fmt", None, None, "format_string", "called_ae", "normal", None, "concurrent"),
        ("concurrent_cstore", None, None, None, None, "cstore_normal", None, "concurrent"),
        ("concurrent_cmove", None, None, None, None, "cmove_normal", None, "concurrent"),
        ("rapid_reconnect", None, None, None, None, "normal", None, "rapid_reconnect"),
        ("memory_exhaust_normal", None, None, None, None, "normal", None, "memory_exhaust"),
        ("memory_exhaust_large_pdu", "max_pdu_length", 0xFFFFFFFF, None, None, "normal", None, "memory_exhaust"),

        # === Seed corpus attacks (use real captured PDUs as base) ===
        ("seed_assoc_normal", None, None, None, None, "normal", None, "seed_assoc"),
        ("seed_assoc_with_fmt", None, None, "format_string", "called_ae", "normal", None, "seed_assoc"),
        ("seed_assoc_with_overflow", None, None, "buffer_overflow", "calling_ae", "normal", None, "seed_assoc"),
        ("seed_assoc_double", None, None, None, None, "double_assoc", None, "seed_assoc"),
        ("seed_assoc_max_pdu", "max_pdu_length", 0xFFFFFFFF, None, None, "normal", None, "seed_assoc"),
        ("seed_pdata_normal", None, None, None, None, "normal", None, "seed_pdata"),
        ("seed_pdata_ctx_zero", "context_id", 0, None, None, "normal", None, "seed_pdata"),
        ("seed_pdata_flood", None, None, None, None, "pdata_flood_5", None, "seed_pdata"),
        ("seed_pdata_cstore", None, None, None, None, "cstore_normal", None, "seed_pdata"),
        ("seed_crossover_normal", None, None, None, None, "normal", None, "seed_crossover"),
        ("seed_crossover_cstore", None, None, None, None, "cstore_normal", None, "seed_crossover"),
        ("seed_crossover_with_fmt", None, None, "format_string", "called_ae", "normal", None, "seed_crossover"),

        # === Rich C-STORE attacks (full dataset with pixel data) ===
        ("cstore_rich_normal", None, None, None, None, "cstore_rich", None, None),
        ("cstore_rich_fmt", None, None, "format_string", "called_ae", "cstore_rich", None, None),
        ("cstore_rich_overflow", None, None, "buffer_overflow", "calling_ae", "cstore_rich", None, None),
        ("cstore_rich_pathuid", None, None, "path_uid", "abstract_syntax", "cstore_rich", None, None),
        ("cstore_rich_byte_flip", None, None, None, None, "cstore_rich", None, "byte_flip"),
        ("cstore_rich_seed_mutate", None, None, None, None, "cstore_rich", None, "seed_mutate"),
        ("cstore_rich_byte_hotspot", None, None, None, None, "cstore_rich", None, "byte_hotspot"),
        ("cstore_rich_intoverflow", "max_pdu_length", 0xFFFFFFFF, None, None, "cstore_rich", None, None),
        ("cstore_rich_nested", None, None, "nested_seq", "abstract_syntax", "cstore_rich", None, None),
        ("cstore_rich_rle", None, None, "rle_attack", "abstract_syntax", "cstore_rich", None, None),

        # === Different modality C-STORE (MR, US, SC) ===
        ("cstore_mr_normal", None, None, None, None, "cstore_mr", None, None),
        ("cstore_mr_fmt", None, None, "format_string", "called_ae", "cstore_mr", None, None),
        ("cstore_mr_byte_flip", None, None, None, None, "cstore_mr", None, "byte_flip"),
        ("cstore_us_normal", None, None, None, None, "cstore_us", None, None),
        ("cstore_us_overflow", None, None, "buffer_overflow", "calling_ae", "cstore_us", None, None),
        ("cstore_sc_normal", None, None, None, None, "cstore_sc", None, None),

        # === Explicit VR encoding C-STORE (exercises VR parser) ===
        ("cstore_explicit_normal", None, None, None, None, "cstore_explicit", None, None),
        ("cstore_explicit_byte_hotspot", None, None, None, None, "cstore_explicit", None, "byte_hotspot"),
        ("cstore_explicit_byte_flip", None, None, None, None, "cstore_explicit", None, "byte_flip"),
        ("cstore_explicit_seed_mutate", None, None, None, None, "cstore_explicit", None, "seed_mutate"),
    ]

    # Components for generating novel combinations
    SEMANTIC_FIELDS_LIST = [
        ("message_id", [0, 1, 255, 256, 32767, 32768, 65534, 65535]),
        ("command_field", [0x0001, 0x0002, 0x0010, 0x0020, 0x0030, 0x0FFF, 0x8030, 0x8031, 0xFFFF]),
        ("data_set_type", [0x0000, 0x0001, 0x0100, 0x0101, 0x0102, 0xFFFF]),
        ("context_id", [0, 1, 2, 3, 127, 128, 254, 255]),
        ("msg_control", [0x00, 0x01, 0x02, 0x03, 0x80, 0xFF]),
        ("max_pdu_length", [0, 1, 4096, 16384, 65535, 0x7FFFFFFF, 0xFFFFFFFF]),
    ]
    PAYLOAD_TYPES_LIST = [
        "format_string", "path_traversal", "buffer_overflow", "null_injection", "special_char",
        "integer_overflow", "path_uid", "large_alloc", "rle_attack", "nested_seq", "type_confusion"
    ]
    TARGETS_LIST = ["called_ae", "calling_ae", "abstract_syntax", "transfer_syntax", "impl_uid"]
    SEQUENCES_LIST = [
        "normal", "pdata_first", "double_assoc", "triple_assoc", "double_pdata",
        "pdata_flood_5", "pdata_flood_10", "release_before_pdata", "abort_before_pdata",
        "pdata_then_assoc", "client_sends_ac", "cstore_normal", "cfind_normal",
        "partial_pdu", "garbage_after_assoc", "rapid_state_changes",
        "cmove_normal", "cmove_no_release", "cmove_flood", "cmove_then_echo",
        "cget_normal", "cget_no_release", "cget_flood", "cget_then_store",
        "find_then_move", "find_then_get", "store_then_move", "all_commands",
        "cstore_rich", "cstore_mr", "cstore_us", "cstore_sc", "cstore_explicit",
    ]
    DIMSE_ATTACKS_LIST = [
        "truncated_cmd", "wrong_length", "negative_length", "zero_length_uid",
        "duplicate_elements", "out_of_order", "invalid_group", "oversized_group_length",
        "cstore_no_dataset", "empty_pdata", "pdv_length_zero",
    ]

    def __init__(self, target_host=None, target_port=4242, called_ae="ORTHANC",
                 max_steps=30, log_path=None, ssh_host=None, ssh_log_path=None,
                 docker_container=None, server_type="orthanc", exploration_rate=0.15,
                 diversity_bonus=1.0, ssh_process=None,
                 ssh_asan_log_pattern=None, ssh_coverage_dir=None,
                 seed_dir=None, seed_pdus=None, disable_slow_attacks=False,
                 corpus_dir=None):
        """
        Initialize hybrid fuzzing environment.

        Args:
            target_host: Target server IP/hostname
            target_port: Target server port
            called_ae: DICOM Called AE title
            max_steps: Maximum steps per episode
            log_path: Path to LOCAL server log file for log-based rewards
            ssh_host: SSH host for REMOTE log monitoring (e.g., user@host)
            ssh_log_path: Path to log file on SSH host
            docker_container: Docker container name for log monitoring
            server_type: Server type for baseline messages ("orthanc", "dcmtk")
            exploration_rate: Probability of generating novel combinations (0.0-1.0)
            diversity_bonus: Scale factor for diversity enforcement (0=disabled, 1.0=default)
            ssh_process: Process name to monitor via SSH (e.g., "storescp")
            ssh_asan_log_pattern: ASAN log file glob on remote host (e.g., "/tmp/asan_storescp.*")
            ssh_coverage_dir: Build directory with .gcda files on remote host
            seed_dir: Base directory for seed PDUs (e.g., fuzzer/data/training_data/pdus)
            seed_pdus: Pre-loaded list of seed PDU bytes (alternative to seed_dir)
            disable_slow_attacks: If True, remove slowloris/fragment/concurrent/rapid_reconnect/
                                  memory_exhaust combos for faster training throughput
        """
        super().__init__()

        self.target_host = target_host
        self.target_port = target_port
        self.exploration_rate = exploration_rate
        self.diversity_bonus = diversity_bonus
        self.called_ae = called_ae.encode() if isinstance(called_ae, str) else called_ae
        self.max_steps = max_steps
        self.disable_slow_attacks = disable_slow_attacks
        self.corpus_dir = corpus_dir  # If set, save crash/hang inputs here during training

        # Seed corpus: real captured PDUs for seed-based mutations
        self.seed_assoc_rq = []  # List of raw ASSOC_RQ bytes
        self.seed_pdata = []     # List of raw PDATA bytes
        self._load_seeds(seed_dir, seed_pdus)

        # Filter slow attacks if requested
        SLOW_SPECIAL_ATTACKS = {"slowloris", "fragment", "concurrent", "rapid_reconnect", "memory_exhaust"}
        if disable_slow_attacks:
            self.active_combos = [c for c in self.ATTACK_COMBOS
                                  if not (len(c) == 8 and c[7] in SLOW_SPECIAL_ATTACKS)]
            n_removed = len(self.ATTACK_COMBOS) - len(self.active_combos)
            logger.info(f"Slow attacks disabled: removed {n_removed} combos "
                       f"({', '.join(sorted(SLOW_SPECIAL_ATTACKS))})")
        else:
            self.active_combos = list(self.ATTACK_COMBOS)

        # Action space: select from active combinations
        self.n_actions = len(self.active_combos)
        self.action_space = spaces.Discrete(self.n_actions)

        # Build category-to-action mapping and Thompson Sampling bandit
        self.category_to_actions = self._build_category_map()
        active_categories = [c for c in self.category_to_actions if self.category_to_actions[c]]
        self.bandit = ThompsonBandit(active_categories) if active_categories else None

        # Observation space (extended for log + ASAN + coverage features)
        self.observation_space = spaces.Box(
            low=0, high=1,
            shape=(30,),
            dtype=np.float32,
        )

        # Server monitor (health checks)
        self.server_monitor = None
        if target_host:
            self.server_monitor = ServerMonitor(
                target_host=target_host,
                target_port=target_port,
                called_ae=called_ae if isinstance(called_ae, str) else called_ae.decode(),
            )

        # Log monitor (for log-based rewards)
        self.log_monitor = None
        if log_path or docker_container or ssh_host:
            self.log_monitor = create_log_monitor(
                server_type=server_type,
                log_path=log_path,
                ssh_host=ssh_host,
                ssh_log_path=ssh_log_path,
                docker_container=docker_container,
            )
            logger.info(f"Log monitoring enabled: path={log_path}, docker={docker_container}")

        # Process monitor (for resource tracking via SSH)
        self.process_monitor = None
        if ssh_host and ssh_process:
            self.process_monitor = ProcessMonitor(
                ssh_host=ssh_host,
                process_name=ssh_process,
                sample_interval=10,
            )
            logger.info(f"Process monitoring enabled: {ssh_process} on {ssh_host}")

        # ASAN monitor (for memory safety bug detection via SSH)
        self.asan_monitor = None
        if ssh_host and ssh_asan_log_pattern:
            self.asan_monitor = AsanMonitor(
                ssh_host=ssh_host,
                asan_log_pattern=ssh_asan_log_pattern,
                sample_interval=5,
            )
            logger.info(f"ASAN monitoring enabled: {ssh_asan_log_pattern} on {ssh_host}")

        # Coverage monitor (requires DCMTK compiled with --coverage + coverage_handler.o linked in)
        # Uses SIGUSR1 to flush .gcda files, then lcov to read coverage.
        # Overhead: ~3s per sample, so sample_interval should be high (every 15-20 steps).
        self.coverage_monitor = None
        if ssh_host and ssh_coverage_dir:
            self.coverage_monitor = CoverageMonitor(
                ssh_host=ssh_host,
                coverage_dir=ssh_coverage_dir,
                sample_interval=15,
                process_name=ssh_process or "storescp",
            )
            logger.info(f"Coverage monitoring enabled: {ssh_coverage_dir} via {ssh_host} "
                       f"(sample every 15 steps)")

        # State
        self.current_fields = {}
        self.current_payloads = {}
        self.reset_state()

        # Tracking
        self.step_count = 0
        self.episode_reward = 0
        self.response_history = []
        self.hang_count = 0
        self.slow_count = 0
        self.crash_count = 0
        self.accept_count = 0
        self.new_error_count = 0
        self.new_location_count = 0
        self.combo_stats = {name: {"count": 0, "reward": 0, "hangs": 0, "slows": 0, "crashes": 0,
                                   "new_errors": 0, "new_locations": 0,
                                   "asan_bugs": 0,
                                   "max_rss_growth_mb": 0.0, "max_fd_growth": 0,
                                   "max_cpu": 0.0, "max_anomaly_score": 0.0}
                           for name, *_ in self.active_combos}

        # Novel combination tracking
        self.novel_combo_count = 0
        self.novel_combos_discovered = {}  # name -> stats
        self.best_novel_combos = []  # Top performing novel combinations

        # Diversity enforcement
        self.action_visit_counts = {}  # action_index -> count (across episodes)
        self.consecutive_same_action = 0  # how many times same action in a row
        self.last_action = None

        # Plateau-aware exploration
        self._plateau_steps = 0          # Steps since last coverage increase
        self._plateau_threshold = 150    # Steps without coverage gain = plateau
        self._base_exploration_rate = exploration_rate
        self._no_new_locations_steps = 0  # Fallback for log-based plateau detection
        self._log_plateau_threshold = 200  # Steps without new code locations

    def reset_state(self):
        self.current_fields = {
            "message_id": 1,
            "command_field": 0x0030,
            "data_set_type": 0x0101,
            "context_id": 1,
            "msg_control": 0x03,
            "max_pdu_length": 16384,
        }
        self.current_payloads = {
            "called_ae": None,
            "calling_ae": None,
            "abstract_syntax": None,
            "transfer_syntax": None,
            "impl_uid": None,
        }
        self._current_dimse_attack = None
        self._current_special_attack = None

    def _load_seeds(self, seed_dir, seed_pdus):
        """Load seed PDUs from directory or pre-loaded list.

        Separates seeds into ASSOC_RQ (type 0x01) and PDATA (type 0x04) pools.
        Other PDU types are stored in the PDATA pool for general mutation.
        """
        all_pdus = []

        # From pre-loaded list
        if seed_pdus:
            for p in seed_pdus:
                if isinstance(p, (list, np.ndarray)):
                    p = bytes(p)
                if len(p) >= 6:
                    all_pdus.append(p)

        # From seed directory
        if seed_dir and os.path.isdir(seed_dir):
            for subdir_name in ["assoc_rq", "pdata", "abort", "assoc_ac", "release_rq"]:
                subdir = os.path.join(seed_dir, subdir_name)
                if not os.path.isdir(subdir):
                    continue

                # Try numpy format first
                bytes_path = os.path.join(subdir, "bytes.npy")
                offsets_path = os.path.join(subdir, "offsets.npy")
                if os.path.exists(bytes_path) and os.path.exists(offsets_path):
                    raw = np.load(bytes_path)
                    offsets = np.load(offsets_path)
                    for i in range(min(len(offsets) - 1, 200)):
                        pdu = bytes(raw[offsets[i]:offsets[i + 1]])
                        if len(pdu) >= 6:
                            all_pdus.append(pdu)
                else:
                    # Fall back to .bin files
                    for f in sorted(glob.glob(os.path.join(subdir, "*.bin")))[:200]:
                        with open(f, 'rb') as fh:
                            pdu = fh.read().rstrip(b'\x00')
                            if len(pdu) >= 6:
                                all_pdus.append(pdu)

        # Separate by PDU type
        for pdu in all_pdus:
            if pdu[0] == 0x01:
                self.seed_assoc_rq.append(pdu)
            elif pdu[0] == 0x04:
                self.seed_pdata.append(pdu)

        if self.seed_assoc_rq or self.seed_pdata:
            logger.info(f"Seed corpus loaded: {len(self.seed_assoc_rq)} ASSOC_RQ, "
                       f"{len(self.seed_pdata)} PDATA")

    def _build_seed_assoc_rq(self):
        """Build ASSOC_RQ from seed corpus with optional field overrides.

        Picks a random seed ASSOC_RQ and applies current payload injections
        (called_ae, calling_ae) by patching the relevant byte offsets.
        """
        if not self.seed_assoc_rq:
            return self._build_assoc_rq()

        seed = bytearray(random.choice(self.seed_assoc_rq))

        # Patch Called AE (offsets 10-26) if payload set
        called = self.current_payloads.get("called_ae")
        if called:
            if isinstance(called, str):
                called = called.encode()
            padded = called.ljust(16, b' ')[:16]
            seed[10:26] = padded

        # Patch Calling AE (offsets 26-42) if payload set
        calling = self.current_payloads.get("calling_ae")
        if calling:
            if isinstance(calling, str):
                calling = calling.encode()
            padded = calling.ljust(16, b' ')[:16]
            seed[26:42] = padded

        # Patch max PDU length in User Information (search for item type 0x51)
        max_pdu = self.current_fields.get("max_pdu_length", 16384)
        if max_pdu != 16384:
            # Find 0x51 user info item (max PDU length)
            for i in range(len(seed) - 8):
                if seed[i] == 0x51 and seed[i + 1] == 0x00:
                    struct.pack_into('>I', seed, i + 4, max_pdu)
                    break

        return bytes(seed)

    def _build_seed_pdata(self):
        """Build PDATA from seed corpus with optional byte mutations.

        Picks a random seed PDATA PDU. Semantic field mutations (context_id,
        msg_control) are applied by patching known offsets in the PDV header.
        """
        if not self.seed_pdata:
            return self._build_pdata()

        seed = bytearray(random.choice(self.seed_pdata))

        # Patch context_id (offset 10 in standard PDATA layout)
        ctx = self.current_fields.get("context_id", 1)
        if ctx != 1 and len(seed) > 10:
            seed[10] = ctx & 0xFF

        # Patch msg_control (offset 11)
        mc = self.current_fields.get("msg_control", 0x03)
        if mc != 0x03 and len(seed) > 11:
            seed[11] = mc & 0xFF

        return bytes(seed)

    def _build_seed_crossover(self, pdu_type):
        """Crossover: splice seed PDU header with programmatic body (or vice versa).

        Takes the header from a seed and the body from programmatic builder,
        creating structural hybrids that test parser boundary handling.
        """
        if pdu_type == "assoc_rq" and self.seed_assoc_rq:
            seed = random.choice(self.seed_assoc_rq)
            prog = self._build_assoc_rq()
            # Use seed header (first 74 bytes: type, length, version, AEs, reserved)
            # with programmatic presentation context items
            cut = min(74, len(seed), len(prog))
            hybrid = bytearray(seed[:cut]) + bytearray(prog[cut:])
            # Fix PDU length
            if len(hybrid) >= 6:
                struct.pack_into('>I', hybrid, 2, len(hybrid) - 6)
            return bytes(hybrid)

        elif pdu_type in ("pdata", "cstore_pdata", "cfind_pdata", "cmove_pdata", "cget_pdata") \
                and self.seed_pdata:
            seed = random.choice(self.seed_pdata)
            prog = self._build_pdu_inner(pdu_type)
            # Use seed PDV header (first 12 bytes) with programmatic DIMSE body
            cut = min(12, len(seed), len(prog))
            hybrid = bytearray(seed[:cut]) + bytearray(prog[cut:])
            # Fix PDU length
            if len(hybrid) >= 6:
                struct.pack_into('>I', hybrid, 2, len(hybrid) - 6)
            return bytes(hybrid)

        # Fallback: no seeds available for this type
        return None

    def _generate_novel_combo(self):
        """
        Generate a random novel attack combination not in predefined list.

        Maximum 5 attack components:
        1. Semantic mutation (60% chance): field=value modification
        2. Payload injection (40% chance): payload_type -> target_field
        3. State sequence (always): protocol state attack pattern
        4. DIMSE attack (30% chance): malformed DIMSE message
        5. Special attack (20% chance): byte-level, timing, concurrent, or seed mutation
        """
        # Randomly decide which components to include
        include_semantic = random.random() < 0.6
        include_payload = random.random() < 0.4
        include_dimse = random.random() < 0.3
        include_special = random.random() < 0.2

        # Select semantic mutation
        sem_field, sem_value = None, None
        if include_semantic:
            field_name, values = random.choice(self.SEMANTIC_FIELDS_LIST)
            sem_field = field_name
            sem_value = random.choice(values)

        # Select payload injection
        payload_type, target = None, None
        if include_payload:
            payload_type = random.choice(self.PAYLOAD_TYPES_LIST)
            target = random.choice(self.TARGETS_LIST)

        # Select sequence (always included)
        sequence = random.choice(self.SEQUENCES_LIST)

        # Select DIMSE attack
        dimse_attack = None
        if include_dimse:
            dimse_attack = random.choice(self.DIMSE_ATTACKS_LIST)

        # Select special attack
        special_attack = None
        if include_special:
            if self.disable_slow_attacks:
                fast_specials = [s for s in SPECIAL_ATTACKS_LIST
                                 if s not in {"slowloris", "fragment", "concurrent",
                                              "rapid_reconnect", "memory_exhaust"}]
                special_attack = random.choice(fast_specials) if fast_specials else None
            else:
                special_attack = random.choice(SPECIAL_ATTACKS_LIST)

        # Generate readable short name
        parts = ["N"]  # N for Novel
        if sem_field:
            field_abbrev = {"message_id": "mid", "command_field": "cmd", "data_set_type": "dst",
                          "context_id": "ctx", "msg_control": "ctl", "max_pdu_length": "pdu"}
            parts.append(f"{field_abbrev.get(sem_field, sem_field[:3])}{sem_value}")
        if payload_type:
            payload_abbrev = {"format_string": "fmt", "path_traversal": "path", "buffer_overflow": "ovf",
                            "null_injection": "nul", "special_char": "spc", "integer_overflow": "int",
                            "path_uid": "puid", "large_alloc": "lrg", "rle_attack": "rle",
                            "nested_seq": "nest", "type_confusion": "typ"}
            target_abbrev = {"called_ae": "cae", "calling_ae": "gae", "abstract_syntax": "abs",
                           "transfer_syntax": "xfr", "impl_uid": "imp"}
            parts.append(f"{payload_abbrev.get(payload_type, payload_type[:3])}->{target_abbrev.get(target, target[:3])}")
        if dimse_attack:
            dimse_abbrev = {"truncated_cmd": "trunc", "wrong_length": "wlen", "negative_length": "neg",
                          "zero_length_uid": "zuid", "duplicate_elements": "dup", "out_of_order": "ooo",
                          "invalid_group": "igrp", "oversized_group_length": "ogrp", "cstore_no_dataset": "nodat",
                          "empty_pdata": "empty", "pdv_length_zero": "pdv0"}
            parts.append(f"D:{dimse_abbrev.get(dimse_attack, dimse_attack[:4])}")
        if special_attack:
            special_abbrev = {"byte_flip": "bflip", "byte_length": "blen", "byte_hotspot": "bhot",
                            "byte_boundary": "bbnd", "seed_mutate": "seed", "slowloris": "slow",
                            "fragment": "frag", "concurrent": "conc", "rapid_reconnect": "rapid",
                            "memory_exhaust": "memex", "seed_assoc": "s_asc", "seed_pdata": "s_pd",
                            "seed_crossover": "s_xov"}
            parts.append(f"X:{special_abbrev.get(special_attack, special_attack[:4])}")
        # Sequence abbreviations
        seq_abbrev = {"normal": "norm", "pdata_first": "pd1st", "double_assoc": "2asc", "triple_assoc": "3asc",
                     "double_pdata": "2pd", "pdata_flood_5": "fl5", "pdata_flood_10": "fl10",
                     "release_before_pdata": "rel1st", "abort_before_pdata": "abt1st", "pdata_then_assoc": "pd+asc",
                     "client_sends_ac": "cliAC", "cstore_normal": "csto", "cfind_normal": "cfnd",
                     "partial_pdu": "part", "garbage_after_assoc": "garb", "rapid_state_changes": "rapid",
                     "cmove_normal": "cmov", "cmove_no_release": "cmov_nr", "cmove_flood": "cmov_fl",
                     "cmove_then_echo": "cmov_e", "cget_normal": "cget", "cget_no_release": "cget_nr",
                     "cget_flood": "cget_fl", "cget_then_store": "cget_s", "find_then_move": "fnd+mov",
                     "find_then_get": "fnd+get", "store_then_move": "sto+mov", "all_commands": "allcmd"}
        parts.append(f"S:{seq_abbrev.get(sequence, sequence[:4])}")

        name = "_".join(str(p) for p in parts)
        self.novel_combo_count += 1

        # Always return 8-tuple for consistency
        return (name, sem_field, sem_value, payload_type, target, sequence, dimse_attack, special_attack)

    def _build_category_map(self):
        """Categorize all active combos for Thompson Sampling bandit."""
        categories = {
            "semantic": [],
            "payload": [],
            "state": [],
            "dimse": [],
            "byte": [],
            "timing": [],
            "concurrent": [],
            "dataset": [],
        }

        # Normal sequences (not interesting for "state" category)
        normal_sequences = {"normal", "cstore_normal", "cfind_normal", "cmove_normal",
                            "cget_normal", "cstore_rich", "cstore_mr", "cstore_us",
                            "cstore_sc", "cstore_explicit"}

        for idx, combo in enumerate(self.active_combos):
            if len(combo) >= 8:
                name, sem_field, sem_value, payload_type, target, sequence, dimse_attack, special_attack = combo
            elif len(combo) == 7:
                name, sem_field, sem_value, payload_type, target, sequence, dimse_attack = combo
                special_attack = None
            else:
                name, sem_field, sem_value, payload_type, target, sequence = combo
                dimse_attack = None
                special_attack = None

            # Classify by primary characteristic (order matters — first match wins)
            if sequence in ("cstore_rich", "cstore_mr", "cstore_us", "cstore_sc", "cstore_explicit"):
                categories["dataset"].append(idx)
            elif special_attack in ("slowloris", "fragment"):
                categories["timing"].append(idx)
            elif special_attack in ("concurrent", "rapid_reconnect", "memory_exhaust"):
                categories["concurrent"].append(idx)
            elif special_attack and (special_attack.startswith("byte_") or special_attack.startswith("seed_")):
                categories["byte"].append(idx)
            elif dimse_attack is not None:
                categories["dimse"].append(idx)
            elif payload_type is not None:
                categories["payload"].append(idx)
            elif sequence not in normal_sequences:
                categories["state"].append(idx)
            elif sem_field is not None:
                categories["semantic"].append(idx)
            else:
                # Fallback: basic normal sequence combos go to state
                categories["state"].append(idx)

        return categories

    def _get_combo_category(self, combo):
        """Determine the category of a combo tuple."""
        if len(combo) >= 8:
            name, sem_field, sem_value, payload_type, target, sequence, dimse_attack, special_attack = combo
        elif len(combo) == 7:
            name, sem_field, sem_value, payload_type, target, sequence, dimse_attack = combo
            special_attack = None
        else:
            name, sem_field, sem_value, payload_type, target, sequence = combo
            dimse_attack = None
            special_attack = None

        normal_sequences = {"normal", "cstore_normal", "cfind_normal", "cmove_normal",
                            "cget_normal", "cstore_rich", "cstore_mr", "cstore_us",
                            "cstore_sc", "cstore_explicit"}

        if sequence in ("cstore_rich", "cstore_mr", "cstore_us", "cstore_sc", "cstore_explicit"):
            return "dataset"
        elif special_attack in ("slowloris", "fragment"):
            return "timing"
        elif special_attack in ("concurrent", "rapid_reconnect", "memory_exhaust"):
            return "concurrent"
        elif special_attack and (special_attack.startswith("byte_") or special_attack.startswith("seed_")):
            return "byte"
        elif dimse_attack is not None:
            return "dimse"
        elif payload_type is not None:
            return "payload"
        elif sequence not in normal_sequences:
            return "state"
        elif sem_field is not None:
            return "semantic"
        return "state"

    def _get_obs(self):
        obs = np.zeros(30, dtype=np.float32)

        # Field values (0-5)
        obs[0] = self.current_fields["message_id"] / 65535.0
        obs[1] = self.current_fields["command_field"] / 65535.0
        obs[2] = self.current_fields["data_set_type"] / 65535.0
        obs[3] = self.current_fields["context_id"] / 255.0
        obs[4] = self.current_fields["msg_control"] / 255.0
        obs[5] = min(self.current_fields["max_pdu_length"] / 65536.0, 1.0)

        # Response history (6-10)
        response_map = {
            "none": 0, "accept": 0.2, "reject": 0.3, "abort": 0.5,
            "timeout": 0.8, "reset": 0.4, "pdata": 0.9, "crash": 1.0,
            "closed": 0.6, "refused": 0.7
        }
        for i, resp in enumerate(self.response_history[-5:]):
            obs[6 + i] = response_map.get(resp, 0.5)

        # Counters (11-14)
        obs[11] = min(self.hang_count / 10.0, 1.0)
        obs[12] = min(self.crash_count / 5.0, 1.0)
        obs[13] = min(self.accept_count / 20.0, 1.0)
        obs[14] = self.step_count / self.max_steps

        # Log-based features (15-19)
        obs[15] = min(self.new_error_count / 20.0, 1.0)      # New errors discovered
        obs[16] = min(self.new_location_count / 50.0, 1.0)   # New code paths

        # Log monitor stats if available
        if self.log_monitor:
            stats = self.log_monitor.get_stats()
            obs[17] = min(stats.get('unique_messages', 0) / 100.0, 1.0)
            obs[18] = min(stats.get('unique_locations', 0) / 100.0, 1.0)
            obs[19] = min(stats.get('errors', 0) / 50.0, 1.0)

        # Process monitoring metrics (20-22)
        if hasattr(self, 'process_monitor') and self.process_monitor:
            metrics = self.process_monitor.get_latest_metrics()
            if metrics:
                obs[20] = min(metrics.get('rss_growth_mb', 0) / 100.0, 1.0)
                obs[21] = min(metrics.get('fd_growth', 0) / 100.0, 1.0)
                obs[22] = min(metrics.get('cpu_percent', 0) / 100.0, 1.0)

        # Diversity metrics (23-24)
        if self.action_visit_counts:
            counts = np.array(list(self.action_visit_counts.values()), dtype=np.float32)
            total = counts.sum()
            if total > 0:
                probs = counts / total
                entropy = -np.sum(probs * np.log(probs + 1e-10))
                max_entropy = math.log(max(len(counts), 1) + 1e-10)
                obs[23] = entropy / max_entropy if max_entropy > 0 else 0  # Action entropy (0-1)
        obs[24] = min(self.consecutive_same_action / 10.0, 1.0)

        # ASAN features (25-26)
        if hasattr(self, 'asan_monitor') and self.asan_monitor:
            bug_counts = self.asan_monitor.get_bug_counts()
            obs[25] = min(bug_counts.get('critical', 0) / 5.0, 1.0)
            obs[26] = min(bug_counts.get('total', 0) / 20.0, 1.0)

        # Coverage features (27-29)
        if hasattr(self, 'coverage_monitor') and self.coverage_monitor:
            cov = self.coverage_monitor.get_current_coverage()
            obs[27] = min(cov.get('lines_from_baseline', 0) / 100.0, 1.0)
            obs[28] = min(cov.get('functions_from_baseline', 0) / 50.0, 1.0)
            obs[29] = min(cov.get('lines', 0) / 1000.0, 1.0)

        return obs

    def _get_payload(self, payload_type):
        """Get a random payload of the specified type."""
        payloads = {
            "format_string": FORMAT_STRING_PAYLOADS,
            "path_traversal": PATH_TRAVERSAL_PAYLOADS,
            "buffer_overflow": BUFFER_OVERFLOW_PAYLOADS,
            "null_injection": NULL_INJECTION_PAYLOADS,
            "special_chars": SPECIAL_CHAR_PAYLOADS,
            # CVE-inspired payloads
            "integer_overflow": INTEGER_OVERFLOW_PAYLOADS,
            "path_uid": PATH_TRAVERSAL_UID_PAYLOADS,
            "large_alloc": LARGE_ALLOC_PAYLOADS,
            "rle_attack": RLE_ATTACK_PAYLOADS,
            "nested_seq": NESTED_SEQUENCE_PAYLOADS,
            "type_confusion": TYPE_CONFUSION_PAYLOADS,
        }
        if payload_type in payloads:
            return random.choice(payloads[payload_type])
        return None

    def _build_assoc_rq(self):
        called = self.current_payloads.get("called_ae") or self.called_ae
        calling = self.current_payloads.get("calling_ae") or b"FUZZER"
        abstract = self.current_payloads.get("abstract_syntax")
        transfer = self.current_payloads.get("transfer_syntax")
        max_pdu = self.current_fields.get("max_pdu_length", 16384)

        return build_smart_assoc_rq(
            called_ae=called,
            calling_ae=calling,
            max_pdu_length=max_pdu,
            abstract_syntax=abstract,
            transfer_syntax=transfer,
        )

    def _build_pdata(self):
        # Check if we have a malformed DIMSE attack to use
        dimse_attack = getattr(self, '_current_dimse_attack', None)
        if dimse_attack:
            return build_malformed_dimse_pdata(dimse_attack)

        # Otherwise use semantic mutations
        return build_smart_cecho_pdata(
            context_id=self.current_fields["context_id"],
            msg_control=self.current_fields["msg_control"],
            command_field=self.current_fields["command_field"],
            message_id=self.current_fields["message_id"],
            data_set_type=self.current_fields["data_set_type"],
        )

    def _build_cstore_pdata(self):
        """Build C-STORE-RQ PDATA with minimal/malformed dataset."""
        ctx_id = self.current_fields.get("context_id", 1)
        msg_id = self.current_fields.get("message_id", 1)

        # C-STORE-RQ command
        sop_class = b'1.2.840.10008.5.1.4.1.1.2'  # CT Image Storage
        if len(sop_class) % 2:
            sop_class += b'\x00'
        sop_instance = b'1.2.3.4.5.6.7.8.9.0'
        if len(sop_instance) % 2:
            sop_instance += b'\x00'

        # Build command set
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class)) + sop_class
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0001)  # C-STORE-RQ
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)
        elem_0700 = struct.pack('<HH I H', 0x0000, 0x0700, 2, 0)  # Priority: medium
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0000)  # Dataset present
        elem_1000 = struct.pack('<HH I', 0x0000, 0x1000, len(sop_instance)) + sop_instance

        command_set = elem_0002 + elem_0100 + elem_0110 + elem_0700 + elem_0800 + elem_1000
        elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
        command_set = elem_0000 + command_set

        # Build command PDV (msg_control = 0x01 = command, not last)
        cmd_pdv = struct.pack('>BB', ctx_id, 0x01) + command_set
        cmd_pdv_item = struct.pack('>I', len(cmd_pdv)) + cmd_pdv

        # Build minimal/malformed dataset
        # Patient Name with payload injection potential
        patient_name = self.current_payloads.get("called_ae") or b"FUZZPATIENT"
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '

        # Minimal dataset elements
        ds_elem_0010_0010 = struct.pack('<HH', 0x0010, 0x0010) + b'PN' + struct.pack('<H', len(patient_name)) + patient_name
        ds_elem_0008_0018 = struct.pack('<HH I', 0x0008, 0x0018, len(sop_instance)) + sop_instance
        dataset = ds_elem_0010_0010 + ds_elem_0008_0018

        # Build data PDV (msg_control = 0x02 = data, last fragment)
        data_pdv = struct.pack('>BB', ctx_id, 0x02) + dataset
        data_pdv_item = struct.pack('>I', len(data_pdv)) + data_pdv

        # Combine into PDATA PDU
        pdu_data = cmd_pdv_item + data_pdv_item
        return struct.pack('>BBi', 0x04, 0, len(pdu_data)) + pdu_data

    def _build_multi_context_assoc_rq(self, sop_class_key="ct", transfer_syntax_key="implicit_vr_le"):
        """Build ASSOC_RQ with multiple presentation contexts (Verification + storage SOP class).

        This ensures C-STORE/C-FIND/C-MOVE are not rejected due to missing SOP negotiation.
        """
        called = self.current_payloads.get("called_ae") or self.called_ae
        calling = self.current_payloads.get("calling_ae") or b"FUZZER"
        max_pdu = self.current_fields.get("max_pdu_length", 16384)

        # Always include Verification + the requested storage SOP class
        xfer = TRANSFER_SYNTAXES.get(transfer_syntax_key, TRANSFER_SYNTAXES["implicit_vr_le"])
        contexts = [
            (STORAGE_SOP_CLASSES["verification"], [TRANSFER_SYNTAXES["implicit_vr_le"]]),
        ]
        sop_uid = STORAGE_SOP_CLASSES.get(sop_class_key, STORAGE_SOP_CLASSES["ct"])
        contexts.append((sop_uid, [xfer]))

        # Optionally inject abstract_syntax/transfer_syntax payloads
        abstract = self.current_payloads.get("abstract_syntax")
        transfer = self.current_payloads.get("transfer_syntax")
        if abstract:
            contexts.append((abstract if isinstance(abstract, bytes) else abstract.encode(), [xfer]))
        if transfer:
            contexts[1] = (sop_uid, [transfer if isinstance(transfer, bytes) else transfer.encode()])

        return build_multi_context_assoc_rq(
            presentation_contexts=contexts,
            called_ae=called,
            calling_ae=calling,
            max_pdu_length=max_pdu,
        )

    def _build_cstore_rich_pdata(self, sop_class_key="ct", explicit_vr=False):
        """Build C-STORE-RQ PDATA with rich dataset (15+ elements + pixel data).

        This exercises dataset parsing, VR validation, pixel data handling,
        and storage code paths that the minimal C-STORE never reaches.
        """
        ctx_id = self.current_fields.get("context_id", 1)
        msg_id = self.current_fields.get("message_id", 1)

        sop_class = STORAGE_SOP_CLASSES.get(sop_class_key, STORAGE_SOP_CLASSES["ct"])
        if len(sop_class) % 2:
            sop_class += b'\x00'
        sop_instance = b'1.2.3.4.5.6.7.8.9.10.11.12'
        if len(sop_instance) % 2:
            sop_instance += b'\x00'
        study_uid = b'1.2.3.4.5.6.7.100'
        if len(study_uid) % 2:
            study_uid += b'\x00'
        series_uid = b'1.2.3.4.5.6.7.200'
        if len(series_uid) % 2:
            series_uid += b'\x00'

        # ---- Command Set (always implicit VR LE) ----
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class)) + sop_class
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0001)  # C-STORE-RQ
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)
        elem_0700 = struct.pack('<HH I H', 0x0000, 0x0700, 2, 0)       # Priority: medium
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0000)  # Dataset present
        elem_1000 = struct.pack('<HH I', 0x0000, 0x1000, len(sop_instance)) + sop_instance

        command_set = elem_0002 + elem_0100 + elem_0110 + elem_0700 + elem_0800 + elem_1000
        elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
        command_set = elem_0000 + command_set

        # Command PDV (flag 0x01 = command, not last fragment)
        cmd_pdv = struct.pack('>BB', ctx_id, 0x01) + command_set
        cmd_pdv_item = struct.pack('>I', len(cmd_pdv)) + cmd_pdv

        # ---- Dataset ----
        # Helper to build dataset elements
        def _implicit_elem(group, element, data):
            return struct.pack('<HH I', group, element, len(data)) + data

        def _explicit_elem(group, element, vr, data):
            vr_bytes = vr.encode('ascii') if isinstance(vr, str) else vr
            # Short VRs (2-byte length): AE, AS, AT, CS, DA, DS, DT, FL, FD, IS, LO, LT, PN, SH, SL, SS, ST, TM, UI, UL, US
            short_vrs = {b'AE', b'AS', b'AT', b'CS', b'DA', b'DS', b'DT', b'FL', b'FD',
                         b'IS', b'LO', b'LT', b'PN', b'SH', b'SL', b'SS', b'ST', b'TM',
                         b'UI', b'UL', b'US'}
            if vr_bytes in short_vrs:
                return struct.pack('<HH', group, element) + vr_bytes + struct.pack('<H', len(data)) + data
            else:
                # Long VRs (OB, OW, SQ, UN, etc.): VR + 2 reserved bytes + 4-byte length
                return struct.pack('<HH', group, element) + vr_bytes + b'\x00\x00' + struct.pack('<I', len(data)) + data

        build_elem = _explicit_elem if explicit_vr else (lambda g, e, vr, d: _implicit_elem(g, e, d))

        # Get a payload for string fields if available
        patient_name = self.current_payloads.get("called_ae") or b"FUZZPATIENT^TEST"
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '

        # Modality based on SOP class
        modality_map = {"ct": b"CT", "mr": b"MR", "us": b"US", "cr": b"CR", "sc": b"OT"}
        modality = modality_map.get(sop_class_key, b"OT")
        if len(modality) % 2:
            modality += b' '

        dataset = b''

        # SOP Class UID (0008,0016) + SOP Instance UID (0008,0018)
        dataset += build_elem(0x0008, 0x0016, 'UI', sop_class)
        dataset += build_elem(0x0008, 0x0018, 'UI', sop_instance)
        # Study Date (0008,0020)
        study_date = b'20260101'
        dataset += build_elem(0x0008, 0x0020, 'DA', study_date)
        # Study Time (0008,0030)
        study_time = b'120000'
        if len(study_time) % 2:
            study_time += b' '
        dataset += build_elem(0x0008, 0x0030, 'TM', study_time)
        # Accession Number (0008,0050)
        accession = b'FUZZ0001'
        dataset += build_elem(0x0008, 0x0050, 'SH', accession)
        # Modality (0008,0060)
        dataset += build_elem(0x0008, 0x0060, 'CS', modality)
        # Referring Physician Name (0008,0090)
        ref_phys = b'DRFUZZ^PHYSICIAN'
        if len(ref_phys) % 2:
            ref_phys += b' '
        dataset += build_elem(0x0008, 0x0090, 'PN', ref_phys)
        # Patient Name (0010,0010) — payload injection target
        dataset += build_elem(0x0010, 0x0010, 'PN', patient_name)
        # Patient ID (0010,0020)
        patient_id = b'FUZZPID001'
        if len(patient_id) % 2:
            patient_id += b' '
        dataset += build_elem(0x0010, 0x0020, 'LO', patient_id)
        # Patient Birth Date (0010,0030)
        dataset += build_elem(0x0010, 0x0030, 'DA', b'19900101')
        # Patient Sex (0010,0040)
        dataset += build_elem(0x0010, 0x0040, 'CS', b'M ')
        # Study Instance UID (0020,000D)
        dataset += build_elem(0x0020, 0x000D, 'UI', study_uid)
        # Series Instance UID (0020,000E)
        dataset += build_elem(0x0020, 0x000E, 'UI', series_uid)
        # Instance Number (0020,0013)
        dataset += build_elem(0x0020, 0x0013, 'IS', b'1 ')
        # Series Number (0020,0011)
        dataset += build_elem(0x0020, 0x0011, 'IS', b'1 ')

        # Image-level attributes
        # Rows (0028,0010) = 64
        dataset += build_elem(0x0028, 0x0010, 'US', struct.pack('<H', 64))
        # Columns (0028,0011) = 64
        dataset += build_elem(0x0028, 0x0011, 'US', struct.pack('<H', 64))
        # Bits Allocated (0028,0100) = 16
        dataset += build_elem(0x0028, 0x0100, 'US', struct.pack('<H', 16))
        # Bits Stored (0028,0101) = 12
        dataset += build_elem(0x0028, 0x0101, 'US', struct.pack('<H', 12))
        # High Bit (0028,0102) = 11
        dataset += build_elem(0x0028, 0x0102, 'US', struct.pack('<H', 11))
        # Pixel Representation (0028,0103) = 0 (unsigned)
        dataset += build_elem(0x0028, 0x0103, 'US', struct.pack('<H', 0))
        # Samples Per Pixel (0028,0002) = 1
        dataset += build_elem(0x0028, 0x0002, 'US', struct.pack('<H', 1))

        # Pixel Data (7FE0,0010): 64x64 pixels x 2 bytes = 8192 bytes
        pixel_data = bytes([random.randint(0, 255) for _ in range(8192)])
        dataset += build_elem(0x7FE0, 0x0010, 'OW', pixel_data)

        # Data PDV (flag 0x02 = data, last fragment)
        data_pdv = struct.pack('>BB', ctx_id, 0x02) + dataset
        data_pdv_item = struct.pack('>I', len(data_pdv)) + data_pdv

        # Combine into PDATA PDU
        pdu_data = cmd_pdv_item + data_pdv_item
        return struct.pack('>BBi', 0x04, 0, len(pdu_data)) + pdu_data

    def _build_cfind_pdata(self):
        """Build C-FIND-RQ PDATA with query dataset."""
        ctx_id = self.current_fields.get("context_id", 1)
        msg_id = self.current_fields.get("message_id", 1)

        # C-FIND-RQ command
        sop_class = b'1.2.840.10008.5.1.4.1.2.2.1'  # Patient Root Query/Retrieve
        if len(sop_class) % 2:
            sop_class += b'\x00'

        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class)) + sop_class
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0020)  # C-FIND-RQ
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)
        elem_0700 = struct.pack('<HH I H', 0x0000, 0x0700, 2, 0)
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0000)  # Dataset present

        command_set = elem_0002 + elem_0100 + elem_0110 + elem_0700 + elem_0800
        elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
        command_set = elem_0000 + command_set

        cmd_pdv = struct.pack('>BB', ctx_id, 0x01) + command_set
        cmd_pdv_item = struct.pack('>I', len(cmd_pdv)) + cmd_pdv

        # Query dataset - try to inject payloads
        patient_name = self.current_payloads.get("calling_ae") or b"*"
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '

        # Query with wildcard or injected payload
        ds_elem = struct.pack('<HH', 0x0010, 0x0010) + b'PN' + struct.pack('<H', len(patient_name)) + patient_name
        # Query level
        level = b'PATIENT '
        ds_level = struct.pack('<HH', 0x0008, 0x0052) + b'CS' + struct.pack('<H', len(level)) + level
        dataset = ds_elem + ds_level

        data_pdv = struct.pack('>BB', ctx_id, 0x02) + dataset
        data_pdv_item = struct.pack('>I', len(data_pdv)) + data_pdv

        pdu_data = cmd_pdv_item + data_pdv_item
        return struct.pack('>BBi', 0x04, 0, len(pdu_data)) + pdu_data

    def _build_cmove_pdata(self):
        """Build C-MOVE-RQ PDATA with query dataset and move destination."""
        ctx_id = self.current_fields.get("context_id", 1)
        msg_id = self.current_fields.get("message_id", 1)

        # C-MOVE-RQ command
        sop_class = b'1.2.840.10008.5.1.4.1.2.2.2'  # Patient Root Q/R - MOVE
        if len(sop_class) % 2:
            sop_class += b'\x00'

        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class)) + sop_class
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0021)  # C-MOVE-RQ
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)
        elem_0700 = struct.pack('<HH I H', 0x0000, 0x0700, 2, 0)  # Priority: medium
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0000)  # Dataset present

        # Move Destination (0000,0600) - called AE or fuzz payload
        move_dest = self.current_payloads.get("called_ae") or self.called_ae
        if isinstance(move_dest, str):
            move_dest = move_dest.encode()
        # Pad to 16 bytes (AE title max length)
        move_dest_padded = move_dest.ljust(16, b' ')[:16]
        elem_0600 = struct.pack('<HH I', 0x0000, 0x0600, len(move_dest_padded)) + move_dest_padded

        command_set = elem_0002 + elem_0100 + elem_0110 + elem_0600 + elem_0700 + elem_0800
        elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
        command_set = elem_0000 + command_set

        cmd_pdv = struct.pack('>BB', ctx_id, 0x01) + command_set
        cmd_pdv_item = struct.pack('>I', len(cmd_pdv)) + cmd_pdv

        # Query dataset
        patient_name = self.current_payloads.get("calling_ae") or b"*"
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '

        ds_elem = struct.pack('<HH', 0x0010, 0x0010) + b'PN' + struct.pack('<H', len(patient_name)) + patient_name
        level = b'STUDY   '
        ds_level = struct.pack('<HH', 0x0008, 0x0052) + b'CS' + struct.pack('<H', len(level)) + level
        dataset = ds_elem + ds_level

        data_pdv = struct.pack('>BB', ctx_id, 0x02) + dataset
        data_pdv_item = struct.pack('>I', len(data_pdv)) + data_pdv

        pdu_data = cmd_pdv_item + data_pdv_item
        return struct.pack('>BBi', 0x04, 0, len(pdu_data)) + pdu_data

    def _build_cget_pdata(self):
        """Build C-GET-RQ PDATA with query dataset."""
        ctx_id = self.current_fields.get("context_id", 1)
        msg_id = self.current_fields.get("message_id", 1)

        # C-GET-RQ command
        sop_class = b'1.2.840.10008.5.1.4.1.2.2.3'  # Patient Root Q/R - GET
        if len(sop_class) % 2:
            sop_class += b'\x00'

        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class)) + sop_class
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0010)  # C-GET-RQ
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)
        elem_0700 = struct.pack('<HH I H', 0x0000, 0x0700, 2, 0)  # Priority: medium
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0000)  # Dataset present

        command_set = elem_0002 + elem_0100 + elem_0110 + elem_0700 + elem_0800
        elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
        command_set = elem_0000 + command_set

        cmd_pdv = struct.pack('>BB', ctx_id, 0x01) + command_set
        cmd_pdv_item = struct.pack('>I', len(cmd_pdv)) + cmd_pdv

        # Query dataset
        patient_name = self.current_payloads.get("calling_ae") or b"*"
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '

        ds_elem = struct.pack('<HH', 0x0010, 0x0010) + b'PN' + struct.pack('<H', len(patient_name)) + patient_name
        level = b'STUDY   '
        ds_level = struct.pack('<HH', 0x0008, 0x0052) + b'CS' + struct.pack('<H', len(level)) + level
        dataset = ds_elem + ds_level

        data_pdv = struct.pack('>BB', ctx_id, 0x02) + dataset
        data_pdv_item = struct.pack('>I', len(data_pdv)) + data_pdv

        pdu_data = cmd_pdv_item + data_pdv_item
        return struct.pack('>BBi', 0x04, 0, len(pdu_data)) + pdu_data

    def _apply_byte_mutations(self, pdu_bytes, mode, n_mutations=None):
        """Apply byte-level mutations to raw PDU bytes.

        Args:
            pdu_bytes: Raw PDU bytes to mutate
            mode: Mutation mode (byte_flip, byte_length, byte_hotspot, byte_boundary, seed_mutate)
            n_mutations: Number of mutations to apply (default varies by mode)

        Returns:
            Mutated bytes
        """
        data = bytearray(pdu_bytes)
        if len(data) < 6:
            return bytes(data)

        if mode == "byte_flip":
            # Flip random bits at random offsets
            count = n_mutations or 3
            for _ in range(count):
                offset = random.randint(0, len(data) - 1)
                bit = random.randint(0, 7)
                data[offset] ^= (1 << bit)

        elif mode == "byte_length":
            # Corrupt 4-byte length fields at offsets 2 and 6
            length_values = [0, 0xFFFFFFFF, 1, 0x7FFFFFFF]
            for base_offset in [2, 6]:
                if base_offset + 4 <= len(data):
                    val = random.choice(length_values)
                    struct.pack_into('>I', data, base_offset, val)

        elif mode == "byte_hotspot":
            # Weighted random selection from critical PDATA offsets
            weights = [w for _, _, _, w in PDATA_HOTSPOT_OFFSETS]
            total = sum(weights)
            probs = [w / total for w in weights]
            count = n_mutations or 2
            for _ in range(count):
                idx = random.choices(range(len(PDATA_HOTSPOT_OFFSETS)), weights=probs, k=1)[0]
                start, end, _, _ = PDATA_HOTSPOT_OFFSETS[idx]
                if start < len(data):
                    actual_end = min(end, len(data))
                    for off in range(start, actual_end):
                        data[off] = random.choice(BOUNDARY_BYTE_VALUES)

        elif mode == "byte_boundary":
            # Replace random bytes with boundary values
            count = n_mutations or 4
            for _ in range(count):
                offset = random.randint(0, len(data) - 1)
                data[offset] = random.choice(BOUNDARY_BYTE_VALUES)

        elif mode == "seed_mutate":
            # Combine flip + length + boundary (5-10 random mutations)
            count = random.randint(5, 10)
            for _ in range(count):
                mutation_type = random.choice(["flip", "length", "boundary"])
                if mutation_type == "flip":
                    offset = random.randint(0, len(data) - 1)
                    bit = random.randint(0, 7)
                    data[offset] ^= (1 << bit)
                elif mutation_type == "length" and len(data) >= 6:
                    base_offset = random.choice([2, 6])
                    if base_offset + 4 <= len(data):
                        val = random.choice([0, 0xFFFFFFFF, 1, 0x7FFFFFFF])
                        struct.pack_into('>I', data, base_offset, val)
                else:
                    offset = random.randint(0, len(data) - 1)
                    data[offset] = random.choice(BOUNDARY_BYTE_VALUES)

        return bytes(data)

    def _send_slowloris(self, sequence_name):
        """Send ASSOC_RQ byte-by-byte with delays to test timeout handling.

        Opens N connections and sends data one byte at a time with 100ms delays.
        Tests server's ability to handle slow/incomplete PDU delivery.
        """
        info = {
            "response": "none",
            "responses": [],
            "crash": False,
            "hang": False,
            "slow": False,
            "sequence": sequence_name,
            "special_attack": "slowloris",
        }
        total_reward = 0.0

        if not self.target_host:
            return total_reward, info

        n_connections = 3
        assoc_rq = self._build_assoc_rq()
        sockets = []

        try:
            # Open multiple connections
            for _ in range(n_connections):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5.0)
                    s.connect((self.target_host, self.target_port))
                    sockets.append(s)
                except Exception:
                    pass

            if not sockets:
                info["response"] = "refused"
                return 0.0, info

            # Send byte-by-byte with delays (limit to 20 bytes, 50ms gap)
            bytes_to_send = min(20, len(assoc_rq))
            for i in range(bytes_to_send):
                for s in sockets:
                    try:
                        s.sendall(assoc_rq[i:i+1])
                    except Exception:
                        pass
                time.sleep(0.05)

            # Test if server can still accept new connections
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.settimeout(2.0)
                test_sock.connect((self.target_host, self.target_port))
                test_sock.close()
                info["response"] = "accept"
                total_reward += 10.0  # Server still responsive
            except socket.timeout:
                info["response"] = "timeout"
                info["hang"] = True
                self.hang_count += 1
                total_reward += 50.0  # Server hung under slowloris
            except ConnectionRefusedError:
                info["response"] = "refused"
                total_reward += 30.0  # Connection pool may be exhausted

            # Collect any responses from slow sockets
            for s in sockets:
                try:
                    s.settimeout(1.0)
                    resp = s.recv(4096)
                    if resp:
                        if resp[0] == 0x07:
                            total_reward += 15.0  # Abort
                        elif resp[0] == 0x03:
                            total_reward += 5.0   # Reject
                except Exception:
                    pass

        except Exception as e:
            info["response"] = "error"
            total_reward += 3.0
        finally:
            for s in sockets:
                try:
                    s.close()
                except Exception:
                    pass

        self.response_history.append(info["response"])
        return total_reward, info

    def _send_fragment(self, sequence_name):
        """Send PDUs split at midpoint with delay between halves.

        Tests TCP reassembly and PDU buffering edge cases.
        """
        info = {
            "response": "none",
            "responses": [],
            "crash": False,
            "hang": False,
            "slow": False,
            "sequence": sequence_name,
            "special_attack": "fragment",
        }
        total_reward = 0.0

        if not self.target_host:
            return total_reward, info

        sequence = None
        for name, seq in STATE_SEQUENCES:
            if name == sequence_name:
                sequence = seq
                break
        if not sequence:
            sequence = ["assoc_rq", "pdata", "release_rq"]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(5.0)
            sock.connect((self.target_host, self.target_port))

            for pdu_type in sequence:
                pdu = self._build_pdu(pdu_type)
                mid = len(pdu) // 2
                t_start = time.monotonic()

                try:
                    # Send first half
                    sock.sendall(pdu[:mid])
                    time.sleep(0.2)
                    # Send second half
                    sock.sendall(pdu[mid:])

                    sock.settimeout(2.0)
                    resp_data = sock.recv(4096)
                    t_end = time.monotonic()
                    resp_time = (t_end - t_start) * 1000

                    if not resp_data:
                        resp_type = "closed"
                        reward = 8.0
                    elif resp_data[0] == 0x02:
                        resp_type = "accept"
                        self.accept_count += 1
                        reward = 5.0
                    elif resp_data[0] == 0x03:
                        resp_type = "reject"
                        reward = 3.0
                    elif resp_data[0] == 0x04:
                        resp_type = "pdata"
                        reward = 25.0
                    elif resp_data[0] == 0x07:
                        resp_type = "abort"
                        reward = 50.0  # Abort: server hit error-handling path
                    else:
                        resp_type = f"type_{resp_data[0]:02x}"
                        reward = 20.0

                    if resp_time > 1000:
                        reward += 30.0  # Very slow reassembly
                    elif resp_time > 500:
                        reward += 15.0

                    info["responses"].append({"pdu": pdu_type, "response": resp_type})
                    info["response"] = resp_type
                    total_reward += reward

                except socket.timeout:
                    info["response"] = "timeout"
                    info["hang"] = True
                    self.hang_count += 1
                    total_reward += 40.0  # Fragment caused hang
                    break

            sock.close()

        except ConnectionResetError:
            info["response"] = "reset"
            total_reward += 5.0
        except ConnectionRefusedError:
            info["response"] = "refused"
            time.sleep(0.3)
            try:
                check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                check.settimeout(2.0)
                check.connect((self.target_host, self.target_port))
                check.close()
            except Exception:
                info["crash"] = True
                self.crash_count += 1
                total_reward += 150.0
        except Exception:
            info["response"] = "error"
            total_reward += 3.0

        self.response_history.append(info["response"])
        return total_reward, info

    def _send_concurrent(self, sequence_name, n_connections=5):
        """Send same sequence from N parallel threads.

        Tests race conditions and connection pool exhaustion.
        """
        info = {
            "response": "none",
            "responses": [],
            "crash": False,
            "hang": False,
            "slow": False,
            "sequence": sequence_name,
            "special_attack": "concurrent",
        }
        total_reward = 0.0

        if not self.target_host:
            return total_reward, info

        sequence = None
        for name, seq in STATE_SEQUENCES:
            if name == sequence_name:
                sequence = seq
                break
        if not sequence:
            sequence = ["assoc_rq", "pdata", "release_rq"]

        # Build PDUs once (shared across threads)
        pdus = [self._build_pdu(pdu_type) for pdu_type in sequence]

        results = {"refused": 0, "timeout": 0, "success": 0, "reset": 0, "error": 0}
        results_lock = threading.Lock()

        def send_one():
            result = "error"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.settimeout(5.0)
                s.connect((self.target_host, self.target_port))
                for pdu in pdus:
                    s.sendall(pdu)
                    s.settimeout(2.0)
                    try:
                        resp = s.recv(4096)
                        if resp:
                            result = "success"
                    except socket.timeout:
                        result = "timeout"
                        break
                s.close()
            except ConnectionRefusedError:
                result = "refused"
            except ConnectionResetError:
                result = "reset"
            except Exception:
                result = "error"

            with results_lock:
                results[result] = results.get(result, 0) + 1

        with ThreadPoolExecutor(max_workers=n_connections) as executor:
            futures = [executor.submit(send_one) for _ in range(n_connections)]
            for f in as_completed(futures, timeout=8):
                try:
                    f.result()
                except Exception:
                    pass

        # Analyze results
        refused_pct = results["refused"] / n_connections
        timeout_pct = results["timeout"] / n_connections

        if refused_pct > 0.5:
            info["response"] = "refused"
            total_reward += 30.0  # Connection pool exhausted
            info["responses"].append({"type": "connection_exhausted", "refused_pct": refused_pct})
        elif timeout_pct > 0.3:
            info["response"] = "timeout"
            info["hang"] = True
            self.hang_count += 1
            total_reward += 40.0  # Race condition or deadlock
        elif results["success"] > 0:
            info["response"] = "accept"
            total_reward += 10.0
        else:
            info["response"] = "error"
            total_reward += 5.0

        info["concurrent_results"] = dict(results)

        # Check server alive after concurrent attack
        time.sleep(0.3)
        try:
            check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            check.settimeout(2.0)
            check.connect((self.target_host, self.target_port))
            check.close()
        except Exception:
            info["crash"] = True
            self.crash_count += 1
            total_reward += 150.0

        self.response_history.append(info["response"])
        return total_reward, info

    def _send_rapid_reconnect(self, n_cycles=10):
        """Rapid TCP connect/disconnect cycles without sending any PDU.

        Tests connection handling cleanup and resource leaks.
        """
        info = {
            "response": "none",
            "responses": [],
            "crash": False,
            "hang": False,
            "slow": False,
            "sequence": "rapid_reconnect",
            "special_attack": "rapid_reconnect",
        }
        total_reward = 0.0

        if not self.target_host:
            return total_reward, info

        connect_ok = 0
        connect_fail = 0

        for _ in range(n_cycles):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect((self.target_host, self.target_port))
                s.close()
                connect_ok += 1
            except Exception:
                connect_fail += 1

        info["responses"].append({
            "type": "rapid_reconnect",
            "connect_ok": connect_ok,
            "connect_fail": connect_fail,
        })

        # If later cycles started failing, server may be resource-exhausted
        if connect_fail > n_cycles * 0.3:
            info["response"] = "refused"
            total_reward += 25.0
        else:
            info["response"] = "accept"
            total_reward += 5.0

        # Check server alive after all cycles
        time.sleep(0.3)
        try:
            check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            check.settimeout(2.0)
            check.connect((self.target_host, self.target_port))
            check.close()
        except Exception:
            info["crash"] = True
            self.crash_count += 1
            total_reward += 150.0

        self.response_history.append(info["response"])
        return total_reward, info

    def _send_memory_exhaust(self, sequence_name, n_rounds=3, pdu_size=65536):
        """Send oversized PDUs in a loop to test memory handling.

        Builds oversized ASSOC_RQ with padding and sends repeatedly.
        """
        info = {
            "response": "none",
            "responses": [],
            "crash": False,
            "hang": False,
            "slow": False,
            "sequence": sequence_name,
            "special_attack": "memory_exhaust",
        }
        total_reward = 0.0

        if not self.target_host:
            return total_reward, info

        # Build oversized ASSOC_RQ with padding
        base_assoc = self._build_assoc_rq()
        padding = bytes([random.randint(0, 255) for _ in range(pdu_size)])
        # Overwrite length to include padding
        padded_len = len(base_assoc) - 6 + len(padding)  # PDU length excludes first 6 bytes
        oversized = bytearray(base_assoc)
        struct.pack_into('>I', oversized, 2, padded_len)
        oversized = bytes(oversized) + padding

        for i in range(n_rounds):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect((self.target_host, self.target_port))
                s.sendall(oversized)

                try:
                    s.settimeout(2.0)
                    resp = s.recv(4096)
                    if resp:
                        if resp[0] == 0x07:
                            total_reward += 10.0  # Abort (server handled it)
                        elif resp[0] == 0x03:
                            total_reward += 5.0
                        else:
                            total_reward += 15.0  # Unexpected response
                except socket.timeout:
                    total_reward += 20.0  # Server stalled processing large PDU
                    info["slow"] = True
                    self.slow_count += 1

                s.close()
            except ConnectionRefusedError:
                info["response"] = "refused"
                total_reward += 20.0
                break
            except ConnectionResetError:
                total_reward += 5.0
            except Exception:
                total_reward += 3.0

            time.sleep(0.1)

        # Check server alive after exhaustion attempts
        time.sleep(0.3)
        try:
            check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            check.settimeout(2.0)
            check.connect((self.target_host, self.target_port))
            check.close()
            if info["response"] == "none":
                info["response"] = "accept"
        except Exception:
            info["crash"] = True
            self.crash_count += 1
            total_reward += 150.0

        self.response_history.append(info["response"])
        return total_reward, info

    def _build_pdu_inner(self, pdu_type):
        """Core PDU dispatch without mutations or seed overrides."""
        if pdu_type == "assoc_rq":
            return self._build_assoc_rq()
        elif pdu_type == "assoc_rq_ct":
            return self._build_multi_context_assoc_rq(sop_class_key="ct", transfer_syntax_key="implicit_vr_le")
        elif pdu_type == "assoc_rq_mr":
            return self._build_multi_context_assoc_rq(sop_class_key="mr", transfer_syntax_key="implicit_vr_le")
        elif pdu_type == "assoc_rq_us":
            return self._build_multi_context_assoc_rq(sop_class_key="us", transfer_syntax_key="implicit_vr_le")
        elif pdu_type == "assoc_rq_sc":
            return self._build_multi_context_assoc_rq(sop_class_key="sc", transfer_syntax_key="implicit_vr_le")
        elif pdu_type == "assoc_rq_ct_explicit":
            return self._build_multi_context_assoc_rq(sop_class_key="ct", transfer_syntax_key="explicit_vr_le")
        elif pdu_type == "pdata":
            return self._build_pdata()
        elif pdu_type == "release_rq":
            return struct.pack('>BBi', 0x05, 0, 4) + b'\x00\x00\x00\x00'
        elif pdu_type == "release_rp":
            return struct.pack('>BBi', 0x06, 0, 4) + b'\x00\x00\x00\x00'
        elif pdu_type == "abort":
            return struct.pack('>BBi', 0x07, 0, 4) + b'\x00\x00\x00\x00'
        elif pdu_type == "assoc_ac":
            return struct.pack('>BBi', 0x02, 0, 4) + b'\x00\x00\x00\x00'
        elif pdu_type == "assoc_rj":
            return struct.pack('>BBi', 0x03, 0, 4) + b'\x00\x01\x01\x01'
        elif pdu_type == "cstore_pdata":
            return self._build_cstore_pdata()
        elif pdu_type == "cstore_rich_pdata":
            return self._build_cstore_rich_pdata(sop_class_key="ct", explicit_vr=False)
        elif pdu_type == "cstore_mr_pdata":
            return self._build_cstore_rich_pdata(sop_class_key="mr", explicit_vr=False)
        elif pdu_type == "cstore_us_pdata":
            return self._build_cstore_rich_pdata(sop_class_key="us", explicit_vr=False)
        elif pdu_type == "cstore_sc_pdata":
            return self._build_cstore_rich_pdata(sop_class_key="sc", explicit_vr=False)
        elif pdu_type == "cstore_explicit_pdata":
            return self._build_cstore_rich_pdata(sop_class_key="ct", explicit_vr=True)
        elif pdu_type == "cfind_pdata":
            return self._build_cfind_pdata()
        elif pdu_type == "cmove_pdata":
            return self._build_cmove_pdata()
        elif pdu_type == "cget_pdata":
            return self._build_cget_pdata()
        elif pdu_type == "partial_pdu":
            full_pdata = self._build_pdata()
            return full_pdata[:len(full_pdata)//2]
        elif pdu_type == "garbage":
            return bytes([random.randint(0, 255) for _ in range(random.randint(10, 100))])
        return self._build_pdata()

    def _build_pdu(self, pdu_type):
        special = getattr(self, '_current_special_attack', None)

        # Seed-based PDU construction
        if special == "seed_assoc" and pdu_type.startswith("assoc_rq"):
            pdu = self._build_seed_assoc_rq()
        elif special == "seed_pdata" and pdu_type in ("pdata", "cstore_pdata", "cfind_pdata",
                                                       "cmove_pdata", "cget_pdata",
                                                       "cstore_rich_pdata", "cstore_mr_pdata",
                                                       "cstore_us_pdata", "cstore_sc_pdata",
                                                       "cstore_explicit_pdata"):
            pdu = self._build_seed_pdata()
        elif special == "seed_crossover":
            crossover = self._build_seed_crossover(pdu_type)
            pdu = crossover if crossover else self._build_pdu_inner(pdu_type)
        else:
            pdu = self._build_pdu_inner(pdu_type)

        # Apply byte-level mutations if special_attack is byte-related
        if special and (special.startswith("byte_") or special == "seed_mutate"):
            pdu = self._apply_byte_mutations(pdu, special)

        return pdu

    def _send_sequence(self, sequence_name):
        info = {
            "response": "none",
            "responses": [],
            "crash": False,
            "hang": False,
            "slow": False,
            "sequence": sequence_name,
        }
        total_reward = 0.0

        if not self.target_host:
            return total_reward, info

        sequence = None
        for name, seq in STATE_SEQUENCES:
            if name == sequence_name:
                sequence = seq
                break
        if not sequence:
            sequence = ["assoc_rq", "pdata", "release_rq"]

        # Track response type counts for diminishing returns
        response_type_counts = {}
        n_responses = 0

        sent_pdus = []  # accumulate for corpus saving

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(2.0)
            sock.connect((self.target_host, self.target_port))

            for pdu_type in sequence:
                pdu = self._build_pdu(pdu_type)
                sent_pdus.append((pdu_type, pdu))
                t_start = time.monotonic()

                try:
                    sock.sendall(pdu)
                    sock.settimeout(1.0)

                    resp_data = sock.recv(4096)
                    t_end = time.monotonic()
                    resp_time = (t_end - t_start) * 1000

                    if not resp_data:
                        resp_type = "closed"
                        reward = 8.0
                    elif resp_data[0] == 0x02:
                        resp_type = "accept"
                        self.accept_count += 1
                        reward = 5.0
                    elif resp_data[0] == 0x03:
                        resp_type = "reject"
                        reward = 3.0
                    elif resp_data[0] == 0x04:
                        resp_type = "pdata"
                        reward = 25.0
                    elif resp_data[0] == 0x07:
                        resp_type = "abort"
                        reward = 50.0  # Abort: server hit error-handling path
                    else:
                        resp_type = f"type_{resp_data[0]:02x}"
                        reward = 20.0

                    if resp_time > 100:
                        reward += 20.0
                    elif resp_time > 50:
                        reward += 10.0

                    # Diminishing returns: decay reward for repeated response types
                    response_type_counts[resp_type] = response_type_counts.get(resp_type, 0) + 1
                    count = response_type_counts[resp_type]
                    if count > 1:
                        reward *= 0.5 ** (count - 1)

                    n_responses += 1

                    info["responses"].append({"pdu": pdu_type, "response": resp_type})
                    info["response"] = resp_type
                    total_reward += reward

                except socket.timeout:
                    # Distinguish slow (server busy) vs hang (server unresponsive)
                    # Retry with shorter timeout to confirm true hang
                    is_hang = False
                    try:
                        sock.settimeout(2.0)
                        retry_data = sock.recv(4096)
                        if not retry_data:
                            is_hang = True  # Connection dead
                    except socket.timeout:
                        is_hang = True  # Still no response after 2s retry
                    except Exception:
                        is_hang = True  # Connection broken

                    total_elapsed = (time.monotonic() - t_start) * 1000
                    info["responses"].append({
                        "pdu": pdu_type,
                        "response": "timeout",
                        "time_ms": total_elapsed,
                    })
                    info["response"] = "timeout"

                    if is_hang:
                        info["hang"] = True
                        self.hang_count += 1
                        total_reward += 50.0  # True hang is very interesting
                    else:
                        info["slow"] = True
                        self.slow_count += 1
                        total_reward += 15.0  # Slow response, server was busy
                    break

            sock.close()

        except ConnectionResetError:
            info["response"] = "reset"
            total_reward += 5.0
        except ConnectionRefusedError:
            info["response"] = "refused"
            time.sleep(0.1)
            try:
                check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                check.settimeout(1.0)
                check.connect((self.target_host, self.target_port))
                check.close()
            except:
                info["crash"] = True
                self.crash_count += 1
                total_reward += 150.0
        except Exception as e:
            info["response"] = "error"
            total_reward += 3.0

        # Normalize by sqrt(n_responses) to prevent flood reward inflation
        if n_responses > 1:
            total_reward /= math.sqrt(n_responses)

        info["sent_pdus"] = sent_pdus  # list of (pdu_type, raw_bytes) for corpus saving
        self.response_history.append(info["response"])
        return total_reward, info

    def reset(self, seed=None, options=None):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        self.reset_state()
        self.step_count = 0
        self.episode_reward = 0
        self.response_history = []

        return self._get_obs(), {}

    def step(self, action):
        # Exploration: Thompson Sampling-guided category selection
        is_novel = False
        if self.exploration_rate > 0 and random.random() < self.exploration_rate:
            # 30% of exploration time: fully novel combos (unconstrained creativity)
            # 70% of exploration time: Thompson Sampling picks a category, random action within it
            if random.random() < 0.3 or not self.bandit:
                combo = self._generate_novel_combo()
                is_novel = True
            else:
                category = self.bandit.sample()
                cat_actions = self.category_to_actions.get(category, [])
                if cat_actions:
                    chosen_idx = random.choice(cat_actions)
                    combo = self.active_combos[chosen_idx]
                else:
                    combo = self._generate_novel_combo()
                    is_novel = True
        else:
            combo = self.active_combos[action]

        # Handle 6, 7, or 8-element combo tuples
        if len(combo) == 8:
            name, sem_field, sem_value, payload_type, target, sequence, dimse_attack, special_attack = combo
        elif len(combo) == 7:
            name, sem_field, sem_value, payload_type, target, sequence, dimse_attack = combo
            special_attack = None
        else:
            name, sem_field, sem_value, payload_type, target, sequence = combo
            dimse_attack = None
            special_attack = None

        # Reset state
        self.reset_state()

        # Apply semantic mutation
        if sem_field and sem_value is not None:
            self.current_fields[sem_field] = sem_value

        # Apply payload injection
        if payload_type and target:
            payload = self._get_payload(payload_type)
            if payload:
                self.current_payloads[target] = payload

        # Store dimse attack type and special attack for _build_pdu
        self._current_dimse_attack = dimse_attack
        self._current_special_attack = special_attack

        # Execute: dispatch based on special_attack type
        if special_attack == "slowloris":
            reward, info = self._send_slowloris(sequence)
        elif special_attack == "fragment":
            reward, info = self._send_fragment(sequence)
        elif special_attack == "concurrent":
            reward, info = self._send_concurrent(sequence)
        elif special_attack == "rapid_reconnect":
            reward, info = self._send_rapid_reconnect()
        elif special_attack == "memory_exhaust":
            reward, info = self._send_memory_exhaust(sequence)
        else:
            # byte_* and seed_mutate are handled in _build_pdu
            reward, info = self._send_sequence(sequence)

        info["combo_name"] = name
        info["semantic"] = f"{sem_field}={sem_value}" if sem_field else None
        info["payload"] = f"{payload_type}->{target}" if payload_type else None
        info["dimse_attack"] = dimse_attack
        info["special_attack"] = special_attack

        # Check server logs for additional reward signals (batched every 3 steps
        # to avoid per-step SSH overhead; tail -n 50 catches accumulated entries)
        if self.log_monitor and self.step_count % 3 == 0:
            log_entries, log_reward_info = self.log_monitor.check_logs()

            # Add log-based rewards
            log_reward = log_reward_info.get('log_reward', 0)
            reward += log_reward

            # Track new errors/locations
            info["new_errors"] = log_reward_info.get('new_errors', 0)
            info["new_locations"] = log_reward_info.get('new_locations', 0)
            info["new_messages"] = log_reward_info.get('new_messages', 0)
            info["depth_score"] = log_reward_info.get('depth_score', 0)
            info["log_reward"] = log_reward
            info["lines_read"] = log_reward_info.get('lines_read', 0)
            info["error_codes"] = log_reward_info.get('error_codes_found', [])

            self.new_error_count += info["new_errors"]
            self.new_location_count += info["new_locations"]

            # Debug: log what we found (first 100 steps only)
            if self.step_count < 100 and (log_entries or info["lines_read"] > 0):
                logger.debug(f"LOG: read {info['lines_read']} lines, {len(log_entries)} entries, "
                            f"errors={info['new_errors']}, locs={info['new_locations']}, "
                            f"codes={info['error_codes']}")
                for entry in log_entries[:3]:
                    logger.debug(f"  [{entry.level}] {entry.source_file}: {entry.message[:60]}")

            # Log significant discoveries
            if info["new_locations"] > 0:
                for entry in log_entries[-3:]:  # Last 3 entries
                    logger.info(f"NEW CODE PATH: {entry.source_file} - {entry.message[:60]}")

        # Process monitoring (sample periodically)
        if self.process_monitor:
            proc_metrics = self.process_monitor.sample()
            if proc_metrics:
                anomaly_reward = self.process_monitor.get_anomaly_reward()
                reward += anomaly_reward
                info["proc_anomaly_score"] = proc_metrics.get('anomaly_score', 0)
                info["proc_rss_growth_mb"] = proc_metrics.get('rss_growth_mb', 0)
                info["proc_rss_delta_mb"] = proc_metrics.get('rss_delta_mb', 0)
                info["proc_fd_growth"] = proc_metrics.get('fd_growth', 0)
                info["proc_cpu"] = proc_metrics.get('cpu_percent', 0)

        # ASAN monitoring (check for memory safety bugs)
        if hasattr(self, 'asan_monitor') and self.asan_monitor:
            new_bugs = self.asan_monitor.sample()
            if new_bugs:
                asan_reward = self.asan_monitor.get_bug_reward()
                reward += asan_reward
                info["asan_bugs"] = len(new_bugs)
                info["asan_reward"] = asan_reward
                for bug in new_bugs:
                    top_frame = bug['stack_frames'][0]['function'] if bug['stack_frames'] else '?'
                    logger.critical(
                        f"ASAN BUG FOUND: {bug['error_type']} [{bug['severity']}] "
                        f"in {top_frame} (combo: {name})"
                    )

        # Coverage monitoring (sample periodically — lcov is slow, ~3s per read)
        if self.coverage_monitor:
            cov_delta = self.coverage_monitor.sample()
            if cov_delta:
                cov_reward = self.coverage_monitor.get_coverage_reward()
                reward += cov_reward
                info["cov_new_lines"] = cov_delta.get('lines', 0)
                info["cov_new_functions"] = cov_delta.get('functions', 0)
                info["cov_reward"] = cov_reward
                if cov_delta.get('lines', 0) > 0 or cov_delta.get('functions', 0) > 0:
                    cov = self.coverage_monitor.get_current_coverage()
                    logger.info(
                        f"COVERAGE: +{cov_delta['lines']} lines, +{cov_delta['functions']} funcs "
                        f"(total: {cov.get('lines', 0)}/{cov.get('lines', 0)+cov.get('lines_from_baseline', 0)} "
                        f"{cov.get('line_pct', 0):.1f}%) | combo: {name}"
                    )

                # Plateau detection (coverage-based)
                if cov_delta.get('lines', 0) > 0:
                    self._plateau_steps = 0
                    # Coverage increased — decay exploration back toward baseline
                    self.exploration_rate = max(self.exploration_rate * 0.95,
                                                self._base_exploration_rate)
                else:
                    self._plateau_steps += 1

                if self._plateau_steps > self._plateau_threshold:
                    # Plateau detected — boost exploration
                    old_rate = self.exploration_rate
                    self.exploration_rate = min(self.exploration_rate + 0.05, 0.5)
                    if self.bandit:
                        self.bandit.boost_exploration()
                    if old_rate < self.exploration_rate:
                        logger.info(
                            f"PLATEAU: {self._plateau_steps} steps without coverage gain. "
                            f"Exploration: {old_rate:.2f} -> {self.exploration_rate:.2f}"
                        )
                    self._plateau_steps = 0  # Reset counter after boosting

        # Plateau detection fallback (log-based, when no coverage monitor)
        if not self.coverage_monitor:
            if info.get("new_locations", 0) > 0:
                self._no_new_locations_steps = 0
                self.exploration_rate = max(self.exploration_rate * 0.95,
                                            self._base_exploration_rate)
            else:
                self._no_new_locations_steps += 1

            if self._no_new_locations_steps > self._log_plateau_threshold:
                old_rate = self.exploration_rate
                self.exploration_rate = min(self.exploration_rate + 0.05, 0.5)
                if self.bandit:
                    self.bandit.boost_exploration()
                if old_rate < self.exploration_rate:
                    logger.info(
                        f"PLATEAU (log): {self._no_new_locations_steps} steps without new locations. "
                        f"Exploration: {old_rate:.2f} -> {self.exploration_rate:.2f}"
                    )
                self._no_new_locations_steps = 0

        # Diversity enforcement
        if self.diversity_bonus > 0 and not is_novel:
            action_key = int(action)
            self.action_visit_counts[action_key] = self.action_visit_counts.get(action_key, 0) + 1
            visit_count = self.action_visit_counts[action_key]

            # Track consecutive same-action
            if action_key == self.last_action:
                self.consecutive_same_action += 1
            else:
                self.consecutive_same_action = 0
            self.last_action = action_key

            # Curiosity bonus for rarely-tried combos (<=2 uses)
            if visit_count <= 2:
                reward += 10.0 * self.diversity_bonus

            # Logarithmic decay after 5 uses of the same combo
            if visit_count > 5:
                reward *= 1.0 / (1.0 + self.diversity_bonus * math.log(visit_count - 4))

            # Adaptive exploration: boost exploration_rate when stuck on same action
            if self.consecutive_same_action >= 3:
                self.exploration_rate = min(self.exploration_rate * 1.5, 0.5)
            elif self.consecutive_same_action == 0 and self.exploration_rate > 0.15:
                # Decay back toward baseline when agent diversifies
                self.exploration_rate = max(self.exploration_rate * 0.9, 0.15)

        # Exploration bonus for ASAN discoveries
        if info.get("asan_bugs", 0) > 0:
            reward += min(info["asan_bugs"] * 50.0, 150.0)

        # Update Thompson Sampling bandit with reward signal
        if self.bandit:
            category = self._get_combo_category(combo)
            self.bandit.update(category, reward)

            # Log bandit stats every 100 steps
            if self.step_count > 0 and self.step_count % 100 == 0:
                stats = self.bandit.get_stats()
                parts = [f"{c}: {s['ratio']:.2f} (a={s['alpha']:.0f}/b={s['beta']:.0f})"
                         for c, s in sorted(stats.items(), key=lambda x: -x[1]['ratio'])]
                logger.info(f"BANDIT [{self.step_count}]: {' | '.join(parts)}")

        info["exploration_rate"] = self.exploration_rate

        # Update stats
        info["is_novel"] = is_novel

        if is_novel:
            # Track novel combination
            if name not in self.novel_combos_discovered:
                self.novel_combos_discovered[name] = {
                    "count": 0, "reward": 0, "hangs": 0, "slows": 0, "crashes": 0,
                    "new_errors": 0, "new_locations": 0,
                    "asan_bugs": 0,
                    "max_rss_growth_mb": 0.0, "max_fd_growth": 0,
                    "max_cpu": 0.0, "max_anomaly_score": 0.0,
                    "combo": combo
                }
            stats = self.novel_combos_discovered[name]
            stats["count"] += 1
            stats["reward"] += reward
            if info.get("hang"):
                stats["hangs"] += 1
            if info.get("slow"):
                stats["slows"] += 1
            if info.get("crash"):
                stats["crashes"] += 1
            if info.get("new_errors", 0) > 0:
                stats["new_errors"] += info["new_errors"]
            if info.get("new_locations", 0) > 0:
                stats["new_locations"] += info["new_locations"]
            if info.get("asan_bugs", 0) > 0:
                stats["asan_bugs"] += info["asan_bugs"]
            rss_g = info.get("proc_rss_growth_mb", 0)
            fd_g = info.get("proc_fd_growth", 0)
            cpu_v = info.get("proc_cpu", 0)
            anom_v = info.get("proc_anomaly_score", 0)
            if rss_g > stats["max_rss_growth_mb"]:
                stats["max_rss_growth_mb"] = rss_g
            if fd_g > stats["max_fd_growth"]:
                stats["max_fd_growth"] = fd_g
            if cpu_v > stats["max_cpu"]:
                stats["max_cpu"] = cpu_v
            if anom_v > stats["max_anomaly_score"]:
                stats["max_anomaly_score"] = anom_v

            # Log promising novel combos
            if reward > 50 or info.get("crash") or info.get("new_locations", 0) > 0 \
               or info.get("asan_bugs", 0) > 0 or info.get("proc_anomaly_score", 0) > 0.5:
                # Combo actions (inside brackets)
                combo_parts = []
                if sem_field:
                    combo_parts.append(f"sem:{sem_field}={sem_value}")
                if payload_type:
                    combo_parts.append(f"pay:{payload_type}->{target}")
                combo_parts.append(f"seq:{sequence}")
                if dimse_attack:
                    combo_parts.append(f"dimse:{dimse_attack}")
                if special_attack:
                    combo_parts.append(f"special:{special_attack}")
                # Metrics (pipe-separated)
                metrics = [f"reward={reward:.1f}", f"resp={info.get('response', '?')}",
                           f"crash={info.get('crash')}", f"hang={info.get('hang')}",
                           f"slow={info.get('slow')}",
                           f"new_locs={info.get('new_locations', 0)}",
                           f"asan={info.get('asan_bugs', 0)}"]
                if info.get("proc_rss_growth_mb", 0) > 0.5 or info.get("proc_fd_growth", 0) > 0:
                    metrics.append(f"rss+{info.get('proc_rss_growth_mb', 0):.1f}MB "
                                   f"delta={info.get('proc_rss_delta_mb', 0):+.1f}MB "
                                   f"fd+{info.get('proc_fd_growth', 0)} "
                                   f"cpu={info.get('proc_cpu', 0):.1f}%")
                if info.get("proc_anomaly_score", 0) > 0.5:
                    metrics.append(f"anomaly:{info['proc_anomaly_score']:.2f}")
                logger.info(f"NOVEL: {name} [{', '.join(combo_parts)}] | "
                           f"{' | '.join(metrics)}")
        else:
            # Update predefined combo stats
            if name in self.combo_stats:
                self.combo_stats[name]["count"] += 1
                self.combo_stats[name]["reward"] += reward
                if info.get("hang"):
                    self.combo_stats[name]["hangs"] += 1
                if info.get("slow"):
                    self.combo_stats[name]["slows"] += 1
                if info.get("crash"):
                    self.combo_stats[name]["crashes"] += 1
                if info.get("new_errors", 0) > 0:
                    self.combo_stats[name]["new_errors"] += info["new_errors"]
                if info.get("new_locations", 0) > 0:
                    self.combo_stats[name]["new_locations"] += info["new_locations"]
                if info.get("asan_bugs", 0) > 0:
                    self.combo_stats[name]["asan_bugs"] += info["asan_bugs"]
                rss_g = info.get("proc_rss_growth_mb", 0)
                fd_g = info.get("proc_fd_growth", 0)
                cpu_v = info.get("proc_cpu", 0)
                anom_v = info.get("proc_anomaly_score", 0)
                if rss_g > self.combo_stats[name]["max_rss_growth_mb"]:
                    self.combo_stats[name]["max_rss_growth_mb"] = rss_g
                if fd_g > self.combo_stats[name]["max_fd_growth"]:
                    self.combo_stats[name]["max_fd_growth"] = fd_g
                if cpu_v > self.combo_stats[name]["max_cpu"]:
                    self.combo_stats[name]["max_cpu"] = cpu_v
                if anom_v > self.combo_stats[name]["max_anomaly_score"]:
                    self.combo_stats[name]["max_anomaly_score"] = anom_v

        self.step_count += 1
        self.episode_reward += reward
        info["episode_reward"] = self.episode_reward

        if info.get("crash"):
            self._save_corpus_entry("crash", info)
        elif info.get("hang"):
            self._save_corpus_entry("hang", info)

        truncated = self.step_count >= self.max_steps
        terminated = info.get("crash", False)

        return self._get_obs(), reward, terminated, truncated, info

    def _save_corpus_entry(self, kind, info):
        """Save a crash or hang input to corpus_dir for later triage/replay.

        Writes two files per finding:
          <corpus_dir>/<kind>s/<kind>_NNNN_<ts>.bin   — concatenated raw PDU bytes
          <corpus_dir>/<kind>s/<kind>_NNNN_<ts>.json  — attack metadata + replay recipe
        """
        if not self.corpus_dir:
            return
        import json
        subdir = os.path.join(self.corpus_dir, f"{kind}s")
        os.makedirs(subdir, exist_ok=True)

        ts = int(time.time())
        idx = getattr(self, "_corpus_idx", 0)
        self._corpus_idx = idx + 1
        stem = f"{kind}_{idx:04d}_{ts}"

        # Concatenate all sent PDU bytes into a single .bin file
        sent_pdus = info.get("sent_pdus", [])
        raw = b"".join(pdu for _, pdu in sent_pdus) if sent_pdus else b""
        if raw:
            bin_path = os.path.join(subdir, f"{stem}.bin")
            with open(bin_path, "wb") as f:
                f.write(raw)

        # Write JSON metadata for triage and replay reproduction
        meta = {
            "kind": kind,
            "index": idx,
            "timestamp": ts,
            "combo_name": info.get("combo_name"),
            "semantic": info.get("semantic"),
            "payload": info.get("payload"),
            "sequence": info.get("sequence"),
            "dimse_attack": info.get("dimse_attack"),
            "special_attack": info.get("special_attack"),
            "response": info.get("response"),
            "response_time_ms": info.get("response_time_ms"),
            "episode_reward": info.get("episode_reward"),
            "asan_bugs": info.get("asan_bugs", 0),
            "new_locations": info.get("new_locations"),
            "sent_pdu_types": [pt for pt, _ in sent_pdus],
            "sent_pdu_sizes": [len(p) for _, p in sent_pdus],
            "fields": dict(getattr(self, "current_fields", {})),
            "payloads_keys": list(getattr(self, "current_payloads", {}).keys()),
        }
        json_path = os.path.join(subdir, f"{stem}.json")
        with open(json_path, "w") as f:
            json.dump(meta, f, indent=2, default=str)

        logger.warning(f"[CORPUS] Saved {kind} input → {json_path}")

    def get_combo_stats(self, top_n=None):
        """Return attack combination statistics (predefined combos)."""
        result = sorted(
            [(name, stats) for name, stats in self.combo_stats.items() if stats["count"] > 0],
            key=lambda x: x[1]["reward"] / max(x[1]["count"], 1),
            reverse=True
        )
        return result[:top_n] if top_n else result

    def get_novel_combo_stats(self, top_n=20):
        """Return novel combination statistics."""
        result = sorted(
            [(name, stats) for name, stats in self.novel_combos_discovered.items()],
            key=lambda x: x[1]["reward"] / max(x[1]["count"], 1),
            reverse=True
        )
        return result[:top_n]

    def get_best_novel_combos(self, min_reward=30.0):
        """Return novel combos that performed well (candidates for adding to predefined list)."""
        best = []
        for name, stats in self.novel_combos_discovered.items():
            avg_reward = stats["reward"] / max(stats["count"], 1)
            if avg_reward >= min_reward or stats["crashes"] > 0 or stats["hangs"] > 0 \
               or stats["new_locations"] > 0 or stats.get("asan_bugs", 0) > 0 \
               or stats.get("max_rss_growth_mb", 0) > 1.0 \
               or stats.get("max_fd_growth", 0) > 0:
                best.append({
                    "name": name,
                    "combo": stats["combo"],
                    "avg_reward": avg_reward,
                    "count": stats["count"],
                    "crashes": stats["crashes"],
                    "hangs": stats["hangs"],
                    "slows": stats.get("slows", 0),
                    "new_locations": stats["new_locations"],
                    "asan_bugs": stats.get("asan_bugs", 0),
                    "max_rss_growth_mb": stats.get("max_rss_growth_mb", 0),
                    "max_fd_growth": stats.get("max_fd_growth", 0),
                    "max_cpu": stats.get("max_cpu", 0),
                    "max_anomaly_score": stats.get("max_anomaly_score", 0),
                })
        return sorted(best, key=lambda x: x["avg_reward"], reverse=True)

    def get_exploration_summary(self):
        """Return summary of exploration vs exploitation."""
        total_predefined = sum(s["count"] for s in self.combo_stats.values())
        total_novel = sum(s["count"] for s in self.novel_combos_discovered.values())
        return {
            "predefined_actions": total_predefined,
            "novel_actions": total_novel,
            "unique_novel_combos": len(self.novel_combos_discovered),
            "exploration_rate": self.exploration_rate,
            "best_novel_combos": self.get_best_novel_combos()[:10],
        }
