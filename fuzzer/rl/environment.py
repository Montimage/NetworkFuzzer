#!/usr/bin/env python3
"""
OpenAI Gymnasium-compatible environment for RL-guided DICOM fuzzing.

v3: Focused action space — mutations only target actual PDU bytes (not padding).
    Deferred evaluation at episode end.  Per-step diversity bonus for new positions.

v4: DICOM-aware mutations:
    - New mutation types targeting length fields, boundaries, strings
    - Critical field definitions with weighted targeting
    - Multi-byte mutations for length corruption
    - Protocol-specific attack patterns
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

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fuzzer.common.pcap_utils import (
    wrap_tcp_ip, build_associate_rq, build_associate_ac,
    build_release_rq, build_release_rp,
)

from fuzzer.rl.reward import RewardComputer, CRITICAL_FIELDS_ASSOC_RQ
from fuzzer.rl.server_monitor import ServerMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# v4: Enhanced Mutation Types
# ============================================================================

# Basic mutations (v3)
MUT_FLIP = 0           # Flip random bit in byte
MUT_REPLACE = 1        # Replace with random byte
MUT_INCREMENT = 2      # Increment byte (mod 256)
MUT_ZERO = 3           # Set to 0x00
MUT_MAX = 4            # Set to 0xFF

# v4: DICOM-aware mutations
MUT_DECREMENT = 5      # Decrement byte (mod 256)
MUT_BOUNDARY = 6       # Set to boundary value (0x7F, 0x80, etc.)
MUT_LENGTH_ZERO = 7    # Set length field to 0 (4-byte, big-endian)
MUT_LENGTH_MAX = 8     # Set length field to max (0xFFFFFFFF)
MUT_LENGTH_OFF1 = 9    # Length field off by +1
MUT_LENGTH_OFF_NEG = 10  # Length field off by -1
MUT_NULL_INJECT = 11   # Insert null byte (shifts subsequent bytes)
MUT_SWAP_BYTES = 12    # Swap with adjacent byte
MUT_REPEAT_BYTE = 13   # Repeat this byte value to next N positions

N_MUTATION_TYPES = 14  # Updated count

# Boundary values for MUT_BOUNDARY
BOUNDARY_VALUES = [
    0x00, 0x01, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF,  # Signed/unsigned boundaries
    0x20, 0x09, 0x0A, 0x0D,  # Whitespace
    0x00, 0x2F, 0x3A, 0x40, 0x5B, 0x60, 0x7B,  # ASCII boundaries
]

# ============================================================================
# v4: DICOM PDU Structure Definitions
# ============================================================================

# Critical field offsets for ASSOC_RQ PDU (for bonus targeting)
# Format: (start_offset, end_offset, field_name, is_length_field)
ASSOC_RQ_STRUCTURE = {
    "pdu_type": (0, 1, False),          # 0x01 for ASSOC_RQ
    "reserved1": (1, 2, False),         # Should be 0x00
    "pdu_length": (2, 6, True),         # 4-byte big-endian length
    "protocol_version": (6, 8, False),  # Should be 0x0001
    "reserved2": (8, 10, False),        # Should be 0x0000
    "called_ae": (10, 26, False),       # 16-byte AE title (space-padded)
    "calling_ae": (26, 42, False),      # 16-byte AE title (space-padded)
    "reserved3": (42, 74, False),       # 32 bytes reserved
    # Variable items start at 74
    "app_ctx_type": (74, 75, False),    # 0x10
    "app_ctx_reserved": (75, 76, False),
    "app_ctx_length": (76, 78, True),   # 2-byte length
}

# Length field offsets (for length-specific mutations)
LENGTH_FIELDS_ASSOC_RQ = [
    (2, 6, "pdu_length"),       # 4-byte big-endian
    (76, 78, "app_ctx_len"),    # 2-byte big-endian
    # Presentation context lengths are variable, detected dynamically
]

# Use a focused PDU length — most ASSOC_RQ PDUs are 230-260 bytes
# Larger than any seed, but not wastefully large
FOCUSED_PDU_LEN = 300


class DicomFuzzEnv(gym.Env):
    """
    Gymnasium environment for RL-guided DICOM PDU mutation (v4).

    Key improvements over v3:
      - DICOM-aware mutation types (length corruption, boundaries, etc.)
      - Critical field targeting with bonus rewards
      - Multi-byte mutations for length fields
      - Protocol-specific attack patterns

    v3 features retained:
      - Focused action space covers only FOCUSED_PDU_LEN (300)
      - Per-step reward for mutating NEW positions (diversity)
      - Final evaluation at episode end with parser depth + response time
    """

    metadata = {"render_modes": ["human"]}

    def __init__(self, seed_pdus=None, target_host=None, target_port=4242,
                 called_ae="ORTHANC", max_steps=50, max_pdu_len=FOCUSED_PDU_LEN):
        super().__init__()

        self.max_pdu_len = max_pdu_len
        self.max_steps = max_steps

        # Store seeds with their actual lengths
        self.seed_pdus = []
        self.seed_lengths = []
        if seed_pdus:
            for p in seed_pdus:
                raw = list(p) if isinstance(p, (bytes, bytearray)) else list(p)
                actual_len = min(len(raw), max_pdu_len)
                self.seed_lengths.append(actual_len)
                self.seed_pdus.append(self._pad_pdu(raw))
        else:
            default_pdu = build_associate_rq()
            self.seed_lengths.append(min(len(default_pdu), max_pdu_len))
            self.seed_pdus.append(self._pad_pdu(default_pdu))

        # v4: Expanded action space with new mutation types
        self.action_space = spaces.Discrete(max_pdu_len * N_MUTATION_TYPES)

        # Observation: PDU bytes + step_fraction + diversity_fraction
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

        # Reward computer with server monitor
        self.reward_computer = RewardComputer(
            target_host=target_host,
            target_port=target_port,
            called_ae=called_ae,
            server_monitor=self.server_monitor,
            pdu_type="assoc_rq",
        )

        self.current_pdu = None
        self.seed_pdu = None
        self.seed_length = 0
        self.step_count = 0
        self.episode_reward = 0
        self.last_reward = 0
        self.mutated_positions = set()

        # v4: Track which critical fields have been targeted
        self.critical_field_hits = {}

        # v4: Episode tracking for periodic health checks
        self.episode_count = 0
        self.health_check_interval = 5  # Only full health check every N episodes

    def _pad_pdu(self, pdu):
        """Pad/truncate PDU to fixed length."""
        if len(pdu) > self.max_pdu_len:
            return pdu[:self.max_pdu_len]
        return pdu + [0] * (self.max_pdu_len - len(pdu))

    def _get_obs(self):
        """Build observation: PDU bytes + progress signals."""
        step_frac = self.step_count / self.max_steps * 255.0
        div_frac = len(self.mutated_positions) / max(self.seed_length, 1) * 255.0
        obs = np.array(self.current_pdu + [step_frac, min(div_frac, 255.0)],
                       dtype=np.float32)
        return obs

    def _decode_action(self, action):
        """Decode flat action index to (offset, mutation_type)."""
        offset = action // N_MUTATION_TYPES
        mutation_type = action % N_MUTATION_TYPES
        return offset, mutation_type

    def _is_length_field_start(self, offset):
        """Check if offset is the start of a known length field."""
        for start, end, name in LENGTH_FIELDS_ASSOC_RQ:
            if offset == start:
                return (start, end, name)
        return None

    def _apply_mutation(self, offset, mutation_type):
        """
        Apply a mutation to the current PDU.

        v4: Extended mutation types including DICOM-aware mutations:
          - Length field corruption (zero, max, off-by-one)
          - Boundary value injection
          - Byte swapping and repetition
        """
        if offset >= len(self.current_pdu):
            return

        original = self.current_pdu[offset]

        # ============================================================
        # Basic mutations (v3)
        # ============================================================
        if mutation_type == MUT_FLIP:
            bit = 1 << random.randint(0, 7)
            self.current_pdu[offset] = original ^ bit

        elif mutation_type == MUT_REPLACE:
            self.current_pdu[offset] = random.randint(0, 255)

        elif mutation_type == MUT_INCREMENT:
            self.current_pdu[offset] = (original + 1) % 256

        elif mutation_type == MUT_ZERO:
            self.current_pdu[offset] = 0x00

        elif mutation_type == MUT_MAX:
            self.current_pdu[offset] = 0xFF

        # ============================================================
        # v4: DICOM-aware mutations
        # ============================================================
        elif mutation_type == MUT_DECREMENT:
            self.current_pdu[offset] = (original - 1) % 256

        elif mutation_type == MUT_BOUNDARY:
            # Set to a boundary value (signed/unsigned edges, etc.)
            self.current_pdu[offset] = random.choice(BOUNDARY_VALUES)

        elif mutation_type == MUT_LENGTH_ZERO:
            # Set length field to 0 (multi-byte, big-endian)
            length_field = self._is_length_field_start(offset)
            if length_field:
                start, end, name = length_field
                for i in range(start, min(end, len(self.current_pdu))):
                    self.current_pdu[i] = 0x00
                    if self.current_pdu[i] != self.seed_pdu[i]:
                        self.mutated_positions.add(i)
            else:
                # Not a length field start, just zero this byte
                self.current_pdu[offset] = 0x00

        elif mutation_type == MUT_LENGTH_MAX:
            # Set length field to max value (multi-byte, big-endian)
            length_field = self._is_length_field_start(offset)
            if length_field:
                start, end, name = length_field
                for i in range(start, min(end, len(self.current_pdu))):
                    self.current_pdu[i] = 0xFF
                    if self.current_pdu[i] != self.seed_pdu[i]:
                        self.mutated_positions.add(i)
            else:
                # Not a length field start, just max this byte
                self.current_pdu[offset] = 0xFF

        elif mutation_type == MUT_LENGTH_OFF1:
            # Increment length field by 1 (off-by-one attack)
            length_field = self._is_length_field_start(offset)
            if length_field:
                start, end, name = length_field
                field_len = end - start
                if field_len == 4 and end <= len(self.current_pdu):
                    # 4-byte big-endian
                    val = struct.unpack('>I', bytes(self.current_pdu[start:end]))[0]
                    val = min(val + 1, 0xFFFFFFFF)
                    new_bytes = struct.pack('>I', val)
                    for i, b in enumerate(new_bytes):
                        self.current_pdu[start + i] = b
                        if self.current_pdu[start + i] != self.seed_pdu[start + i]:
                            self.mutated_positions.add(start + i)
                elif field_len == 2 and end <= len(self.current_pdu):
                    # 2-byte big-endian
                    val = struct.unpack('>H', bytes(self.current_pdu[start:end]))[0]
                    val = min(val + 1, 0xFFFF)
                    new_bytes = struct.pack('>H', val)
                    for i, b in enumerate(new_bytes):
                        self.current_pdu[start + i] = b
                        if self.current_pdu[start + i] != self.seed_pdu[start + i]:
                            self.mutated_positions.add(start + i)
            else:
                # Not a length field, just increment
                self.current_pdu[offset] = (original + 1) % 256

        elif mutation_type == MUT_LENGTH_OFF_NEG:
            # Decrement length field by 1 (off-by-one attack)
            length_field = self._is_length_field_start(offset)
            if length_field:
                start, end, name = length_field
                field_len = end - start
                if field_len == 4 and end <= len(self.current_pdu):
                    val = struct.unpack('>I', bytes(self.current_pdu[start:end]))[0]
                    val = max(val - 1, 0)
                    new_bytes = struct.pack('>I', val)
                    for i, b in enumerate(new_bytes):
                        self.current_pdu[start + i] = b
                        if self.current_pdu[start + i] != self.seed_pdu[start + i]:
                            self.mutated_positions.add(start + i)
                elif field_len == 2 and end <= len(self.current_pdu):
                    val = struct.unpack('>H', bytes(self.current_pdu[start:end]))[0]
                    val = max(val - 1, 0)
                    new_bytes = struct.pack('>H', val)
                    for i, b in enumerate(new_bytes):
                        self.current_pdu[start + i] = b
                        if self.current_pdu[start + i] != self.seed_pdu[start + i]:
                            self.mutated_positions.add(start + i)
            else:
                self.current_pdu[offset] = (original - 1) % 256

        elif mutation_type == MUT_NULL_INJECT:
            # Inject null byte (useful for string termination attacks)
            self.current_pdu[offset] = 0x00

        elif mutation_type == MUT_SWAP_BYTES:
            # Swap with next byte (useful for endianness confusion)
            if offset + 1 < len(self.current_pdu):
                next_byte = self.current_pdu[offset + 1]
                self.current_pdu[offset + 1] = original
                self.current_pdu[offset] = next_byte
                # Track both positions
                if self.current_pdu[offset + 1] != self.seed_pdu[offset + 1]:
                    self.mutated_positions.add(offset + 1)
                elif offset + 1 in self.mutated_positions:
                    self.mutated_positions.discard(offset + 1)

        elif mutation_type == MUT_REPEAT_BYTE:
            # Repeat current byte value to next 2-4 positions (buffer pattern)
            repeat_count = random.randint(2, 4)
            for i in range(repeat_count):
                pos = offset + i
                if pos < len(self.current_pdu):
                    self.current_pdu[pos] = original
                    if self.current_pdu[pos] != self.seed_pdu[pos]:
                        self.mutated_positions.add(pos)
                    elif pos in self.mutated_positions:
                        self.mutated_positions.discard(pos)

        # Track if byte actually differs from seed (for primary offset)
        if self.current_pdu[offset] != self.seed_pdu[offset]:
            self.mutated_positions.add(offset)
        elif offset in self.mutated_positions:
            self.mutated_positions.discard(offset)

        # v4: Track critical field hits
        for (start, end), (field_name, _) in CRITICAL_FIELDS_ASSOC_RQ.items():
            if start <= offset < end:
                self.critical_field_hits[field_name] = \
                    self.critical_field_hits.get(field_name, 0) + 1
                break

    def _pdu_to_packets(self):
        """Wrap current PDU bytes in a DICOM TCP session."""
        # Only send the meaningful bytes (up to seed_length or furthest mutation)
        effective_len = self.seed_length
        if self.mutated_positions:
            effective_len = max(effective_len, max(self.mutated_positions) + 1)
        effective_len = min(effective_len, self.max_pdu_len)

        pdu_bytes = bytes(self.current_pdu[:effective_len])
        session = [
            pdu_bytes,
            build_associate_ac(),
            build_release_rq(),
            build_release_rp(),
        ]
        return wrap_tcp_ip(session)

    def _compute_divergence(self):
        """Compute fraction of PDU bytes that differ from seed."""
        diffs = sum(1 for i in range(self.seed_length)
                    if self.current_pdu[i] != self.seed_pdu[i])
        return diffs / max(self.seed_length, 1)

    def _evaluate_final(self):
        """Evaluate the final mutated PDU once at episode end with server metrics."""
        self.episode_count += 1  # v4: Track episode number

        effective_len = self.seed_length
        if self.mutated_positions:
            effective_len = max(effective_len, max(self.mutated_positions) + 1)
        effective_len = min(effective_len, self.max_pdu_len)
        pdu_bytes = bytes(self.current_pdu[:effective_len])

        # Scapy packet building is optional — failure must not block live testing
        packets = None
        try:
            packets = self._pdu_to_packets()
        except Exception as e:
            logger.debug("_pdu_to_packets failed (scapy): %s", e)

        try:
            reward, info = self.reward_computer.compute_reward(
                packets, pdu_bytes, mutated_positions=self.mutated_positions
            )
        except Exception as e:
            reward = 0.0
            info = {"error": str(e), "live_response": "none"}

        # Undo the -1 step penalty from compute_reward
        reward = reward + 1.0

        divergence = self._compute_divergence()
        info["divergence"] = divergence
        info["mutated_positions"] = len(self.mutated_positions)

        response = info.get("live_response", "none")
        parser_depth = info.get("parser_depth", 0)
        response_ms = info.get("response_time_ms", 0)

        # Reward hierarchy: crash > abort > hang > accept > other
        if info.get("crash", False):
            resp_score = 100.0
        elif response in ("abort", "true_hang"):
            resp_score = 50.0
        elif response == "true_hang":
            resp_score = 20.0
        elif response == "accept" and divergence > 0.15:
            resp_score = 15.0   # accept with high divergence: validation bypass
        elif response == "accept" and divergence > 0.05:
            resp_score = 8.0
        elif response == "accept":
            resp_score = 2.0
        else:
            resp_score = max(parser_depth * 3.0, 1.0)

        time_bonus = 0.0
        if response_ms > 100:
            time_bonus = 10.0
        elif response_ms > 20:
            time_bonus = 3.0
        elif response_ms > 10:
            time_bonus = 1.0

        novelty_bonus = 5.0 if info.get("response_novelty", False) else 0.0
        div_bonus = 1.0 + min(divergence * 5.0, 3.0)
        mmt_bonus = info.get("mmt_alerts", 0) * 5.0 + info.get("new_rules", 0) * 10.0

        # Server health degradation bonus (from server_monitor via compute_reward)
        impact_score = info.get("impact_score", 0)
        health_bonus = 0.0
        if impact_score > 50:
            health_bonus = 30.0
        elif impact_score > 20:
            health_bonus = 15.0
        elif impact_score > 5:
            health_bonus = 5.0

        if info.get("echo_lost", False):
            health_bonus += 20.0
        if info.get("assoc_lost", False):
            health_bonus += 15.0
        if info.get("connections_lost", 0) > 0:
            health_bonus += info["connections_lost"] * 5.0

        echo_delta = info.get("echo_latency_delta_ms", 0)
        if echo_delta > 500:
            health_bonus += 15.0
        elif echo_delta > 100:
            health_bonus += 8.0
        elif echo_delta > 20:
            health_bonus += 3.0

        final_reward = resp_score * div_bonus + time_bonus + novelty_bonus + mmt_bonus + health_bonus
        info["final_reward"] = final_reward
        info["resp_score"] = resp_score
        info["div_bonus"] = div_bonus
        info["time_bonus"] = time_bonus
        info["novelty_bonus"] = novelty_bonus
        info["mmt_bonus"] = mmt_bonus
        info["health_bonus"] = health_bonus

        return final_reward, info

    def reset(self, seed=None, options=None):
        """Reset: pick a random seed PDU."""
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
        self.critical_field_hits = {}  # v4: Reset critical field tracking
        self.reward_computer.reset_episode()

        return self._get_obs(), {}

    def _is_critical_field(self, offset):
        """Check if offset is within a critical DICOM field."""
        for (start, end), (field_name, bonus) in CRITICAL_FIELDS_ASSOC_RQ.items():
            if start <= offset < end:
                return (field_name, bonus)
        return None

    def step(self, action):
        """
        Apply mutation. Per-step: diversity + critical field bonus.
        Episode end: full evaluation.

        v4 Changes:
          - Bonus for targeting critical DICOM fields
          - Higher reward for DICOM-aware mutation types
          - Track mutation patterns for analysis
        """
        offset, mutation_type = self._decode_action(action)

        # Reward for mutating within actual PDU range
        in_pdu = offset < self.seed_length
        already_mutated = offset in self.mutated_positions

        # Check if targeting critical field BEFORE mutation
        critical_field = self._is_critical_field(offset)

        self._apply_mutation(offset, mutation_type)
        self.step_count += 1

        # Per-step reward: encourage diversity of mutation positions
        if not in_pdu:
            # Mutating beyond the PDU — slight penalty (not useful)
            step_reward = -0.3
        elif not already_mutated and offset in self.mutated_positions:
            # New position changed from seed — good, increases divergence
            step_reward = 0.5
            # v4: Bonus for critical field targeting
            if critical_field:
                field_name, bonus = critical_field
                # Scale bonus: first hit gets full bonus, subsequent hits get less
                hit_count = self.critical_field_hits.get(field_name, 0)
                if hit_count == 1:
                    step_reward += bonus * 0.3  # 30% of field bonus per step
                else:
                    step_reward += bonus * 0.1  # Diminishing returns
        elif already_mutated and offset not in self.mutated_positions:
            # Reverted a position back to seed — bad, decreases divergence
            step_reward = -0.3
        else:
            # Re-mutating an already-changed position — neutral
            step_reward = 0.0

        # v4: Small bonus for using DICOM-aware mutation types
        if mutation_type >= MUT_DECREMENT:
            step_reward += 0.1  # Encourage using advanced mutations

        truncated = self.step_count >= self.max_steps
        terminated = False
        info = {"step": self.step_count, "mutations": len(self.mutated_positions),
                "critical_hits": dict(self.critical_field_hits)}

        # Evaluate at episode end
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
        div = self._compute_divergence()
        print(f"Step {self.step_count} | mutations={len(self.mutated_positions)} | "
              f"div={div:.1%} | first20=[{hex_str}]")
