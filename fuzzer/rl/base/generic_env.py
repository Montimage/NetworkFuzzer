#!/usr/bin/env python3
"""
Generic Protocol Fuzzing Environment.

This environment works with any protocol that has a ProtocolAdapter implementation.
It combines semantic mutations, payload injection, and state machine attacks.
"""

import hashlib
import json
import os
import struct
import sys
import random
import socket
import time
import logging
from typing import Dict, List, Any, Optional, Set, Tuple

import numpy as np

try:
    import gymnasium as gym
    from gymnasium import spaces
except ImportError:
    import gym
    from gym import spaces

from .protocol_adapter import ProtocolAdapter, HealthCheckResult

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Common attack payloads (protocol-agnostic)
GENERIC_PAYLOADS = {
    "format_string": [
        b'%s%s%s%s%s%s%s%s',
        b'%n%n%n%n%n%n',
        b'%x' * 50,
        b'%08x.' * 20,
        b'AAAA%08x.%08x.%08x.%08x.%n',
    ],
    "path_traversal": [
        b'../../../etc/passwd',
        b'....//....//....//etc/passwd',
        b'..\\..\\..\\windows\\system32\\config\\sam',
        b'/etc/passwd%00.txt',
        b'....//....//....//etc/shadow',
    ],
    "buffer_overflow": [
        b'A' * 16,
        b'A' * 17,
        b'A' * 64,
        b'A' * 65,
        b'A' * 256,
        b'A' * 1024,
        b'A' * 4096,
    ],
    "null_injection": [
        b'\x00' * 8,
        b'VALID\x00HIDDEN',
        b'\x00\x00\x00\x00',
        b'A' * 10 + b'\x00' + b'B' * 10,
    ],
    "special_chars": [
        b'\xff\xfe',
        b'\x00\x00\x00\x00',
        b'\r\n\r\n',
        b"'; DROP TABLE;--",
        b'<script>alert(1)</script>',
    ],
    "large_overflow": [
        b'A' * 65536,          # 64KB — heap allocation stress
        b'A' * 131072,         # 128KB
        b'\xff' * 65536,       # 64KB of 0xFF — integer boundary stress
        b'\x00' * 65536,       # 64KB null — parser termination stress
    ],
}


class GenericFuzzEnv(gym.Env):
    """
    Protocol-agnostic fuzzing environment.

    Uses a ProtocolAdapter to handle protocol-specific logic.
    Supports semantic mutations, payload injection, and state machine attacks.
    """

    metadata = {"render_modes": ["human"]}

    def __init__(
        self,
        adapter: ProtocolAdapter,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        max_steps: int = 30,
        mode: str = "hybrid",  # "semantic", "aggressive", "state", "hybrid"
        corpus_dir: Optional[str] = None,
        seed_dir: Optional[str] = None,
    ):
        super().__init__()

        self.adapter = adapter
        self.target_host = target_host
        self.target_port = target_port or adapter.default_port
        self.max_steps = max_steps
        self.mode = mode
        self.corpus_dir = corpus_dir
        self.seed_dir = seed_dir
        self._corpus_idx = 0
        self._seeds: List[Dict[str, Any]] = []
        if seed_dir:
            self._load_seeds(seed_dir)

        # Build action space based on mode
        self._build_action_space()

        # Observation space
        obs_size = adapter.get_observation_size()
        self.observation_space = spaces.Box(
            low=0, high=1,
            shape=(obs_size,),
            dtype=np.float32,
        )

        # Current state
        self.current_fields: Dict[str, Any] = {}
        self.current_payloads: Dict[str, bytes] = {}
        self.reset_state()

        # Episode tracking
        self.step_count = 0
        self.episode_reward = 0
        self.response_history: List[str] = []
        self.counters = {
            'hangs': 0,
            'crashes': 0,
            'successes': 0,
            'errors': 0,
        }

        # Statistics
        self.action_stats: Dict[str, Dict[str, Any]] = {}

        # Deduplication: one corpus entry per semantic (action_type, mutation) bucket
        self._seen_mutation_keys: Set[str] = set()
        self._skipped_duplicates: int = 0
        # Diminishing reward: track how many times each action_type hung
        self._hang_counts: Dict[str, int] = {}
        # Visit count decay: prevent RL from farming the same action indefinitely.
        # Reward is decayed for actions visited >5 times.  Persists across episodes.
        self._visit_counts: Dict[str, int] = {}

    def _build_action_space(self):
        """Build action space based on mode and protocol."""
        self.actions: List[Tuple[str, Dict[str, Any]]] = []

        semantic_fields = self.adapter.get_semantic_fields()
        state_transitions = self.adapter.get_state_transitions()
        payload_targets = self.adapter.get_payload_targets()

        if self.mode in ("semantic", "hybrid"):
            # Add semantic mutation actions
            for field_def in semantic_fields:
                values = self.adapter.get_mutation_values(field_def.name)
                for val in values:
                    self.actions.append((
                        "semantic",
                        {"field": field_def.name, "value": val}
                    ))

        if self.mode in ("state", "hybrid"):
            # Add state machine actions
            for transition in state_transitions:
                self.actions.append((
                    "state",
                    {
                        "sequence": transition.name,
                        "messages": transition.message_sequence,
                        "flood": transition.flood,
                    }
                ))

        if self.mode in ("aggressive", "hybrid"):
            # Add payload injection actions
            for target in payload_targets:
                for payload_type, payloads in GENERIC_PAYLOADS.items():
                    self.actions.append((
                        "payload",
                        {"target": target.name, "payload_type": payload_type}
                    ))

        # Add combined actions for hybrid mode
        if self.mode == "hybrid" and semantic_fields and state_transitions:
            # Semantic + non-standard state
            invalid_states = [t for t in state_transitions if not t.is_valid]
            for field_def in semantic_fields[:3]:  # Top 3 fields
                for val in self.adapter.get_mutation_values(field_def.name)[:3]:  # Top 3 values
                    for state in invalid_states[:3]:  # Top 3 invalid states
                        self.actions.append((
                            "combo",
                            {
                                "field": field_def.name,
                                "value": val,
                                "sequence": state.name,
                                "messages": state.message_sequence,
                                "flood": state.flood,
                            }
                        ))

        self.n_actions = len(self.actions)
        self.action_space = spaces.Discrete(self.n_actions)

        logger.debug(f"Built action space with {self.n_actions} actions for {self.adapter.protocol_name}")

    def reset_state(self):
        """Reset to default field values."""
        self.current_fields = {}
        for field_def in self.adapter.get_semantic_fields():
            if field_def.valid_values:
                self.current_fields[field_def.name] = field_def.valid_values[0]

        self.current_payloads = {}
        for target in self.adapter.get_payload_targets():
            self.current_payloads[target.name] = None

    def _load_seeds(self, seed_dir: str):
        """Load seed field dicts from companion .json sidecars in seed_dir.

        Looks for *.json files (corpus entries) that contain a "fields" key.
        Falls back to scanning subdirectories (hangs/, crashes/).
        """
        import glob as _glob
        patterns = [
            os.path.join(seed_dir, "*.json"),
            os.path.join(seed_dir, "hangs", "*.json"),
            os.path.join(seed_dir, "crashes", "*.json"),
        ]
        for pat in patterns:
            for path in _glob.glob(pat):
                try:
                    with open(path) as f:
                        data = json.load(f)
                    if "fields" in data and data["fields"]:
                        self._seeds.append(data["fields"])
                except Exception:
                    pass
        if self._seeds:
            logger.info(f"[seeds] Loaded {len(self._seeds)} seed field dicts from {seed_dir}")

    def _get_obs(self) -> np.ndarray:
        """Get observation vector."""
        obs = self.adapter.encode_observation(
            fields=self.current_fields,
            response_history=self.response_history,
            counters=self.counters,
            step=self.step_count,
            max_steps=self.max_steps,
        )
        return np.array(obs, dtype=np.float32)

    def _execute_action(self, action_type: str, action_params: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """Execute a fuzzing action and return reward + info."""
        info = {
            "action_type": action_type,
            "response": "none",
            "crash": False,
            "hang": False,
        }
        reward = 0.0

        if not self.target_host:
            return reward, info

        # Apply mutations based on action type
        if action_type == "semantic":
            self.current_fields[action_params["field"]] = action_params["value"]
            info["mutation"] = f"{action_params['field']}={action_params['value']}"

        elif action_type == "payload":
            payload_type = action_params["payload_type"]
            target = action_params["target"]
            payload = random.choice(GENERIC_PAYLOADS[payload_type])
            self.current_payloads[target] = payload
            info["payload"] = f"{payload_type}->{target}"

        elif action_type == "combo":
            self.current_fields[action_params["field"]] = action_params["value"]
            info["mutation"] = f"{action_params['field']}={action_params['value']}"

        # Determine message sequence
        flood_mode = False
        if action_type in ("state", "combo"):
            messages = action_params.get("messages", self.adapter.get_message_types()[:1])
            info["sequence"] = action_params.get("sequence", "default")
            flood_mode = action_params.get("flood", False)
        elif action_type == "payload":
            # Route payload to the sequence that actually delivers it to the right DIMSE layer.
            # Dataset-level targets (patient_name, sop_instance_uid) must travel inside
            # C-FIND/C-STORE commands; sending them via generic pdata is a no-op.
            preferred_seq = None
            for pt in self.adapter.get_payload_targets():
                if pt.name == target and getattr(pt, "preferred_sequence", None):
                    preferred_seq = pt.preferred_sequence
                    break
            if preferred_seq:
                for t in self.adapter.get_state_transitions():
                    if t.name == preferred_seq:
                        messages = t.message_sequence
                        flood_mode = t.flood
                        info["sequence"] = t.name
                        break
                else:
                    # Fallback if named transition no longer exists
                    preferred_seq = None
            if not preferred_seq:
                # ASSOC-level targets: use shortest valid sequence
                valid_transitions = [t for t in self.adapter.get_state_transitions() if t.is_valid]
                shortest = min(valid_transitions, key=lambda t: len(t.message_sequence))
                messages = shortest.message_sequence
        else:
            # Default: use shortest valid sequence (no release_rq).
            # "normal" ends with release_rq which always times out after a
            # malformed PDATA (server ABORTs and stops responding).  Using
            # "normal_no_release" (assoc_rq + pdata) cuts step time from
            # ~4.5s to ~0.6s and avoids false-positive "hang" corpus entries.
            valid_transitions = [t for t in self.adapter.get_state_transitions() if t.is_valid]
            # Prefer shortest valid sequence to minimise false RELEASE_RQ timeouts
            if valid_transitions:
                shortest = min(valid_transitions, key=lambda t: len(t.message_sequence))
                messages = shortest.message_sequence
            else:
                messages = self.adapter.get_message_types()[:1]

        # Execute the message sequence
        reward, exec_info = self._send_sequence(messages, flood_mode=flood_mode)
        info.update(exec_info)

        return reward, info

    def _send_sequence(self, message_types: List[str],
                       flood_mode: bool = False) -> Tuple[float, Dict[str, Any]]:
        """Send a sequence of messages and return reward + info.

        flood_mode: when True, intermediate PDU timeouts do NOT stop the loop;
                    only the last PDU uses the full timeout for hang detection.
        """
        info = {
            "responses": [],
            "response": "none",
            "crash": False,
            "hang": False,
            "response_time_ms": 0,
        }
        total_reward = 0.0

        conn_params = self.adapter.get_connection_params()
        sent_pdus = []   # (msg_type, raw_bytes) for corpus saving
        recv_pdus = []   # (msg_type, raw_bytes) received from server

        try:
            # Create socket
            if conn_params.get('socket_type') == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if conn_params.get('tcp_nodelay') and conn_params.get('socket_type') != 'udp':
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            sock.settimeout(5.0)
            sock.connect((self.target_host, self.target_port))

            # Send each message in sequence
            n_msgs = len(message_types)
            for i, msg_type in enumerate(message_types):
                is_last = (i == n_msgs - 1)

                # Build message
                message = self.adapter.build_message(
                    message_type=msg_type,
                    fields=self.current_fields,
                    payloads={k: v for k, v in self.current_payloads.items() if v is not None}
                )
                sent_pdus.append((msg_type, message))

                t_start = time.monotonic()

                try:
                    sock.sendall(message)
                except (BrokenPipeError, ConnectionResetError):
                    info["responses"].append({
                        "message": msg_type,
                        "response": "closed",
                        "time_ms": (time.monotonic() - t_start) * 1000,
                    })
                    info["response"] = "closed"
                    break

                # Timeout strategy for multi-step sequences:
                # - Last PDU: 4s full hang detection window
                # - Flood mode non-last: 0.3s (keep sending even if server busy)
                # - ASSOC_RQ (i==0): 4s — server cold-start; shorter value causes
                #   false-positive server_busy on every step under modest load
                # - Other intermediate non-last PDUs: 1.5s — aborts arrive in ~300ms,
                #   so 1.5s catches genuine intermediate hangs while keeping long chains fast
                is_assoc = (i == 0)
                if is_last:
                    recv_timeout = 4.0
                elif flood_mode:
                    recv_timeout = 0.3
                elif is_assoc:
                    recv_timeout = 4.0
                else:
                    recv_timeout = 1.5  # Intermediate PDUs: fast abort (~300ms) or short hang
                sock.settimeout(recv_timeout)

                try:
                    resp_data = sock.recv(4096)
                    t_end = time.monotonic()
                    resp_time = (t_end - t_start) * 1000

                    if not resp_data:
                        parsed = {"type": "closed", "success": False}
                    else:
                        parsed = self.adapter.parse_response(resp_data)
                        recv_pdus.append((msg_type, resp_data))

                    info["responses"].append({
                        "message": msg_type,
                        "response": parsed.get("type", "unknown"),
                        "time_ms": resp_time,
                        "recv_bytes": len(resp_data) if resp_data else 0,
                    })
                    info["response"] = parsed.get("type", "unknown")
                    info["response_time_ms"] = resp_time

                    # Compute reward
                    reward = self.adapter.compute_reward(
                        response=parsed,
                        response_time_ms=resp_time,
                        field_mutations=self.current_fields,
                        payload_injections={k: v for k, v in self.current_payloads.items() if v}
                    )
                    total_reward += reward

                    if parsed.get("success"):
                        self.counters["successes"] += 1

                except socket.timeout:
                    elapsed_ms = (time.monotonic() - t_start) * 1000

                    if not is_last and flood_mode:
                        # Non-last PDU in flood mode: server is busy, keep sending.
                        info["responses"].append({
                            "message": msg_type,
                            "response": "flood_continue",
                            "time_ms": elapsed_ms,
                        })
                        continue

                    # Confirm true hang: check the socket is still alive
                    # (server didn't silently close it after the timeout)
                    import select as _select
                    try:
                        rd, _, ex = _select.select([sock], [], [sock], 0.1)
                        if ex:
                            socket_alive = False
                        elif rd:
                            peek = sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                            socket_alive = len(peek) > 0
                        else:
                            socket_alive = True  # No data, no error → truly alive
                    except Exception:
                        socket_alive = False

                    # Determine if a meaningful DICOM hang occurred.
                    # A timeout on the FIRST PDU (ASSOC_RQ) with socket still alive
                    # indicates server overload — NOT a protocol-level hang.
                    # Real protocol hangs require at least getting past the ASSOC stage
                    # (i.e., the server accepted the association and then got stuck).
                    prev_responses = info["responses"]  # responses BEFORE this timeout
                    got_past_assoc = any(
                        r["response"] in ("accept", "pdata", "release")
                        for r in prev_responses
                    )

                    if socket_alive and not got_past_assoc:
                        # Server overload: ASSOC_RQ itself didn't get a response.
                        # Flag as server_busy (not a corpus-worthy hang), backoff.
                        info["responses"].append({
                            "message": msg_type,
                            "response": "server_busy",
                            "time_ms": elapsed_ms,
                        })
                        info["response"] = "server_busy"
                        info["response_time_ms"] = elapsed_ms
                        info["hang"] = False
                        info["server_busy"] = True
                        self._consecutive_busy = getattr(self, '_consecutive_busy', 0) + 1
                        # Exponential-ish backoff when server is consistently busy
                        backoff = min(0.5 * self._consecutive_busy, 5.0)
                        time.sleep(backoff)
                    else:
                        self._consecutive_busy = 0
                        info["responses"].append({
                            "message": msg_type,
                            "response": "true_hang" if socket_alive else "timeout",
                            "time_ms": elapsed_ms,
                        })
                        info["response"] = "true_hang" if socket_alive else "timeout"
                        info["response_time_ms"] = elapsed_ms
                        info["hang"] = socket_alive
                        if socket_alive:
                            self.counters["hangs"] += 1
                            action_type = info.get("action_type", "unknown")
                            n = self._hang_counts.get(action_type, 0)
                            self._hang_counts[action_type] = n + 1
                            if n == 0:
                                hang_reward = 80.0
                            elif n == 1:
                                hang_reward = 40.0
                            elif n < 10:
                                hang_reward = 15.0
                            else:
                                hang_reward = 3.0
                            total_reward += hang_reward
                        else:
                            total_reward += 5.0
                    break

            # Sequence depth bonus: reward intermediate PDUs that got valid responses
            depth_bonus = sum(
                3.0 for r in info["responses"]
                if r["response"] not in ("timeout", "true_hang", "closed", "flood_continue")
            )
            if len(info["responses"]) > 1 and depth_bonus > 0:
                total_reward += depth_bonus

            # If a hang was detected, send A-ABORT before closing so Orthanc's
            # DICOM handler can clean up its thread instead of staying stuck.
            if info.get("hang"):
                try:
                    abort_pdu = struct.pack('>BBi', 0x07, 0, 4) + b'\x00\x00\x00\x00'
                    sock.settimeout(0.5)
                    sock.sendall(abort_pdu)
                except Exception:
                    pass
                # Brief cooldown: let the server process the abort before the
                # next connection.  Prevents connection-pool exhaustion.
                time.sleep(0.5)

            sock.close()

        except ConnectionResetError:
            info["response"] = "reset"
            total_reward += 5.0
        except ConnectionRefusedError:
            info["response"] = "refused"
            # Check if crash
            time.sleep(0.3)
            health = self.adapter.check_health(self.target_host, self.target_port, timeout=2.0)
            if not health.is_healthy:
                info["crash"] = True
                self.counters["crashes"] += 1
                total_reward += 150.0
        except Exception as e:
            info["response"] = "error"
            info["error"] = str(e)
            self.counters["errors"] += 1
            total_reward += 3.0

        info["sent_pdus"] = sent_pdus
        info["recv_pdus"] = recv_pdus
        self.response_history.append(info["response"])
        return total_reward, info

    def reset(self, seed=None, options=None):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        self.reset_state()

        # 15% chance: initialize fields from a random seed entry
        if self._seeds and random.random() < 0.15:
            seed_fields = random.choice(self._seeds)
            for k, v in seed_fields.items():
                if k in self.current_fields:
                    self.current_fields[k] = v

        self.step_count = 0
        self.episode_reward = 0
        self.response_history = []

        return self._get_obs(), {}

    def step(self, action: int):
        action_type, action_params = self.actions[action]

        reward, info = self._execute_action(action_type, action_params)

        # Visit count decay: each time the same (action, value) is chosen, the
        # reward is scaled down after 5 visits.  This prevents the RL from
        # farming a single high-reward action (e.g. message_id=0 → fast pdata)
        # instead of exploring the action space.
        visit_key = (
            info.get("mutation")
            or info.get("payload")
            or info.get("sequence")
            or f"{action_type}:{action}"
        )
        self._visit_counts[visit_key] = self._visit_counts.get(visit_key, 0) + 1
        n = self._visit_counts[visit_key]
        if n > 5:
            decay = max(0.15, 1.0 / (1.0 + 0.35 * (n - 5)))
            reward *= decay

        # Update statistics
        action_key = f"{action_type}:{action_params.get('field', action_params.get('target', action_params.get('sequence', 'unknown')))}"
        if action_key not in self.action_stats:
            self.action_stats[action_key] = {"count": 0, "reward": 0, "hangs": 0, "crashes": 0}
        self.action_stats[action_key]["count"] += 1
        self.action_stats[action_key]["reward"] += reward
        if info.get("hang"):
            self.action_stats[action_key]["hangs"] += 1
        if info.get("crash"):
            self.action_stats[action_key]["crashes"] += 1

        self.step_count += 1
        self.episode_reward += reward
        info["episode_reward"] = self.episode_reward
        info["current_fields"] = dict(self.current_fields)

        if info.get("crash"):
            self.save_corpus_entry("crash", self.step_count, None, reward, info)
        elif info.get("hang"):
            if self._is_novel_hang(info):
                # Post-association hangs are real by definition (server accepted the
                # ASSOC and then got stuck processing a command).  Skip the expensive
                # _quick_validate_hang re-connection which just adds more load.
                self.save_corpus_entry("hang", self.step_count, None, reward, info)
            else:
                self._skipped_duplicates += 1

        truncated = self.step_count >= self.max_steps
        terminated = info.get("crash", False)

        return self._get_obs(), reward, terminated, truncated, info

    def save_corpus_entry(self, kind: str, idx: int, pdu_bytes: Optional[bytes],
                          ep_reward: float, info: Dict[str, Any]) -> str:
        """Save a crash or hang input to corpus_dir for later triage/replay.

        Writes two files:
          <corpus_dir>/<kind>s/<kind>_NNNN_<ts>.bin   — concatenated raw PDU bytes
          <corpus_dir>/<kind>s/<kind>_NNNN_<ts>.json  — attack metadata

        Returns the path of the saved .json file (or '' if corpus_dir not set).
        """
        if not self.corpus_dir:
            return ""
        subdir = os.path.join(self.corpus_dir, f"{kind}s")
        os.makedirs(subdir, exist_ok=True)

        ts = int(time.time())
        stem = f"{kind}_{self._corpus_idx:04d}_{ts}"
        self._corpus_idx += 1

        # Raw bytes: use provided pdu_bytes or reconstruct from info["sent_pdus"]
        sent_pdus = info.get("sent_pdus", [])
        raw = pdu_bytes or (b"".join(p for _, p in sent_pdus) if sent_pdus else b"")
        if raw:
            bin_path = os.path.join(subdir, f"{stem}.bin")
            with open(bin_path, "wb") as f:
                f.write(raw)

        # Server response bytes — save alongside sent PDUs so C-FIND responses
        # can be decoded offline (e.g. with pydicom) to extract patient data.
        recv_pdus = info.get("recv_pdus", [])
        if recv_pdus:
            resp_raw = b"".join(p for _, p in recv_pdus)
            resp_path = os.path.join(subdir, f"{stem}.resp.bin")
            with open(resp_path, "wb") as f:
                f.write(resp_raw)

        meta = {
            "kind": kind,
            "index": self._corpus_idx - 1,
            "timestamp": ts,
            "protocol": self.adapter.protocol_name,
            "action_type": info.get("action_type"),
            "mutation": info.get("mutation"),
            "payload": info.get("payload"),
            "sequence": info.get("sequence"),
            "response": info.get("response"),
            "response_time_ms": info.get("response_time_ms"),
            "episode_reward": ep_reward,
            "fields": dict(self.current_fields),
            "sent_pdu_types": [pt for pt, _ in sent_pdus],
            "sent_pdu_sizes": [len(p) for _, p in sent_pdus],
            # Per-PDU exchange log: shows exactly which PDU triggered the hang
            # and what the server replied to each prior PDU.
            "exchanges": info.get("responses", []),
        }
        json_path = os.path.join(subdir, f"{stem}.json")
        with open(json_path, "w") as f:
            json.dump(meta, f, indent=2, default=str)

        logger.warning(f"[CORPUS] Saved {kind} → {json_path}")
        return json_path

    def _is_novel_hang(self, info: Dict[str, Any]) -> bool:
        """Return True only if this hang is semantically novel.

        Uses a single-level semantic key: (action_type, mutation/payload/sequence).
        One corpus entry per bucket — e.g. one entry for "payload:format_string->called_ae"
        regardless of which specific format string bytes were used.
        This prevents saving 5+ variants of the same attack against the same target.
        """
        action_type = info.get("action_type", "unknown")
        mutation_val = (
            info.get("mutation")
            or info.get("payload")
            or info.get("sequence")
            or "?"
        )
        semantic_key = f"{action_type}:{mutation_val}"
        if semantic_key in self._seen_mutation_keys:
            return False
        self._seen_mutation_keys.add(semantic_key)
        return True

    def _quick_validate_hang(self, info: Dict[str, Any]) -> bool:
        """Fast 1.5s re-check to filter training-time false positives.

        Under fuzzing load the server sometimes takes >5s to send an ABORT,
        causing the training timeout to fire and the input to be mislabelled
        as a hang. When the server is idle it responds in <1s.

        Strategy: re-send the same PDUs with a 1.5s timeout.
        - Responds within 1.5s  → false positive (slow ABORT under load) → discard
        - Still no response      → confirmed true hang → save
        Only adds ~1.5s per novel confirmed hang (rare), not per false positive.
        """
        if not self.target_host:
            return True  # Offline mode: accept all

        sent_pdus = info.get("sent_pdus", [])
        if not sent_pdus:
            return True

        try:
            sock = socket.create_connection(
                (self.target_host, self.target_port), timeout=3.0
            )
            # Use 3s here: less than the 4s main timeout so we correctly
            # identify slow-but-responding servers as false positives.
            sock.settimeout(3.0)
            for _, pdu in sent_pdus:
                sock.sendall(pdu)
            try:
                sock.recv(4096)
                sock.close()
                return False   # Server responded within 3s → false positive
            except socket.timeout:
                sock.close()
                return True    # Still hanging → confirmed real
            except Exception:
                return False
        except Exception:
            return False       # Can't connect → don't save

    def _validate_hang(self, info: Dict[str, Any]) -> bool:
        """Re-send the same PDU sequence once to confirm hang is reproducible.

        Uses a shorter 4s timeout. If the server again fails to respond with
        the socket alive, the hang is real. If it responds or closes, it was
        a training-time false positive (server was under load).
        """
        if not self.target_host:
            return True  # No live target, accept all hangs

        sent_pdus = info.get("sent_pdus", [])
        if not sent_pdus:
            return True  # Can't validate without PDU bytes

        try:
            sock = socket.create_connection((self.target_host, self.target_port), timeout=5.0)
            sock.settimeout(4.0)
            for _, pdu in sent_pdus:
                sock.sendall(pdu)
            try:
                data = sock.recv(4096)
                # Got a response → not a hang
                sock.close()
                return False
            except socket.timeout:
                # Check socket alive
                import select as _sel
                rd, _, ex = _sel.select([sock], [], [sock], 0.1)
                if ex:
                    sock.close()
                    return False
                elif rd:
                    peek = sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                    sock.close()
                    return len(peek) == 0  # No data = alive but silent = hang
                else:
                    sock.close()
                    return True  # Truly alive and silent = confirmed hang
            except Exception:
                return False
        except Exception:
            return False  # Can't connect = don't save

    def render(self, mode="human"):
        print(f"[{self.adapter.protocol_name}] Step {self.step_count}")
        print(f"  Fields: {self.current_fields}")
        print(f"  Counters: {self.counters}")

    def get_action_stats(self, top_n: int = 15) -> List[Tuple[str, Dict]]:
        """Return top action statistics."""
        return sorted(
            [(k, v) for k, v in self.action_stats.items() if v["count"] > 0],
            key=lambda x: x[1]["reward"] / max(x[1]["count"], 1),
            reverse=True
        )[:top_n]

    def close(self):
        pass
