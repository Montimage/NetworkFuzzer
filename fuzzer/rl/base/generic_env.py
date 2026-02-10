#!/usr/bin/env python3
"""
Generic Protocol Fuzzing Environment.

This environment works with any protocol that has a ProtocolAdapter implementation.
It combines semantic mutations, payload injection, and state machine attacks.
"""

import os
import sys
import random
import socket
import time
import logging
from typing import Dict, List, Any, Optional, Tuple

import numpy as np

try:
    import gymnasium as gym
    from gymnasium import spaces
except ImportError:
    import gym
    from gym import spaces

from .protocol_adapter import ProtocolAdapter, HealthCheckResult

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
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
    ):
        super().__init__()

        self.adapter = adapter
        self.target_host = target_host
        self.target_port = target_port or adapter.default_port
        self.max_steps = max_steps
        self.mode = mode

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
                    {"sequence": transition.name, "messages": transition.message_sequence}
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
                            }
                        ))

        self.n_actions = len(self.actions)
        self.action_space = spaces.Discrete(self.n_actions)

        logger.info(f"Built action space with {self.n_actions} actions for {self.adapter.protocol_name}")

    def reset_state(self):
        """Reset to default field values."""
        self.current_fields = {}
        for field_def in self.adapter.get_semantic_fields():
            if field_def.valid_values:
                self.current_fields[field_def.name] = field_def.valid_values[0]

        self.current_payloads = {}
        for target in self.adapter.get_payload_targets():
            self.current_payloads[target.name] = None

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
        if action_type in ("state", "combo"):
            messages = action_params.get("messages", self.adapter.get_message_types()[:1])
            info["sequence"] = action_params.get("sequence", "default")
        else:
            # Default: use first valid state transition
            valid_transitions = [t for t in self.adapter.get_state_transitions() if t.is_valid]
            if valid_transitions:
                messages = valid_transitions[0].message_sequence
            else:
                messages = self.adapter.get_message_types()[:1]

        # Execute the message sequence
        reward, exec_info = self._send_sequence(messages)
        info.update(exec_info)

        return reward, info

    def _send_sequence(self, message_types: List[str]) -> Tuple[float, Dict[str, Any]]:
        """Send a sequence of messages and return reward + info."""
        info = {
            "responses": [],
            "response": "none",
            "crash": False,
            "hang": False,
            "response_time_ms": 0,
        }
        total_reward = 0.0

        conn_params = self.adapter.get_connection_params()

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
            for msg_type in message_types:
                # Build message
                message = self.adapter.build_message(
                    message_type=msg_type,
                    fields=self.current_fields,
                    payloads={k: v for k, v in self.current_payloads.items() if v is not None}
                )

                t_start = time.monotonic()

                try:
                    sock.sendall(message)
                    sock.settimeout(2.0)

                    resp_data = sock.recv(4096)
                    t_end = time.monotonic()
                    resp_time = (t_end - t_start) * 1000

                    if not resp_data:
                        parsed = {"type": "closed", "success": False}
                    else:
                        parsed = self.adapter.parse_response(resp_data)

                    info["responses"].append({
                        "message": msg_type,
                        "response": parsed.get("type", "unknown"),
                        "time_ms": resp_time,
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
                    info["responses"].append({
                        "message": msg_type,
                        "response": "timeout",
                        "time_ms": 2000,
                    })
                    info["response"] = "timeout"
                    info["hang"] = True
                    self.counters["hangs"] += 1
                    total_reward += 50.0  # Timeout is interesting
                    break

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

    def step(self, action: int):
        action_type, action_params = self.actions[action]

        reward, info = self._execute_action(action_type, action_params)

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

        truncated = self.step_count >= self.max_steps
        terminated = info.get("crash", False)

        return self._get_obs(), reward, terminated, truncated, info

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
