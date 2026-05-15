#!/usr/bin/env python3
"""
Generic Protocol Fuzzing Environment.

This environment works with any protocol that has a ProtocolAdapter implementation.
It combines semantic mutations, payload injection, and state machine attacks.
"""

import json
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
    # NAS 5GMM seed payloads: these bytes are used as a seed to select a
    # NAS_BODY_VARIANTS entry in adapter.build_message() via sum(seed) % len.
    # They are NOT injected directly as the NAS body.
    # Each entry should have a different byte-sum to select different variants:
    #   sum=0  → variant 0  (empty body)
    #   sum=1  → variant 1  (reg type only)
    #   sum=5  → variant 5  (null SUCI)
    #   ...
    # Spread across 0–255 to cover all 16 Registration Request variants.
    # JSON fuzzing payloads for HTTP/REST-based protocols (SBI, HTTP2, REST).
    # These replace NAS bodies with JSON parser stress inputs.
    "json_injection": [
        b'{}',
        b'{"a":' + b'"A"' * 100 + b'}',
        b'null',
        b'[' + b'1,' * 500 + b'0]',
        b'{"nfType":"' + b'X' * 256 + b'"}',
        b'{"plmnId":{"mcc":null,"mnc":null}}',
        b'{"nfStatus":"REGISTERED","capacity":-1}',
        b'{"__proto__":{"polluted":true}}',
        b'{"a":{"b":{"c":{"d":{"e":{"f":{}}}}}}}',
        b'\x00invalid\xff json \x80',
    ],
    "json_oversized": [
        b'{"nfType":"' + b'A' * 4096 + b'"}',
        b'{' + b'"k":"v",' * 2000 + b'"z":"z"}',
        b'["x"]' * 1000,
        b'"' + b'A' * 8192 + b'"',
    ],
    "nas_5gmm": [
        bytes([0x00]),                          # sum=0   → variant 0
        bytes([0x01]),                          # sum=1   → variant 1
        bytes([0x02]),                          # sum=2   → variant 2
        bytes([0x03]),                          # sum=3   → variant 3
        bytes([0x04]),                          # sum=4   → variant 4
        bytes([0x05]),                          # sum=5   → variant 5
        bytes([0x06]),                          # sum=6   → variant 6
        bytes([0x07]),                          # sum=7   → variant 7
        bytes([0x08]),                          # sum=8   → variant 8
        bytes([0x09]),                          # sum=9   → variant 9
        bytes([0x0a]),                          # sum=10  → variant 10
        bytes([0x0b]),                          # sum=11  → variant 11
        bytes([0x0c]),                          # sum=12  → variant 12
        bytes([0x0d]),                          # sum=13  → variant 13
        bytes([0x0e]),                          # sum=14  → variant 14
        bytes([0x0f]),                          # sum=15  → variant 15
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
        recv_timeout: float = 0.5,   # per-message recv timeout (seconds)
        connect_timeout: float = 3.0,  # SCTP/TCP connect timeout (seconds)
        inter_step_delay: float = 0.0,  # sleep between actions (seconds); helps with SCTP backlog
        crash_dir: str = "fuzzer/data/crashes",  # directory to save crash-inducing PDU bytes
        persistent_conn: bool = False,  # reuse one SCTP association per episode
        scenario_filter: Optional[List[str]] = None,  # restrict to named scenarios
        api_filter: Optional[str] = None,  # restrict to message/scenario name prefix
    ):
        super().__init__()

        self.adapter = adapter
        self.target_host = target_host
        self.target_port = target_port or adapter.default_port
        self.max_steps = max_steps
        self.mode = mode
        self.recv_timeout = recv_timeout
        self.connect_timeout = connect_timeout
        self.inter_step_delay = inter_step_delay
        self.crash_dir = crash_dir
        self.persistent_conn = persistent_conn
        self.scenario_filter = scenario_filter  # exact scenario names to include
        self.api_filter = api_filter            # message/scenario name prefix to include

        # Persistent connection state (used when persistent_conn=True)
        self._sock: Optional[socket.socket] = None
        self._conn_params: Optional[Dict[str, Any]] = None
        # True once NGSetup has been sent successfully on the current association.
        # Cleared on every new connection.  When True, UE-centric messages can
        # be sent without getting "No GlobalRANNodeID" from AMF.
        self._association_ready: bool = False

        # Set to True once a crash or hang is confirmed by _check_server_state.
        # Cleared when the server is reached successfully again.
        # Used to avoid awarding the same crash/hang reward on every subsequent
        # episode while the server is already known to be down.
        self._server_known_down: bool = False

        # Optional shell command to restart all NFs after a crash/hang.
        self._restart_cmd: Optional[str] = None

        # Crash corpus: last two action records for correct crash attribution.
        # _last_action_record  — the action currently executing (overwritten each step).
        # _prev_action_record  — the action that executed one step earlier.
        # When the crash manifests as a connect failure the PREVIOUS action is the
        # one that killed the server; when it manifests as a reset/OSError during
        # send/recv the CURRENT action is the trigger.
        self._last_action_record: Optional[Dict[str, Any]] = None
        self._prev_action_record: Optional[Dict[str, Any]] = None

        # Crash deduplication: map crash_signature → number of times seen.
        # Only the first occurrence of each unique signature is saved to disk.
        self._crash_signatures: Dict[str, int] = {}

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

        # Per-action visit counts for cooling (exploration pressure)
        self._action_visit_counts: Dict[int, int] = {}

    # Default payload types for NGAP/NAS fuzzing.  Protocols override via
    # ProtocolAdapter.get_priority_payload_types().
    _PRIORITY_PAYLOAD_TYPES = ("nas_5gmm", "buffer_overflow", "null_injection")

    def _build_action_space(self):
        """Build action space based on mode and protocol.

        Action categories, in order of expected exploration depth:

        seq_payload  NEW — invalid state sequence + payload injection.
                     Highest priority: combines deep AMF state context from
                     the sequence with IE-level mutations from the payload.
                     All invalid sequences × priority payload types.

        seq_mutation NEW — invalid state sequence + semantic field mutation.
                     Applies boundary / invalid field values *inside* a real
                     AMF session, so they reach the NAS/GMM handler rather
                     than being rejected at the NGAP connection stage.

        state        — state machine sequences (no mutation).  Already proven
                     effective (flood_ul avg=357); kept as-is.

        semantic     — single-field mutation sent in its correct sequence
                     context (ng_setup → … → field_message).  Previously
                     these sent only the bare field message, which triggered
                     "No GlobalRANNodeID" before reaching the target code.

        payload      — generic payload injection in the first valid sequence.

        combo        — field mutation + invalid state sequence.
                     Expanded from top-3 to ALL invalid sequences.
        """
        self.actions: List[Tuple[str, Dict[str, Any]]] = []

        semantic_fields   = self.adapter.get_semantic_fields()
        state_transitions = self.adapter.get_state_transitions()
        payload_targets   = self.adapter.get_payload_targets()

        # Apply API prefix filter to state transitions and scenarios.
        # --api nrf  → only actions whose messages all start with 'nrf_'
        # --api nrf_nf_register → only that specific message type
        def _msg_matches(msg_type: str) -> bool:
            if not self.api_filter:
                return True
            return msg_type.startswith(self.api_filter)

        def _transition_matches(t) -> bool:
            if not self.api_filter:
                return True
            return all(_msg_matches(m) for m in t.message_sequence)

        def _scenario_matches(s) -> bool:
            if self.scenario_filter and s.name not in self.scenario_filter:
                return False
            if self.api_filter and not s.name.startswith(self.api_filter):
                return False
            return True

        state_transitions = [t for t in state_transitions if _transition_matches(t)]
        invalid_states    = [t for t in state_transitions if not t.is_valid]

        # Allow each protocol adapter to declare which payload types are relevant.
        priority_ptypes = (self.adapter.get_priority_payload_types()
                           if hasattr(self.adapter, 'get_priority_payload_types')
                           else self._PRIORITY_PAYLOAD_TYPES)

        # ── seq_payload: invalid sequence + payload injection ─────────────
        # These are the highest-value actions: deep AMF state reached via the
        # sequence, then the payload triggers NAS-decoder / pkbuf errors.
        if self.mode in ("aggressive", "hybrid") and invalid_states and payload_targets:
            for state in invalid_states:
                for target in payload_targets:
                    for ptype in priority_ptypes:
                        if ptype in GENERIC_PAYLOADS:
                            self.actions.append((
                                "seq_payload",
                                {
                                    "sequence": state.name,
                                    "messages": state.message_sequence,
                                    "target":   target.name,
                                    "payload_type": ptype,
                                }
                            ))

        # ── seq_mutation: invalid sequence + semantic field mutation ───────
        # Boundary / invalid field values inside a real AMF session reach
        # gmm-handler / NAS decoder instead of being rejected at setup stage.
        if self.mode in ("semantic", "hybrid") and invalid_states and semantic_fields:
            for state in invalid_states:
                for field_def in semantic_fields:
                    boundary_vals = field_def.boundary_values or []
                    for val in boundary_vals:
                        self.actions.append((
                            "seq_mutation",
                            {
                                "sequence": state.name,
                                "messages": state.message_sequence,
                                "field":    field_def.name,
                                "value":    val,
                            }
                        ))

        # ── state: sequence-only actions ───────────────────────────────────
        if self.mode in ("state", "hybrid"):
            for transition in state_transitions:
                self.actions.append((
                    "state",
                    {"sequence": transition.name, "messages": transition.message_sequence}
                ))

        # ── semantic: field mutation in proper context sequence ────────────
        # FIX: previously sent only the bare field-message (e.g. ['ul_nas']),
        # which AMF rejected with "No GlobalRANNodeID" before the mutation
        # reached its target.  Now sends the full context sequence so the
        # mutation lands in the correct AMF state.
        if self.mode in ("semantic", "hybrid"):
            for field_def in semantic_fields:
                values = self.adapter.get_mutation_values(field_def.name)
                for val in values:
                    field_msg = self.adapter.get_field_message_type(field_def.name)
                    ctx_seq   = self._sequence_for_field_msg(field_msg)
                    self.actions.append((
                        "semantic",
                        {
                            "field":    field_def.name,
                            "value":    val,
                            "messages": ctx_seq,   # full context sequence
                        }
                    ))

        # ── payload: generic payload injection in valid sequence ───────────
        if self.mode in ("aggressive", "hybrid"):
            valid_seq = (
                [t for t in state_transitions if t.is_valid][0].message_sequence
                if any(t.is_valid for t in state_transitions)
                else self.adapter.get_message_types()[:1]
            )
            for target in payload_targets:
                for payload_type in GENERIC_PAYLOADS:
                    self.actions.append((
                        "payload",
                        {
                            "target":       target.name,
                            "payload_type": payload_type,
                            "messages":     valid_seq,
                        }
                    ))

        # ── combo: field mutation + invalid state sequence ─────────────────
        # Expanded: all invalid sequences (was: only top-3).
        if self.mode == "hybrid" and semantic_fields and invalid_states:
            for field_def in semantic_fields[:3]:
                for val in self.adapter.get_mutation_values(field_def.name)[:3]:
                    for state in invalid_states:          # all invalid, not top-3
                        self.actions.append((
                            "combo",
                            {
                                "field":    field_def.name,
                                "value":    val,
                                "sequence": state.name,
                                "messages": state.message_sequence,
                            }
                        ))

        # ── scenario: predefined setup + targeted fuzz message ─────────────
        # Each scenario establishes prerequisite state with baseline/valid
        # messages, then fuzzes a specific API call.  This gives the agent
        # direct access to deep handler paths that would otherwise require
        # multi-step credit assignment across independent actions.
        scenarios = [s for s in self.adapter.get_scenarios() if _scenario_matches(s)]
        if scenarios:
            for scenario in scenarios:
                # One action per relevant field × mutation value
                for fname in (scenario.relevant_fields or []):
                    for val in self.adapter.get_mutation_values(fname):
                        self.actions.append((
                            "scenario",
                            {
                                "scenario":       scenario.name,
                                "target_api":     scenario.target_api,
                                "setup_messages": scenario.setup_messages,
                                "fuzz_message":   scenario.fuzz_message,
                                "field":          fname,
                                "value":          val,
                            }
                        ))
                # One action per payload target (body injection) using
                # adapter-specific payload types (not all GENERIC_PAYLOADS).
                for target in payload_targets:
                    for ptype in priority_ptypes:
                        if ptype in GENERIC_PAYLOADS:
                            self.actions.append((
                                "scenario",
                                {
                                    "scenario":       scenario.name,
                                    "target_api":     scenario.target_api,
                                    "setup_messages": scenario.setup_messages,
                                    "fuzz_message":   scenario.fuzz_message,
                                    "target":         target.name,
                                    "payload_type":   ptype,
                                }
                            ))

        # ── body_fuzz: generic leaf-field mutation on schema-valid bodies ──────
        # For every message template that produces a JSON body, walk every leaf
        # field and register one action per (field_path, mutation) pair.
        # Unlike semantic mutations (which target known fields by name), these
        # actions exercise every field in every message body including fields the
        # fuzzer was never explicitly told about.
        body_fuzz_variants = self.adapter.get_body_fuzz_actions(
            self.adapter.get_baseline_fields()
        )
        for template_name, field_path, mutation_label, mutation_idx in body_fuzz_variants:
            self.actions.append((
                "body_fuzz",
                {
                    "template":      template_name,
                    "field_path":    field_path,
                    "mutation_label": mutation_label,
                    "mutation_idx":  mutation_idx,
                }
            ))

        self.n_actions = len(self.actions)
        self.action_space = spaces.Discrete(self.n_actions)

        n_by_type: Dict[str, int] = {}
        for atype, _ in self.actions:
            n_by_type[atype] = n_by_type.get(atype, 0) + 1
        logger.info("Built action space: %d actions %s for %s",
                    self.n_actions, n_by_type, self.adapter.protocol_name)

    def _sequence_for_field_msg(self, field_msg: Optional[str]) -> List[str]:
        """Return the minimal proper sequence that ends with *field_msg*.

        Without NGSetup, UE-centric messages (initial_ue, ul_nas, ue_ctx_release)
        trigger "No GlobalRANNodeID" before reaching the target field handler.
        This method prepends the right preamble so the mutation lands in the
        correct AMF state rather than being rejected at the connection stage.
        """
        if not field_msg:
            valid = [t for t in self.adapter.get_state_transitions() if t.is_valid]
            return valid[0].message_sequence if valid else self.adapter.get_message_types()[:1]

        # ng_setup mutates the setup message itself — no prior context needed
        if field_msg == 'ng_setup':
            return ['ng_setup']

        # For each UE-centric message, use the first valid transition that
        # contains it so the sequence is protocol-correct.
        for t in self.adapter.get_state_transitions():
            if t.is_valid and field_msg in t.message_sequence:
                return t.message_sequence

        # Fallback: prepend NGSetup for NGAP protocols; for others just send directly
        if 'ng_setup' in self.adapter.get_message_types():
            return ['ng_setup', field_msg]
        return [field_msg]

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
        """Execute a fuzzing action and return reward + info.

        Field-mutation isolation: mutations applied here are scoped to this
        single action.  Without isolation, setting e.g. pdu_present=0x20 in
        one step would corrupt every subsequent build_message() call in the
        same episode, causing the agent to exploit a single mutation pattern
        across all 10 steps rather than exploring genuinely different actions.
        """
        info = {
            "action_type": action_type,
            "response": "none",
            "crash": False,
            "hang": False,
        }

        if not self.target_host:
            return 0.0, info

        # Snapshot: take a shallow copy of field/payload state so we can restore
        # it after this action's mutations are applied and the sequence is sent.
        _fields_snap  = dict(self.current_fields)
        _payload_snap = dict(self.current_payloads)

        # Apply mutations / payloads and determine the message sequence to send.
        #
        # seq_payload  — invalid sequence establishes deep AMF state, then
        #                payload injection triggers NAS/IE decoder errors.
        # seq_mutation — invalid sequence + boundary field mutation; reaches
        #                gmm-handler / security layer instead of being rejected
        #                at NGSetup stage.
        # semantic     — field mutation in its proper context sequence (NGSetup
        #                preamble already baked into action_params["messages"]).
        # state        — sequence only (no mutation).
        # payload      — payload in valid sequence (messages pre-computed).
        # combo        — field mutation + invalid sequence.

        try:
            if action_type == "seq_payload":
                payload_type = action_params["payload_type"]
                target       = action_params["target"]
                self.current_payloads[target] = random.choice(GENERIC_PAYLOADS[payload_type])
                messages = action_params["messages"]
                info["sequence"] = action_params["sequence"]
                info["payload"]  = f"{payload_type}->{target}"

            elif action_type == "seq_mutation":
                self.current_fields[action_params["field"]] = action_params["value"]
                messages = action_params["messages"]
                info["sequence"] = action_params["sequence"]
                info["mutation"] = f"{action_params['field']}={action_params['value']}"

            elif action_type == "semantic":
                self.current_fields[action_params["field"]] = action_params["value"]
                # Use the pre-computed context sequence (includes NGSetup preamble
                # so the mutation reaches its target rather than hitting the
                # "No GlobalRANNodeID" guard at the NGAP connection stage).
                messages = action_params.get("messages",
                               self._sequence_for_field_msg(
                                   self.adapter.get_field_message_type(action_params["field"])))
                info["mutation"] = f"{action_params['field']}={action_params['value']}"

            elif action_type == "payload":
                payload_type = action_params["payload_type"]
                target       = action_params["target"]
                self.current_payloads[target] = random.choice(GENERIC_PAYLOADS[payload_type])
                messages = action_params.get("messages", self.adapter.get_message_types()[:1])
                info["payload"] = f"{payload_type}->{target}"

            elif action_type in ("state", "combo"):
                if action_type == "combo":
                    self.current_fields[action_params["field"]] = action_params["value"]
                    info["mutation"] = f"{action_params['field']}={action_params['value']}"
                messages = action_params.get("messages", self.adapter.get_message_types()[:1])
                info["sequence"] = action_params.get("sequence", "default")

            elif action_type == "body_fuzz":
                # Generic leaf-field mutation: build a schema-valid body then
                # replace one leaf with a boundary/type-confusion value.
                # The adapter stores the pre-built mutated bytes keyed by
                # (template, field_path, mutation_idx) in current_payloads so
                # build_message() picks it up when it processes the template.
                template    = action_params["template"]
                field_path  = action_params["field_path"]
                mut_idx     = action_params["mutation_idx"]
                mut_label   = action_params.get("mutation_label", "?")
                self.current_fields["__body_fuzz_template__"] = template
                self.current_fields["__body_fuzz_field__"]    = field_path
                self.current_fields["__body_fuzz_idx__"]      = mut_idx
                info["mutation"] = f"body:{template}@{field_path}={mut_label}"
                # Use the message type that corresponds to this template.
                messages = [template]
                info["sequence"] = f"body_fuzz:{template}"

            elif action_type == "scenario":
                # Setup messages use baseline valid fields; only the fuzz_message
                # gets the field mutation / payload injection from action_params.
                info["scenario"]  = action_params.get("scenario", "")
                info["target_api"] = action_params.get("target_api", "")
                if "field" in action_params:
                    self.current_fields[action_params["field"]] = action_params["value"]
                    info["mutation"] = f"{action_params['field']}={action_params['value']}"
                if "target" in action_params:
                    payload_type = action_params["payload_type"]
                    self.current_payloads[action_params["target"]] = random.choice(
                        GENERIC_PAYLOADS[payload_type])
                    info["payload"] = f"{payload_type}->{action_params['target']}"
                # Tag the fuzz_message with a sentinel so _send_sequence
                # knows to switch from baseline fields to fuzz fields at that point.
                # Setup messages prefixed with 'fuzz:' use fuzz fields (same SUPI
                # as the fuzz_message), enabling state-dependent attack sequences
                # where setup must target the exact UE context being fuzzed.
                messages = []
                for _sm in action_params.get("setup_messages", []):
                    if _sm.startswith('fuzz:'):
                        messages.append(_sm[5:])
                    else:
                        messages.append(f'__baseline__:{_sm}')
                messages.append(action_params["fuzz_message"])
                info["sequence"] = action_params.get("scenario", "scenario")

            else:
                valid_transitions = [t for t in self.adapter.get_state_transitions() if t.is_valid]
                messages = (valid_transitions[0].message_sequence if valid_transitions
                            else self.adapter.get_message_types()[:1])

            # Execute the message sequence
            reward, exec_info = self._send_sequence(messages)
            info.update(exec_info)

        finally:
            # Restore: mutations applied above were for this action only.
            # Next action in the episode starts from the same clean state.
            self.current_fields   = _fields_snap
            self.current_payloads = _payload_snap

        return reward, info

    def _send_sequence(self, message_types: List[str]) -> Tuple[float, Dict[str, Any]]:
        """Send a sequence of messages and return reward + info.

        Supports two connection modes:
          persistent_conn=False (default): open a new socket per action, close after.
          persistent_conn=True:            reuse self._sock across actions within the
                                           episode; only reconnect when the socket dies.
                                           This avoids SCTP backlog flooding and is
                                           more realistic (real gNBs maintain one
                                           long-lived SCTP association per AMF).

        Distinguishes three server-failure modes:
          crash  — process died: ConnectionRefusedError + process not running
          hang   — process alive but unresponsive: connect timeout + process running
          error  — other transport error (OS error, reset, etc.)
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
        self._conn_params = conn_params

        # Build all messages.  Messages prefixed with '__baseline__:' are setup
        # steps in a FuzzScenario — they use the adapter's baseline fields
        # (valid values that establish prerequisite server state) rather than
        # the current fuzz fields.  Only the final un-prefixed message is fuzzed.
        baseline_fields = (self.adapter.get_baseline_fields()
                           if hasattr(self.adapter, 'get_baseline_fields') else {})
        # Fuzz fields: start from baseline (provides non-semantic defaults like
        # dnn/snssai_sd/rat_type needed by build_body), then overlay current_fields
        # so any mutations take priority over baseline values.
        fuzz_fields  = {**baseline_fields, **self.current_fields}
        fuzz_payloads = {k: v for k, v in self.current_payloads.items() if v is not None}

        built_messages: List[Tuple[str, bytes]] = []
        for msg_type in message_types:
            if msg_type.startswith('__baseline__:'):
                real_type = msg_type[len('__baseline__:'):]
                message = self.adapter.build_message(
                    message_type=real_type,
                    fields=baseline_fields,
                    payloads={},
                )
                if message:
                    built_messages.append((real_type, message))
            else:
                message = self.adapter.build_message(
                    message_type=msg_type,
                    fields=fuzz_fields,
                    payloads=fuzz_payloads,
                )
                if message:
                    built_messages.append((msg_type, message))

        # Rotate records: prev ← last, then record the current action.
        self._prev_action_record = self._last_action_record
        self._last_action_record = {
            "fields": dict(self.current_fields),
            "messages": [(mt, data.hex()) for mt, data in built_messages],
        }

        # In persistent mode, reuse self._sock; in ephemeral mode use a local sock
        own_sock = not self.persistent_conn   # whether we close the socket after use
        sock = self._sock if self.persistent_conn else None

        try:
            # (Re)connect if we don't have a live socket
            if sock is None:
                sock = self._make_socket(conn_params)
                sock.settimeout(self.connect_timeout)
                try:
                    sock.connect((self.target_host, self.target_port))
                    # Successful connect: server is (back) up
                    self._server_known_down = False
                except socket.timeout:
                    info["response"] = "connect_timeout"
                    if not self._server_known_down:
                        # First time we discover the server is unreachable:
                        # run a proper health check to distinguish crash vs hang.
                        self._check_server_state(info)
                        if info.get("crash"):
                            total_reward += 200.0
                            self._server_known_down = True
                            # The PREVIOUS action killed the server; this action
                            # merely discovered it couldn't connect.
                            self._save_crash_corpus(
                                info,
                                trigger=self._prev_action_record,
                                detection=self._last_action_record,
                            )
                        elif info.get("hang"):
                            total_reward += 20.0
                            self._server_known_down = True
                        else:
                            # Transient — small signal
                            total_reward += 5.0
                    else:
                        # Server already known down: no reward, avoid farming
                        info["hang"] = True
                    self.response_history.append(info["response"])
                    self._close_sock(sock)
                    if self.persistent_conn:
                        self._sock = None
                    return total_reward, info
                except ConnectionRefusedError:
                    info["response"] = "refused"
                    if not self._server_known_down:
                        self._check_server_state(info)
                        if info.get("crash"):
                            total_reward += 200.0
                            self._server_known_down = True
                            self._save_crash_corpus(
                                info,
                                trigger=self._prev_action_record,
                                detection=self._last_action_record,
                            )
                        elif info.get("hang"):
                            total_reward += 20.0
                            self._server_known_down = True
                    self.response_history.append(info["response"])
                    self._close_sock(sock)
                    if self.persistent_conn:
                        self._sock = None
                    return total_reward, info

                if self.persistent_conn:
                    self._sock = sock

            # In persistent mode, send NGSetup on every fresh connection to
            # register the gNB with AMF before sending any UE-centric messages.
            # Skip if the action sequence already starts with ng_setup — sending
            # two NGSetups on the same association causes AMF to reset it.
            if self.persistent_conn and not self._association_ready:
                first_msg = built_messages[0][0] if built_messages else ''
                if first_msg == 'ng_setup':
                    # The sequence will send NGSetup itself; mark ready so we
                    # don't double-send after the sequence completes.
                    self._association_ready = True
                else:
                    self._do_ng_setup(sock, conn_params)

            # Send each message in sequence.
            # built_messages[i] is a (msg_type, bytes) pair.  The final message
            # in the list is always the fuzz target; earlier messages are setup
            # steps whose reward contribution we deliberately skip so the agent
            # only gets credit for the targeted API response.
            fuzz_idx = len(built_messages) - 1
            for step_i, (msg_type, message) in enumerate(built_messages):
                is_setup = step_i < fuzz_idx and len(built_messages) > 1

                # HTTP/2 uses one request per connection (include_preface=True on
                # every build_message).  Sending a second preface on an established
                # connection is a protocol violation — nghttp2 would GOAWAY.
                # Reconnect before each message so every request starts a fresh
                # TCP+HTTP/2 session.  Server-side state (NF registration) persists
                # in the NRF DB across connections, so scenarios still work.
                if step_i > 0 and not self.persistent_conn:
                    self._close_sock(sock)
                    sock = self._make_socket(conn_params)
                    sock.settimeout(self.connect_timeout)
                    try:
                        sock.connect((self.target_host, self.target_port))
                    except (socket.timeout, ConnectionRefusedError) as e:
                        info["response"] = "reconnect_failed"
                        logger.debug("Scenario reconnect failed at step %d: %s", step_i, e)
                        break

                # Snapshot log position before the request so compute_reward
                # only scores log lines produced by THIS request (no lag).
                log_snap = (self.adapter.pre_request_snapshot()
                            if hasattr(self.adapter, 'pre_request_snapshot') else 0)
                t_start = time.monotonic()

                try:
                    self._sock_send(sock, message, conn_params)

                    resp_data = self.adapter.recv_data(sock, timeout=self.recv_timeout)
                    t_end = time.monotonic()
                    resp_time = (t_end - t_start) * 1000

                    if not resp_data:
                        parsed = {"type": "closed", "success": False}
                        # Server closed the connection — invalidate persistent socket
                        if self.persistent_conn:
                            self._close_sock(sock)
                            self._sock = None
                            self._association_ready = False
                            sock = None
                    else:
                        parsed = self.adapter.parse_response(resp_data)

                    rtype = parsed.get("type", "unknown")
                    info["responses"].append({
                        "message": msg_type,
                        "response": rtype,
                        "time_ms": resp_time,
                    })
                    info["response"] = rtype
                    info["response_time_ms"] = resp_time

                    # Log setup failures so scenario health is visible.
                    if is_setup and not parsed.get("success") and rtype not in (
                            "closed", "connect_timeout", "refused"):
                        logger.debug("Scenario setup step '%s' failed: %s",
                                     msg_type, rtype)

                    # Only compute reward for the fuzz target message (last in
                    # sequence).  Setup messages establish prerequisite state and
                    # their responses don't reflect fuzz quality.
                    if not is_setup:
                        reward_kwargs: Dict[str, Any] = dict(
                            response=parsed,
                            response_time_ms=resp_time,
                            field_mutations=self.current_fields,
                            payload_injections={k: v for k, v in
                                                self.current_payloads.items() if v},
                        )
                        if log_snap:
                            reward_kwargs['log_snapshot'] = log_snap
                        reward = self.adapter.compute_reward(**reward_kwargs)
                        total_reward += reward

                        if parsed.get("success"):
                            self.counters["successes"] += 1

                    if not resp_data:
                        break  # connection gone, stop sequence

                except socket.timeout:
                    info["responses"].append({
                        "message": msg_type,
                        "response": "timeout",
                        "time_ms": self.recv_timeout * 1000,
                    })
                    info["response"] = "timeout"
                    info["hang"] = True
                    self.counters["hangs"] += 1
                    # Reduced from 50: recv-timeout is common and easy to farm.
                    # Only award when the server is not already known to be down.
                    if not self._server_known_down:
                        total_reward += 15.0
                    # Persistent socket that timed out is likely broken — reset it
                    if self.persistent_conn:
                        self._close_sock(sock)
                        self._sock = None
                        self._association_ready = False
                        sock = None
                    break

            # In ephemeral mode, always close after the sequence
            if own_sock and sock is not None:
                self._close_sock(sock)
                sock = None

        except ConnectionResetError:
            info["response"] = "reset"
            if not self._server_known_down:
                self._check_server_state(info)
                if info.get("crash"):
                    total_reward += 200.0
                    self._server_known_down = True
                else:
                    total_reward += 10.0
            if self.persistent_conn:
                self._close_sock(sock)
                self._sock = None
                self._association_ready = False
                sock = None
            # TCP RST is usually caused by the PREVIOUS request crashing the
            # server asynchronously — the current action merely gets the RST.
            # Save _prev_action_record as the trigger (same logic as the
            # connect_timeout / refused paths).  Fall through to save below.
        except OSError as e:
            info["response"] = "error"
            info["error"] = str(e)
            self.counters["errors"] += 1
            total_reward += 3.0
            if self.persistent_conn:
                self._close_sock(self._sock)
                self._sock = None
                self._association_ready = False
                sock = None
        except Exception as e:
            info["response"] = "error"
            info["error"] = str(e)
            self.counters["errors"] += 1
            total_reward += 3.0
        finally:
            # Only clean up if we own the socket (ephemeral mode)
            if own_sock and sock is not None:
                self._close_sock(sock)

        # Save crash corpus when crash confirmed (ConnectionResetError path).
        # The PREVIOUS action is the most likely trigger; the CURRENT action
        # is the one that first observed the TCP RST (detection).
        if info.get("crash") and self._last_action_record:
            self._save_crash_corpus(
                info,
                trigger=self._prev_action_record,
                detection=self._last_action_record,
            )

        if self.inter_step_delay > 0:
            time.sleep(self.inter_step_delay)

        self.response_history.append(info["response"])
        return total_reward, info

    @staticmethod
    def _make_socket(conn_params: dict) -> socket.socket:
        """Create a socket appropriate for the given connection params."""
        sock_type = conn_params.get('socket_type', 'tcp')
        _IPPROTO_SCTP = 132
        if sock_type == 'udp':
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif sock_type == 'sctp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, _IPPROTO_SCTP)
            _SCTP_NODELAY = getattr(socket, 'SCTP_NODELAY', 3)
            sock.setsockopt(_IPPROTO_SCTP, _SCTP_NODELAY, 1)
            return sock
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if conn_params.get('tcp_nodelay'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock

    @staticmethod
    def _close_sock(sock: Optional[socket.socket]):
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def _save_crash_corpus(
        self,
        info: Dict[str, Any],
        trigger: Optional[Dict[str, Any]] = None,
        detection: Optional[Dict[str, Any]] = None,
    ):
        """Save the crash-triggering input to disk for later reproduction.

        trigger   — the action whose payload caused the crash.
                    None → falls back to _last_action_record (reset-during-send path).
        detection — the action that first observed the crash symptom (connect failure).
                    None → same as trigger (crash manifested on the triggering request).
        """
        try:
            # ── Crash signature & deduplication ───────────────────────────────
            # Ask the monitor for the FATAL assertion text; use it as a dedup key
            # so only the first instance of each unique root-cause is saved.
            monitor = getattr(self.adapter, '_monitor', None)
            sig  = monitor.get_crash_signature() if monitor else 'unknown'
            logs = monitor.get_stack_trace()      if monitor else []

            count = self._crash_signatures.get(sig, 0) + 1
            self._crash_signatures[sig] = count
            if count > 1:
                logger.warning(
                    "Duplicate crash skipped (sig=%r, seen=%d×). "
                    "Use replay_crash.py on the first saved corpus to reproduce.",
                    sig, count,
                )
                return

            os.makedirs(self.crash_dir, exist_ok=True)
            ts = int(time.time() * 1000)
            path = os.path.join(self.crash_dir, f"crash_{ts}.json")

            trig = trigger or self._last_action_record or {}
            trig_msgs = trig.get("messages", [])

            record: Dict[str, Any] = {
                "timestamp": ts,
                "target": f"{self.target_host}:{self.target_port}",
                "protocol": self.adapter.protocol_name,
                # How the crash was observed ("reset", "connect_timeout", "refused")
                "detection": info.get("response", "unknown"),
                "error": info.get("error"),
                # ── Root-cause summary ────────────────────────────────────────
                "crash_signature": sig,
                "stack_trace": logs,
                # ── Crash trigger ─────────────────────────────────────────────
                # The payload that was sent to the server immediately before it
                # died.  Replay these messages against a fresh server to confirm.
                "crash_trigger": {
                    "fields": trig.get("fields", {}),
                    "messages": trig_msgs,
                    # Human-readable decode: method, path, JSON body (HTTP/2)
                    # or raw byte count (NGAP/SCTP).  Used for root-cause triage.
                    "decoded": self._decode_messages(trig_msgs),
                },
            }

            # When the crash was discovered on a *different* action than the one
            # that triggered it (connect-failure case), record the detecting action
            # as context so the full sequence can be reconstructed.
            if detection and detection is not trig:
                det_msgs = detection.get("messages", [])
                record["detection_action"] = {
                    "fields": detection.get("fields", {}),
                    "messages": det_msgs,
                    "decoded": self._decode_messages(det_msgs),
                }
            # Always include the preceding action for sequence context.
            elif self._prev_action_record and self._prev_action_record is not trig:
                ctx_msgs = self._prev_action_record.get("messages", [])
                record["preceding_action"] = {
                    "fields": self._prev_action_record.get("fields", {}),
                    "messages": ctx_msgs,
                    "decoded": self._decode_messages(ctx_msgs),
                }

            with open(path, "w") as f:
                json.dump(record, f, indent=2)
            logger.warning(
                "CRASH CORPUS saved: %s  (sig=%r  trigger=%s  detection=%s)",
                path, sig,
                [m for m, _ in trig_msgs],
                info.get("response"),
            )
        except Exception as e:
            logger.error("Failed to save crash corpus: %s", e)

    # ------------------------------------------------------------------
    # Crash corpus helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_messages(messages: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """Return a human-readable decode of each raw message in *messages*.

        Each element of *messages* is a (message_type, hex_string) pair as
        stored in _last_action_record.  For HTTP/2 (SBI) payloads the method,
        path, and JSON body are extracted; for SCTP/NGAP payloads only the byte
        count is recorded.
        """
        result = []
        for msg_type, hex_str in messages:
            entry: Dict[str, Any] = {"message_type": msg_type}
            try:
                raw = bytes.fromhex(hex_str)
                if raw.startswith(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'):
                    entry.update(GenericFuzzEnv._parse_h2_frames(raw[24:]))
                else:
                    entry["raw_bytes"] = len(raw)
            except Exception as exc:
                entry["decode_error"] = str(exc)
            result.append(entry)
        return result

    @staticmethod
    def _parse_h2_frames(raw: bytes) -> Dict[str, Any]:
        """Scan HTTP/2 frames and return headers dict + decoded body."""
        headers_block = b''
        data_block = b''
        offset = 0
        while offset + 9 <= len(raw):
            length = int.from_bytes(raw[offset:offset + 3], 'big')
            ftype  = raw[offset + 3]
            offset += 9
            end = offset + length
            if end > len(raw):
                break
            payload = raw[offset:end]
            offset  = end
            if ftype == 0x1:    # HEADERS
                headers_block += payload
            elif ftype == 0x0:  # DATA
                data_block += payload

        result: Dict[str, Any] = {}
        if headers_block:
            result['headers'] = GenericFuzzEnv._decode_hpack_literal(headers_block)
        if data_block:
            try:
                result['body'] = json.loads(data_block)
            except Exception:
                result['body_text'] = data_block.decode('utf-8', errors='replace')
        return result

    @staticmethod
    def _decode_hpack_literal(data: bytes) -> Dict[str, str]:
        """Decode an HPACK block produced by hpack_encode() (literal-without-indexing,
        no Huffman, new-name form: prefix byte 0x00).

        Format per header:  0x00 | <name-len> <name-bytes> <val-len> <val-bytes>
        """
        headers: Dict[str, str] = {}
        pos = 0
        while pos + 2 < len(data):
            if data[pos] != 0x00:
                # Unexpected representation (e.g. mutated header block) — skip byte.
                pos += 1
                continue
            pos += 1
            # Name
            nlen = data[pos] & 0x7f   # bit-7 = Huffman flag (always 0 in our encoder)
            pos += 1
            if pos + nlen > len(data):
                break
            name = data[pos:pos + nlen].decode('latin-1', errors='replace')
            pos += nlen
            # Value
            if pos >= len(data):
                break
            vlen = data[pos] & 0x7f
            pos += 1
            if pos + vlen > len(data):
                break
            val = data[pos:pos + vlen].decode('latin-1', errors='replace')
            pos += vlen
            headers[name] = val
        return headers

    def _check_server_state(self, info: Dict[str, Any],
                             recovery_timeout: float = 15.0,
                             recovery_poll: float = 1.5):
        """Check whether server crashed (dead process) or hung (alive but unresponsive).

        After detecting a failure, polls for recovery up to `recovery_timeout`
        seconds before giving up.  This prevents a burst of hang warnings when
        AMF's SCTP listener temporarily closes and then comes back up.

        Failure modes:
          crash       — process died: info["crash"]=True
          hang        — process alive, port unresponsive: info["hang"]=True
          transient   — recovered before timeout: no flag set (counted once below)
        """
        time.sleep(0.6)  # ASAN abort_on_error=1 needs ~0.5s to kill the process

        # First check: is the server already healthy again?
        health = self.adapter.check_health(
            self.target_host, self.target_port, timeout=1.5
        )
        if health.is_healthy:
            return  # transient glitch — no flag needed

        # RSS critical path: NF is alive but leaking memory. Restart now before
        # the VM degrades further. Not counted as a crash or hang.
        if health.details.get('rss_critical'):
            logger.warning("RSS critical — restarting: %s", health.error)
            if self._restart_cmd:
                self._restart_server()
                self._close_sock(self._sock)
                self._sock = None
                self._association_ready = False
            return

        process_alive = health.details.get('amf_alive',
                         health.details.get('process_alive', None))
        transport     = health.details.get('transport_state', '')

        # Describe the failure for the log
        if process_alive is False:
            mode_str = "process not running (crash)"
        elif transport == 'refused':
            mode_str = f"N2 listener closed (port refused, process alive)"
        elif transport == 'timeout':
            mode_str = f"port bound but not responding (process alive)"
        else:
            mode_str = health.error or "unknown"

        logger.warning("Server down — %s. Waiting up to %.0fs for recovery…",
                       mode_str, recovery_timeout)

        # Dead process cannot self-revive: skip the 15-second recovery poll and
        # confirm crash immediately.  Waiting serves no purpose and blocks the
        # fuzzer (and crash detection) for the full recovery_timeout every time
        # AMF dies.
        if process_alive is False:
            info["crash"] = True
            self.counters["crashes"] += 1
            logger.warning("SERVER CRASH CONFIRMED: process not running")
            if self._restart_cmd:
                self._restart_server()
                self._close_sock(self._sock)
                self._sock = None
                self._association_ready = False
            return

        # Process alive but port unresponsive: wait out the recovery_timeout.
        # AMF's SCTP listener sometimes temporarily closes and then comes back.
        deadline = time.monotonic() + recovery_timeout
        recovered = False
        while time.monotonic() < deadline:
            time.sleep(recovery_poll)
            h2 = self.adapter.check_health(self.target_host, self.target_port, timeout=1.5)
            if h2.is_healthy:
                logger.info("Server recovered after %.0fs.",
                            recovery_timeout - (deadline - time.monotonic()))
                recovered = True
                break
            # Process may have died during the poll (ASAN delayed exit) — reclassify.
            poll_alive = h2.details.get('amf_alive', h2.details.get('process_alive', None))
            if poll_alive is False:
                process_alive = False
                logger.warning("Process died during recovery poll — reclassifying as crash.")
                break

        if recovered:
            info["transient_failure"] = True
            return

        # Still unresponsive after timeout → classify
        if process_alive is True:
            info["hang"] = True
            self.counters["hangs"] += 1
            if transport == 'refused':
                logger.warning("SERVER HANG CONFIRMED: N2 SCTP listener closed "
                               "(port %s refused, process alive)", self.target_port)
            else:
                logger.warning("SERVER HANG CONFIRMED: process alive but port "
                               "not responding (timeout)")
        else:
            info["crash"] = True
            self.counters["crashes"] += 1
            logger.warning("SERVER DOWN (unknown state): %s", health.error)

        # Auto-restart for hang / unknown-state cases
        if self._restart_cmd and (info.get("hang") or info.get("crash")):
            self._restart_server()
            self._close_sock(self._sock)
            self._sock = None
            self._association_ready = False

    @staticmethod
    def _sock_send(sock: socket.socket, data: bytes, conn_params: dict):
        """
        Send data on sock using the transport appropriate for conn_params.

        TCP/UDP: plain sendall.
        SCTP:    sendmsg with SCTP_SNDINFO ancillary data carrying the PPID
                 (default 60 = NGAP) and stream number (default 0).
                 This replicates what inject_sctp.c does via sctp_sendmsg().
        """
        if conn_params.get('socket_type') == 'sctp':
            import struct as _struct
            _IPPROTO_SCTP = 132
            _SCTP_SNDINFO = 2   # Linux kernel constant
            ppid   = conn_params.get('sctp_ppid', 60)
            stream = conn_params.get('sctp_stream', 0)
            # struct sctp_sndinfo: snd_sid(u16) snd_flags(u16) snd_ppid(u32)
            #                      snd_context(u32) snd_assoc_id(i32)
            sndinfo = _struct.pack('=HHIIi', stream, 0, socket.htonl(ppid), 0, 0)
            sock.sendmsg([data], [(_IPPROTO_SCTP, _SCTP_SNDINFO, sndinfo)])
        else:
            sock.sendall(data)

    def set_restart_cmd(self, cmd: str):
        """Register a shell command to restart all NFs on confirmed hang/crash."""
        self._restart_cmd = cmd

    def _restart_server(self):
        """Run the restart command and wait up to 45s for the stack to become healthy."""
        import subprocess
        logger.warning("Executing restart command: %s", self._restart_cmd)
        try:
            # The restart script manages its own log files — discard its stdout/stderr
            # here to avoid permission errors on system-owned log directories.
            subprocess.Popen(self._restart_cmd, shell=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             close_fds=True)
        except Exception as e:
            logger.error("Restart command failed: %s", e)
            return

        logger.info("Waiting for server to come back up…")
        for _ in range(30):
            time.sleep(1.5)
            if self.adapter.check_health(self.target_host, self.target_port, timeout=2.0).is_healthy:
                logger.info("Server healthy after restart.")
                return
        logger.warning("Server did not become healthy within 45s after restart.")

    def _do_ng_setup(self, sock: socket.socket, conn_params: dict):
        """Send a valid NGSetup on a freshly-connected persistent socket.

        A real gNB always sends NGSetup as the first message on a new SCTP
        association.  Without it, AMF logs "No GlobalRANNodeID" for every
        subsequent UE-centric message and may eventually destabilise the N2
        listener.

        Sets self._association_ready=True on success, leaves it False on failure
        so the next send attempt will retry.
        """
        if not hasattr(self.adapter, 'get_message_types'):
            return
        if 'ng_setup' not in self.adapter.get_message_types():
            return

        ng_setup_bytes = self.adapter.build_message(
            message_type='ng_setup',
            fields={},
            payloads={},
        )
        if not ng_setup_bytes:
            return

        try:
            self._sock_send(sock, ng_setup_bytes, conn_params)
            sock.settimeout(self.recv_timeout)
            resp = sock.recv(4096)
            if resp:
                parsed = self.adapter.parse_response(resp)
                if parsed.get('type', '') in ('ng_setup_response',):
                    self._association_ready = True
                    logger.debug("NGSetup on persistent association: success")
                else:
                    logger.debug("NGSetup on persistent association: got %s",
                                 parsed.get('type'))
                    self._association_ready = True   # proceed even on non-success response
            else:
                logger.debug("NGSetup on persistent association: empty response")
        except (socket.timeout, OSError) as e:
            logger.debug("NGSetup on persistent association failed: %s", e)
            # Leave _association_ready=False; will retry next connect

    def reset(self, seed=None, options=None):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        # Close persistent socket at episode boundary so the next episode
        # opens a fresh SCTP association (avoids AMF state confusion between episodes).
        if self.persistent_conn and self._sock is not None:
            self._close_sock(self._sock)
            self._sock = None
        self._association_ready = False

        self.reset_state()

        # Log episode coverage summary BEFORE reset_episode() clears the counters
        _monitor = getattr(self.adapter, '_monitor', None)
        _gcov_enabled = _monitor is not None and getattr(_monitor, '_gcov_gcda_dir', None)
        if _gcov_enabled and getattr(self, '_episode_gcov_lines', 0) > 0:
            ep = getattr(self, '_episode_count', 0)
            total = _monitor.gcov_coverage_count
            logger.info(
                "── Episode %d summary: gcov +%d new lines this episode │ "
                "campaign total: %d lines │ episode reward: %.2f",
                ep, self._episode_gcov_lines, total, self.episode_reward,
            )

        self.step_count = 0
        self.episode_reward = 0
        self.response_history = []
        self._episode_gcov_lines = 0
        self._episode_count = getattr(self, '_episode_count', 0) + 1
        # Decay rather than reset: frequently-exploited actions remain penalised
        # across episodes while rarely-chosen ones recover back toward 0.
        self._action_visit_counts = {
            k: int(v * 0.85) for k, v in self._action_visit_counts.items() if v > 0
        }

        # Reset per-episode state (response novelty set, monitor freq counters).
        # Without this, freq_factor → 0 after ~500 episodes, collapsing rewards.
        if hasattr(self.adapter, 'reset_episode'):
            self.adapter.reset_episode()
        else:
            if _monitor is not None and hasattr(_monitor, 'reset_episode'):
                _monitor.reset_episode()

        return self._get_obs(), {}

    def step(self, action):
        action = int(action)
        action_type, action_params = self.actions[action]

        # Compute action key early — needed for gcov attribution logging below.
        if action_type == 'body_fuzz':
            action_key = (f"body_fuzz:{action_params.get('template', 'unknown')}"
                          f":{action_params.get('field_path', 'unknown')}")
        else:
            action_key = f"{action_type}:{action_params.get('field', action_params.get('target', action_params.get('sequence', 'unknown')))}"

        # Snapshot gcov coverage count before executing so we can attribute
        # any new lines to the specific action that triggered them.
        _monitor = getattr(self.adapter, '_monitor', None)
        _gcov_enabled = _monitor is not None and getattr(_monitor, '_gcov_gcda_dir', None)
        _gcov_before = _monitor.gcov_coverage_count if _gcov_enabled else 0

        reward, info = self._execute_action(action_type, action_params)

        # gcov attribution: log which action unlocked new source lines.
        if _gcov_enabled:
            _gcov_after = _monitor.gcov_coverage_count
            _gcov_delta = _gcov_after - _gcov_before
            if _gcov_delta > 0:
                logger.info(
                    "gcov ▸ %-52s +%3d lines  (campaign total: %d)",
                    action_key, _gcov_delta, _gcov_after,
                )
                self._episode_gcov_lines = getattr(self, '_episode_gcov_lines', 0) + _gcov_delta
            # Coverage growth checkpoint every 200 global steps
            if self.step_count > 0 and self.step_count % 200 == 0:
                logger.info(
                    "Coverage checkpoint [step %4d]: %d lines covered",
                    self.step_count, _monitor.gcov_coverage_count,
                )

        # Apply per-action cooling to push the agent toward unexplored actions.
        visit = self._action_visit_counts.get(action, 0)
        self._action_visit_counts[action] = visit + 1
        cool_factor = 1.0 / (1.0 + visit * 0.25)
        reward *= cool_factor

        # Normalize reward scale so value function can converge.
        # Raw rewards reach ~100/step; PPO value function needs ~1-10 range.
        reward /= 100.0

        # Update statistics
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
        if self._sock is not None:
            self._close_sock(self._sock)
            self._sock = None
