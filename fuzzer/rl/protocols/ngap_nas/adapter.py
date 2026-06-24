#!/usr/bin/env python3
"""
Stateful NAS-layer fuzzer for ella-core AMF (ngap_nas protocol).

Extends NgapAdapter with live UE context tracking so NAS-targeted fuzz
messages always carry a valid AMF-UE-NGAP-ID assigned by ella at runtime.

How it works
------------
1. parse_response() watches every NGAP PDU ella sends back.
   When ella sends DownlinkNASTransport or InitialContextSetupRequest the
   AMF-UE-NGAP-ID it assigned is extracted and cached as _live_amf_ue_id.

2. build_message() injects _live_amf_ue_id into the NGAP envelope for all
   NAS-targeted message types (nas_* and context_* variants).

3. Scenario setup_messages include 'ng_setup' + 'initial_ue_valid' so the
   agent reaches deep NAS states (Authentication, Security Mode, PDU Session)
   with a real ella-assigned context ID before fuzzing begins.

Usage
-----
    python -m fuzzer.rl.train_protocol --protocol ngap_nas \\
        --target-host 10.3.0.2 --target-port 38412         \\
        --plmn-mcc 001 --plmn-mnc 01                       \\
        --persistent-conn --timesteps 100000 --max-steps 25
"""

import logging
import random
from typing import Any, Dict, List, Optional, Tuple

from fuzzer.rl.base.protocol_adapter import (
    FuzzScenario,
    StateTransition,
    register_protocol,
)
from fuzzer.rl.protocols.ngap.adapter import NgapAdapter
from fuzzer.rl.protocols.ngap.templates import encode_plmn

logger = logging.getLogger(__name__)

# ── NAS 5GSM PDU Session Establishment Request payloads ──────────────────────
# Embedded inside a 5GMM UL NAS Transport or sent raw to fuzz EPD handling.
# Structure (TS 24.501 §8.3.1):
#   EPD=0x2e (5GSM), PDU session ID, PTI, msg_type=0xc1
#   Mandatory IEs: PDU session type (IEI=0x59), SSC mode (IEI=0xA-)

def _gsm_pdu_session_request(session_id: int = 1, pdu_type: int = 1) -> bytes:
    """Minimal valid 5GSM PDU Session Establishment Request."""
    return bytes([
        0x2e,          # EPD: 5GSM (session management)
        session_id & 0xFF,
        0x01,          # PTI = 1
        0xc1,          # PDU Session Establishment Request
        0x59, 0x01, pdu_type & 0xFF,   # PDU session type IE (IEI=0x59, len=1)
        0xa1, 0x01, 0x01,              # SSC mode IE (IEI=0xa1 high-nibble, len=1)
    ])

def _nas_ul_transport_wrapping_gsm(session_id: int = 1) -> bytes:
    """5GMM UL NAS Transport (msg 0x68) wrapping a 5GSM PDU Session Est Req.

    This is the correct way a UE requests PDU session establishment: wrap the
    5GSM message in a 5GMM container with Payload Container Type and PDU
    session ID IEs.  Reaching this path requires ella to have an active UE
    security context.
    """
    gsm_pdu = _gsm_pdu_session_request(session_id)
    # Payload container IE (IEI=0x7b, 2-byte length, value=5GSM PDU)
    container_ie = bytes([0x7b, 0x00, len(gsm_pdu)]) + gsm_pdu
    # PDU session ID IE (IEI=0x12, len=1, value=session_id)
    session_ie = bytes([0x12, 0x01, session_id & 0xFF])
    # Request type IE (IEI=0x8-, type=1=initial request, packed with another nibble)
    request_ie = bytes([0x81])  # IEI+value packed: upper nibble=0x8 (Request type), lower=1

    body = (
        bytes([0x70, 0x01, 0x01])  # Payload container type IE: IEI=0x70, len=1, type=1 (N1 SM)
        + container_ie
        + session_ie
        + request_ie
    )
    return bytes([0x7e, 0x00, 0x68]) + body   # 5GMM plain NAS + UL NAS Transport

# ── NAS body variants for NAS-targeted message types ─────────────────────────

# Authentication Response variants (after challenge is sent by AMF)
_NAS_AUTH_RESPONSE_VARIANTS: List[bytes] = [
    # (1) Valid-looking RES* (16 bytes all-zero — wrong value but correct structure)
    bytes([0x2d, 0x10]) + bytes(16),
    # (2) RES* all-0xff
    bytes([0x2d, 0x10]) + bytes([0xff] * 16),
    # (3) Empty body — nil deref on missing RES* (ella CVE-2026-32948 seed)
    bytes([]),
    # (4) RES* with declared length 0 — zero-length IE
    bytes([0x2d, 0x00]),
    # (5) Oversized RES* (declared len=32, spec max is 16) — buffer boundary
    bytes([0x2d, 0x20]) + bytes(32),
    # (6) EAP message IE instead of RES* — wrong IE type for auth response
    bytes([0x78, 0x04, 0x02, 0x00, 0x00, 0x04]),
    # (7) Multiple IEs: RES* + unexpected extra IE
    bytes([0x2d, 0x10]) + bytes(16) + bytes([0x78, 0x01, 0xff]),
]

# Authentication Failure variants
_NAS_AUTH_FAILURE_VARIANTS: List[bytes] = [
    # (1) Cause=MAC failure (0x15), AUTS IE missing (wrong state)
    bytes([0x11, 0x15]),
    # (2) Cause=SQN failure (0x21) + AUTS IE (IEI=0x30, 14 bytes)
    bytes([0x11, 0x21, 0x30, 0x0e]) + bytes(14),
    # (3) Empty body — no cause IE
    bytes([]),
    # (4) Cause=0xff — invalid cause code
    bytes([0x11, 0xff]),
    # (5) Oversized AUTS (declared len=255) — bounds check
    bytes([0x11, 0x21, 0x30, 0xff]) + bytes(64),
]

# Security Mode Complete variants
_NAS_SMC_VARIANTS: List[bytes] = [
    # (1) Empty body — no optional IEs (minimal valid SMC)
    bytes([]),
    # (2) IMEISV (IEI=0x77 TLV-E) — all-zero IMEISV
    bytes([0x77, 0x00, 0x09, 0xf0]) + bytes(8),
    # (3) Piggybacked NAS PDU (IEI=0x71 TLV-E) = Registration Request
    bytes([0x71, 0x00, 0x06, 0x7e, 0x00, 0x41, 0x01, 0x77, 0x00]),
    # (4) Both IMEISV + piggybacked NAS PDU
    (bytes([0x77, 0x00, 0x09, 0xf0]) + bytes(8) +
     bytes([0x71, 0x00, 0x06, 0x7e, 0x00, 0x41, 0x01, 0x77, 0x00])),
    # (5) Oversized IMEISV — allocation stress
    bytes([0x77, 0x00, 0x40]) + bytes(64),
]

# Deregistration Request variants
_NAS_DEREG_VARIANTS: List[bytes] = [
    # (1) Normal deregister, 3GPP access, no switch-off
    bytes([0x01]),
    # (2) Switch-off deregister
    bytes([0x09]),
    # (3) With 5G-GUTI (IEI=0x77 TLV-E) all-zeros
    bytes([0x02, 0x77, 0x00, 0x0b, 0xf4]) + bytes(10),
    # (4) Invalid type=0xff
    bytes([0xff]),
    # (5) Emergency deregister (access=non-3GPP)
    bytes([0x02]),
]

# PDU Session Establishment variants (raw 5GSM inside NGAP UplinkNASTransport)
_NAS_PDU_SESSION_VARIANTS: List[bytes] = [
    # (1) Properly wrapped: 5GMM UL NAS Transport with 5GSM container, session=1
    _nas_ul_transport_wrapping_gsm(1),
    # (2) Raw 5GSM PDU directly (wrong EPD for plain 5GMM path — probes EPD dispatch)
    _gsm_pdu_session_request(1),
    # (3) Session ID=0 — below minimum (valid range: 1-15)
    _nas_ul_transport_wrapping_gsm(0),
    # (4) Session ID=16 — above maximum
    _nas_ul_transport_wrapping_gsm(16),
    # (5) Session ID=255 — far out-of-range
    _gsm_pdu_session_request(255),
    # (6) Session ID=15 — maximum valid
    _nas_ul_transport_wrapping_gsm(15),
    # (7) Truncated 5GSM body — just EPD + session ID
    bytes([0x2e, 0x01]),
    # (8) All-zero 5GSM body (maximal boundary)
    bytes([0x2e, 0x01, 0x00, 0xc1]) + bytes(32),
]

# "Wrong state" NAS message types — messages that make no sense in the
# current registration state, targeting GMM FSM assertion violations.
_NAS_WRONG_STATE_TYPES: List[int] = [
    0x43,   # Registration Complete (before Accept)
    0x44,   # Deregistration Accept (UE-initiated, AMF never sent request)
    0x48,   # Service Accept (AMF→UE direction, invalid from UE)
    0x55,   # Configuration Update Complete (before Config Update Command)
    0x68,   # UL NAS Transport (without 5GSM container)
    0x7a,   # Control Plane Service Request
    0x00,   # Reserved message type
    0xff,   # Unknown message type
]


# ── Step 2: AMF-UE-NGAP-ID extraction from raw APER bytes ────────────────────

def _extract_amf_ue_id(data: bytes) -> Optional[int]:
    """Parse AMF-UE-NGAP-ID (IE id=10) from raw NGAP APER PDU.

    AMF-UE-NGAP-ID IE encoding in NGAP open-type wrapper:
      id(2 bytes) = 0x000a
      criticality(1 byte)
      length(1 byte) = 0x05   (5-byte constrained integer, 40-bit)
      value(5 bytes)           the actual ID
    """
    try:
        idx = 0
        while idx < len(data) - 8:
            pos = data.find(b'\x00\x0a', idx)
            if pos == -1:
                break
            # id=0x000a at pos, criticality at pos+2, length at pos+3
            if pos + 9 <= len(data) and data[pos + 3] == 0x05:
                val = int.from_bytes(data[pos + 4: pos + 9], 'big')
                if val > 0:    # 0 is reserved/invalid
                    return val
            idx = pos + 1
    except Exception:
        pass
    return None


# ── Adapter ───────────────────────────────────────────────────────────────────

@register_protocol("ngap_nas")
class NgapNasAdapter(NgapAdapter):
    """
    Stateful NAS-layer fuzzer for ella-core AMF.

    Tracks the AMF-UE-NGAP-ID ella assigns at runtime and injects it into
    all NAS-targeted fuzz messages so they reach the real NAS handler instead
    of ella's early "unknown UE context" rejection path.

    New message types (in addition to NgapAdapter's full set):
      initial_ue_valid          — InitialUEMessage, no NAS mutations (preamble)
      nas_auth_response_fuzz    — Auth Response, valid AMF-UE-ID, fuzz RES* IE
      nas_auth_failure_fuzz     — Auth Failure, valid context, fuzz cause IE
      nas_smc_complete_fuzz     — Security Mode Complete, valid context
      nas_deregister_fuzz       — Deregistration Request, valid context
      nas_service_request_fuzz  — Service Request, valid context
      nas_pdu_session_establish — PDU Session Establishment (5GSM), valid context
      nas_wrong_state_msg       — Random NAS type wrong for current GMM state
      nas_replay                — Re-send last captured NAS message type
      ul_nas_released_ctx       — UplinkNASTransport to stale post-release ID
      double_initial_ue_fuzz    — Second InitialUEMessage, same RAN-UE-ID
      context_id_adjacent       — UplinkNASTransport with AMF-UE-ID ± 1
      ul_nas_flood              — Rapid UplinkNASTransport burst, same context
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Live UE context state — updated by parse_response()
        self._live_amf_ue_id: Optional[int] = None
        self._stale_amf_ue_id: Optional[int] = None   # saved after release
        self._setup_done: bool = False
        self._ue_context_active: bool = False
        # Last NAS type received from ella (for nas_replay action)
        self._last_dl_nas_type: Optional[int] = None
        # Episode-stable RAN-UE-NGAP-ID (so context lookups are consistent)
        self._episode_ran_id: int = 1

    # ── Step 3: Stateful episode reset ───────────────────────────────────────

    def reset_episode(self) -> None:
        self._live_amf_ue_id     = None
        self._stale_amf_ue_id    = None
        self._setup_done         = False
        self._ue_context_active  = False
        self._last_dl_nas_type   = None
        self._episode_ran_id     = random.randint(1, 0xFFFF)

    # ── Step 2: AMF-UE-NGAP-ID tracking via parse_response ──────────────────

    def parse_response(self, data: bytes) -> Dict[str, Any]:
        result = super().parse_response(data)
        rtype = result.get('type', '')

        if rtype == 'ng_setup_response':
            self._setup_done = True

        elif rtype in ('dl_nas_transport', 'initial_context_setup'):
            # Extract AMF-UE-NGAP-ID from the PDU — try mmt-dpi first, fall back
            # to raw byte parser if mmt-dpi can't decode ella's response format.
            amf_id = result.get('amf_ue_id') or _extract_amf_ue_id(data)
            if amf_id:
                self._live_amf_ue_id    = amf_id
                self._ue_context_active = True
                logger.debug("Captured AMF-UE-NGAP-ID=%d from %s", amf_id, rtype)
            # Track the NAS type ella sent (for nas_replay action)
            nas_type = result.get('nas_msg_type')
            if nas_type:
                self._last_dl_nas_type = nas_type

        elif rtype == 'ue_ctx_release_command':
            # Context released — save stale ID for ul_nas_released_ctx attack
            self._stale_amf_ue_id   = self._live_amf_ue_id
            self._ue_context_active = False
            # Keep _live_amf_ue_id so we can still send UplinkNASTransport to it

        return result

    # ── Step 4: New message types ─────────────────────────────────────────────

    def get_message_types(self) -> List[str]:
        base = super().get_message_types()
        return base + [
            # Preamble (no mutations — used in setup_messages for scenarios)
            'initial_ue_valid',
            # NAS-targeted actions (inject live AMF-UE-NGAP-ID automatically)
            'nas_auth_response_fuzz',
            'nas_auth_failure_fuzz',
            'nas_smc_complete_fuzz',
            'nas_deregister_fuzz',
            'nas_service_request_fuzz',
            'nas_pdu_session_establish',
            'nas_wrong_state_msg',
            'nas_replay',
            # Step 5: context manipulation / state confusion
            'ul_nas_released_ctx',
            'double_initial_ue_fuzz',
            'context_id_adjacent',
            'ul_nas_flood',
        ]

    # ── Step 4 + 5: Message building ──────────────────────────────────────────

    def build_message(self, message_type: str,
                      fields: Dict[str, Any],
                      payloads: Dict[str, bytes]) -> bytes:

        # ── initial_ue_valid: return patched template unchanged (no mutations) ──
        if message_type == 'initial_ue_valid':
            self._ensure_templates()
            tpl = self._templates.get(15, b'')
            # Override ran_ue_ngap_id with the episode-stable ID
            if tpl and len(tpl) >= 8:
                tpl = _patch_ran_ue_id(tpl, self._episode_ran_id)
            return tpl

        # ── Inject live AMF-UE-NGAP-ID for NAS-targeted actions ───────────────
        if message_type.startswith('nas_') or message_type in (
                'ul_nas_released_ctx', 'context_id_adjacent', 'ul_nas_flood'):

            fields = dict(fields)
            fields['ran_ue_ngap_id'] = self._episode_ran_id

            if message_type == 'ul_nas_released_ctx' and self._stale_amf_ue_id:
                fields['amf_ue_ngap_id'] = self._stale_amf_ue_id
            elif message_type == 'context_id_adjacent' and self._live_amf_ue_id:
                # Probe neighbour context: ±1 around the real ID
                delta = random.choice([-1, 1, 2, -2])
                fields['amf_ue_ngap_id'] = max(0, self._live_amf_ue_id + delta)
            elif self._live_amf_ue_id:
                fields['amf_ue_ngap_id'] = self._live_amf_ue_id
            # If no live ID yet, fall through — uses field value from RL agent

        # ── NAS Authentication Response (fuzz RES* IE) ────────────────────────
        if message_type == 'nas_auth_response_fuzz':
            seed = payloads.get('nas_container', b'')
            idx = sum(seed) % len(_NAS_AUTH_RESPONSE_VARIANTS) if seed else random.randrange(len(_NAS_AUTH_RESPONSE_VARIANTS))
            nas_body = _NAS_AUTH_RESPONSE_VARIANTS[idx]
            fields['nas_msg_type'] = 0x57
            payloads = dict(payloads)
            payloads['nas_container'] = bytes([0x7e, 0x00, 0x57]) + nas_body
            return super().build_message('ul_nas', fields, payloads)

        # ── NAS Authentication Failure ────────────────────────────────────────
        if message_type == 'nas_auth_failure_fuzz':
            idx = random.randrange(len(_NAS_AUTH_FAILURE_VARIANTS))
            nas_body = _NAS_AUTH_FAILURE_VARIANTS[idx]
            payloads = dict(payloads)
            payloads['nas_container'] = bytes([0x7e, 0x00, 0x58]) + nas_body
            return super().build_message('ul_nas', fields, payloads)

        # ── NAS Security Mode Complete ────────────────────────────────────────
        if message_type == 'nas_smc_complete_fuzz':
            seed = payloads.get('nas_container', b'')
            idx = sum(seed) % len(_NAS_SMC_VARIANTS) if seed else random.randrange(len(_NAS_SMC_VARIANTS))
            nas_body = _NAS_SMC_VARIANTS[idx]
            payloads = dict(payloads)
            payloads['nas_container'] = bytes([0x7e, 0x00, 0x5e]) + nas_body
            return super().build_message('ul_nas', fields, payloads)

        # ── NAS Deregistration Request ────────────────────────────────────────
        if message_type == 'nas_deregister_fuzz':
            idx = random.randrange(len(_NAS_DEREG_VARIANTS))
            nas_body = _NAS_DEREG_VARIANTS[idx]
            payloads = dict(payloads)
            payloads['nas_container'] = bytes([0x7e, 0x00, 0x42]) + nas_body
            return super().build_message('ul_nas', fields, payloads)

        # ── NAS Service Request ───────────────────────────────────────────────
        if message_type == 'nas_service_request_fuzz':
            # Service Request body variant from NAS_BODY_VARIANTS[0x46]
            fields['nas_msg_type'] = 0x46
            return super().build_message('ul_nas_svc', fields, payloads)

        # ── NAS PDU Session Establishment (5GSM, wrapped or raw) ─────────────
        if message_type == 'nas_pdu_session_establish':
            idx = random.randrange(len(_NAS_PDU_SESSION_VARIANTS))
            nas_pdu = _NAS_PDU_SESSION_VARIANTS[idx]
            payloads = dict(payloads)
            # Don't prepend 7e 00 header — some variants are already full PDUs
            payloads['nas_container'] = nas_pdu
            # Force the NAS container into the template as-is (bypass header prepend)
            return self._build_ul_nas_raw(nas_pdu, fields)

        # ── NAS wrong-state message ───────────────────────────────────────────
        if message_type == 'nas_wrong_state_msg':
            msg_type = random.choice(_NAS_WRONG_STATE_TYPES)
            # Send with empty body to trigger decoder nil-check on the first IE
            payloads = dict(payloads)
            payloads['nas_container'] = bytes([0x7e, 0x00, msg_type])
            return super().build_message('ul_nas', fields, payloads)

        # ── NAS replay (re-send same NAS type ella last sent us) ──────────────
        if message_type == 'nas_replay':
            if self._last_dl_nas_type:
                # Re-send the same NAS message type ella last sent downlink —
                # this shouldn't be a valid UE→AMF direction for most DL types,
                # testing GMM direction validation
                payloads = dict(payloads)
                payloads['nas_container'] = bytes([0x7e, 0x00, self._last_dl_nas_type])
                return super().build_message('ul_nas', fields, payloads)
            # No DL NAS seen yet — fall through to generic ul_nas
            return super().build_message('ul_nas', fields, payloads)

        # ── Step 5: Context manipulation ─────────────────────────────────────

        if message_type == 'ul_nas_released_ctx':
            # Send UplinkNASTransport to the stale (post-release) AMF-UE-NGAP-ID.
            # AMF-UE-ID already injected above; use any NAS type.
            return super().build_message('ul_nas', fields, payloads)

        if message_type == 'double_initial_ue_fuzz':
            # Second InitialUEMessage with same RAN-UE-NGAP-ID as first.
            # ella should evict the first context; if it doesn't: context collision.
            self._ensure_templates()
            tpl = self._templates.get(15, b'')
            return _patch_ran_ue_id(tpl, self._episode_ran_id)

        if message_type == 'context_id_adjacent':
            # AMF-UE-ID ±1 already injected into fields above
            return super().build_message('ul_nas', fields, payloads)

        if message_type == 'ul_nas_flood':
            # Rapid-fire UplinkNASTransport: same context, random NAS types.
            # The RL env sends one message per step, but rapid sequential steps
            # from this action stress AMF's per-UE message queuing.
            nas_type = random.choice([0x41, 0x57, 0x5e, 0x42, 0x46, 0x5c])
            payloads = dict(payloads)
            payloads['nas_container'] = bytes([0x7e, 0x00, nas_type])
            return super().build_message('ul_nas', fields, payloads)

        # Delegate everything else to the parent adapter unchanged
        return super().build_message(message_type, fields, payloads)

    # ── Step 4: NAS-focused state transitions ────────────────────────────────

    def get_state_transitions(self) -> List[StateTransition]:
        base = super().get_state_transitions()
        return base + [

            # ── Auth Response with live context ────────────────────────────
            StateTransition(
                'auth_response_after_registration',
                ['ng_setup', 'initial_ue_valid', 'nas_auth_response_fuzz'],
                'NGSetup + Registration, then fuzz Auth Response with live AMF-UE-ID',
                is_valid=False,
            ),
            StateTransition(
                'auth_failure_after_registration',
                ['ng_setup', 'initial_ue_valid', 'nas_auth_failure_fuzz'],
                'NGSetup + Registration, then send Auth Failure with live context',
                is_valid=False,
            ),

            # ── Security Mode with live context ────────────────────────────
            StateTransition(
                'smc_with_live_context',
                ['ng_setup', 'initial_ue_valid', 'nas_smc_complete_fuzz'],
                'NGSetup + Registration, then fuzz Security Mode Complete',
                is_valid=False,
            ),

            # ── NAS type flood with live context ──────────────────────────
            StateTransition(
                'nas_type_flood_live',
                ['ng_setup', 'initial_ue_valid',
                 'nas_auth_response_fuzz', 'nas_smc_complete_fuzz',
                 'nas_deregister_fuzz'],
                'Registration then rapid NAS type switching: Auth→SMC→Dereg (live context)',
                is_valid=False,
            ),

            # ── PDU Session with live context ─────────────────────────────
            StateTransition(
                'pdu_session_after_registration',
                ['ng_setup', 'initial_ue_valid', 'nas_pdu_session_establish'],
                'NGSetup + Registration, then send PDU Session Establishment request',
                is_valid=False,
            ),
            StateTransition(
                'pdu_session_burst',
                ['ng_setup', 'initial_ue_valid',
                 'nas_pdu_session_establish', 'nas_pdu_session_establish',
                 'nas_pdu_session_establish'],
                'Three consecutive PDU Session Establishment requests (session ID exhaustion)',
                is_valid=False,
            ),

            # ── Wrong-state NAS with live context ────────────────────────
            StateTransition(
                'wrong_state_nas_live',
                ['ng_setup', 'initial_ue_valid', 'nas_wrong_state_msg'],
                'Registration then wrong-direction NAS message (GMM FSM confusion)',
                is_valid=False,
            ),

            # ── NAS replay attack ─────────────────────────────────────────
            StateTransition(
                'nas_replay_attack',
                ['ng_setup', 'initial_ue_valid', 'nas_replay'],
                'Registration then replay the last DL NAS type ella sent (direction bypass)',
                is_valid=False,
            ),

            # ── Step 5: Context manipulation attacks ──────────────────────

            # UplinkNASTransport to a context that ella has already released.
            # ella should return error indication; if it dereferences the freed
            # context pointer: use-after-free / nil deref (ella CVE-2026-33281 class).
            StateTransition(
                'ul_nas_after_ctx_release',
                ['ng_setup', 'initial_ue_valid', 'ue_ctx_release',
                 'ul_nas_released_ctx'],
                'UplinkNASTransport to stale post-release AMF-UE-NGAP-ID (UAF probe)',
                is_valid=False,
            ),

            # Double InitialUEMessage with the same RAN-UE-NGAP-ID.
            # Second one should evict the first context; combined with a NAS message
            # it tests whether the old context pointer is still reachable.
            StateTransition(
                'double_register_context_collision',
                ['ng_setup', 'initial_ue_valid', 'double_initial_ue_fuzz',
                 'nas_auth_response_fuzz'],
                'Double InitialUEMessage same RAN-UE-ID, then Auth Response '
                '(context eviction race — #10012 class)',
                is_valid=False,
            ),

            # Context ID ±1 probe — does ella look up the neighbouring context?
            # Maps to GHSA-class: UE context lookup without boundary validation.
            StateTransition(
                'context_id_neighbour_probe',
                ['ng_setup', 'initial_ue_valid', 'context_id_adjacent'],
                'UplinkNASTransport with AMF-UE-ID ±1 (neighbour context lookup probe)',
                is_valid=False,
            ),

            # UplinkNASTransport flood with live context — tests per-UE queue depth
            # and whether ella drops or panics on rapid same-context messages.
            StateTransition(
                'ul_nas_flood_live',
                ['ng_setup', 'initial_ue_valid',
                 'ul_nas_flood', 'ul_nas_flood', 'ul_nas_flood',
                 'ul_nas_flood', 'ul_nas_flood'],
                'Five rapid UplinkNASTransport messages, same live context (queue stress)',
                is_valid=False,
            ),

            # Full deep-state chain: registration → auth → SMC → PDU session → dereg
            StateTransition(
                'full_nas_state_chain',
                ['ng_setup', 'initial_ue_valid',
                 'nas_auth_response_fuzz', 'nas_smc_complete_fuzz',
                 'nas_pdu_session_establish', 'nas_deregister_fuzz'],
                'Full NAS state walk: Registration→Auth→SMC→PDU Session→Deregister',
                is_valid=False,
            ),
        ]

    # ── Step 4: NAS-focused scenarios ────────────────────────────────────────

    def get_scenarios(self) -> List[FuzzScenario]:
        return [
            # ── Auth Response depth ───────────────────────────────────────
            FuzzScenario(
                name='auth_response_with_context',
                target_api='nas_auth',
                setup_messages=['ng_setup', 'initial_ue_valid'],
                fuzz_message='nas_auth_response_fuzz',
                description='NGSetup + Registration to get live AMF-UE-ID, '
                            'then fuzz Authentication Response RES* IE',
                relevant_fields=['ran_ue_ngap_id', 'amf_ue_ngap_id'],
            ),
            FuzzScenario(
                name='auth_failure_with_context',
                target_api='nas_auth',
                setup_messages=['ng_setup', 'initial_ue_valid'],
                fuzz_message='nas_auth_failure_fuzz',
                description='Registration then Auth Failure — fuzz cause IE and AUTS',
                relevant_fields=['amf_ue_ngap_id'],
            ),
            # ── Security Mode ─────────────────────────────────────────────
            FuzzScenario(
                name='smc_complete_with_context',
                target_api='nas_smc',
                setup_messages=['ng_setup', 'initial_ue_valid'],
                fuzz_message='nas_smc_complete_fuzz',
                description='Registration then Security Mode Complete — fuzz IMEISV and piggybacked NAS',
                relevant_fields=['amf_ue_ngap_id'],
            ),
            # ── PDU Session ───────────────────────────────────────────────
            FuzzScenario(
                name='pdu_session_with_context',
                target_api='nas_pdu_session',
                setup_messages=['ng_setup', 'initial_ue_valid'],
                fuzz_message='nas_pdu_session_establish',
                description='Registration then PDU Session Establishment — '
                            'fuzz session ID, PDU type, and 5GSM container',
                relevant_fields=['amf_ue_ngap_id'],
            ),
            # ── NAS wrong-state ───────────────────────────────────────────
            FuzzScenario(
                name='wrong_state_with_context',
                target_api='nas_gmm',
                setup_messages=['ng_setup', 'initial_ue_valid'],
                fuzz_message='nas_wrong_state_msg',
                description='Registration then send NAS message type wrong for GMM state',
                relevant_fields=['amf_ue_ngap_id'],
            ),
            # ── Use-after-free probe ──────────────────────────────────────
            FuzzScenario(
                name='ul_nas_after_release',
                target_api='nas_uaf',
                setup_messages=['ng_setup', 'initial_ue_valid', 'ue_ctx_release'],
                fuzz_message='ul_nas_released_ctx',
                description='Registration → context release → UplinkNASTransport '
                            'to stale AMF-UE-ID (use-after-free probe, CVE-2026-33281 class)',
                relevant_fields=['amf_ue_ngap_id'],
            ),
            # ── Double registration ───────────────────────────────────────
            FuzzScenario(
                name='double_registration_collision',
                target_api='nas_context',
                setup_messages=['ng_setup', 'initial_ue_valid'],
                fuzz_message='double_initial_ue_fuzz',
                description='Registration then second InitialUE with same RAN-UE-ID '
                            '(context eviction + collision, ella CVE-2026-32316 class)',
                relevant_fields=['ran_ue_ngap_id'],
            ),
            # ── Full state chain ──────────────────────────────────────────
            FuzzScenario(
                name='full_nas_state_walk',
                target_api='nas_chain',
                setup_messages=['ng_setup', 'initial_ue_valid', 'nas_auth_response_fuzz'],
                fuzz_message='nas_smc_complete_fuzz',
                description='Registration → Auth Response → fuzz Security Mode Complete '
                            '(deepest reachable NAS state without full crypto)',
                relevant_fields=['amf_ue_ngap_id'],
            ),
        ]

    # ── Reward bonuses for NAS-specific paths ────────────────────────────────

    def compute_reward(self, response: Dict[str, Any],
                       response_time_ms: float,
                       field_mutations: Dict[str, Any],
                       payload_injections: Dict[str, bytes]) -> float:
        reward = super().compute_reward(
            response, response_time_ms, field_mutations, payload_injections)

        rtype   = response.get('type', '')
        msg_type = getattr(self, '_last_message_type', '')

        # DL NAS Transport received — AMF reached the NAS handler deep enough
        # to send a response. High value because this only happens when our
        # UplinkNASTransport carried a valid AMF-UE-NGAP-ID AND was processed.
        if rtype == 'dl_nas_transport':
            reward += 20.0
            nas_type = response.get('nas_msg_type', 0)
            # Authentication Request → we probed deep into auth state machine
            if nas_type == 0x56:
                reward += 15.0
            # Identity Request → AMF parsed our Registration Request
            elif nas_type == 0x5b:
                reward += 10.0
            # Security Mode Command → we got past authentication entirely
            elif nas_type == 0x5d:
                reward += 25.0
            # Registration Accept → full registration path reached
            elif nas_type == 0x42:
                reward += 40.0

        # Initial Context Setup → AMF committed to a full UE context
        if rtype == 'initial_context_setup':
            reward += 30.0

        # Penalise NAS-targeted actions when no live AMF-UE-ID is available:
        # the message cannot reach any real NAS handler without context.
        if (msg_type in ('nas_auth_response_fuzz', 'nas_auth_failure_fuzz',
                         'nas_smc_complete_fuzz', 'nas_deregister_fuzz',
                         'nas_service_request_fuzz', 'nas_pdu_session_establish',
                         'nas_wrong_state_msg', 'nas_replay',
                         'ul_nas_released_ctx', 'context_id_adjacent')
                and self._live_amf_ue_id is None):
            reward -= 3.0   # nudge agent to run setup first

        return reward

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_ul_nas_raw(self, nas_pdu: bytes,
                          fields: Dict[str, Any]) -> bytes:
        """Build UplinkNASTransport NGAP PDU with an arbitrary NAS-PDU blob.

        Differs from the parent's UplinkNASTransport path in that the NAS blob
        is injected verbatim — no 7e/00/msg_type header is prepended.  Used
        for 5GSM PDUs that have their own EPD byte (0x2e, not 0x7e).
        """
        self._ensure_templates()
        template = self._templates.get(46, b'')  # UplinkNASTransport
        if not template:
            return b''

        msg = self._bridge.decode(template)
        if msg is None:
            return template

        if 'ran_ue_ngap_id' in fields:
            msg.ran_ue_id = int(fields['ran_ue_ngap_id']) & 0xFFFFFFFF
        if 'amf_ue_ngap_id' in fields:
            msg.amf_ue_id = int(fields['amf_ue_ngap_id']) & 0xFFFFFFFFFF

        msg.nas_pdu.data = nas_pdu
        msg.nas_pdu.size = len(nas_pdu)

        encoded = self._bridge.encode(msg, template)
        return encoded if encoded else template


# ── Utility: patch RAN-UE-NGAP-ID in raw APER bytes ──────────────────────────

def _patch_ran_ue_id(data: bytes, new_id: int) -> bytes:
    """Overwrite RAN-UE-NGAP-ID (IE id=0x0055) in a raw NGAP PDU.

    IE encoding: id(2=0x0055) + criticality(1) + length(1=0x04) + value(4 bytes).
    """
    try:
        idx = data.find(b'\x00\x55')
        if idx != -1 and idx + 8 <= len(data) and data[idx + 3] == 0x04:
            val_bytes = new_id.to_bytes(4, 'big')
            return data[:idx + 4] + val_bytes + data[idx + 8:]
    except Exception:
        pass
    return data
