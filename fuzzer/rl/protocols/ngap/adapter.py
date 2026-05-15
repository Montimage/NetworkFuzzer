#!/usr/bin/env python3
"""
NGAP Protocol Adapter for RL fuzzing of open5GS AMF.

Implements ProtocolAdapter for the N2 interface (gNB ↔ AMF):
- Transport:   SCTP, PPID=60, port 38412
- Encoding:    ASN.1 Aligned PER via libmmt_tmobile.so (mmt-dpi)
- Target:      open5GS open5gs-amfd process

Message building strategy:
  proc ∈ {4, 29, 41}  → decode template via mmt-dpi → mutate fields → re-encode
  proc = 6 (NGSetup)  → patched binary template (mmt-dpi cannot re-encode it)

Usage:
    python -m fuzzer.rl.train_protocol --protocol ngap \\
        --target-host 127.0.0.5 --target-port 38412    \\
        --plmn-mcc 001 --plmn-mnc 01 --gnb-id 1        \\
        --mode hybrid --timesteps 30000 --test
"""

import os
import socket
import struct
import time
import logging
from typing import List, Dict, Any, Tuple, Optional

from fuzzer.rl.base.protocol_adapter import (
    ProtocolAdapter,
    FieldDefinition,
    StateTransition,
    PayloadTarget,
    HealthCheckResult,
    register_protocol,
)
from .mmt_bridge import MmtNgapBridge, NgapMessage
from .templates import build_ng_setup_request, encode_plmn
from .open5gs_monitor import Open5GSMonitor  # kept for reference
from fuzzer.rl.monitor import NfMonitor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Semantic mutation value tables
# ---------------------------------------------------------------------------

PROCEDURE_CODE_VALUES = [
    # Standard 3GPP TS 38.413 gNB→AMF procedure codes
    21,   # id-NGSetup
    15,   # id-InitialUEMessage
    46,   # id-UplinkNASTransport
    42,   # id-UEContextReleaseRequest
    # Fuzzing: wrong/boundary procedure codes (from rules/7,8,9,10)
    0, 4, 6, 29, 41,        # wrong (AMF→gNB codes or undefined)
    127, 128, 255,           # boundary / undefined
]

# PDU choice (byte[0]): 0x00=initiatingMessage, 0x20=successfulOutcome,
# 0x40=unsuccessfulOutcome.  gNB→AMF messages are always initiatingMessage;
# sending successfulOutcome or unsuccessfulOutcome from gNB is invalid and
# exercises AMF's PDU choice dispatch (rules/7,8 fuzz pdu_present).
PDU_PRESENT_VALUES = [
    0x00,   # initiatingMessage (valid for gNB→AMF)
    0x20,   # successfulOutcome (invalid from gNB — tests AMF direction check)
    0x40,   # unsuccessfulOutcome (invalid from gNB)
    0x60,   # reserved / undefined
    0xFF,   # boundary
]

RAN_UE_ID_VALUES = [
    1, 2, 77, 100,          # valid values seen in pcap
    0,                      # invalid: 0 is reserved
    0x7FFFFFFF,             # near-max signed
    0xFFFFFFFF,             # max uint32
]

AMF_UE_ID_VALUES = [
    1, 77, 4294967356,      # valid (seen in pcap)
    0,                      # invalid: 0 is reserved
    0xFFFFFFFFFF,           # max uint40 (AMF-UE-NGAP-ID is 40-bit)
]

NAS_MSG_TYPE_VALUES = [
    0x41,   # Registration Request
    0x57,   # Authentication Response
    0x5E,   # Security Mode Complete
    0x45,   # Registration Complete
    0x42,   # Deregistration Request (UE-initiated)
    0x46,   # Service Request
    0x5C,   # Identity Response
    0x00,   # invalid / unknown
    0xFF,   # invalid / unknown
    0x7F,   # boundary
]

# Per-NAS-message-type body variants.
#
# Each list is the body bytes that follow the 3-byte NAS 5GS plain header
# [0x7e, 0x00, msg_type] prepended by build_message().
# The variant is chosen as: sum(seed_bytes) % len(variants), so different
# seed payloads from GENERIC_PAYLOADS map to different variants with no
# collision bias.
#
# ── Registration Request (0x41) ───────────────────────────────────────────
# 3GPP TS 24.501: mandatory fields = 5GS reg type (byte[0]) + mobile identity
# (TLV-E: IEI=0x77, 2-byte length, value).  Optional: UE security capability
# (IEI=0x2e).
#
# Security capability byte layout (TS 24.501 §9.11.3.54):
#   byte0 = 5G-EA  bit7=NEA0  bit6=NEA1_128  ...
#   byte1 = 5G-IA  bit7=NIA0  bit6=NIA1_128  ...
#   0x80/0x80 = only null algos → NIA0 rejection at gmm-handler.c:351
#   0xff/0xfe = all except NIA0 → bypasses NIA0 check, deeper GMM logic
#   0xff/0xff = all including NIA0 → "NIA0 present but not only option" branch
#
# ── Authentication Response (0x57) ───────────────────────────────────────
# Mandatory IE: RES* (IEI=0x2d, TLV, max 16 bytes EAP-AKA' result)
# Sending Auth Response without a prior Auth Request from AMF → GMM state
# machine error at gmm-sm.c (ogs_assert on missing security context).
#
# ── Security Mode Complete (0x5E) ─────────────────────────────────────────
# Optional IEs: IMEISV (IEI=0x77 TLV-E), NAS-PDU (IEI=0x71 TLV-E)
# Sending SMC without prior Security Mode Command → assertion / context error.
#
# ── Service Request (0x46) ────────────────────────────────────────────────
# Mandatory: service type (upper 4 bits of byte[0]), NAS KSI (lower 3 bits).
# Optional: PDU session status (IEI=0x50), uplink data status (IEI=0x40).
# Sending Service Request during initial registration → AMF looks for a
# session context that doesn't exist → potential NULL dereference.
#
# ── Deregistration Request UE-initiated (0x42) ───────────────────────────
# Mandatory: de-registration type + access type (byte[0])
# Optional: 5GS mobile identity (TLV-E IEI=0x77)
# Sending without registration context → assertion in amf-sm / context.c.
#
# ── Identity Response (0x5C) ─────────────────────────────────────────────
# Mandatory: 5GS mobile identity (TLV-E IEI=0x77)
# Sending without prior Identity Request → GMM state check failure.
NAS_BODY_VARIANTS: Dict[int, List[bytes]] = {
    0x41: [
        # (1) Empty body — immediate pkbuf on mandatory reg-type field
        bytes([]),
        # (2) Registration type only — pkbuf when decoder reads mobile identity
        bytes([0x01]),
        # (3) IEI=0x77 present but length too short — pkbuf in ies.c
        bytes([0x01, 0x77, 0x02, 0x00]),
        # (4) IEI=0x77 with zero length — bounds check in ies.c
        bytes([0x01, 0x77, 0x00]),
        # (5) Invalid IEI=0x00 after registration type — "Unknown type(0x0)"
        bytes([0x01, 0x00]),
        # (6) Null SUCI (MCC/MNC=0) — NIA0 rejection at gmm-handler.c:351
        bytes([0x01, 0x77, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        # (7) Null SUCI + NIA0/NEA0-only security cap → guaranteed NIA0 rejection
        bytes([0x01, 0x77, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x2e, 0x04, 0x80, 0x80, 0x00, 0x00]),
        # (8) Null SUCI + all-algorithms cap (0xff/0xfe) — deeper GMM logic
        bytes([0x01, 0x77, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x2e, 0x04, 0xff, 0xfe, 0x00, 0x00]),
        # (9) Null SUCI + 0xff/0xff — "NIA0 present but not only option" branch
        bytes([0x01, 0x77, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x2e, 0x04, 0xff, 0xff, 0x00, 0x00]),
        # (10) Emergency registration (type=0x07) with null SUCI
        bytes([0x07, 0x77, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        # (11) Oversized mobile identity (length=0xff) — large allocation test
        bytes([0x01, 0x77, 0x00, 0xff]) + bytes(64),
        # (12) Truncated mid-IE — declared len=32, only 4 bytes present
        bytes([0x01, 0x77, 0x00, 0x20]) + bytes(4),
        # (13) SUCI with zero-length MSIN → AMF creates "imsi-" SUPI → UDR crash
        #      path at dbi/subscription.c:333 (issue #4412)
        bytes([0x01, 0x77, 0x00, 0x09, 0x01, 0x99, 0xf9, 0x07, 0x00, 0x00, 0x00]),
        # (14) Requested NSSAI with 8 S-NSSAIs (max=8, OGS_MAX_NUM_OF_SESS=4)
        #      AMF processes all 8 → array overflow at context.c:2763 (issue #4406)
        bytes([0x01, 0x77, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x2f, 0x28] + [0x04, 0x01, 0x01, 0x00, 0x00] * 8),
        # (15) Periodic registration update (type=0x03) — different code path
        bytes([0x03, 0x77, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        # (16) Mobility registration (type=0x02) with all-zeros 5G-GUTI
        bytes([0x02, 0x77, 0x00, 0x0b, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, 0x00, 0x00, 0x00]),
    ],

    0x57: [
        # Authentication Response body (sent without prior Auth Request → GMM error)
        # (1) Empty — pkbuf on RES* IE
        bytes([]),
        # (2) RES* IE with zero length
        bytes([0x2d, 0x00]),
        # (3) RES* all-zero (16 bytes) — authentication failure path
        bytes([0x2d, 0x10]) + bytes(16),
        # (4) RES* all-0xff
        bytes([0x2d, 0x10]) + bytes([0xff] * 16),
        # (5) Short RES* (4 bytes only, declared len=4)
        bytes([0x2d, 0x04, 0x00, 0x00, 0x00, 0x00]),
        # (6) Oversized RES* (declared len=32, max is 16 per spec)
        bytes([0x2d, 0x20]) + bytes(32),
        # (7) EAP message IE (IEI=0x78) without RES* — wrong IE type
        bytes([0x78, 0x04, 0x02, 0x00, 0x00, 0x04]),
    ],

    0x5E: [
        # Security Mode Complete body (sent without prior SMC → context error)
        # (1) Empty — minimal valid SMC (no optional IEs)
        bytes([]),
        # (2) IMEISV with zero length (TLV-E: IEI=0x77, 2-byte len=0)
        bytes([0x77, 0x00, 0x00]),
        # (3) Valid-looking IMEISV (15-digit IMEI + 1 check digit, 8 bytes BCD)
        bytes([0x77, 0x00, 0x09, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x00, 0x00]),
        # (4) Piggybacked NAS-PDU IE with zero length
        bytes([0x71, 0x00, 0x00]),
        # (5) Oversized IMEISV — allocation stress
        bytes([0x77, 0x00, 0x40]) + bytes(64),
        # (6) Both IMEISV and NAS-PDU present (NAS-PDU = Registration Request)
        bytes([0x77, 0x00, 0x09, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x00, 0x00,
               0x71, 0x00, 0x06, 0x7e, 0x00, 0x41, 0x01, 0x77, 0x00]),
    ],

    0x46: [
        # Service Request body
        # (1) Empty — pkbuf on service type byte
        bytes([]),
        # (2) Service type=signalling (0x0), KSI=0
        bytes([0x00]),
        # (3) Service type=data (0x2), KSI=0
        bytes([0x20]),
        # (4) Service type=0x0 + PDU session status all-active (IEI=0x50)
        bytes([0x00, 0x50, 0x02, 0xff, 0xff]),
        # (5) Service type=0x2 + UL data status all-active (IEI=0x40)
        bytes([0x20, 0x40, 0x02, 0xff, 0xff]),
        # (6) Invalid service type=0xf + PDU session status
        bytes([0xf0, 0x50, 0x02, 0xff, 0xff]),
        # (7) Emergency service (0x1) — different AMF handling branch
        bytes([0x10]),
    ],

    0x42: [
        # Deregistration Request (UE-initiated) body
        # (1) Empty — pkbuf on de-reg type byte
        bytes([]),
        # (2) Normal deregister, access=3GPP (type=0x01)
        bytes([0x01]),
        # (3) Switch-off flag set (type=0x09)
        bytes([0x09]),
        # (4) With all-zero 5G-GUTI as identity
        bytes([0x01, 0x77, 0x00, 0x0b, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, 0x00, 0x00, 0x00]),
        # (5) Invalid type=0xff
        bytes([0xff]),
    ],

    0x5C: [
        # Identity Response body
        # (1) Empty — pkbuf on mobile identity IE
        bytes([]),
        # (2) IEI=0x77 with zero length
        bytes([0x77, 0x00, 0x00]),
        # (3) SUCI with null PLMN and zero scheme output
        bytes([0x77, 0x00, 0x07, 0x01, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00]),
        # (4) 5G-TMSI (GUTI type=0xf4, AMF pointer=0, TMSI=all zeros)
        bytes([0x77, 0x00, 0x0b, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, 0x00, 0x00, 0x00]),
        # (5) IMEI: odd-length BCD with all digits=f
        bytes([0x77, 0x00, 0x08, 0x23, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    ],
}

RRC_CAUSE_VALUES = [
    1,      # mo-Signalling
    3,      # emergency
    6,      # highPriorityAccess
    0,      # invalid (0 is not a valid enum value)
    7,      # boundary
    255,    # out-of-range
]

# Procedure code → NGAP message type name (for logging / parse_response)
_PROC_NAMES = {
    4:  'InitialUEMessage',
    6:  'NGSetup',
    9:  'ErrorIndication',
    14: 'Paging',
    15: 'InitialContextSetup',
    21: 'NGSetup',           # successfulOutcome shares code with request
    25: 'UEContextRelease',
    29: 'UplinkNASTransport',
    41: 'UEContextReleaseRequest',
    46: 'DownlinkNASTransport',
}

# (pdu_choice_byte, proc_code) → human-readable response name
_RESPONSE_NAMES = {
    (0x20, 21): 'ng_setup_response',
    (0x40, 21): 'ng_setup_failure',
    (0x00, 15): 'initial_context_setup',
    (0x00, 46): 'dl_nas_transport',
    (0x00,  9): 'error_indication',
    (0x20, 41): 'ue_ctx_release_command',
    (0x20, 25): 'ue_ctx_release_complete',
    (0x00, 14): 'paging',
}


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

@register_protocol("ngap")
class NgapAdapter(ProtocolAdapter):
    """
    NGAP protocol adapter.

    Targets the N2 interface of an open5GS AMF over SCTP.
    Re-uses libmmt_tmobile.so (mmt-dpi) for ASN.1 APER encode/decode.
    """

    def __init__(self,
                 gnb_id:   int = 1,
                 plmn_mcc: str = '999',   # matches open5GS default sample.yaml
                 plmn_mnc: str = '70',
                 amf_log:  str = '/var/log/open5gs/amf.log',
                 core:     str = 'open5gs',
                 bin_dir:  Optional[str] = None):
        self._gnb_id   = gnb_id
        self._plmn_mcc = plmn_mcc
        self._plmn_mnc = plmn_mnc
        self._plmn     = encode_plmn(plmn_mcc, plmn_mnc)
        self._bridge   = MmtNgapBridge()
        self._monitor  = NfMonitor(
            core=core, primary_nf='AMF', log_path=amf_log,
            protocol='ngap', bin_dir=bin_dir,
        )

        # Templates for decodable procedures: proc_code → raw APER bytes
        # Loaded lazily from 5g-sa.pcap on first build_message() call.
        self._templates: Dict[int, bytes] = {}
        self._templates_loaded = False

    # ── ProtocolAdapter identity ──────────────────────────────────────────

    @property
    def protocol_name(self) -> str:
        return "ngap"

    @property
    def default_port(self) -> int:
        return 38412   # OGS_NGAP_SCTP_PORT

    # ── Connection params ─────────────────────────────────────────────────

    def get_connection_params(self) -> Dict[str, Any]:
        return {
            'socket_type': 'sctp',
            'sctp_ppid':   60,      # NGAP PPID
            'sctp_stream': 0,
        }

    # ── Field definitions ─────────────────────────────────────────────────

    def get_semantic_fields(self) -> List[FieldDefinition]:
        return [
            FieldDefinition(
                name='procedure_code',
                offset=1,   # byte 1 of every NGAP PDU
                size=1,
                encoding='uint8',
                valid_values=[4, 29, 41],
                boundary_values=[0, 128, 255],
                description='NGAP Procedure Code',
            ),
            # pdu_present = byte[0]: PDU choice (initiating/successful/unsuccessful).
            # Sourced from rules/7.fuzz-ngap.xml and rules/8.fuzz-ngap-custom.xml
            # which fuzz ngap.pdu_present.  Sending successfulOutcome or
            # unsuccessfulOutcome from the gNB exercises AMF's direction check.
            FieldDefinition(
                name='pdu_present',
                offset=0,   # byte 0 of every NGAP PDU
                size=1,
                encoding='uint8',
                valid_values=[0x00],
                boundary_values=[0x20, 0x40, 0x60, 0xFF],
                description='NGAP PDU choice byte (0x00=initiating, 0x20=successful, 0x40=unsuccessful)',
            ),
            FieldDefinition(
                name='ran_ue_ngap_id',
                offset=None,   # variable: inside IE list
                size=4,
                encoding='uint32_be',
                valid_values=[1, 2, 77],
                boundary_values=[0, 0xFFFFFFFF],
                description='RAN-UE-NGAP-ID (gNB-local UE identifier, uint32)',
            ),
            FieldDefinition(
                name='amf_ue_ngap_id',
                offset=None,
                size=5,
                encoding='uint40',
                valid_values=[1, 77],
                boundary_values=[0, 0xFFFFFFFF],
                description='AMF-UE-NGAP-ID (AMF-local UE identifier, uint40)',
            ),
            FieldDefinition(
                name='nas_msg_type',
                offset=None,   # inside NAS-PDU blob, offset 2
                size=1,
                encoding='uint8',
                valid_values=[0x41, 0x57, 0x5E],
                boundary_values=[0x00, 0xFF],
                description='NAS-5G message_type byte inside NAS-PDU container',
            ),
            FieldDefinition(
                name='rrc_cause',
                offset=None,
                size=1,
                encoding='uint8',
                valid_values=[1, 3],
                boundary_values=[0, 7, 255],
                description='RRC Establishment Cause (enum, valid range 0-7)',
            ),
        ]

    def get_field_message_type(self, field_name: str) -> Optional[str]:
        """Map each semantic field to the one message type that carries it."""
        return {
            'procedure_code':  'ng_setup',       # affects the outer PDU header
            'pdu_present':     'initial_ue',     # PDU choice byte — any message type works
            'ran_ue_ngap_id':  'initial_ue',     # gNB-local UE ID in InitialUEMessage
            'amf_ue_ngap_id':  'ue_ctx_release', # AMF-local UE ID in release request
            'nas_msg_type':    'ul_nas',          # NAS message type byte in UplinkNASTransport
            'rrc_cause':       'initial_ue',      # RRC establishment cause in InitialUEMessage
        }.get(field_name)

    def get_mutation_values(self, field_name: str) -> List[Any]:
        return {
            'procedure_code': PROCEDURE_CODE_VALUES,
            'pdu_present':    PDU_PRESENT_VALUES,
            'ran_ue_ngap_id': RAN_UE_ID_VALUES,
            'amf_ue_ngap_id': AMF_UE_ID_VALUES,
            'nas_msg_type':   NAS_MSG_TYPE_VALUES,
            'rrc_cause':      RRC_CAUSE_VALUES,
        }.get(field_name, [])

    # ── Message types ─────────────────────────────────────────────────────

    def get_message_types(self) -> List[str]:
        return [
            'ng_setup',               # NGSetup (proc=21, valid PLMN)
            'ng_setup_inv',           # NGSetup with wrong/non-configured PLMN
            'initial_ue',             # InitialUEMessage with Registration Request
            'ul_nas',                 # UplinkNASTransport (NAS type from fields)
            'ul_nas_auth',            # UplinkNASTransport: forced NAS Auth Response (0x57)
            'ul_nas_smc',             # UplinkNASTransport: forced NAS Security Mode Complete (0x5E)
            'ul_nas_svc',             # UplinkNASTransport: forced NAS Service Request (0x46)
            'ul_nas_dereg',           # UplinkNASTransport: forced NAS Deregistration Request (0x42)
            'ul_nas_id',              # UplinkNASTransport: forced NAS Identity Response (0x5C)
            'pdu_session_setup_resp', # PDUSessionResourceSetupResponse (proc=29, issue #4413)
            'ue_ctx_release',         # UEContextReleaseRequest
        ]

    # ── State transitions ─────────────────────────────────────────────────

    def get_state_transitions(self) -> List[StateTransition]:
        return [
            # Valid flows
            StateTransition(
                'normal_registration',
                ['ng_setup', 'initial_ue', 'ul_nas'],
                'Normal UE registration: NGSetup → InitialUE → UplinkNAS',
                is_valid=True,
            ),
            StateTransition(
                'setup_only',
                ['ng_setup'],
                'NG Setup with no subsequent UE activity',
                is_valid=True,
            ),

            # Invalid / fuzzing sequences
            StateTransition(
                'ue_before_setup',
                ['initial_ue'],
                'InitialUEMessage without prior NGSetup',
                is_valid=False,
            ),
            StateTransition(
                'double_setup',
                ['ng_setup', 'ng_setup'],
                'Duplicate NGSetup requests on the same association',
                is_valid=False,
            ),
            StateTransition(
                'ul_without_initial',
                ['ng_setup', 'ul_nas'],
                'UplinkNASTransport without InitialUEMessage (no UE context)',
                is_valid=False,
            ),
            StateTransition(
                'release_then_ul',
                ['ng_setup', 'initial_ue', 'ue_ctx_release', 'ul_nas'],
                'UplinkNASTransport after UE context has been released',
                is_valid=False,
            ),
            StateTransition(
                'flood_ul',
                ['ng_setup', 'initial_ue',
                 'ul_nas', 'ul_nas', 'ul_nas', 'ul_nas', 'ul_nas'],
                'UplinkNASTransport flood after registration',
                is_valid=False,
            ),
            StateTransition(
                'release_before_setup',
                ['ue_ctx_release'],
                'UEContextReleaseRequest before any setup',
                is_valid=False,
            ),
            StateTransition(
                'setup_release_setup',
                ['ng_setup', 'ue_ctx_release', 'ng_setup'],
                'NGSetup → release → NGSetup again',
                is_valid=False,
            ),
            # From rules/4.nas-smc-replay-attack.xml:
            # Send NAS Security Mode Complete (msg_type=0x5E) without a prior
            # Security Mode Command from the AMF.  Tests GMM security-context
            # handling when the UE skips the command step.
            # NOTE: uses ul_nas_smc (forced NAS type=0x5E) instead of bare ul_nas
            # to ensure the Security Mode Complete body is actually sent.
            StateTransition(
                'smc_replay',
                ['ng_setup', 'initial_ue', 'ul_nas_smc'],
                'NAS Security Mode Complete without prior SMC command (replay attack)',
                is_valid=False,
            ),

            # ── New: NAS message-type-specific sequences ───────────────────
            # Each sends a valid NGAP envelope but with a NAS message that AMF
            # does not expect in the current GMM state, targeting gmm-sm.c
            # state-machine assertions and NAS decoder edge cases.
            StateTransition(
                'auth_response_no_request',
                ['ng_setup', 'initial_ue', 'ul_nas_auth'],
                'NAS Authentication Response without prior Auth Request from AMF',
                is_valid=False,
            ),
            StateTransition(
                'service_request_initial',
                ['ng_setup', 'initial_ue', 'ul_nas_svc'],
                'NAS Service Request during initial (non-registered) state',
                is_valid=False,
            ),
            StateTransition(
                'service_request_interrupt',
                ['ng_setup', 'initial_ue', 'ul_nas_svc', 'ue_ctx_release'],
                'Service Request immediately interrupted by UE context release '
                '(interrupt AMF mid-SBI call to SMF)',
                is_valid=False,
            ),
            StateTransition(
                'deregister_no_context',
                ['ng_setup', 'initial_ue', 'ul_nas_dereg'],
                'NAS Deregistration Request without prior registration',
                is_valid=False,
            ),
            StateTransition(
                'identity_response_no_request',
                ['ng_setup', 'initial_ue', 'ul_nas_id'],
                'NAS Identity Response without prior Identity Request from AMF',
                is_valid=False,
            ),
            StateTransition(
                'nas_type_flood',
                ['ng_setup', 'initial_ue',
                 'ul_nas_auth', 'ul_nas_smc', 'ul_nas_svc', 'ul_nas_dereg'],
                'Rapid NAS type switching: Auth→SMC→SvcReq→Dereg to confuse GMM FSM',
                is_valid=False,
            ),
            StateTransition(
                'double_initial_ue',
                ['ng_setup', 'initial_ue', 'initial_ue'],
                'Duplicate InitialUEMessage with same RAN-UE-NGAP-ID → context collision',
                is_valid=False,
            ),
            StateTransition(
                'invalid_plmn_setup',
                ['ng_setup_inv', 'initial_ue'],
                'NGSetup with non-configured PLMN, then send InitialUE anyway',
                is_valid=False,
            ),
            # ── open5gs issue #4413 sequences ──────────────────────────────
            # PDUSessionResourceSetupResponse without a pending request.
            # When AMF receives a gNB successfulOutcome(PDUSessionResourceSetup)
            # for which it never sent a request, it looks up a pending context
            # that does not exist → ngap-handler.c error path + AMF/SMF context
            # lookup assertion.
            StateTransition(
                'pdu_session_resp_unsolicited',
                ['ng_setup', 'pdu_session_setup_resp'],
                'PDUSessionResourceSetupResponse without prior setup request (unsolicited)',
                is_valid=False,
            ),
            # Malformed QoS response after UE context established.
            # Sends the response with QoS flow data but missing upTNLInformation,
            # which is the exact condition that crashes SMF at n4-build.c:337
            # (open5gs issue #4413).
            StateTransition(
                'pdu_session_resp_malformed_qos',
                ['ng_setup', 'initial_ue', 'pdu_session_setup_resp'],
                'PDUSessionResourceSetupResponse with QoS flow but no upTNLInformation '
                '(SMF crash: n4-build.c:337, issue #4413)',
                is_valid=False,
            ),
        ]

    # ── Payload targets ───────────────────────────────────────────────────

    def get_payload_targets(self) -> List[PayloadTarget]:
        # GENERIC_PAYLOADS from generic_env.py are injected into these targets.
        return [
            PayloadTarget(
                'nas_container',
                'nas_pdu',
                max_size=512,
                encoding='bytes',
            ),
            PayloadTarget(
                'ran_node_name',
                'ran_node_name_ie',
                max_size=150,
                encoding='string',
            ),
        ]

    # ── Message building ──────────────────────────────────────────────────

    # NAS message types forced by alias message-type names.
    # These all use the UplinkNASTransport APER template (proc=46) but override
    # the NAS message type byte so the sequence reaches a specific GMM handler.
    _NAS_FORCED_TYPES: Dict[str, int] = {
        'ul_nas_auth':  0x57,   # Authentication Response
        'ul_nas_smc':   0x5E,   # Security Mode Complete
        'ul_nas_svc':   0x46,   # Service Request
        'ul_nas_dereg': 0x42,   # Deregistration Request (UE-initiated)
        'ul_nas_id':    0x5C,   # Identity Response
    }

    def build_message(self, message_type: str,
                      fields: Dict[str, Any],
                      payloads: Dict[str, bytes]) -> bytes:
        self._ensure_templates()

        if message_type == 'ng_setup':
            return build_ng_setup_request(
                gnb_id=self._gnb_id,
                plmn_mcc=self._plmn_mcc,
                plmn_mnc=self._plmn_mnc,
            )

        # NGSetup with a non-configured PLMN — AMF will reject with NG-Setup
        # failure "Cannot find Served TAI" / "No PLMN" but the fuzzer continues
        # sending UE messages on the same association, exercising AMF's handling
        # of UE messages on an unregistered gNB.  Use MCC=000/MNC=00 (all BCD-0)
        # which no real network will have configured.
        if message_type == 'ng_setup_inv':
            return build_ng_setup_request(
                gnb_id=self._gnb_id,
                plmn_mcc='000',
                plmn_mnc='00',
            )

        # PDUSessionResourceSetupResponse: alternate between the minimal template
        # (Template A: no session list — exercises unsolicited-response path) and
        # the malformed-QoS template (Template B: missing upTNLInformation —
        # issue #4413 crash path at SMF n4-build.c:337).
        # Variant chosen by parity of the ran_ue_ngap_id field value so both
        # templates are used across different actions.
        if message_type == 'pdu_session_setup_resp':
            use_malformed = (int(fields.get('ran_ue_ngap_id', 1)) % 2 == 0)
            return self._PROC29_MALFORMED if use_malformed else self._templates.get(29, b'')

        proc_map = {
            # Standard 3GPP TS 38.413 gNB→AMF procedure codes
            'initial_ue':    15,   # id-InitialUEMessage
            'ul_nas':        46,   # id-UplinkNASTransport
            'ue_ctx_release': 42,  # id-UEContextReleaseRequest
        }
        # NAS-type alias message types all use the UplinkNASTransport template
        if message_type in self._NAS_FORCED_TYPES:
            proc_map[message_type] = 46

        proc = proc_map.get(message_type, 4)
        template = self._templates.get(proc)

        if template is None:
            logger.warning("No template for message_type=%s proc=%d", message_type, proc)
            return b''

        # 1. Decode the template using mmt-dpi
        msg = self._bridge.decode(template)
        if msg is None:
            logger.warning("decode_ngap failed for proc=%d, sending template unchanged", proc)
            return template

        # 2. Apply semantic field mutations chosen by the RL agent.
        #    NOTE: procedure_code is NOT set on the mmt-dpi message object because
        #    mmt-dpi re-encoding with a foreign proc code corrupts the PDU choice
        #    byte (byte[0]: initiatingMessage/successfulOutcome/unsuccessfulOutcome).
        #    Instead we patch byte[1] directly in the final encoded bytes below.
        if 'ran_ue_ngap_id' in fields:
            msg.ran_ue_id = int(fields['ran_ue_ngap_id']) & 0xFFFFFFFF
        if 'amf_ue_ngap_id' in fields:
            msg.amf_ue_id = int(fields['amf_ue_ngap_id']) & 0xFFFFFFFFFF

        # 3. Apply NAS-PDU construction.
        #
        # NAS type priority (highest wins):
        #   a. message_type alias (ul_nas_smc → 0x5E, etc.)
        #   b. fields['nas_msg_type'] explicit override
        #   c. default: 0x41 (Registration Request)
        #
        # Body selection (for both aliased and payload-injected cases):
        #   NAS_BODY_VARIANTS[nas_type] contains per-type crafted bodies.
        #   Variant index = sum(seed_bytes) % len(variants) to avoid the
        #   first-two-bytes collision bug where most seeds mapped to index 3.
        nas_forced_type = self._NAS_FORCED_TYPES.get(message_type)
        nas_payload     = payloads.get('nas_container')

        if nas_forced_type is not None or nas_payload is not None:
            # Determine the NAS message type
            if nas_forced_type is not None:
                nas_type = nas_forced_type
            else:
                nas_type = int(fields.get('nas_msg_type', 0x41)) & 0xFF

            # Determine the NAS body
            type_variants = NAS_BODY_VARIANTS.get(nas_type, [])
            if type_variants:
                # Use sum of seed bytes for better distribution across variants.
                # If no seed payload, use a pseudo-random seed from the fields.
                seed = nas_payload if nas_payload else bytes(
                    [int(fields.get('ran_ue_ngap_id', 1)) & 0xFF,
                     int(fields.get('procedure_code', 15)) & 0xFF]
                )
                idx = sum(seed) % len(type_variants)
                nas_body = type_variants[idx]
            elif nas_payload:
                nas_body = nas_payload[:200]
            else:
                nas_body = bytes([])

            # NAS-5GS plain header: EPD=0x7e, security_header=0x00, msg_type
            nas_blob = bytes([0x7e, 0x00, nas_type]) + nas_body
            msg.nas_pdu.data = nas_blob
            msg.nas_pdu.size = len(nas_blob)

        # 4. Re-encode with mmt-dpi (ASN.1 APER)
        encoded = self._bridge.encode(msg, template)
        if encoded is None:
            logger.warning("encode_ngap failed for proc=%d, sending template unchanged", proc)
            return template

        # 5. Patch header bytes directly in the encoded output.
        #
        #    byte[0] = pdu_present (PDU choice: initiating/successful/unsuccessful)
        #    byte[1] = procedure_code
        #
        #    We patch these after encoding rather than via the mmt-dpi struct because
        #    mmt-dpi re-encoding with a foreign proc/choice corrupts the PDU layout.
        #    Patching bytes is safe: the APER body stays valid for the original
        #    procedure while the header exercises AMF's dispatch logic.
        choice = encoded[0] if encoded else 0x00
        pc     = encoded[1] if len(encoded) >= 2 else 0x00

        if 'pdu_present' in fields and len(encoded) >= 1:
            choice = int(fields['pdu_present']) & 0xFF
        if 'procedure_code' in fields and len(encoded) >= 2:
            pc = int(fields['procedure_code']) & 0xFF

        if len(encoded) >= 2 and (choice != encoded[0] or pc != encoded[1]):
            encoded = bytes([choice, pc]) + encoded[2:]

        return encoded

    # ── Response parsing ──────────────────────────────────────────────────

    def parse_response(self, data: bytes) -> Dict[str, Any]:
        if not data or len(data) < 2:
            return {'type': 'empty', 'success': False}

        pdu_choice = data[0]   # 0x00=initiating 0x20=successful 0x40=unsuccessful
        proc_code  = data[1]

        rtype = _RESPONSE_NAMES.get(
            (pdu_choice, proc_code),
            f'ngap_{pdu_choice:#04x}_proc{proc_code}',
        )
        success = (pdu_choice == 0x20)

        result: Dict[str, Any] = {
            'type':           rtype,
            'success':        success,
            'pdu_choice':     pdu_choice,
            'procedure_code': proc_code,
            'raw_length':     len(data),
        }

        # Enrich with decoded fields when mmt-dpi can parse the response
        msg = self._bridge.decode(data)
        if msg:
            result['ran_ue_id'] = msg.ran_ue_id
            result['amf_ue_id'] = msg.amf_ue_id
            nas = self._bridge.get_nas_pdu(data)
            if nas:
                result['nas_len']      = len(nas)
                result['nas_msg_type'] = nas[2] if len(nas) >= 3 else 0

        return result

    # ── Interesting response classification ───────────────────────────────

    def is_interesting_response(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        rtype = response.get('type', '')

        table = {
            # Crash signals — highest value
            'timeout':                 (True,  4.0),  # AMF not responding: potentially stuck
            'reset':                   (True,  3.0),  # Connection reset: potentially crashed
            # Unexpected/rare responses — high value
            'ng_setup_failure':        (True,  2.5),  # AMF rejects our setup
            'dl_nas_transport':        (True,  2.5),  # AMF sends downlink NAS (interesting)
            'initial_context_setup':   (True,  2.0),  # AMF creates UE context (rare for fuzz)
            'paging':                  (True,  2.0),  # AMF sends paging (unexpected)
            'empty':                   (True,  1.5),  # Empty response: protocol anomaly
            # Expected error responses — lower value (normal rejection behavior)
            'error_indication':        (True,  1.0),  # Expected for malformed messages
            'ue_ctx_release_command':  (True,  1.0),
            'ue_ctx_release_complete': (True,  0.5),
            'ng_setup_response':       (True,  0.5),  # Normal success — not interesting
            'refused':                 (False, 0.2),
        }

        # Any response type we don't recognise is very interesting
        if rtype.startswith('ngap_0x') or 'proc' in rtype:
            return (True, 4.0)

        return table.get(rtype, (False, 0.5))

    # ── Reward computation ────────────────────────────────────────────────

    def compute_reward(self, response: Dict[str, Any],
                       response_time_ms: float,
                       field_mutations: Dict[str, Any],
                       payload_injections: Dict[str, bytes]) -> float:
        reward = 0.0

        is_interesting, mult = self.is_interesting_response(response)
        if is_interesting:
            reward += 15.0 * mult

        # Slow response bonus (same thresholds as DicomAdapter)
        if response_time_ms > 100:
            reward += 25.0
        elif response_time_ms > 50:
            reward += 12.0

        # Boundary value bonus for NGAP-specific fields
        if field_mutations.get('ran_ue_ngap_id') in {0, 0x7FFFFFFF, 0xFFFFFFFF}:
            reward += 5.0
        if field_mutations.get('procedure_code') in {0, 127, 128, 255}:
            reward += 5.0
        if field_mutations.get('amf_ue_ngap_id') in {0, 0xFFFFFFFFFF}:
            reward += 5.0
        # PDU choice byte fuzzing bonus (sending successfulOutcome from gNB)
        if field_mutations.get('pdu_present') in {0x20, 0x40, 0x60, 0xFF}:
            reward += 5.0

        # NAS payload injection bonus
        if payload_injections.get('nas_container'):
            reward += 8.0

        # Crash detected by process monitor — highest reward signal
        if self._monitor.detect_crash():
            reward += 200.0
        else:
            # Log-anomaly reward using anomaly_score() × multiplier.
            #
            # anomaly_score() = max(depth × severity × freq_factor) + novelty_bonus
            #   depth:       0.05 (unknown) … 0.95 (aper_decode)
            #   severity:    WARNING=0.50, ERROR=0.85, FATAL=1.00
            #   freq_factor: 1.0 (1st) → 0.57 (6th) → 0.40 (11th) → 0.25 (21st)
            #   novelty:     +0.15 for first-ever unique error signature
            #
            # Reward examples (× 80):
            #   1st ERROR in pkbuf (0.90×0.85×1.0 + 0.15):  0.915 × 80 = 73.2
            #   1st WARNING in gmm-handler (0.70×0.50 + 0.15):  0.50 × 80 = 40.0
            #   1st WARNING in gmm-sm.c (0.68×0.50 + 0.15):    0.49 × 80 = 39.2
            #   10th "Not implemented" (0.15×0.85×0.40):        0.051 × 80 =  4.1
            #   1st ERROR "Not implemented" (0.15×0.85 + 0.15): 0.278 × 80 = 22.2
            #
            # NOTE: Flat per-level bonuses (previously +30 for ERROR, +10 for WARN)
            # have been removed.  They made even shallow repeated ERRORs very
            # rewarding (flat 30 + depth 7.6 = 37.6) and prevented the RL agent
            # from moving away from the "Not implemented(choice:3, proc:42)" loop
            # observed in real fuzzing.  The freq_factor diminishing returns now
            # fully handle that without the flat bonus distorting the signal.
            #
            # FATAL (ogs_assert / ogs_fatal without process crash) still gets
            # a flat bonus because it represents an internal invariant violation
            # that the depth×severity score alone would underweight if it came
            # from a shallow code location.
            logs = self._monitor.recent_logs_by_level(30)
            if logs['fatal']:
                reward += 60.0   # ogs_fatal / ogs_assert — invariant violation

            score = self._monitor.anomaly_score()
            if score > 0:
                reward += score * 80.0

        return reward

    # ── Health check ──────────────────────────────────────────────────────

    def kill_server(self) -> bool:
        """Terminate the AMF process so a clean restart can be performed."""
        return self._monitor.kill_amf()

    def check_health(self, host: str, port: int,
                     timeout: float = 5.0) -> HealthCheckResult:
        result = HealthCheckResult(is_healthy=False)

        # Fast path: process not running → no point trying SCTP
        if not self._monitor.is_amf_alive():
            result.error = f'AMF process ({self._monitor._proc_name("AMF")}) is not running'
            result.details['amf_alive'] = False
            return result

        IPPROTO_SCTP = 132
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
            sock.settimeout(timeout)

            t0 = time.monotonic()
            sock.connect((host, port))

            ng_setup = build_ng_setup_request(self._gnb_id, self._plmn_mcc, self._plmn_mnc)
            # Send with PPID=60 via SCTP_SNDINFO ancillary data
            sndinfo = struct.pack('=HHIIi', 0, 0, socket.htonl(60), 0, 0)
            sock.sendmsg([ng_setup], [(IPPROTO_SCTP, 2, sndinfo)])

            resp = sock.recv(4096)
            result.latency_ms = (time.monotonic() - t0) * 1000

            if resp and len(resp) >= 2:
                parsed = self.parse_response(resp)
                result.is_healthy = True
                result.details['response'] = parsed['type']
                result.details['proc_code'] = parsed['procedure_code']

            sock.close()

        except socket.timeout:
            # Port bound but not accepting: SCTP socket is bound but AMF isn't
            # calling accept / processing connections (backlog full or event loop stuck)
            result.error = 'SCTP connect/recv timeout'
            result.details['transport_state'] = 'timeout'
        except ConnectionRefusedError:
            # Port is NOT bound: AMF's SCTP listen socket was closed.
            # The process may still be alive (e.g., SCTP handler crashed but main
            # process continues, or AMF is mid-restart of its listener).
            result.error = 'SCTP port not bound (N2 listener closed)'
            result.details['transport_state'] = 'refused'
        except OSError as e:
            result.error = str(e)
            result.details['transport_state'] = 'os_error'

        amf_alive = self._monitor.is_amf_alive()
        result.details['amf_alive']  = amf_alive
        result.details['amf_errors'] = self._monitor.recent_errors(10)

        # Classify failure mode for the generic environment
        if not result.is_healthy and not result.error:
            result.error = 'No valid response from AMF'
        if not amf_alive:
            result.details['failure_mode'] = 'crash'   # process dead
        elif not result.is_healthy:
            result.details['failure_mode'] = 'hang'    # process alive, port unresponsive

        return result

    # ── Observation encoding ──────────────────────────────────────────────

    def get_observation_size(self) -> int:
        # 6 semantic fields + 5 response history + 4 counters + step = 16
        # Pad to 20 to match default in ProtocolAdapter base class.
        return 20

    # ── Private helpers ───────────────────────────────────────────────────

    # Hardcoded APER templates for gNB→AMF procedures.
    # Generated via pycrate (pycrate_asn1dir.NGAP) with PLMN=999/70.
    # PLMN bytes 99f907 are patched at runtime by build_message().
    _BUILTIN_TEMPLATES = {
        # InitialUEMessage (proc=15): RAN-UE-NGAP-ID=1, minimal Registration Request NAS,
        #   NR-CGI PLMN=999/70 TAC=1, RRC cause=mo-Signalling
        15: bytes.fromhex(
            '000f403800000400550002000100260013127e004179000b0199f907000000000000000000'
            '79000f4099f907000000001099f907000001005a400118'
        ),
        # UplinkNASTransport (proc=46): AMF-UE-NGAP-ID=1, RAN-UE-NGAP-ID=1,
        #   NAS = Registration Request (0x41), NR-CGI PLMN=999/70 TAC=1
        #   Note: was 0x67 (Security Mode Reject) which caused AMF to log
        #   "Invalid 5GMM message type [103]" when proc_code was fuzzed to 15.
        46: bytes.fromhex(
            '002e402c000004000a0002000100550002000100260006057e004101000079400f40'
            '99f907000000001099f907000001'
        ),
        # UEContextReleaseRequest (proc=42): AMF-UE-NGAP-ID=1, RAN-UE-NGAP-ID=1,
        #   Cause=radioNetwork:unspecified
        42: bytes.fromhex('002a4015000003000a00020001005500020001000f40020000'),

        # PDUSessionResourceSetupResponse (proc=29, successfulOutcome=0x20):
        #
        # Template A: minimal — only AMF-UE-NGAP-ID + RAN-UE-NGAP-ID, no session list.
        # Sending this without a pending PDUSessionResourceSetup request exercises
        # AMF's unsolicited-response guard at ngap-handler.c (lookup of pending context).
        #
        # Template B: malformed QoS — adds PDUSessionResourceSetupListSURes IE (id=75)
        # with PDU session ID=1 but a truncated transfer body that contains
        # qosFlowIdentifier but is missing upTNLInformation. This is the exact
        # condition that crashes SMF at n4-build.c:337 (open5gs issue #4413):
        #   "smf_n4_build_pdr_to_modify_list: Assertion [...] failed"
        # The two templates are selected by build_message() based on the payload seed.
        29: bytes.fromhex('201d400f000002000a00020001005500020001'),          # Template A (minimal)
        # Template B is accessed via _PROC29_MALFORMED below
    }

    # PDUSessionResourceSetupResponse with malformed QoS transfer (issue #4413).
    # Contains PDUSessionResourceSetupListSURes IE (id=75, crit=ignore) with
    # PDU-session-ID=1 and a 3-byte stub transfer that lacks upTNLInformation.
    _PROC29_MALFORMED = bytes.fromhex(
        '201d4017'                  # successfulOutcome, proc=29, crit, len=23
        '000003'                    # 3 IEs
        '000a00020001'              # AMF-UE-NGAP-ID=1
        '005500020001'              # RAN-UE-NGAP-ID=1
        '004b400401000000'          # PDUSessionResourceSetupListSURes: id=75, crit=ignore,
                                    #   len=4, value=PDU-session-ID=1 + 3-byte truncated transfer
                                    #   (no upTNLInformation → SMF assertion at n4-build.c:337)
    )

    # Original PLMN in the builtin templates (MCC=999 MNC=70)
    _TEMPLATE_PLMN = bytes.fromhex('99f907')

    def _ensure_templates(self):
        """Load APER templates: use hardcoded pycrate-generated ones as primary source.

        The 5g-sa.pcap uses non-standard procedure codes (from a pre-3GPP
        implementation) so we cannot extract standard proc=15/42/46 from it.
        Instead, the templates were generated via pycrate against the 3GPP
        TS 38.413 ASN.1 schema and verified against a live open5GS AMF.
        """
        if self._templates_loaded:
            return
        self._templates_loaded = True

        target_plmn = self._plmn  # 3-byte BCD from adapter init

        for proc, tpl in self._BUILTIN_TEMPLATES.items():
            # Patch the PLMN bytes if different from the template's default (999/70)
            if target_plmn != self._TEMPLATE_PLMN:
                tpl = tpl.replace(self._TEMPLATE_PLMN, target_plmn)
            self._templates[proc] = tpl
            logger.debug("Loaded builtin template for proc=%d (%d bytes)", proc, len(tpl))

