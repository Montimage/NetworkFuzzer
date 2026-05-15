#!/usr/bin/env python3
"""
HTTP/2 SBI Protocol Adapter for RL fuzzing of open5GS NFs.

Implements ProtocolAdapter for the 5G Service-Based Interface (3GPP TS 29.500):
- Transport:  HTTP/2 over plain TCP (no TLS — open5GS dev config default)
- Encoding:   JSON bodies (TS 29.510 NRF / 29.518 AMF / 29.502 SMF)
- Targets:    open5GS NRF, AMF, SMF, UDM over their SBI ports

Message building strategy:
  Every build_message() call returns a complete HTTP/2 request:
    [H2_PREFACE] + [SETTINGS frame] + [HEADERS frame] + [DATA frame]
  This mirrors inject_http2.c's approach of bundling preface + payload into
  a single sendall() over a fresh TCP socket (inject_http2_alloc → connect →
  handshake → inject_http2_send_packet).

  For ephemeral connections (default): correct — each RL action opens a new
  TCP socket, so the preface is always valid.
  For persistent connections (--persistent-conn): the server receives a new
  preface on each action, triggering GOAWAY responses — those are scored as
  interesting fuzzing signals by is_interesting_response().

HTTP/2 frame-level fuzzing is available via the stream_id semantic field:
  stream_id=0   → PROTOCOL_ERROR (stream 0 cannot carry requests)
  stream_id=2   → PROTOCOL_ERROR (client streams must be odd)
  stream_id=1   → valid first stream

Usage:
    python -m fuzzer.rl.train_protocol --protocol sbi \\
        --target-host 127.0.0.10 --target-port 7777    \\
        --nf-type NRF --mode hybrid --timesteps 50000 --test

    python -m fuzzer.rl.train_protocol --protocol sbi \\
        --target-host 127.0.0.5 --target-port 7777     \\
        --nf-type AMF --plmn-mcc 001 --plmn-mnc 01    \\
        --mode semantic --timesteps 30000
"""

import json
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
from .http2_client import (
    build_sbi_request,
    build_fuzz_headers_frame,
    build_window_amplification,
    build_header_amplification,
    parse_response as parse_h2_response,
    H2_PREFACE,
    build_settings_frame,
    FRAME_GOAWAY,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    FRAME_WINDOW_UPDATE,
    H2_PROTOCOL_ERROR,
    recv_h2_response,
)
from .templates import (build_body, NF_INSTANCE_FUZZ,
                        get_body_fuzz_variants, apply_body_field_mutation)
from .open5gs_sbi_monitor import Open5GsSbiMonitor  # kept for reference
from fuzzer.rl.monitor import NfMonitor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RFC 7807 ProblemDetails body depth scorer
# ---------------------------------------------------------------------------

# Keywords in error detail strings mapped to code-path depth scores.
# Higher = deeper NRF/SBI validation reached.
_BODY_DEPTH: List[Tuple[float, str]] = [
    # High-value: deep application validation (handler was reached, field was parsed)
    (0.95, 'MandatoryFieldMissing'),
    (0.93, 'MandatoryIeMissing'),
    (0.92, 'InvalidMandatoryParameter'),
    (0.90, 'InvalidFormat'),
    (0.88, 'JsonParseError'),
    (0.85, 'InvalidParam'),
    (0.82, 'UnexpectedQueryParameter'),
    (0.80, 'nfInstanceId'),
    (0.78, 'nfType'),
    (0.75, 'nfStatus'),
    (0.72, 'plmnId'),
    (0.70, 'sNssai'),
    # UDR-specific handler errors (body parsed, handler entered, field validated)
    (0.70, 'No Amf3GppAccessRegistration'),   # PUT context-data, body parsed OK
    (0.68, 'Unknwon SUPI Type'),               # handler reached, SUPI rejected
    (0.65, 'No SUPI'),                         # handler reached, SUPI missing
    (0.65, 'subscriptionId'),
    (0.60, 'UnsupportedMediaType'),
    (0.55, 'MethodNotAllowed'),
    (0.50, 'ResourceNotFound'),
    (0.45, 'Unknown resource name'),           # routing reached, path unknown
    (0.40, 'Invalid resource name'),
    (0.40, 'InvalidProblem'),
    # Low but non-zero: SBI parse failed before handler (body reached server at all)
    (0.10, 'cannot parse HTTP message'),       # ogs_sbi_parse_request failed
]


def _score_problem_detail(body: bytes) -> float:
    """Parse a RFC 7807 ProblemDetails JSON body and return a depth score [0,1].

    Looks at the 'detail', 'title', and 'cause' fields for keywords that
    indicate how deep into NRF/SBI validation the request got.
    Returns 0.0 if the body is not valid JSON or has no recognisable keywords.
    """
    try:
        obj = json.loads(body)
    except Exception:
        return 0.0
    text = ' '.join(str(obj.get(k, ''))
                    for k in ('detail', 'title', 'cause', 'invalidParams'))
    for score, kw in _BODY_DEPTH:
        if kw.lower() in text.lower():
            return score
    return 0.0


# ---------------------------------------------------------------------------
# Semantic mutation value tables
# ---------------------------------------------------------------------------

# 3GPP TS 29.510: valid NF types
NF_TYPE_VALUES = [
    'NRF', 'AMF', 'SMF', 'UDM', 'PCF', 'UDR', 'AUSF',  # valid, common
    'SCP', 'NSSF', 'BSF', 'CHF',                         # valid, less-tested
    '',         # empty — triggers NF type validation error
    'UNKNOWN',  # generic unknown
    'NOPE',     # free5GC #434: panics in oauth2/token handler (missing guard)
    'A' * 64,   # oversized string
    'amf',      # lowercase — case-sensitivity test
    'null',     # JSON null coerced to string
]

# SUPI values (IMSI format: imsi-<15 digits>)
# Extended with SUCI, 5G-GUTI, and null-byte variants from issue analysis:
# #975-979 (free5GC MobileIdentity5GS panics on short SUCI/GUTI)
# #1048 (null-byte injection in supiOrSuci path parameter)
# #4398 (AMF crash on 5G-GUTI UE context transfer)
SUPI_VALUES = [
    'imsi-001010000000001',               # valid default open5GS
    'imsi-208930000000001',               # valid free5GC
    'imsi-001010000000002',               # second valid
    '',                                    # empty — mandatory field missing
    'imsi-000000000000000',               # all zeros — boundary
    'imsi-999999999999999',               # all nines — boundary
    'imsi-0',                             # too short
    'imsi-' + '1' * 30,                  # too long
    'supi:' + 'A' * 20,                  # wrong format prefix
    '\x00\x01\x02',                       # binary garbage
    'imsi-001010000000001\x00injected',   # null injection (#1048)
    'A' * 256,                            # very long non-IMSI
    # SUCI variants — trigger SUCI parser in AMF/AUSF/UDM
    'suci-0-208-93-0-0-0-0000000001',    # valid SUCI
    'suci-0-208-93-0-0-0-',              # SUCI with empty scheme-output (#975-979)
    'suci-0-001-01-0-0-0-0000000001',    # SUCI for open5GS PLMN
    '5g-guti-9990700000000000001',        # 5G-GUTI — triggers #4398 AMF transfer crash
    'imsi-208930000000099\x00',           # null-terminated (#1048 UDM generate-auth-data)
]

# NF instance IDs (UUID format)
# Extended with non-UUID strings from open5GS issue analysis:
# #4469 oversized smfInfo crash via fake-smf-nrf registration
# #4467 oversized amfInfo crash via fake-amf-nrf registration
# #4522 SCP SIGSEGV on mutated NF instance ID header
NF_INSTANCE_ID_VALUES = [
    NF_INSTANCE_FUZZ,                                     # valid test UUID
    '00000000-0000-0000-0000-000000000000',               # all zeros
    'ffffffff-ffff-ffff-ffff-ffffffffffff',               # all f's
    '',                                                    # empty — missing mandatory
    'not-a-uuid',                                          # invalid format
    '11111111-1111-1111-1111',                             # truncated UUID
    'A' * 36,                                              # right length, wrong chars
    '11111111-1111-1111-1111-1111111111111',               # one char too long
    'fake-smf-nrf',                                        # #4469: non-UUID triggers smfInfo overflow
    'fake-amf-nrf',                                        # #4467: non-UUID triggers amfInfo overflow
    'AMF-fuzz-' + 'A' * 8,                               # #4522: SCP crash on mutated instance ID
]

# PDU session IDs (valid range 1–15 per 3GPP TS 29.502)
PDU_SESSION_ID_VALUES = [
    1, 2, 5, 15,        # valid
    0,                  # invalid: 0 is reserved
    16, 255,            # out-of-range (>15)
    -1,                 # negative (triggers integer validation)
    2**31 - 1,          # INT_MAX
]

# S-NSSAI SST values (Slice/Service Type)
SNSSAI_SST_VALUES = [
    1,    # eMBB (most common)
    2,    # URLLC
    3,    # MIoT
    0,    # reserved / invalid
    255,  # boundary / out-of-range
    -1,   # negative
    256,  # overflow
]

# S-NSSAI SD values (hex string, "FFFFFF" = no SD)
SNSSAI_SD_VALUES = [
    '010203',   # valid
    'FFFFFF',   # no SD (3GPP defined)
    '',          # absent SD
    '000000',   # all zeros
    'GGGGGG',   # invalid hex
    '0000000',  # one char too long (7 chars, must be exactly 6)
    'zzzzzz',   # invalid characters
    '0' * 64,   # oversized
]

# HTTP methods (used for frame-level fuzzing)
HTTP_METHOD_VALUES = [
    'POST', 'PUT', 'GET', 'DELETE', 'PATCH',  # valid SBI methods
    'HEAD', 'OPTIONS',                          # valid but unexpected for SBI
    '',                                          # empty method — HPACK error
    'FUZZ', 'HACK',                             # invalid methods
    'A' * 100,                                  # oversized method
]

# Content-Type header values
CONTENT_TYPE_VALUES = [
    'application/json',            # standard SBI
    'application/json; charset=utf-8',
    'multipart/related',           # N1/N2 messages use multipart
    'text/plain',                  # wrong type — should be rejected
    'application/xml',             # wrong type
    '',                             # empty
    'A' * 256,                     # oversized
]

# HTTP/2 stream IDs (for frame-level fuzzing)
STREAM_ID_VALUES = [
    1,          # valid first client stream
    3, 5,       # valid subsequent client streams
    0,          # invalid: stream 0 is reserved for connection-level frames
    2,          # invalid: client-initiated streams must be odd
    0x7fffffff, # max valid stream ID
    0xffffffff, # max value (R bit should be masked)
    -1,         # negative (wraps to large uint)
]

# PLMN MCC values
PLMN_MCC_VALUES = [
    '001',   # valid test PLMN
    '999',   # valid boundary PLMN
    '000',   # invalid (no real network)
    '',       # empty
    '9999',  # too long
    'ABC',   # non-numeric
]

# PLMN MNC values
PLMN_MNC_VALUES = [
    '01',    # valid 2-digit MNC
    '001',   # valid 3-digit MNC
    '70',    # open5GS default sample
    '',       # empty
    '9999',  # too long
    'ZZ',    # non-numeric
]

# Access type values
ACCESS_TYPE_VALUES = [
    '3GPP_ACCESS',      # valid
    'NON_3GPP_ACCESS',  # valid (non-3GPP)
    '',                  # empty — missing mandatory
    'UNKNOWN',          # invalid type
]

# RAT type values
RAT_TYPE_VALUES = [
    'NR',      # 5G NR (most common)
    'EUTRA',   # LTE (4G)
    'NR_U',    # NR Unlicensed
    '',         # empty
    'UNKNOWN', # invalid
]

# Array element counts for fixed-size array overflow testing.
# open5gs uses OGS_MAX_NUM_OF_SLICE=8 and handle_scp_info() fixed 8-slot array;
# sending n > 8 overflows.  RL agent sweeps these to discover the threshold.
# Extended with 64/128 for NRF instance table overflow (#4466/#4524) and
# smfInfo.dnnInfos overflow (#4406/#4469/#4470).
ARRAY_COUNT_VALUES = [1, 2, 4, 7, 8, 9, 10, 12, 16, 32, 64, 128]

# SUPI format variants for path segment fuzzing.
# 'prefix_only' = bare "imsi" without number → triggers #4412 assertion.
SUPI_PATH_VARIANT_VALUES = [
    'valid',            # imsi-001010000000001 — normal
    'prefix_only',      # imsi             — no number suffix (#4412)
    'no_number',        # imsi-             — trailing dash, missing digits
    'wrong_sep',        # imsi:001010000000001 — colon instead of dash
    'numeric_only',     # 001010000000001   — no type prefix
    'empty',            # (empty string)
    'null_byte',        # imsi-001010000000001\x00 — null injection (free5GC #780)
    'url_encoded_null', # imsi-001010000000001%00 — URL-encoded null
    'double_slash',     # //imsi-001010000000001 — path confusion
    'traversal',        # ../imsi-001010000000001 — path traversal
]

# GPSI values — see templates.GPSI_VALUES for rationale
GPSI_VALUES = [
    'msisdn-15550001234',
    'external-id-user@domain.com',
    'msisdn-',
    'ms',
    'm',
    '',
    'msisdn-\x00',
    'msisdn-' + 'A' * 100,
    'msisdn-0',
    'msisdn-15550001234\x00injected',
    '../admin',
    'msisdn-99999999999999999',
]


# ---------------------------------------------------------------------------
# URI path builders
# ---------------------------------------------------------------------------

def _nrf_nf_instance_path(nf_id: str) -> str:
    return f'/nnrf-nfm/v1/nf-instances/{nf_id}'


def _nrf_status_notify_path() -> str:
    return '/nnrf-nfm/v1/nf-status-notify'


def _amf_ue_ctx_transfer_path(ue_id: str) -> str:
    return f'/namf-comm/v1/ue-contexts/{ue_id}/transfer'


def _amf_ue_ctx_transfer_update_path(ue_id: str) -> str:
    return f'/namf-comm/v1/ue-contexts/{ue_id}/transfer-update'


def _amf_comm_sub_path(sub_id: str = '') -> str:
    base = '/namf-comm/v1/subscriptions'
    return f'{base}/{sub_id}' if sub_id else base


def _amf_callback_sdm_notify_path(ctx_id: str = 'fuzz-ctx') -> str:
    return f'/namf-callback/v1/{ctx_id}/sdmsubscription-notify'


def _amf_callback_n1_notify_path() -> str:
    return '/namf-callback/v1/n1-message-notify'


def _ausf_auth_path() -> str:
    return '/nausf-auth/v1/ue-authentications'


def _ausf_eap_path(supi: str) -> str:
    return f'/nausf-auth/v1/ue-authentications/{supi}/eap-session'


def _udm_auth_data_path(supi: str) -> str:
    return f'/nudm-ueau/v1/{supi}/security-information/generate-auth-data'


def _udm_uecm_amf_path(supi: str) -> str:
    return f'/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access'


def _smf_policy_notify_path(ctx_id: str = '1') -> str:
    return f'/nsmf-callback/v1/sm-policy-notify/{ctx_id}/update'


def _nrf_disc_path(target_nf: str, requester_nf: str = 'AMF') -> str:
    return f'/nnrf-disc/v1/nf-instances?target-nf-type={target_nf}&requester-nf-type={requester_nf}'


def _nrf_disc_gpsi_path(target_nf: str, gpsi: str, requester_nf: str = 'AMF') -> str:
    return (f'/nnrf-disc/v1/nf-instances'
            f'?target-nf-type={target_nf}&requester-nf-type={requester_nf}'
            f'&gpsi={gpsi}')


def _nrf_disc_snssai_path(target_nf: str, snssai: str = '',
                          requester_nf: str = 'AMF') -> str:
    # Empty snssai string triggers free5GC #758 nil access in Discovery handler
    return (f'/nnrf-disc/v1/nf-instances'
            f'?target-nf-type={target_nf}&requester-nf-type={requester_nf}'
            f'&snssai={snssai}')


def _nrf_oauth2_path() -> str:
    return '/nnrf-nfm/v1/oauth2/token'


def _udm_sdm_shared_data_path() -> str:
    # free5GC #762: GET without supported-features → HandleGetSharedData panic
    return '/nudm-sdm/v2/shared-data'


def _amf_evts_sub_ref_path(sub_id: str) -> str:
    return f'/namf-evts/v1/subscriptions/{sub_id}'


def _nrf_sub_path(sub_id: str = '') -> str:
    return f'/nnrf-nfm/v1/subscriptions/{sub_id}'


def _amf_ue_ctx_path(ue_id: str) -> str:
    return f'/namf-comm/v1/ue-contexts/{ue_id}'


def _amf_n1n2_path(ue_id: str) -> str:
    return f'/namf-comm/v1/ue-contexts/{ue_id}/n1-n2-messages'


def _amf_evts_path() -> str:
    return '/namf-evts/v1/subscriptions'


def _smf_sm_ctx_path(ref: str = '') -> str:
    return f'/nsmf-pdusession/v1/sm-contexts/{ref}'


def _smf_sm_ctx_modify_path(ref: str) -> str:
    return f'/nsmf-pdusession/v1/sm-contexts/{ref}/modify'


def _smf_sm_ctx_release_path(ref: str) -> str:
    return f'/nsmf-pdusession/v1/sm-contexts/{ref}/release'


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

@register_protocol("sbi")
class SbiAdapter(ProtocolAdapter):
    """
    HTTP/2 SBI protocol adapter.

    Targets the 5G Service-Based Interface of open5GS NFs over plain TCP.
    Reuses inject_http2.c's TCP-with-preface approach for raw frame injection.
    """

    def __init__(self,
                 nf_type:       str = 'NRF',
                 plmn_mcc:      str = '001',
                 plmn_mnc:      str = '01',
                 nf_log:        str = '',
                 extra_nfs:     Optional[List[str]] = None,
                 core:          str = 'open5gs',
                 bin_dir:       Optional[str] = None,
                 gcov_gcda_dir: Optional[str] = None,
                 gcov_src_dir:  Optional[str] = None):
        """
        nf_type:       Target NF type ('NRF', 'AMF', 'SMF', 'UDM', 'PCF')
        plmn_mcc:      PLMN Mobile Country Code
        plmn_mnc:      PLMN Mobile Network Code
        nf_log:        Override log file path for the monitor
        extra_nfs:     Additional NFs to monitor for crashes (e.g. ['SMF', 'AMF'])
        core:          5G core implementation: 'open5gs' or 'free5gc'
        bin_dir:       free5GC bin/ directory for precise process matching
        gcov_gcda_dir: BUILD_DIR/src — where .gcda files are written (open5GS --gcov build)
        gcov_src_dir:  open5GS source root — passed as --root to gcovr
        """
        self._nf_type    = nf_type.upper()
        self._plmn_mcc   = plmn_mcc
        self._plmn_mnc   = plmn_mnc
        self._core       = core
        self._monitor    = NfMonitor(
            core=core,
            primary_nf=self._nf_type,
            extra_nfs=extra_nfs or [],
            log_path=nf_log or None,
            protocol='sbi',
            bin_dir=bin_dir,
            gcov_gcda_dir=gcov_gcda_dir,
            gcov_src_dir=gcov_src_dir,
        )
        # Source subdirectory filter for lcov (only scan the target NF's code)
        self._gcov_nf_filter = f'src/{self._nf_type.lower()}' if gcov_gcda_dir else None
        # Zero stale .gcda files from previous campaigns so reward signal is clean
        if self._gcov_nf_filter:
            ok = self._monitor.gcov_campaign_reset()
            logger.info("gcov campaign reset: %s", "ok" if ok else "lcov --zerocounters failed (non-fatal)")
        # Persistent-connection state: tracks HTTP/2 stream ID across actions
        self._stream_id: int = 1
        # Per-episode response type set for novelty bonus in compute_reward()
        self._episode_resp_types: set = set()

    def reset_episode(self) -> None:
        """Reset per-episode state at each RL episode boundary."""
        self._episode_resp_types.clear()
        self._monitor.reset_episode()

    # ── ProtocolAdapter identity ──────────────────────────────────────────

    @property
    def protocol_name(self) -> str:
        return "sbi"

    @property
    def default_port(self) -> int:
        # open5GS uses 7777; free5GC uses 8000
        return 8000 if self._core == 'free5gc' else 7777

    # ── Connection params ─────────────────────────────────────────────────

    def get_connection_params(self) -> Dict[str, Any]:
        # Plain TCP — HTTP/2 framing is handled in build_message()
        return {'socket_type': 'tcp'}

    def recv_data(self, sock: Any, timeout: float, buf_size: int = 4096) -> bytes:
        return recv_h2_response(sock, timeout=timeout, buf_size=max(buf_size, 8192))

    # ── Field definitions ─────────────────────────────────────────────────

    def get_semantic_fields(self) -> List[FieldDefinition]:
        return [
            FieldDefinition(
                name='nf_type',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['NRF', 'AMF', 'SMF', 'UDM'],
                boundary_values=['', 'UNKNOWN', 'A' * 64],
                description='NF type string in NF Profile and discovery queries',
            ),
            FieldDefinition(
                name='supi',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['imsi-001010000000001', 'imsi-001010000000002'],
                boundary_values=['', 'imsi-000000000000000', 'imsi-' + '9' * 15],
                description='Subscriber Permanent Identifier (IMSI format)',
            ),
            FieldDefinition(
                name='nf_instance_id',
                offset=None,
                size=None,
                encoding='string',
                valid_values=[NF_INSTANCE_FUZZ],
                boundary_values=['', '00000000-0000-0000-0000-000000000000',
                                  'not-a-uuid'],
                description='NF Instance ID (UUID format, RFC 4122)',
            ),
            FieldDefinition(
                name='pdu_session_id',
                offset=None,
                size=4,
                encoding='int',
                valid_values=[1, 2, 5, 15],
                boundary_values=[0, 16, 255],
                description='PDU Session ID (valid range 1-15 per TS 29.502)',
            ),
            FieldDefinition(
                name='snssai_sst',
                offset=None,
                size=1,
                encoding='uint8',
                valid_values=[1, 2, 3],
                boundary_values=[0, 255],
                description='S-NSSAI Slice/Service Type',
            ),
            FieldDefinition(
                name='snssai_sd',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['010203', 'FFFFFF'],
                boundary_values=['', '000000', 'GGGGGG'],
                description='S-NSSAI Slice Differentiator (6-char hex)',
            ),
            FieldDefinition(
                name='plmn_mcc',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['001', '999'],
                boundary_values=['', '000', '9999'],
                description='PLMN Mobile Country Code',
            ),
            FieldDefinition(
                name='plmn_mnc',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['01', '001', '70'],
                boundary_values=['', '0', '9999'],
                description='PLMN Mobile Network Code',
            ),
            FieldDefinition(
                name='http_method',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['POST', 'PUT', 'GET', 'DELETE', 'PATCH'],
                boundary_values=['', 'FUZZ', 'A' * 100],
                description='HTTP method in :method pseudo-header',
            ),
            FieldDefinition(
                name='content_type',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['application/json'],
                boundary_values=['', 'text/plain', 'application/xml'],
                description='Content-Type header for request body',
            ),
            FieldDefinition(
                name='stream_id',
                offset=None,
                size=4,
                encoding='uint32',
                valid_values=[1, 3, 5],
                boundary_values=[0, 2, 0x7fffffff],
                description='HTTP/2 stream ID (0 and even values are invalid from client)',
            ),
            FieldDefinition(
                name='access_type',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['3GPP_ACCESS', 'NON_3GPP_ACCESS'],
                boundary_values=['', 'UNKNOWN'],
                description='Access type in SM Context and UE Context (TS 29.571)',
            ),
            FieldDefinition(
                name='rat_type',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['NR', 'EUTRA'],
                boundary_values=['', 'UNKNOWN', 'NR_U'],
                description='RAT type in SM Context creation (TS 29.571)',
            ),
            FieldDefinition(
                name='dnn',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['internet', 'ims'],
                boundary_values=['', 'A' * 100, '\x00\x01\x02'],
                description='Data Network Name in SM Context (3GPP APN format)',
            ),
            FieldDefinition(
                name='nf_status',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['REGISTERED', 'UNDISCOVERABLE'],
                boundary_values=['', 'DEREGISTERED', 'UNKNOWN_STATUS'],
                description='NF status in NF Profile (TS 29.510 §6.1.6.2.1)',
            ),
            FieldDefinition(
                name='array_count',
                offset=None,
                size=None,
                encoding='int',
                valid_values=[1, 2, 4, 7, 8],
                boundary_values=[0, 9, 10, 16, 32],
                description='Number of elements in array fields (scpDomainInfoList, '
                            'defaultSingleNssais, plmnList). Values > 8 overflow fixed '
                            'open5gs arrays — RL agent learns to increase this to crash.',
            ),
            FieldDefinition(
                name='supi_path_variant',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['valid'],
                boundary_values=['prefix_only', 'no_number', 'wrong_sep',
                                 'numeric_only', 'empty'],
                description='SUPI format variant injected into URL path segments. '
                            '"prefix_only" (bare "imsi") triggers #4412 UDR assertion. '
                            '"null_byte" probes free5GC #780 null-byte injection.',
            ),
            FieldDefinition(
                name='gpsi',
                offset=None,
                size=None,
                encoding='string',
                valid_values=['msisdn-15550001234', 'external-id-user@domain.com'],
                boundary_values=['ms', 'm', '', 'msisdn-', 'msisdn-\x00'],
                description='General Public Subscription Identifier used in NRF '
                            'discovery query param and AMF UE context gpsis field. '
                            'Short values (2-char) trigger free5GC #757 NRF '
                            'buildFilter slice-bounds panic.',
            ),
        ]

    def get_field_message_type(self, field_name: str) -> Optional[str]:
        """Map each semantic field to the message type that carries it."""
        return {
            'nf_type':           'nrf_nf_register',
            'supi':              'smf_ctx_create',
            'nf_instance_id':    'nrf_nf_register',
            'pdu_session_id':    'smf_ctx_create',
            'snssai_sst':        'smf_ctx_create',
            'snssai_sd':         'smf_ctx_create',
            'plmn_mcc':          'nrf_nf_register',
            'plmn_mnc':          'nrf_nf_register',
            'http_method':       'nrf_nf_discover',
            'content_type':      'nrf_nf_register',
            'stream_id':         'nrf_nf_discover',
            'access_type':       'smf_ctx_create',
            'rat_type':          'smf_ctx_create',
            'dnn':               'smf_ctx_create',
            'nf_status':         'nrf_nf_register',
            'array_count':       'nrf_scp_array_fuzz',
            'supi_path_variant': 'udr_policy_supi_fuzz',
            'gpsi':              'nrf_disc_gpsi',
        }.get(field_name)

    def get_mutation_values(self, field_name: str) -> List[Any]:
        return {
            'nf_type':           NF_TYPE_VALUES,
            'supi':              SUPI_VALUES,
            'nf_instance_id':    NF_INSTANCE_ID_VALUES,
            'pdu_session_id':    PDU_SESSION_ID_VALUES,
            'snssai_sst':        SNSSAI_SST_VALUES,
            'snssai_sd':         SNSSAI_SD_VALUES,
            'plmn_mcc':          PLMN_MCC_VALUES,
            'plmn_mnc':          PLMN_MNC_VALUES,
            'http_method':       HTTP_METHOD_VALUES,
            'content_type':      CONTENT_TYPE_VALUES,
            'stream_id':         STREAM_ID_VALUES,
            'access_type':       ACCESS_TYPE_VALUES,
            'rat_type':          RAT_TYPE_VALUES,
            'dnn':               ['internet', 'ims', '', 'A' * 100, '\x00\x01'],
            'nf_status':         ['REGISTERED', 'UNDISCOVERABLE', 'DEREGISTERED',
                                  '', 'UNKNOWN_STATUS', 'A' * 64],
            'array_count':       ARRAY_COUNT_VALUES,
            'supi_path_variant': SUPI_PATH_VARIANT_VALUES,
            'gpsi':              GPSI_VALUES,
        }.get(field_name, [])

    # ── Message types ─────────────────────────────────────────────────────

    def get_message_types(self) -> List[str]:
        return [
            # NRF (TS 29.510)
            'nrf_nf_register',          # PUT /nnrf-nfm/v1/nf-instances/{id}
            'nrf_nf_discover',          # GET /nnrf-disc/v1/nf-instances?...
            'nrf_nf_subscribe',         # POST /nnrf-nfm/v1/subscriptions
            'nrf_nf_deregister',        # DELETE /nnrf-nfm/v1/nf-instances/{id}
            'nrf_nf_register_malformed',# PUT with missing mandatory fields
            # AMF (TS 29.518)
            'amf_ue_ctx_create',        # PUT /namf-comm/v1/ue-contexts/{ueId}
            'amf_ue_ctx_get',           # GET /namf-comm/v1/ue-contexts/{ueId}
            'amf_n1n2_msg',             # POST /namf-comm/v1/ue-contexts/{ueId}/n1-n2-messages
            'amf_evts_subscribe',       # POST /namf-evts/v1/subscriptions
            'amf_ue_ctx_bad_supi',      # PUT with malformed SUPI
            # SMF (TS 29.502)
            'smf_ctx_create',           # POST /nsmf-pdusession/v1/sm-contexts
            'smf_ctx_modify',           # POST /nsmf-pdusession/v1/sm-contexts/{ref}/modify
            'smf_ctx_release',          # POST /nsmf-pdusession/v1/sm-contexts/{ref}/release
            'smf_ctx_delete',           # DELETE /nsmf-pdusession/v1/sm-contexts/{ref}
            'smf_ctx_create_wrong_plmn',# POST with mismatched PLMN
            # Frame-level attacks
            'h2_window_amplification',  # WINDOW_UPDATE flood
            'h2_header_amplification',  # HEADERS + CONTINUATION amplification
            # v2.7.7 exact-PoC triggers (one request per known bug)
            'nrf_plmn_overflow',         # #4382: GET /nnrf-disc with 13+ PLMNs in query
            'nrf_scp_overflow',          # #4383: PUT /nf-instances with 9 scpDomainInfoList
            'multipart_empty',           # #3942: POST multipart/related + empty body
            'udm_psi_zero',              # #4255: GET /smf-registrations/0
            'udr_prefix_supi',           # #4412: GET with bare "imsi" SUPI in path
            'udr_malformed_pei',         # #4411: PUT with pei="foo"
            'udm_purgeflag',             # #4420: PATCH amf-3gpp-access purgeFlag:true
            'amf_oversized_nssais',      # #4403: PUT ue-contexts with 9 defaultSingleNssais
            'amf_malformed_gpsi',        # #4405: PUT ue-contexts with gpsis:["msisdn"]
            # Generic mutation-driven targets (RL discovers crash threshold)
            'nrf_scp_array_fuzz',        # PUT /nf-instances, scpDomainInfoList count=array_count
            'amf_nssai_array_fuzz',      # PUT ue-contexts, defaultSingleNssais count=array_count
            'udm_smf_reg_psi_fuzz',      # GET /smf-registrations/{pdu_session_id}
            'udr_policy_supi_fuzz',      # GET /policy-data/ues/{supi_variant}/am-data
            'udr_sub_supi_fuzz',         # GET /subscription-data/{supi_variant}/authentication-data
            # ── New crash-confirmed endpoints (from issue analysis) ──────────
            # AMF context transfer — #4397/#4399/#4402 null-deref on empty body
            'amf_ue_ctx_transfer',       # POST /namf-comm/v1/ue-contexts/{id}/transfer
            'amf_ue_ctx_transfer_update',# POST /namf-comm/v1/ue-contexts/{id}/transfer-update
            # AMF subscription sequence — #876/#902 panic on DELETE after PUT
            'amf_comm_sub_create',       # POST /namf-comm/v1/subscriptions
            'amf_comm_sub_delete',       # DELETE /namf-comm/v1/subscriptions/{id}
            # AMF callbacks — #4395 sdm notify nil-deref, #1029 n1-notify nil ranNodeId
            'amf_callback_sdm_notify',   # POST /namf-callback/v1/{ctx}/sdmsubscription-notify
            'amf_callback_n1_notify',    # POST /namf-callback/v1/n1-message-notify
            # AUSF — #1030/#982/#983 decodeEapAkaPrime OOB, #4472/#4523 SIGABRT
            'ausf_auth_create',          # POST /nausf-auth/v1/ue-authentications
            'ausf_eap_session',          # POST /nausf-auth/v1/ue-authentications/{id}/eap-session
            # UDM — #4418/#1037 nil sequenceNumber, #4419/#4420 uecm nil deref
            'udm_auth_data',             # POST /nudm-ueau/v1/{supi}/security-information/generate-auth-data
            'udm_uecm_amf_reg',          # PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access
            # UDM regression/boundary — probe code paths adjacent to patched bugs
            'udm_smf_reg_psi_fuzz',      # GET /smf-registrations/{psi}: sweep 0–255 for OOB beyond psi>15
            # SMF callback — #4442/#4453 policy notify nil deref
            'smf_policy_notify',         # POST /nsmf-callback/v1/sm-policy-notify/{id}/update
            # NRF status notify — #4406 oversized dnnInfos array crash in AMF
            'nrf_status_notify',         # POST /nnrf-nfm/v1/nf-status-notify
            # ── Cross-platform messages (free5GC + open5GS) ─────────────────
            # NRF: discovery with gpsi/snssai params, OAuth2 token endpoint
            'nrf_disc_gpsi',            # GET /nnrf-disc with gpsi query param (free5GC #757)
            'nrf_disc_snssai_fuzz',     # GET /nnrf-disc with empty snssai (free5GC #758)
            'nrf_oauth2_token',         # POST /nnrf-nfm/v1/oauth2/token (free5GC #434)
            # UDM: SDM shared-data, incomplete AMF registration, null-byte path
            'udm_sdm_shared_data',          # GET /nudm-sdm/v2/shared-data (free5GC #762)
            'udm_uecm_amf_reg_incomplete',  # PUT amf-3gpp-access, missing fields (free5GC #761)
            # AMF: event sub modify, restrictedRatList unchecked access
            'amf_evts_sub_modify',          # PATCH /namf-evts/v1/subscriptions/{id} (free5GC #754)
            'amf_ue_ctx_restricted_rat',    # PUT ue-contexts with restrictedRatList (free5GC #756)
        ]

    # ── State transitions ─────────────────────────────────────────────────

    def get_state_transitions(self) -> List[StateTransition]:
        return [
            # Valid flows
            StateTransition(
                'nrf_register_discover',
                ['nrf_nf_register', 'nrf_nf_discover'],
                'NF Registration followed by NF Discovery (normal NF startup)',
                is_valid=True,
            ),
            StateTransition(
                'smf_full_pdu_session',
                ['smf_ctx_create', 'smf_ctx_modify', 'smf_ctx_release'],
                'SM Context create → modify → release (complete PDU session lifecycle)',
                is_valid=True,
            ),

            # Invalid / attack sequences
            StateTransition(
                'discover_before_register',
                ['nrf_nf_discover'],
                'NF Discovery before any registration (empty NRF database)',
                is_valid=False,
            ),
            StateTransition(
                'double_register_same_id',
                ['nrf_nf_register', 'nrf_nf_register'],
                'Duplicate PUT /nf-instances/{id} with same nfInstanceId (idempotency test)',
                is_valid=False,
            ),
            StateTransition(
                'deregister_before_register',
                ['nrf_nf_deregister'],
                'DELETE /nf-instances/{id} before any registration',
                is_valid=False,
            ),
            StateTransition(
                'flood_subscriptions',
                ['nrf_nf_subscribe', 'nrf_nf_subscribe', 'nrf_nf_subscribe',
                 'nrf_nf_subscribe', 'nrf_nf_subscribe'],
                'POST /subscriptions × 5 without DELETE (subscription table overflow)',
                is_valid=False,
            ),
            StateTransition(
                'n1n2_before_ue_ctx',
                ['amf_n1n2_msg'],
                'N1N2MessageTransfer before UE Context exists (context-not-found error path)',
                is_valid=False,
            ),
            StateTransition(
                'smf_ctx_wrong_plmn',
                ['smf_ctx_create_wrong_plmn'],
                'SM Context create with PLMN not configured in open5GS',
                is_valid=False,
            ),
            StateTransition(
                'amf_bad_supi',
                ['amf_ue_ctx_bad_supi'],
                'UE Context create with malformed SUPI (format validation / IMSI parse error)',
                is_valid=False,
            ),
            StateTransition(
                'double_sm_create',
                ['smf_ctx_create', 'smf_ctx_create'],
                'POST /sm-contexts twice with same PDU session ID (duplicate context)',
                is_valid=False,
            ),
            StateTransition(
                'release_nonexistent_sm',
                ['smf_ctx_release'],
                'SM Context release for a context that was never created (ref not found)',
                is_valid=False,
            ),
            StateTransition(
                'malformed_then_valid',
                ['nrf_nf_register_malformed', 'nrf_nf_register'],
                'Malformed NF Profile followed by valid registration (state recovery test)',
                is_valid=False,
            ),
            StateTransition(
                'h2_frame_attack',
                ['h2_window_amplification', 'nrf_nf_register'],
                'WINDOW_UPDATE flood then NF registration (HTTP/2 flow-control stress)',
                is_valid=False,
            ),
            StateTransition(
                'h2_header_bomb',
                ['h2_header_amplification'],
                'HEADERS + CONTINUATION amplification (HTTP2_HEADER_AMPLIFICATION from http2.h)',
                is_valid=False,
            ),
        ]

    # ── Baseline fields for scenario setup messages ───────────────────────

    def get_priority_payload_types(self) -> list:
        """JSON-focused payload types for SBI/HTTP2 fuzzing."""
        return ["json_injection", "json_oversized", "special_chars"]

    def get_baseline_fields(self) -> Dict[str, Any]:
        """Valid field values used for setup_messages in FuzzScenario.

        These are applied verbatim so setup steps succeed and establish the
        required server state before the fuzz_message is executed.
        """
        return {
            'nf_instance_id': NF_INSTANCE_FUZZ,
            'nf_type':        'AMF',
            'nf_status':      'REGISTERED',
            'plmn_mcc':       self._plmn_mcc,
            'plmn_mnc':       self._plmn_mnc,
            'snssai_sst':     1,
            'snssai_sd':      '010203',
            'supi':           'imsi-001010000000001',
            'pdu_session_id': 1,
            'dnn':            'internet',
            'access_type':    '3GPP_ACCESS',
            'rat_type':       'NR',
        }

    # ── Generic body leaf-field mutation actions ──────────────────────────

    # Templates to include in body_fuzz action space, keyed by target NF type.
    # Only include templates whose API is served by that NF — cross-NF templates
    # all return "Invalid API name" 400 which is indistinguishable noise.
    _BODY_FUZZ_TEMPLATES_BY_NF: Dict[str, List[str]] = {
        'NRF':  ['nrf_nf_register', 'nrf_nf_subscribe', 'nrf_status_notify',
                 'nrf_oauth2_token'],
        'AMF':  ['amf_ue_ctx_create', 'amf_n1n2_msg',
                 'amf_ue_ctx_transfer', 'amf_comm_sub_create',
                 'amf_callback_sdm_notify', 'amf_evts_sub_modify',
                 'amf_ue_ctx_restricted_rat'],
        'SMF':  ['smf_ctx_create', 'smf_policy_notify'],
        'UDM':  ['amf_ue_ctx_create', 'udm_auth_data', 'udm_uecm_amf_reg',
                 'udm_uecm_amf_reg_incomplete'],
        'UDR':  ['udr_malformed_pei'],
        'PCF':  ['smf_ctx_create'],
        'AUSF': ['ausf_auth_create', 'ausf_eap_session'],
    }

    def get_body_fuzz_actions(
            self, baseline_fields: Dict[str, Any]
    ) -> List[tuple]:
        """Return (template, field_path, mutation_label, mutation_idx) tuples.

        Called once at env startup to register body_fuzz actions in the action
        space.  For each template × leaf field × mutation variant we register
        one discrete action.  The RL agent learns which (template, field,
        mutation) combinations cause interesting server behaviour.
        """
        actions = []
        templates = self._BODY_FUZZ_TEMPLATES_BY_NF.get(self._nf_type, [])
        for tmpl in templates:
            for field_path, label, _body_bytes in get_body_fuzz_variants(
                    tmpl, baseline_fields):
                # mutation_idx is just the ordinal within the mutation list —
                # apply_body_field_mutation uses modular indexing so the index
                # stays stable even if we add mutations later.
                idx = len([a for a in actions
                           if a[0] == tmpl and a[1] == field_path])
                actions.append((tmpl, field_path, label, idx))
        return actions

    # ── Predefined fuzzing scenarios ──────────────────────────────────────

    def get_scenarios(self) -> List[FuzzScenario]:
        """Per-API fuzzing scenarios with explicit setup + fuzz target.

        Each scenario:
          setup_messages  — sent with get_baseline_fields() so they succeed
          fuzz_message    — the API call under test; mutations applied here
          relevant_fields — which semantic fields to cycle through for this API
        """
        _nfm = 'NRF_NFM'    # NRF NF Management  (TS 29.510 §6.1)
        _disc = 'NRF_DISC'  # NRF Discovery       (TS 29.510 §6.2)
        _amf  = 'AMF_UE'    # AMF UE Context      (TS 29.518 §6.3)
        _smf  = 'SMF_SM'    # SMF SM Context      (TS 29.502 §5.2)

        return [
            # ── NRF NF Management ─────────────────────────────────────────
            FuzzScenario(
                name='nrf_fuzz_register_body',
                target_api=_nfm,
                setup_messages=[],
                fuzz_message='nrf_nf_register',
                description='PUT /nf-instances/{id} — fuzz NF profile body fields '
                            '(nfType, nfStatus, plmnList, sNssais, nfServices)',
                relevant_fields=['nf_type', 'nf_status', 'plmn_mcc', 'plmn_mnc',
                                  'snssai_sst', 'snssai_sd', 'nf_instance_id'],
            ),
            FuzzScenario(
                name='nrf_fuzz_register_malformed',
                target_api=_nfm,
                setup_messages=[],
                fuzz_message='nrf_nf_register_malformed',
                description='PUT /nf-instances/{id} — missing mandatory fields '
                            '(nfType/nfStatus absent → MandatoryFieldMissing)',
                relevant_fields=['nf_instance_id'],
            ),
            FuzzScenario(
                name='nrf_fuzz_update_after_register',
                target_api=_nfm,
                setup_messages=['nrf_nf_register'],
                fuzz_message='nrf_nf_register',
                description='Register valid NF, then PUT again with fuzz nfStatus/PLMN '
                            '(update path: NRF checks existing instance, runs merge logic)',
                relevant_fields=['nf_status', 'plmn_mcc', 'plmn_mnc',
                                  'snssai_sst', 'snssai_sd'],
            ),
            FuzzScenario(
                name='nrf_fuzz_deregister_after_register',
                target_api=_nfm,
                setup_messages=['nrf_nf_register'],
                fuzz_message='nrf_nf_deregister',
                description='Register valid NF, then DELETE /nf-instances/{id} — '
                            'fuzz nf_instance_id path (valid, missing, malformed UUID)',
                relevant_fields=['nf_instance_id'],
            ),
            FuzzScenario(
                name='nrf_fuzz_deregister_unregistered',
                target_api=_nfm,
                setup_messages=[],
                fuzz_message='nrf_nf_deregister',
                description='DELETE /nf-instances/{id} with no prior registration — '
                            'exercises not-found / 404 handler in nrf-context.c',
                relevant_fields=['nf_instance_id'],
            ),
            FuzzScenario(
                name='nrf_fuzz_subscribe_after_register',
                target_api=_nfm,
                setup_messages=['nrf_nf_register'],
                fuzz_message='nrf_nf_subscribe',
                description='Register NF, then POST /subscriptions with fuzz body — '
                            'nf_instance_id, subscriptionId, reqNfType fields',
                relevant_fields=['nf_instance_id', 'nf_type'],
            ),
            FuzzScenario(
                name='nrf_fuzz_subscribe_flood',
                target_api=_nfm,
                setup_messages=['nrf_nf_register'] + ['nrf_nf_subscribe'] * 10,
                fuzz_message='nrf_nf_subscribe',
                description='Register NF, flood 10 subscriptions, then fuzz an 11th — '
                            'pushes subscription table to its true capacity limit; '
                            'tests memory pressure and table-full error handling',
                relevant_fields=['nf_instance_id', 'nf_type'],
            ),
            FuzzScenario(
                name='nrf_fuzz_deregister_reregister',
                target_api=_nfm,
                setup_messages=['nrf_nf_register', 'nrf_nf_deregister'],
                fuzz_message='nrf_nf_register',
                description='Register NF, deregister it, then register again — '
                            'tests state cleanup after DELETE: freed/stale context '
                            'bugs in nrf-context.c re-use path',
                relevant_fields=['nf_instance_id', 'nf_type', 'nf_status'],
            ),
            FuzzScenario(
                name='nrf_fuzz_type_mismatch',
                target_api=_nfm,
                setup_messages=[],
                fuzz_message='nrf_nf_register_type_mismatch',
                description='PUT /nf-instances with nfType=AMF but smfInfo + SMF '
                            'service names — cross-field inconsistency that passes '
                            'JSON schema validation but may reach NF-type-specific '
                            'merge logic in nrf-context.c with mismatched pointers',
                relevant_fields=['nf_instance_id'],
            ),

            # ── NRF Discovery ─────────────────────────────────────────────
            FuzzScenario(
                name='nrf_fuzz_discover_empty_db',
                target_api=_disc,
                setup_messages=[],
                fuzz_message='nrf_nf_discover',
                description='GET /nf-instances?target-nf-type=X with empty NRF DB — '
                            'fuzz nf_type query param and HTTP method',
                relevant_fields=['nf_type', 'http_method'],
            ),
            FuzzScenario(
                name='nrf_fuzz_discover_after_register',
                target_api=_disc,
                setup_messages=['nrf_nf_register'],
                fuzz_message='nrf_nf_discover',
                description='Register NF first, then GET discovery — NRF runs DB lookup '
                            'and filter logic; fuzz nf_type, plmn, snssai query params',
                relevant_fields=['nf_type', 'plmn_mcc', 'plmn_mnc',
                                  'snssai_sst', 'http_method'],
            ),
            FuzzScenario(
                name='nrf_fuzz_discover_multi_registered',
                target_api=_disc,
                setup_messages=['nrf_nf_register', 'nrf_nf_register'],
                fuzz_message='nrf_nf_discover',
                description='Register same NF twice (PUT idempotent), then fuzz discovery — '
                            'exercises result pagination / limit logic',
                relevant_fields=['nf_type', 'snssai_sst'],
            ),

            # ── AMF UE Context ────────────────────────────────────────────
            FuzzScenario(
                name='amf_fuzz_ue_ctx_create_supi',
                target_api=_amf,
                setup_messages=[],
                fuzz_message='amf_ue_ctx_create',
                description='PUT /ue-contexts/{id} — fuzz SUPI (format validation, '
                            'empty, overflow, non-IMSI format)',
                relevant_fields=['supi', 'snssai_sst', 'plmn_mcc', 'plmn_mnc'],
            ),
            FuzzScenario(
                name='amf_fuzz_ue_ctx_bad_supi',
                target_api=_amf,
                setup_messages=[],
                fuzz_message='amf_ue_ctx_bad_supi',
                description='PUT /ue-contexts/{id} with malformed SUPI values — '
                            'exercises SUPI parser and IMSI format validation',
                relevant_fields=['supi'],
            ),
            FuzzScenario(
                name='amf_fuzz_n1n2_after_ctx',
                target_api=_amf,
                setup_messages=['amf_ue_ctx_create'],
                fuzz_message='amf_n1n2_msg',
                description='Create UE context, then POST N1N2MessageTransfer — '
                            'fuzz pduSessionId, sNssai to reach N2/NAS handler',
                relevant_fields=['pdu_session_id', 'snssai_sst', 'supi'],
            ),
            FuzzScenario(
                name='amf_fuzz_n1n2_no_ctx',
                target_api=_amf,
                setup_messages=[],
                fuzz_message='amf_n1n2_msg',
                description='POST N1N2MessageTransfer without UE context — '
                            'exercises context-not-found path in amf-handler.c',
                relevant_fields=['pdu_session_id', 'supi'],
            ),
            FuzzScenario(
                name='amf_fuzz_event_subscribe_after_ctx',
                target_api=_amf,
                setup_messages=['amf_ue_ctx_create'],
                fuzz_message='amf_evts_subscribe',
                description='Create UE context, then POST event subscription — '
                            'fuzz nf_instance_id and eventList content',
                relevant_fields=['nf_instance_id', 'nf_type'],
            ),

            # ── SMF SM Context ────────────────────────────────────────────
            FuzzScenario(
                name='smf_fuzz_ctx_create_fields',
                target_api=_smf,
                setup_messages=[],
                fuzz_message='smf_ctx_create',
                description='POST /sm-contexts — fuzz supi, dnn, sNssai, ratType, '
                            'accessType; exercises full SMF request validation',
                relevant_fields=['supi', 'dnn', 'snssai_sst', 'snssai_sd',
                                  'rat_type', 'access_type', 'plmn_mcc', 'plmn_mnc'],
            ),
            FuzzScenario(
                name='smf_fuzz_ctx_create_wrong_plmn',
                target_api=_smf,
                setup_messages=[],
                fuzz_message='smf_ctx_create_wrong_plmn',
                description='POST /sm-contexts with mismatched PLMN — '
                            'exercises PLMN validation and serving-network check',
                relevant_fields=['plmn_mcc', 'plmn_mnc'],
            ),
            FuzzScenario(
                name='smf_fuzz_ctx_modify_after_create',
                target_api=_smf,
                setup_messages=['smf_ctx_create'],
                fuzz_message='smf_ctx_modify',
                description='Create SM context (valid), then POST modify — '
                            'fuzz pduSessionId, cause, hoState to reach session handler',
                relevant_fields=['pdu_session_id', 'supi'],
            ),
            FuzzScenario(
                name='smf_fuzz_ctx_release_after_create',
                target_api=_smf,
                setup_messages=['smf_ctx_create'],
                fuzz_message='smf_ctx_release',
                description='Create SM context (valid), then POST release — '
                            'fuzz pduSessionId and release cause codes',
                relevant_fields=['pdu_session_id'],
            ),
            FuzzScenario(
                name='smf_fuzz_ctx_double_create',
                target_api=_smf,
                setup_messages=['smf_ctx_create'],
                fuzz_message='smf_ctx_create',
                description='POST /sm-contexts twice with same PDU session — '
                            'exercises duplicate-context detection and error path',
                relevant_fields=['pdu_session_id', 'dnn', 'snssai_sst'],
            ),
            FuzzScenario(
                name='smf_fuzz_issue4408_wrong_n2type',
                target_api=_smf,
                setup_messages=['smf_ctx_create'],
                fuzz_message='smf_ctx_modify_wrong_state',
                description='Reproduce open5GS #4408: POST /modify with '
                            'n2SmInfoType=PDU_RES_SETUP_REQ (valid for setup, invalid '
                            'for modify state) → assert in nsmf-handler.c:364',
                relevant_fields=['pdu_session_id'],
            ),

            # ── v2.7.7 exact-PoC scenarios ────────────────────────────────
            FuzzScenario(
                name='poc_4382_plmn_overflow',
                target_api=_disc,
                setup_messages=[],
                fuzz_message='nrf_plmn_overflow',
                description='#4382: GET /nnrf-disc with 13 PLMN entries in '
                            'requester-plmn-list → heap buffer overflow in '
                            'ogs_sbi_parse_plmn_list() (fixed 12-element array)',
                relevant_fields=[],
            ),
            FuzzScenario(
                name='poc_4383_scp_overflow',
                target_api=_nfm,
                setup_messages=[],
                fuzz_message='nrf_scp_overflow',
                description='#4383: PUT /nf-instances with 9 scpDomainInfoList entries '
                            '→ stack buffer overflow in handle_scp_info() (fixed 8-slot array)',
                relevant_fields=['nf_instance_id'],
            ),
            FuzzScenario(
                name='poc_3942_multipart_empty',
                target_api=_nfm,
                setup_messages=[],
                fuzz_message='multipart_empty',
                description='#3942: POST with Content-Type: multipart/related and empty '
                            'body → NULL deref in parse_multipart() at sbi/message.c:2825',
                relevant_fields=[],
            ),
            FuzzScenario(
                name='poc_4255_udm_psi_zero',
                target_api='UDM_UCM',
                setup_messages=[],
                fuzz_message='udm_psi_zero',
                description='#4255: GET /nudm-uecm/v1/{supi}/registrations/smf-registrations/0 '
                            '→ psi=0 (OGS_NAS_PDU_SESSION_IDENTITY_UNASSIGNED). '
                            'Patched in v2.7.7 (returns 400); kept to probe session-state '
                            'machine edge cases and detect regressions.',
                relevant_fields=['supi'],
            ),
            FuzzScenario(
                name='poc_4412_udr_prefix_supi',
                target_api='UDR_DR',
                setup_messages=[],
                fuzz_message='udr_prefix_supi',
                description='#4412: GET /nudr-dr/v1/policy-data/ues/imsi/am-data '
                            '(bare "imsi" SUPI) → assertion at subscription.c:333',
                relevant_fields=[],
            ),
            FuzzScenario(
                name='poc_4411_udr_malformed_pei',
                target_api='UDR_DR',
                setup_messages=[],
                fuzz_message='udr_malformed_pei',
                description='#4411: PUT subscription context-data with pei="foo" '
                            '(no type separator) → ogs_id_get_value() returns NULL → assert. '
                            'SUPI must be a valid imsi- prefix or the SUPI-type guard returns '
                            '403 before reaching the pei parsing code.',
                relevant_fields=[],
            ),
            FuzzScenario(
                name='poc_4411_udr_bad_pei_type',
                target_api='UDR_DR',
                setup_messages=[],
                fuzz_message='udr_malformed_pei_bad_type',
                description='#4411 variant: PUT context-data/amf-3gpp-access with '
                            'pei="unknown-1234567890123456" — valid format but unknown '
                            'type. ogs_id_get_type()="unknown", strcmp("unknown","imeisv") '
                            'fails → ogs_fatal + ogs_assert_if_reached() at nudr-handler.c:315. '
                            'Different crash path from pei="foo" (NULL value vs unknown type). '
                            'SUPI locked: non-IMSI SUPIs are rejected by the type guard at line 272.',
                relevant_fields=[],
            ),
            FuzzScenario(
                name='udr_prefix_sub_provisioned',
                target_api='UDR_DR',
                setup_messages=[],
                fuzz_message='udr_prefix_supi_sub',
                description='#4412 via subscription-data path: GET '
                            '/nudr-dr/v1/subscription-data/imsi/00101/provisioned-data '
                            '— bare "imsi" SUPI routes to handle_subscription_provisioned '
                            'which calls ogs_dbi_subscription_data() with ogs_assert(supi_id). '
                            'Different URL from poc_4412 (policy-data) but same DBI crash.',
                relevant_fields=[],
            ),
            FuzzScenario(
                name='udr_fuzz_sub_provisioned_supi',
                target_api='UDR_DR',
                setup_messages=[],
                fuzz_message='udr_sub_provisioned_fuzz',
                description='GET /subscription-data/{supi}/00101/provisioned-data with '
                            'supi_path_variant mutation. Unlike authentication-data '
                            '(ogs_dbi_auth_info handles NULL gracefully), provisioned-data '
                            'calls ogs_dbi_subscription_data which has ogs_assert(supi_id) '
                            '— prefix_only variant crashes. RL explores variant boundaries.',
                relevant_fields=['supi_path_variant', 'supi'],
            ),
            FuzzScenario(
                name='poc_4420_udm_purgeflag',
                target_api='UDM_UCM',
                setup_messages=['fuzz:udm_uecm_amf_reg'],
                fuzz_message='udm_purgeflag',
                description='#4420: PUT /amf-3gpp-access first (sets udm_ue->guami and '
                            'amf_3gpp_access_registration), then PATCH purgeFlag:true — '
                            'without prior registration amf_3gpp_access_registration is NULL '
                            '→ ogs_assert at nudm-handler.c:454. SUPI locked to valid IMSI: '
                            'mutating SUPI causes 403 from the handler type guard before reaching '
                            'the purge code path.',
                relevant_fields=[],
            ),
            FuzzScenario(
                name='udm_purgeflag_guami_mismatch',
                target_api='UDM_UCM',
                setup_messages=['fuzz:udm_psi_zero'],
                fuzz_message='udm_purgeflag',
                description='GET /smf-registrations/0 creates udm_ue (zero guami), then '
                            'PATCH purgeFlag with real Guami → hits 403 Guami-mismatch. '
                            'Fuzzes the memcmp boundary at nudm-handler.c:429; '
                            'also probes for comparison bypass with malformed Guami fields.',
                relevant_fields=['supi', 'plmn_mcc', 'plmn_mnc'],
            ),
            FuzzScenario(
                name='udm_purgeflag_after_auth',
                target_api='UDM_UCM',
                setup_messages=['fuzz:udm_auth_data', 'fuzz:udm_uecm_amf_reg'],
                fuzz_message='udm_purgeflag',
                description='POST auth-data then PUT amf-3gpp-access (sets guami via auth '
                            'path), then PATCH purgeFlag:true with matching Guami. '
                            'Tests #4420 patch completeness through the AUSF-driven '
                            'registration sequence; both steps use the fuzz SUPI.',
                relevant_fields=['supi'],
            ),
            FuzzScenario(
                name='poc_4403_oversized_nssais',
                target_api=_amf,
                setup_messages=[],
                fuzz_message='amf_oversized_nssais',
                description='#4403: PUT ue-contexts with 9 defaultSingleNssais '
                            '(> OGS_MAX_NUM_OF_SLICE=8) → out-of-bounds write at nudm-handler.c:95',
                relevant_fields=['supi'],
            ),
            FuzzScenario(
                name='poc_4405_malformed_gpsi',
                target_api=_amf,
                setup_messages=[],
                fuzz_message='amf_malformed_gpsi',
                description='#4405: PUT ue-contexts with gpsis:["msisdn"] (no number suffix) '
                            '→ ogs_id_get_value() NULL → assert at nudm-handler.c:66',
                relevant_fields=['supi'],
            ),

            # ── Generic mutation-driven scenarios ─────────────────────────
            # These use mutation fields (array_count, supi_path_variant,
            # pdu_session_id) so the RL agent discovers crash boundaries
            # without hardcoded payloads.
            FuzzScenario(
                name='nrf_fuzz_scp_array_count',
                target_api=_nfm,
                setup_messages=[],
                fuzz_message='nrf_scp_array_fuzz',
                description='PUT /nf-instances with N scpDomainInfoList entries '
                            '(N=array_count). RL sweeps 1→32; crash at N>8 '
                            '(handle_scp_info fixed 8-slot stack array, #4383).',
                relevant_fields=['array_count', 'nf_instance_id'],
            ),
            FuzzScenario(
                name='amf_fuzz_nssai_array_count',
                target_api=_amf,
                setup_messages=[],
                fuzz_message='amf_nssai_array_fuzz',
                description='PUT ue-contexts with N defaultSingleNssais (N=array_count). '
                            'RL sweeps 1→32; crash at N>8 (OGS_MAX_NUM_OF_SLICE=8, #4403).',
                relevant_fields=['array_count', 'supi'],
            ),
            FuzzScenario(
                name='udm_fuzz_smf_reg_psi_boundary',
                target_api='UDM_UCM',
                setup_messages=[],
                fuzz_message='udm_smf_reg_psi_fuzz',
                description='GET /smf-registrations/{pduSessionId} with pdu_session_id '
                            'mutation. psi=0 now returns 400 (patched #4255); RL sweeps '
                            '0–255 to find session-array OOB beyond 3GPP limit (psi>15) '
                            'or incomplete patch on adjacent psi=255/overflow values.',
                relevant_fields=['pdu_session_id', 'supi'],
            ),
            FuzzScenario(
                name='udm_fuzz_psi_after_context',
                target_api='UDM_UCM',
                setup_messages=['fuzz:udm_psi_zero'],
                fuzz_message='udm_smf_reg_psi_fuzz',
                description='GET /smf-registrations/0 first (creates udm_ue context in '
                            'memory for the fuzz SUPI), then GET /smf-registrations/{psi} '
                            'sweeps psi 1–255. With udm_ue already present, each unique '
                            'psi calls udm_sess_add(udm_ue, psi); psi > '
                            'OGS_MAX_NUM_OF_PDU_SESSIONS (15) may OOB-write the session '
                            'array — independent of the #4255 psi=0 patch.',
                relevant_fields=['pdu_session_id', 'supi'],
            ),
            FuzzScenario(
                name='udm_smf_reg_delete_before_get',
                target_api='UDM_UCM',
                setup_messages=[],
                fuzz_message='udm_smf_reg_psi_fuzz',
                description='GET /smf-registrations/{psi} with psi values 16–32 (> '
                            'OGS_MAX_NUM_OF_PDU_SESSIONS). Session add path calls '
                            'udm_sess_add(udm_ue, psi) without bounds check; OOB write '
                            'if psi exceeds the session array size.',
                relevant_fields=['pdu_session_id', 'supi'],
            ),
            FuzzScenario(
                name='udr_fuzz_policy_supi_variant',
                target_api='UDR_DR',
                setup_messages=[],
                fuzz_message='udr_policy_supi_fuzz',
                description='GET /policy-data/ues/{supi}/am-data with supi_path_variant '
                            'mutation. "prefix_only" (bare "imsi") triggers #4412 assertion '
                            '(supi_id NULL at subscription.c:333).',
                relevant_fields=['supi_path_variant', 'supi'],
            ),
            # ── AUSF EAP-AKA' session  (#1030/#982/#983/#4472/#4523) ──────────
            FuzzScenario(
                name='ausf_fuzz_eap_session',
                target_api='AUSF_AUTH',
                setup_messages=['ausf_auth_create'],
                fuzz_message='ausf_eap_session',
                description='POST /nausf-auth/v1/ue-authentications then POST '
                            '/eap-session — decodeEapAkaPrime OOB panic on short '
                            'eapPayload (#1030/#982/#983); supiOrSuci field also '
                            'fuzzes AUSF SUPI/SUCI parser (#4472/#4523)',
                relevant_fields=['supi', 'pdu_session_id'],
            ),
            FuzzScenario(
                name='ausf_fuzz_auth_create',
                target_api='AUSF_AUTH',
                setup_messages=[],
                fuzz_message='ausf_auth_create',
                description='POST /nausf-auth/v1/ue-authentications — fuzz '
                            'supiOrSuci field: SUCI short-length, null-byte, '
                            '5G-GUTI; exercises SUPI/SUCI parser in AUSF/UDM',
                relevant_fields=['supi'],
            ),

            # ── AMF context transfer  (#4397/#4399/#4402) ─────────────────
            FuzzScenario(
                name='amf_fuzz_ue_ctx_transfer',
                target_api='AMF_UE',
                setup_messages=[],
                fuzz_message='amf_ue_ctx_transfer',
                description='POST /namf-comm/v1/ue-contexts/{id}/transfer with '
                            'empty/minimal body — nil-deref crash in AMF when no '
                            'UE context exists (#4397/#4402); fuzz SUPI path param '
                            'including 5G-GUTI format (#4398)',
                relevant_fields=['supi'],
            ),
            FuzzScenario(
                name='amf_fuzz_comm_sub_seq',
                target_api='AMF_UE',
                setup_messages=['amf_comm_sub_create'],
                fuzz_message='amf_comm_sub_delete',
                description='POST /namf-comm/v1/subscriptions then DELETE — '
                            'panic on free of stale subscription pointer (#876/#902); '
                            'pdu_session_id drives the subscription ref ID',
                relevant_fields=['pdu_session_id', 'nf_instance_id'],
            ),
            FuzzScenario(
                name='amf_fuzz_callback_sdm_notify',
                target_api='AMF_CB',
                setup_messages=[],
                fuzz_message='amf_callback_sdm_notify',
                description='POST /namf-callback/v1/{ctx}/sdmsubscription-notify — '
                            'nil-deref when subscription context unknown (#4395); '
                            'pdu_session_id drives the ctx path segment',
                relevant_fields=['pdu_session_id', 'supi'],
            ),

            # ── UDM generate-auth-data  (#4418/#1037) ────────────────────
            FuzzScenario(
                name='udm_fuzz_auth_data_supi',
                target_api='UDM_UEAU',
                setup_messages=[],
                fuzz_message='udm_auth_data',
                description='POST /nudm-ueau/v1/{supi}/security-information/'
                            'generate-auth-data — nil sequenceNumber deref when '
                            'SUPI has no auth subscription (#4418/#1037); null-byte '
                            'SUPI in path also triggers UDM handler panic (#1048)',
                relevant_fields=['supi'],
            ),

            # ── NRF status notify overflow  (#4406/#4469/#4470) ───────────
            FuzzScenario(
                name='nrf_fuzz_status_notify_dnn',
                target_api='NRF_CB',
                setup_messages=[],
                fuzz_message='nrf_status_notify',
                description='POST /nnrf-nfm/v1/nf-status-notify with oversized '
                            'smfInfo.dnnInfos array — AMF crashes importing NF '
                            'profile when dnn_count > threshold (#4406/#4469/#4470); '
                            'array_count drives dnn_count so RL sweeps the boundary',
                relevant_fields=['array_count', 'nf_instance_id'],
            ),

            # ── SMF policy-notify callback  (#4442/#4453) ────────────────
            FuzzScenario(
                name='smf_fuzz_policy_notify',
                target_api='SMF_CB',
                setup_messages=[],
                fuzz_message='smf_policy_notify',
                description='POST /nsmf-callback/v1/sm-policy-notify/{id}/update — '
                            'nil-deref on null RouteToLAN when smPolicyDecision is '
                            'empty (#4442); or wrong vsmf-pdu-session path (#4453)',
                relevant_fields=['pdu_session_id'],
            ),

            FuzzScenario(
                name='udr_fuzz_sub_supi_variant',
                target_api='UDR_DR',
                setup_messages=[],
                fuzz_message='udr_sub_supi_fuzz',
                description='GET /subscription-data/{supi}/authentication-data with '
                            'supi_path_variant mutation — explores UDR auth-data endpoint '
                            'for SUPI parsing vulnerabilities similar to #4412.',
                relevant_fields=['supi_path_variant', 'supi'],
            ),

            # ── Cross-platform NRF  (free5GC #757/#758/#434 + open5GS) ─────
            FuzzScenario(
                name='nrf_fuzz_disc_gpsi_short',
                target_api=_disc,
                setup_messages=['nrf_nf_register'],
                fuzz_message='nrf_disc_gpsi',
                description='free5GC #757: GET /nnrf-disc with short gpsi query param '
                            '(e.g. "ms", 2 chars) — buildFilter computes '
                            'negative slice length → bounds panic. RL sweeps all '
                            'GPSI_VALUES including empty, null-byte, and oversized '
                            'to find both free5GC and open5GS validation gaps.',
                relevant_fields=['gpsi', 'nf_type'],
            ),
            FuzzScenario(
                name='nrf_fuzz_disc_empty_snssai',
                target_api=_disc,
                setup_messages=['nrf_nf_register'],
                fuzz_message='nrf_disc_snssai_fuzz',
                description='free5GC #758: GET /nnrf-disc with empty snssai query '
                            'param → nil pointer dereference in Discovery handler. '
                            'open5GS may return 400 — cross-platform probe of snssai '
                            'input validation in NRF discovery.',
                relevant_fields=['snssai_sst', 'snssai_sd'],
            ),
            FuzzScenario(
                name='nrf_fuzz_oauth2_unknown_type',
                target_api=_nfm,
                setup_messages=[],
                fuzz_message='nrf_oauth2_token',
                description='free5GC #434: POST /nnrf-nfm/v1/oauth2/token with unknown '
                            'targetNfType ("NOPE", "UNKNOWN", empty) → panic in '
                            'NrfNfmOauth2TokenPost handler (missing enum guard). '
                            'open5GS may return 400/501. pdu_session_id cycles through '
                            'unknown type variants.',
                relevant_fields=['nf_type', 'nf_instance_id'],
            ),

            # ── Cross-platform UDM  (free5GC #761/#762/#780 + open5GS) ────
            FuzzScenario(
                name='udm_fuzz_sdm_shared_data',
                target_api='UDM_SDM',
                setup_messages=[],
                fuzz_message='udm_sdm_shared_data',
                description='free5GC #762: GET /nudm-sdm/v2/shared-data without '
                            '"supported-features" query param → UDM '
                            'HandleGetSharedData panics on nil pointer dereference. '
                            'open5GS SDM endpoint at same path — cross-platform probe.',
                relevant_fields=['supi'],
            ),
            FuzzScenario(
                name='udm_fuzz_uecm_incomplete_reg',
                target_api='UDM_UCM',
                setup_messages=[],
                fuzz_message='udm_uecm_amf_reg_incomplete',
                description='free5GC #761: PUT /nudm-uecm/v1/{supi}/registrations/'
                            'amf-3gpp-access with missing mandatory fields '
                            '(amfInstanceId, deregCallbackUri absent) → nil deref '
                            'in RegistrationAmf3gppAccessProcedure. Complements '
                            'poc_4420: attacks the initial PUT path, not PATCH purgeFlag.',
                relevant_fields=['supi', 'plmn_mcc', 'plmn_mnc'],
            ),
            FuzzScenario(
                name='udm_null_byte_supi_path',
                target_api='UDM_UCM',
                setup_messages=[],
                fuzz_message='udm_uecm_amf_reg',
                description='free5GC #780: null byte injected into SUPI URL path — '
                            'PUT /nudm-uecm/v1/imsi-001...\\x00/registrations/amf-3gpp-access. '
                            'C implementations (open5GS) truncate at NUL; Go (free5GC) '
                            'may panic on unexpected NUL in string comparison. '
                            'supi_path_variant=null_byte drives the injection.',
                relevant_fields=['supi_path_variant', 'supi'],
            ),

            # ── Cross-platform AMF  (free5GC #754/#755/#756 + open5GS) ────
            FuzzScenario(
                name='amf_fuzz_multipart_ue_ctx',
                target_api=_amf,
                setup_messages=[],
                fuzz_message='amf_ue_ctx_create',
                description='free5GC #755: PUT /namf-comm/v1/ue-contexts/{id} with '
                            'Content-Type: multipart/related → AMF CreateUEContext '
                            'panics trying to decode multipart as JSON UE context. '
                            'content_type field drives the Content-Type mutation; '
                            'also probes open5GS multipart handling on AMF endpoint.',
                relevant_fields=['content_type', 'supi'],
            ),
            FuzzScenario(
                name='amf_fuzz_evts_sub_modify',
                target_api='AMF_EVTS',
                setup_messages=['amf_evts_subscribe', 'amf_evts_subscribe'],
                fuzz_message='amf_evts_sub_modify',
                description='free5GC #754: PATCH /namf-evts/v1/subscriptions/{id} '
                            'after DELETE → ModifySubscription panics on nil pointer. '
                            'Setup: two subscribe calls to ensure a subscription exists; '
                            'fuzz: PATCH on a new sub-id (sub-{pdu_sid}) which was never '
                            'created — exercises not-found path in both implementations.',
                relevant_fields=['pdu_session_id', 'supi'],
            ),
            FuzzScenario(
                name='amf_fuzz_restricted_rat_list',
                target_api=_amf,
                setup_messages=[],
                fuzz_message='amf_ue_ctx_restricted_rat',
                description='free5GC #756: PUT /namf-comm/v1/ue-contexts with '
                            'non-empty restrictedRatList — handler accesses [0] without '
                            'checking length → nil/bounds panic in free5GC. '
                            'Cross-platform: open5GS amf-context.c has similar '
                            'list-traversal code for restrictedRatList.',
                relevant_fields=['supi', 'rat_type'],
            ),
        ]

    # ── Payload targets ───────────────────────────────────────────────────

    def get_payload_targets(self) -> List[PayloadTarget]:
        return [
            PayloadTarget(
                'json_body',
                'http2_data',
                max_size=4096,
                encoding='bytes',
            ),
            PayloadTarget(
                'path_param',
                'http2_path',
                max_size=256,
                encoding='string',
            ),
        ]

    # ── Message building ──────────────────────────────────────────────────

    # Maps message_type → (HTTP method, URI path builder, template name)
    # Path builders are called with field values at build time.
    _MSG_TABLE: Dict[str, Tuple[str, str, str]] = {
        # NRF
        'nrf_nf_register':              ('PUT',    'nrf_nf_instance',  'nrf_nf_register'),
        'nrf_nf_discover':              ('GET',    'nrf_disc',         'nrf_nf_discover'),
        'nrf_nf_subscribe':             ('POST',   'nrf_sub',          'nrf_nf_subscribe'),
        'nrf_nf_deregister':            ('DELETE', 'nrf_nf_instance',  'nrf_nf_deregister'),
        'nrf_nf_register_malformed':    ('PUT',    'nrf_nf_instance',  'nrf_nf_register_malformed'),
        'nrf_nf_register_type_mismatch':('PUT',    'nrf_nf_instance',  'nrf_nf_register_type_mismatch'),
        # AMF
        'amf_ue_ctx_create':        ('PUT',    'amf_ue_ctx',       'amf_ue_ctx_create'),
        'amf_ue_ctx_get':           ('GET',    'amf_ue_ctx',       'amf_ue_ctx_get'),
        'amf_n1n2_msg':             ('POST',   'amf_n1n2',         'amf_n1n2_msg'),
        'amf_evts_subscribe':       ('POST',   'amf_evts',         'amf_evts_subscribe'),
        'amf_ue_ctx_bad_supi':      ('PUT',    'amf_ue_ctx',       'amf_ue_ctx_bad_supi'),
        # SMF
        'smf_ctx_create':           ('POST',   'smf_ctx',          'smf_ctx_create'),
        'smf_ctx_modify':            ('POST',   'smf_ctx_modify',        'smf_ctx_modify'),
        'smf_ctx_modify_wrong_state':('POST',   'smf_ctx_modify',        'smf_ctx_modify_wrong_state'),
        'smf_ctx_release':           ('POST',   'smf_ctx_release',       'smf_ctx_release'),
        'smf_ctx_delete':           ('DELETE', 'smf_ctx',          'smf_ctx_delete'),
        'smf_ctx_create_wrong_plmn':('POST',   'smf_ctx',          'smf_ctx_create_wrong_plmn'),
        # v2.7.7 exact-PoC triggers
        'nrf_scp_overflow':         ('PUT',    'nrf_nf_instance',  'nrf_scp_overflow'),
        'udm_purgeflag':            ('PATCH',  'udm_amf_reg',      'udm_purgeflag'),
        'udr_malformed_pei':        ('PUT',    'udr_ctx_data',     'udr_malformed_pei'),
        'udr_malformed_pei_bad_type':('PUT',   'udr_ctx_data',     'udr_malformed_pei_bad_type'),
        'amf_oversized_nssais':     ('PUT',    'amf_ue_ctx',       'amf_oversized_nssais'),
        'amf_malformed_gpsi':       ('PUT',    'amf_ue_ctx',       'amf_malformed_gpsi'),
        # GET-only PoCs — path key encodes the special path; body is empty
        'nrf_plmn_overflow':        ('GET',    'nrf_plmn_overflow','nrf_plmn_overflow'),
        'udm_psi_zero':             ('GET',    'udm_psi_zero',     'udm_psi_zero'),
        'udr_prefix_supi':          ('GET',    'udr_prefix_supi',  'udr_prefix_supi'),
        'udr_prefix_supi_sub':      ('GET',    'udr_prefix_sub_provisioned', 'udr_prefix_supi_sub'),
        # multipart/related PoC — Content-Type override handled in build_message()
        'multipart_empty':          ('POST',   'nrf_sub',          'multipart_empty'),
        # Generic mutation-driven messages
        'nrf_scp_array_fuzz':       ('PUT',    'nrf_nf_instance',  'nrf_scp_array_fuzz'),
        'amf_nssai_array_fuzz':     ('PUT',    'amf_ue_ctx',       'amf_nssai_array_fuzz'),
        'udm_smf_reg_psi_fuzz':     ('GET',    'udm_smf_reg_psi',  'udm_smf_reg_psi_fuzz'),
        'udr_policy_supi_fuzz':     ('GET',    'udr_policy_supi',  'udr_policy_supi_fuzz'),
        'udr_sub_supi_fuzz':        ('GET',    'udr_sub_supi',       'udr_sub_supi_fuzz'),
        'udr_sub_provisioned_fuzz': ('GET',    'udr_sub_provisioned','udr_sub_provisioned_fuzz'),
        # ── New crash-confirmed endpoints ──────────────────────────────────
        'amf_ue_ctx_transfer':      ('POST',   'amf_ue_ctx_transfer',        'amf_ue_ctx_transfer'),
        'amf_ue_ctx_transfer_update':('POST',  'amf_ue_ctx_transfer_update', 'amf_ue_ctx_transfer_update'),
        'amf_comm_sub_create':      ('POST',   'amf_comm_sub',               'amf_comm_sub_create'),
        'amf_comm_sub_delete':      ('DELETE', 'amf_comm_sub_ref',           'amf_comm_sub_delete'),
        'amf_callback_sdm_notify':  ('POST',   'amf_cb_sdm_notify',          'amf_callback_sdm_notify'),
        'amf_callback_n1_notify':   ('POST',   'amf_cb_n1_notify',           'amf_callback_n1_notify'),
        'ausf_auth_create':         ('POST',   'ausf_auth',                  'ausf_auth_create'),
        'ausf_eap_session':         ('POST',   'ausf_eap',                   'ausf_eap_session'),
        'udm_auth_data':            ('POST',   'udm_auth_data',              'udm_auth_data'),
        'udm_uecm_amf_reg':         ('PUT',    'udm_uecm_amf',               'udm_uecm_amf_reg'),
        'smf_policy_notify':        ('POST',   'smf_policy_notify',          'smf_policy_notify'),
        'nrf_status_notify':        ('POST',   'nrf_status_notify',          'nrf_status_notify'),
        # ── Cross-platform messages (free5GC + open5GS) ─────────────────────
        'nrf_disc_gpsi':              ('GET',   'nrf_disc_gpsi',              'nrf_disc_gpsi'),
        'nrf_disc_snssai_fuzz':       ('GET',   'nrf_disc_snssai_fuzz',       'nrf_disc_snssai_fuzz'),
        'nrf_oauth2_token':           ('POST',  'nrf_oauth2',                 'nrf_oauth2_token'),
        'udm_sdm_shared_data':        ('GET',   'udm_sdm_shared_data',        'udm_sdm_shared_data'),
        'udm_uecm_amf_reg_incomplete':('PUT',   'udm_uecm_amf',               'udm_uecm_amf_reg_incomplete'),
        'amf_evts_sub_modify':        ('PATCH', 'amf_evts_sub_ref',           'amf_evts_sub_modify'),
        'amf_ue_ctx_restricted_rat':  ('PUT',   'amf_ue_ctx',                 'amf_ue_ctx_restricted_rat'),
    }

    def _build_path(self, path_key: str, fields: Dict[str, Any]) -> str:
        """Resolve a path key to a URI path using current field values."""
        nf_id     = str(fields.get('nf_instance_id', NF_INSTANCE_FUZZ))
        supi      = str(fields.get('supi', 'imsi-001010000000001'))
        nf_type   = str(fields.get('nf_type', 'AMF'))
        pdu_sid   = int(fields.get('pdu_session_id', 1))
        # Synthesise a deterministic SM context reference from pdu_session_id
        sm_ref    = f'ctx-{pdu_sid:04d}'
        # Inject payload into path if requested
        path_payload = fields.get('_path_payload', None)

        # 13-PLMN list for #4382 — fixed in path so the query string is exact
        plmn_list = ','.join(f'{i:03d}-{i:02d}' for i in range(1, 14))

        # SUPI path variant: controls the SUPI segment in UDR/UDM paths.
        # 'prefix_only' = bare "imsi" (no number) → triggers #4412 assertion.
        supi_parts = supi.split('-', 1)
        supi_type  = supi_parts[0] if supi_parts else 'imsi'
        supi_num   = supi_parts[1] if len(supi_parts) > 1 else '001010000000001'
        supi_path  = {
            'valid':             supi,
            'prefix_only':       supi_type,
            'no_number':         f'{supi_type}-',
            'wrong_sep':         f'{supi_type}:{supi_num}',
            'numeric_only':      supi_num,
            'empty':             '',
            'null_byte':         f'{supi}\x00',
            'url_encoded_null':  f'{supi}%00',
            'double_slash':      f'//{supi}',
            'traversal':         f'../{supi}',
        }.get(str(fields.get('supi_path_variant', 'valid')), supi)

        table = {
            'nrf_nf_instance': _nrf_nf_instance_path(
                path_payload or nf_id),
            'nrf_disc':        _nrf_disc_path(nf_type),
            'nrf_sub':         '/nnrf-nfm/v1/subscriptions',
            'amf_ue_ctx':      _amf_ue_ctx_path(
                path_payload or f'amf-ue-ngap-id-{pdu_sid}'),
            'amf_n1n2':        _amf_n1n2_path(
                path_payload or f'amf-ue-ngap-id-{pdu_sid}'),
            'amf_evts':        _amf_evts_path(),
            'smf_ctx':         '/nsmf-pdusession/v1/sm-contexts',
            'smf_ctx_modify':  _smf_sm_ctx_modify_path(sm_ref),
            'smf_ctx_release': _smf_sm_ctx_release_path(sm_ref),
            # v2.7.7 PoC paths
            'nrf_plmn_overflow': (
                f'/nnrf-disc/v1/nf-instances'
                f'?target-nf-type=AMF&requester-nf-type=AMF'
                f'&requester-plmn-list={plmn_list}'   # 13 PLMNs → #4382
            ),
            'udm_amf_reg':     f'/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access',
            'udm_psi_zero':    f'/nudm-uecm/v1/{supi}/registrations/smf-registrations/0',
            'udr_prefix_supi': '/nudr-dr/v1/policy-data/ues/imsi/am-data',
            # #4412 second path: subscription-data provisioned endpoint also calls
            # ogs_dbi_subscription_data() which has ogs_assert(supi_id) → crash.
            'udr_prefix_sub_provisioned': '/nudr-dr/v1/subscription-data/imsi/00101/provisioned-data',
            'udr_ctx_data':    f'/nudr-dr/v1/subscription-data/{supi}/context-data/amf-3gpp-access',
            # Generic path-fuzz paths (use mutation field values directly)
            # pdu_session_id field substituted into path — boundary value 0 triggers #4255
            'udm_smf_reg_psi': f'/nudm-uecm/v1/{supi}/registrations/smf-registrations/{pdu_sid}',
            # supi_path_variant substituted — prefix_only triggers #4412
            'udr_policy_supi': f'/nudr-dr/v1/policy-data/ues/{supi_path}/am-data',
            'udr_sub_supi':    f'/nudr-dr/v1/subscription-data/{supi_path}/authentication-data',
            # supi_path_variant on provisioned-data — prefix_only hits ogs_assert(supi_id)
            # via ogs_dbi_subscription_data (auth-data path handles NULL gracefully, this doesn't)
            'udr_sub_provisioned': f'/nudr-dr/v1/subscription-data/{supi_path}/00101/provisioned-data',
            # ── New crash-confirmed endpoint paths ─────────────────────────
            # AMF context transfer (#4397/#4399/#4402) — SUPI or 5G-GUTI in path
            'amf_ue_ctx_transfer':        _amf_ue_ctx_transfer_path(path_payload or supi),
            'amf_ue_ctx_transfer_update': _amf_ue_ctx_transfer_update_path(path_payload or supi),
            # AMF comm subscriptions (#876/#902)
            'amf_comm_sub':     _amf_comm_sub_path(),
            'amf_comm_sub_ref': _amf_comm_sub_path(f'fuzz-sub-{pdu_sid}'),
            # AMF callbacks (#4395/#1029)
            'amf_cb_sdm_notify': _amf_callback_sdm_notify_path(f'ctx-{pdu_sid}'),
            'amf_cb_n1_notify':  _amf_callback_n1_notify_path(),
            # AUSF (#1030/#982/#983/#4472/#4523)
            'ausf_auth': _ausf_auth_path(),
            'ausf_eap':  _ausf_eap_path(path_payload or supi),
            # UDM (#4418/#1037/#4419/#4420)
            'udm_auth_data':  _udm_auth_data_path(path_payload or supi),
            'udm_uecm_amf':   _udm_uecm_amf_path(path_payload or supi),
            # SMF callback (#4442/#4453)
            'smf_policy_notify': _smf_policy_notify_path(f'ctx-{pdu_sid}'),
            # NRF status notify (#4406)
            'nrf_status_notify': _nrf_status_notify_path(),
            # ── Cross-platform path keys ───────────────────────────────────
            'nrf_disc_gpsi':      _nrf_disc_gpsi_path(nf_type,
                                      str(fields.get('gpsi', 'ms'))),
            'nrf_disc_snssai_fuzz': _nrf_disc_snssai_path(nf_type, ''),
            'nrf_oauth2':         _nrf_oauth2_path(),
            'udm_sdm_shared_data': _udm_sdm_shared_data_path(),
            'amf_evts_sub_ref':   _amf_evts_sub_ref_path(f'sub-{pdu_sid}'),
        }
        return table.get(path_key, '/')

    def _authority(self, host: Optional[str] = None,
                   port: Optional[int] = None) -> str:
        # For the HEADERS frame :authority pseudo-header.
        # We store the target host/port from the last check_health() call.
        h = host or getattr(self, '_last_host', '127.0.0.1')
        p = port or getattr(self, '_last_port', self.default_port)
        return f'{h}:{p}'

    def build_message(self, message_type: str,
                      fields: Dict[str, Any],
                      payloads: Dict[str, bytes]) -> bytes:
        # ── Frame-level attack messages ────────────────────────────────────
        if message_type == 'h2_window_amplification':
            return H2_PREFACE + build_settings_frame() + build_window_amplification(1)

        if message_type == 'h2_header_amplification':
            return H2_PREFACE + build_settings_frame() + build_header_amplification(1)

        # ── #3942: empty body with multipart/related Content-Type ──────────
        # parse_multipart() dereferences the first boundary token which is NULL
        # when the body is empty → segfault in sbi/message.c:2825.
        if message_type == 'multipart_empty':
            authority = self._authority()
            return build_sbi_request(
                method='POST',
                path='/nnrf-nfm/v1/subscriptions',
                authority=authority,
                body=b'',
                content_type='multipart/related; boundary=Boundary',
                include_preface=True,
            )

        # ── Standard SBI messages ──────────────────────────────────────────
        entry = self._MSG_TABLE.get(message_type)
        if entry is None:
            logger.warning("Unknown SBI message type: %s", message_type)
            return b''

        method, path_key, template_name = entry

        # Apply path payload injection if requested
        if payloads.get('path_param'):
            fields = dict(fields)
            fields['_path_payload'] = payloads['path_param'].decode('latin-1',
                                                                     errors='replace')

        # Apply HTTP method override from field mutation
        if 'http_method' in fields:
            method = str(fields['http_method']).upper() or method

        path      = self._build_path(path_key, fields)
        authority = self._authority()

        # Build JSON body (or empty bytes for GET / DELETE)
        if payloads.get('json_body'):
            # Raw payload injection: send arbitrary bytes as the JSON body
            # (tests JSON parser robustness against non-JSON input)
            body = payloads['json_body']
        elif ('__body_fuzz_template__' in fields and
              fields['__body_fuzz_template__'] == template_name):
            # body_fuzz action: apply generic leaf-field mutation to the body
            body_bytes = apply_body_field_mutation(
                template_name, fields,
                fields['__body_fuzz_field__'],
                int(fields['__body_fuzz_idx__']),
            )
            body = body_bytes if body_bytes else None
        else:
            body_bytes = build_body(template_name, fields)
            body = body_bytes if body_bytes else None

        # Override Content-Type if mutated
        content_type = str(fields.get('content_type', 'application/json'))

        # Override stream ID if mutated (frame-level fuzzing)
        sid_raw = fields.get('stream_id', 1)
        try:
            stream_id = int(sid_raw) & 0xffffffff
        except (TypeError, ValueError):
            stream_id = 1

        # 3gpp-sbi-target-nf-type: identify which NF service we're calling.
        # Derived from message type prefix so NRF requests don't send "AMF"
        # (which triggers "Not allowed nf-type[AMF] in nf-instance[AMF]" errors
        # because the registered profile has allowedNfTypes=['SMF','PCF','UDM']).
        # Only use fields['nf_type'] when explicitly fuzzing the nf_type field
        # (action type 'semantic' with field_name='nf_type').
        _target_by_prefix = {'nrf_': 'NRF', 'amf_': 'AMF', 'smf_': 'SMF'}
        default_target = next(
            (v for k, v in _target_by_prefix.items() if message_type.startswith(k)),
            'NRF',
        )
        # Allow explicit nf_type fuzz override only when the field is actually
        # being mutated (i.e. not the baseline 'AMF' default).
        fuzz_nf_type = fields.get('nf_type')
        if fuzz_nf_type and fuzz_nf_type != 'AMF':
            target_nf_type = str(fuzz_nf_type)
        else:
            target_nf_type = default_target
        extra_headers = [
            ('3gpp-sbi-target-nf-type', target_nf_type),
        ]

        return build_sbi_request(
            method=method,
            path=path,
            authority=authority,
            body=body if (body and len(body) > 0) else None,
            extra_headers=extra_headers,
            stream_id=stream_id,
            content_type=content_type,
            include_preface=True,
        )

    # ── Response parsing ──────────────────────────────────────────────────

    def parse_response(self, data: bytes) -> Dict[str, Any]:
        if not data:
            return {'type': 'empty', 'success': False, 'status': None}

        parsed = parse_h2_response(data)
        status = parsed.get('status')

        # Determine response type string.
        # RST_STREAM only takes precedence when no HTTP status was received —
        # open5GS routinely sends HEADERS(4xx) + RST_STREAM as normal HTTP/2
        # stream termination, and classifying that as 'rst_stream' would both
        # misrepresent the server's response and inflate rewards (+35) for
        # ordinary error replies.  A bare RST_STREAM (no status) is a genuine
        # H2 framing anomaly and keeps its classification.
        if parsed.get('goaway'):
            rtype = 'goaway'
        elif parsed.get('rst_stream') and status is None:
            rtype = 'rst_stream'
        elif status is None:
            # Could not extract status — might be only SETTINGS + WINDOW_UPDATE
            # (server ACKing our preface but no actual response yet)
            if FRAME_SETTINGS in parsed.get('frame_types', []):
                rtype = 'settings_only'
            else:
                rtype = 'no_status'
        elif status == 200:
            rtype = 'ok'
        elif status == 201:
            rtype = 'created'
        elif status == 204:
            rtype = 'no_content'
        elif status == 400:
            rtype = 'bad_request'
        elif status == 401:
            rtype = 'unauthorized'
        elif status == 403:
            rtype = 'forbidden'
        elif status == 404:
            rtype = 'not_found'
        elif status == 405:
            rtype = 'method_not_allowed'
        elif status == 409:
            rtype = 'conflict'
        elif status == 415:
            rtype = 'unsupported_media_type'
        elif status == 422:
            rtype = 'unprocessable_entity'
        elif status == 500:
            rtype = 'internal_server_error'
        elif status == 501:
            rtype = 'not_implemented'
        elif status == 503:
            rtype = 'service_unavailable'
        elif 500 <= status <= 599:
            rtype = f'server_error_{status}'
        elif 400 <= status <= 499:
            rtype = f'client_error_{status}'
        else:
            rtype = f'http_{status}'

        success = status is not None and 200 <= status < 300

        result: Dict[str, Any] = {
            'type':         rtype,
            'success':      success,
            'status':       status,
            'raw_length':   len(data),
            'frame_types':  parsed.get('frame_types', []),
            'goaway':       parsed.get('goaway', False),
            'h2_error':     parsed.get('h2_error', 0),
        }

        # Parse response body: extract ProblemDetails depth signal + body length
        body = parsed.get('body', b'')
        if body:
            result['body_len'] = len(body)
            result['body_preview'] = body[:200]
            # RFC 7807 ProblemDetails: score how deep the validation error is
            result['body_depth_score'] = _score_problem_detail(body)

        return result

    # ── Interesting response classification ───────────────────────────────

    def is_interesting_response(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        rtype = response.get('type', '')

        table = {
            # Connection-level signals
            'timeout':              (True,  4.0),  # NF not responding
            'reset':                (True,  3.5),  # TCP reset (NF crashed or restarted)
            'refused':              (True,  2.0),  # port closed
            # HTTP/2 framing errors — server rejects our frame structure
            'goaway':               (True,  3.0),  # server sends GOAWAY: protocol error
            'rst_stream':           (True,  2.5),  # stream reset: request rejected
            'no_status':            (True,  2.0),  # no HEADERS response at all
            'settings_only':        (True,  1.0),  # only SETTINGS, no response headers
            # 5xx responses — server-side errors are high value
            'internal_server_error':(True,  3.5),  # 500: NF internal error
            'not_implemented':      (True,  2.5),  # 501: unexpected code path
            'service_unavailable':  (True,  2.5),  # 503: NF overloaded
            # 4xx responses — 400 is the NRF's default fuzz response; keep base LOW
            # so body_depth_score (0–0.95 × 40 = 0–38) becomes the real discriminator.
            # Rare 4xx codes (409, 415, 422) stay higher — they're genuinely unexpected.
            'unprocessable_entity': (True,  2.0),  # 422: deep JSON validation
            'bad_request':          (True,  0.3),  # 400: expected for most fuzz → low base
            'unsupported_media_type':(True, 1.5),  # 415: content-type rejected
            'conflict':             (True,  1.5),  # 409: state collision
            'method_not_allowed':   (True,  1.0),  # 405: wrong method
            'forbidden':            (True,  1.0),  # 403: auth failure
            'unauthorized':         (True,  0.8),  # 401
            'not_found':            (False, 0.3),  # 404: normal for nonexistent resource
            # Success responses
            'ok':                   (False, 0.3),
            'created':              (False, 0.3),
            'no_content':           (False, 0.2),
            'empty':                (True,  2.0),
        }

        # Unknown 5xx codes are very interesting
        if rtype.startswith('server_error_'):
            return (True, 3.0)
        # Unknown 4xx codes are moderately interesting
        if rtype.startswith('client_error_'):
            return (True, 1.5)
        if rtype.startswith('http_'):
            return (True, 2.0)

        return table.get(rtype, (True, 1.0))

    # ── Reward computation ────────────────────────────────────────────────

    def pre_request_snapshot(self) -> int:
        """Snapshot log position before sending a request.

        Also resets gcov counters when gcov mode is active (gcov_gcda_dir set),
        so coverage collected by compute_reward() reflects only this request.
        """
        if self._gcov_nf_filter:
            self._monitor.gcov_reset()
        return self._monitor.snapshot_log_position()

    def compute_reward(self, response: Dict[str, Any],
                       response_time_ms: float,
                       field_mutations: Dict[str, Any],
                       payload_injections: Dict[str, bytes],
                       log_snapshot: int = 0) -> float:
        reward = 0.0

        stream_id_fuzz = field_mutations.get('stream_id') is not None

        is_interesting, mult = self.is_interesting_response(response)
        # stream_id mutations produce GOAWAY by spec — it's not an anomaly.
        # Zero out the base score so the agent is not rewarded for protocol-level noise.
        if stream_id_fuzz and response.get('goaway'):
            mult = 0.0
        if is_interesting:
            reward += 15.0 * mult

        # Novelty bonus: reward the first time a response type appears this episode.
        # Steers the agent away from the 400 wall and toward unexplored code paths.
        rtype = response.get('type', '')
        if rtype and rtype not in self._episode_resp_types:
            reward += 10.0
            self._episode_resp_types.add(rtype)

        # Response body depth: ProblemDetails 'detail' / 'cause' field reveals
        # exactly which NRF validation layer was reached (0–0.95 scale × 40).
        body_depth = response.get('body_depth_score', 0.0)
        if body_depth > 0:
            reward += body_depth * 40.0

        # Slow response bonus — baseline latency to this NRF is ~100ms (HTTP/2
        # connection overhead over loopback).  Only reward responses that are
        # meaningfully slower than the baseline, indicating extra server work.
        if response_time_ms > 800:
            reward += 50.0
        elif response_time_ms > 400:
            reward += 30.0
        elif response_time_ms > 200:
            reward += 12.0

        # HTTP/2 error bonus: bare RST_STREAM (no HTTP status) means the server
        # rejected the stream at framing level — parser edge-case or OOM.
        # Normal responses with RST_STREAM (HEADERS + RST_STREAM) are already
        # classified by HTTP status; no extra bonus there.
        # GOAWAY closes the whole connection so it's still interesting but less
        # targeted than a bare stream reset.
        # Both are suppressed for stream_id fuzz (GOAWAY is the expected response).
        if response.get('type') == 'rst_stream' and not stream_id_fuzz:
            reward += 35.0
        elif response.get('goaway') and not stream_id_fuzz:
            reward += 20.0
        # Non-zero H2 error code (PROTOCOL_ERROR, COMPRESSION_ERROR, etc.)
        # Suppress for stream_id fuzz — PROTOCOL_ERROR on stream 0 is expected.
        if response.get('h2_error', 0) not in (0, 8) and not stream_id_fuzz:
            reward += 15.0

        # Boundary field bonuses — steer the agent toward values that probe
        # known-vulnerable boundaries.  pdu_session_id > 15 is outside the
        # 3GPP-defined range (OGS_MAX_NUM_OF_PDU_SESSIONS=15) and may expose
        # OOB in udm_sess_add(); 0 exercises the #4255 patch.
        # stream_id excluded: its boundary values produce only expected GOAWAY.
        _BOUNDARY_FIELDS = {
            'pdu_session_id': {0, 15, 16, 32, 255},
            'snssai_sst':     {0, 255},
            'supi':           {'', 'imsi-000000000000000'},
            'nf_instance_id': {'', 'not-a-uuid', '00000000-0000-0000-0000-000000000000'},
        }
        for _fname, _bvals in _BOUNDARY_FIELDS.items():
            if field_mutations.get(_fname) in _bvals:
                reward += 5.0

        # Payload injection bonus
        if payload_injections.get('json_body'):
            reward += 8.0
        if payload_injections.get('path_param'):
            reward += 6.0

        # Crash detected — highest reward signal
        if self._monitor.detect_crash():
            reward += 200.0
        else:
            # Log-anomaly reward: score only lines written SINCE log_snapshot
            # so this step's reward is not contaminated by prior requests.
            if log_snapshot > 0:
                new_lines = self._monitor.lines_since_snapshot(log_snapshot)
            else:
                new_lines = None  # fallback: use last-30-lines tail

            logs_by_level = self._monitor.recent_logs_by_level(10)
            if logs_by_level['fatal']:
                reward += 60.0   # ogs_fatal / ogs_assert — invariant violation

            score = self._monitor.anomaly_score(lines=new_lines)
            if score > 0:
                reward += score * 80.0

            # Log-level file:line coverage bonus (AFL-style, log-derived).
            if new_lines:
                new_locs = self._monitor.new_file_lines(new_lines)
                if new_locs:
                    reward += min(len(new_locs) * 25.0, 75.0)

            # gcov source coverage bonus — only active when gcov build is in use.
            # Dumps .gcda via SIGUSR2, runs gcovr on the NF's source subdirectory,
            # and rewards newly-reached (file, lineno) pairs not seen this episode.
            # +20 per new source line, capped at +100 per step.
            if self._gcov_nf_filter:
                gcov_locs = self._monitor.gcov_new_lines(
                    nf_filter=self._gcov_nf_filter,
                    dump_first=True,
                    eval_every=5,   # run lcov every 5 steps; SIGUSR2 still sent every step
                )
                gcov_bonus = min(len(gcov_locs) * 20.0, 100.0) if gcov_locs else 0.0
                if gcov_bonus > 0:
                    reward += gcov_bonus
                    logger.info(
                        "gcov +%.0f reward | %d new lines | %d total covered",
                        gcov_bonus, len(gcov_locs),
                        self._monitor.gcov_coverage_count,
                    )
                else:
                    logger.debug(
                        "gcov: no new lines (total covered: %d)",
                        self._monitor.gcov_coverage_count,
                    )

        return reward

    # ── Health check ──────────────────────────────────────────────────────

    def kill_server(self) -> bool:
        return self._monitor.kill_nf(self._nf_type)

    def check_health(self, host: str, port: int,
                     timeout: float = 5.0) -> HealthCheckResult:
        result = HealthCheckResult(is_healthy=False)
        self._last_host = host
        self._last_port = port

        # Fast path: primary NF process not running
        if not self._monitor.is_nf_alive(self._nf_type):
            result.error = f'{self._nf_type} process ({self._monitor._proc_name(self._nf_type)}) is not running'
            result.details['process_alive'] = False
            return result

        # Send a GET /nnrf-nfm/v1/nf-instances?limit=1 request and check for
        # a valid HTTP/2 response (200, 404, or any framed response is OK).
        # This mirrors how inject_http2_alloc() verifies connectivity.
        health_path = {
            'NRF':  '/nnrf-nfm/v1/nf-instances?limit=1',
            'AMF':  '/namf-comm/v1/ue-contexts/health-check',
            'SMF':  '/nsmf-pdusession/v1/sm-contexts',
            'UDM':  '/nudm-uecm/v1/health-check',
            'PCF':  '/npcf-am-policy-control/v1/health-check',
        }.get(self._nf_type, '/')

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            t0 = time.monotonic()
            sock.connect((host, port))

            # Build a minimal health-check GET request
            request = build_sbi_request(
                method='GET',
                path=health_path,
                authority=self._authority(host, port),
                body=None,
                include_preface=True,
            )
            sock.sendall(request)

            data = recv_h2_response(sock, timeout=timeout)
            result.latency_ms = (time.monotonic() - t0) * 1000

            if data:
                parsed = parse_h2_response(data)
                status = parsed.get('status')
                frame_types = parsed.get('frame_types', [])

                # Any HTTP/2 response (even 404/500) means the NF is alive
                # and processing HTTP/2 requests.
                if status is not None or any(
                        ft not in (FRAME_SETTINGS, FRAME_WINDOW_UPDATE)
                        for ft in frame_types):
                    result.is_healthy = True
                    result.details['status'] = status
                    result.details['frame_types'] = frame_types
                elif frame_types:
                    # Only SETTINGS/WINDOW_UPDATE — TCP connected but no response yet
                    result.is_healthy = True
                    result.details['status'] = 'settings_only'

            sock.close()

        except socket.timeout:
            result.error   = f'HTTP/2 connect/recv timeout on {host}:{port}'
            result.details['transport_state'] = 'timeout'
        except ConnectionRefusedError:
            result.error   = f'SBI port not bound ({host}:{port})'
            result.details['transport_state'] = 'refused'
        except OSError as exc:
            result.error   = str(exc)
            result.details['transport_state'] = 'os_error'

        alive = self._monitor.is_nf_alive(self._nf_type)
        result.details['process_alive'] = alive
        result.details['nf_errors']     = self._monitor.recent_errors(10)

        # Memory growth check — warn at 200 MB, trigger restart at 500 MB.
        rss_msg = self._monitor.check_resource_growth(self._nf_type)
        if rss_msg:
            import logging as _logging
            _log = _logging.getLogger(__name__)
            if rss_msg.startswith('CRITICAL:'):
                _log.warning('RSS critical — forcing restart: %s', rss_msg)
                result.is_healthy = False
                result.details['rss_critical'] = True
                result.details['process_alive'] = True
                result.error = rss_msg
            else:
                _log.warning('Resource growth: %s', rss_msg)
                result.details['resource_warning'] = rss_msg

        if not result.is_healthy:
            if not alive:
                result.details['failure_mode'] = 'crash'
            else:
                result.details['failure_mode'] = 'hang'

        return result

    # ── Observation encoding ──────────────────────────────────────────────

    # Deterministic response-type → [0,1] index (stable across runs).
    # Groups: 0=no_response, 0.1=success, 0.2=400, 0.3=rare4xx, 0.4=5xx,
    #         0.6=h2_error, 0.8=timeout/crash  — ordered by "interestingness".
    _RESP_INDEX: Dict[str, float] = {
        'empty':                    0.0,
        'settings_only':            0.05,
        'no_status':                0.08,
        'ok':                       0.10,
        'created':                  0.12,
        'no_content':               0.14,
        'not_found':                0.20,
        'bad_request':              0.25,
        'unauthorized':             0.30,
        'forbidden':                0.33,
        'method_not_allowed':       0.36,
        'conflict':                 0.40,
        'unsupported_media_type':   0.43,
        'unprocessable_entity':     0.46,
        'internal_server_error':    0.60,
        'not_implemented':          0.65,
        'service_unavailable':      0.70,
        'rst_stream':               0.75,
        'goaway':                   0.80,
        'reset':                    0.88,
        'timeout':                  0.92,
        'refused':                  0.95,
    }

    def get_observation_size(self) -> int:
        # [0-4]   last 5 response types (deterministic index, not hash)
        # [5-9]   response type histogram: (2xx, 400, rare4xx, 5xx, h2err) counts
        # [10]    unique response types seen this episode / 10
        # [11]    step progress (step / max_steps)
        # [12]    crash counter (capped at 1)
        # [13]    hang counter (capped at 1)
        # [14]    success counter / 20
        # [15-24] top 10 semantic field values (normalised)
        return 25

    def encode_observation(self, fields: Dict[str, Any],
                           response_history: List[str],
                           counters: Dict[str, int],
                           step: int, max_steps: int) -> List[float]:
        import numpy as np
        obs = np.zeros(25, dtype=np.float32)

        # [0-4] last 5 response types as deterministic float index
        for i, rtype in enumerate(response_history[-5:]):
            obs[i] = self._RESP_INDEX.get(rtype, 0.5)

        # [5-9] response histogram over full episode
        counts = [0, 0, 0, 0, 0]  # 2xx, 400, rare4xx, 5xx, h2/conn
        for rtype in response_history:
            if rtype in ('ok', 'created', 'no_content'):
                counts[0] += 1
            elif rtype == 'bad_request':
                counts[1] += 1
            elif rtype in ('conflict', 'unsupported_media_type',
                           'unprocessable_entity', 'method_not_allowed',
                           'forbidden', 'unauthorized', 'not_found'):
                counts[2] += 1
            elif rtype in ('internal_server_error', 'not_implemented',
                           'service_unavailable'):
                counts[3] += 1
            elif rtype in ('goaway', 'rst_stream', 'reset', 'timeout',
                           'refused', 'no_status', 'settings_only'):
                counts[4] += 1
        total = max(len(response_history), 1)
        for i, c in enumerate(counts):
            obs[5 + i] = c / total

        # [10] unique response types seen / 10
        obs[10] = min(len(set(response_history)) / 10.0, 1.0)

        # [11] episode progress
        obs[11] = step / max(max_steps, 1)

        # [12-14] counters
        obs[12] = min(counters.get('crashes', 0), 1.0)
        obs[13] = min(counters.get('hangs', 0) / 5.0, 1.0)
        obs[14] = min(counters.get('successes', 0) / 20.0, 1.0)

        # [15-24] semantic field values (normalised)
        _FIELD_NORMS: Dict[str, float] = {
            'snssai_sst': 255.0, 'pdu_session_id': 255.0, 'stream_id': 0x7fffffff,
        }
        for i, field_def in enumerate(self.get_semantic_fields()[:10]):
            val = fields.get(field_def.name, 0)
            norm = _FIELD_NORMS.get(field_def.name, 1.0)
            try:
                obs[15 + i] = min(float(val) / norm, 1.0)
            except (TypeError, ValueError):
                obs[15 + i] = 0.5

        return obs.tolist()
