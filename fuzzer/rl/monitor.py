#!/usr/bin/env python3
"""
Generic 5G NF process monitor supporting open5GS and free5GC.

Drop-in replacement for:
  - protocols/ngap/open5gs_monitor.py  (Open5GSMonitor)
  - protocols/sbi/open5gs_sbi_monitor.py  (Open5GsSbiMonitor)

Both adapters now construct NfMonitor(core=...) instead of the core-specific
classes.  The old files are left in place for reference.
"""

import os
import re
import subprocess
import time
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Per-core process name tables
# ---------------------------------------------------------------------------

_PROC_NAMES: Dict[str, Dict[str, str]] = {
    'open5gs': {
        'NRF':  'open5gs-nrfd',
        'AMF':  'open5gs-amfd',
        'SMF':  'open5gs-smfd',
        'UDM':  'open5gs-udmd',
        'UDR':  'open5gs-udrd',
        'PCF':  'open5gs-pcfd',
        'AUSF': 'open5gs-ausfd',
        'BSF':  'open5gs-bsfd',
        'NSSF': 'open5gs-nssfd',
        'UPF':  'open5gs-upfd',
        'CHF':  'open5gs-chfd',
    },
    'free5gc': {
        'NRF':  'nrf',
        'AMF':  'amf',
        'SMF':  'smf',
        'UDM':  'udm',
        'UDR':  'udr',
        'PCF':  'pcf',
        'AUSF': 'ausf',
        'BSF':  'bsf',
        'NSSF': 'nssf',
        'UPF':  'upf',
        'CHF':  'chf',
    },
}

# ---------------------------------------------------------------------------
# Error keywords per core (lines worth collecting from logs)
# ---------------------------------------------------------------------------

_ERROR_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    'open5gs': (
        'Segmentation fault', 'core dumped', 'SIGSEGV', 'SIGABRT', 'Aborted',
        'assert', 'FATAL',
        'ERROR', 'WARNING',
    ),
    'free5gc': (
        'Segmentation fault', 'core dumped', 'SIGSEGV', 'SIGABRT',
        'panic:', 'goroutine', 'runtime error:',
        '[FATA]', '[ERRO]', '[WARN]',
        # Raw Go/SCTP error lines that have no log-level prefix
        'SCTPConn:', 'bad file descriptor', 'connection reset by peer',
    ),
}

# ---------------------------------------------------------------------------
# Background noise patterns per core
# ---------------------------------------------------------------------------

_NOISE_PATTERNS: Dict[str, Tuple[str, ...]] = {
    'open5gs': (
        'Retry registration with NRF',
        "Couldn't connect to server",
        'ogs_sbi_client_handler() failed',
        'nf-sm.c',
    ),
    'free5gc': (
        'Failed to connect to NRF',
        'Retry sending to NRF',
        'NRF registration',
    ),
}

# ---------------------------------------------------------------------------
# Severity weights per core
# ---------------------------------------------------------------------------

_LEVEL_SEVERITY: Dict[str, Dict[str, float]] = {
    'open5gs': {
        'Segmentation fault': 1.00,
        'core dumped':        1.00,
        'SIGSEGV':            1.00,
        'SIGABRT':            1.00,
        'Aborted':            0.95,
        'assert':             0.90,
        'FATAL':              1.00,
        'ERROR':              0.85,
        'WARN':               0.50,
        'WARNING':            0.50,
    },
    'free5gc': {
        'Segmentation fault': 1.00,
        'core dumped':        1.00,
        'SIGSEGV':            1.00,
        'SIGABRT':            1.00,
        'panic:':             1.00,
        'runtime error:':     0.97,
        'nil pointer':        0.95,
        'goroutine':          0.90,
        '[FATA]':             1.00,
        '[ERRO]':             0.85,
        '[WARN]':             0.50,
    },
}

# ---------------------------------------------------------------------------
# Depth patterns — open5GS NGAP
# (copied from protocols/ngap/open5gs_monitor.py _DEPTH_PATTERNS)
# ---------------------------------------------------------------------------

_OPEN5GS_NGAP_DEPTH: List[Tuple[float, str]] = [
    (0.95, 'aper_decode'),
    (0.93, 'tlv_decode'),
    (0.92, 'tlv_build'),
    (0.90, 'Not enough pkbuf'),
    (0.90, 'pkbuf'),
    (0.88, 'ies.c'),
    (0.88, 'decoder.c'),
    (0.87, 'nas-5gs-plain'),
    (0.86, 'ogs_nas_5gs_decode_registration_request'),
    (0.84, 'ogs_nas_5gs_decode_5gs_mobile_identity'),
    (0.85, 'nas-decoder'),
    (0.85, 'nas_5gs_decode'),
    (0.83, 'ogs_nas_5gmm_decode'),
    (0.80, 'Integrity check'),
    (0.78, 'MAC failure'),
    (0.75, 'integrity'),
    (0.73, 'ciphering'),
    (0.70, 'gmm-handler'),
    (0.70, '5gmm-handler'),
    (0.68, 'gmm-sm.c'),
    (0.66, 'gmm_handle_registration_request'),
    (0.68, 'ngap-path'),
    (0.66, 'authentication'),
    (0.65, 'Invalid 5GMM message type'),
    (0.63, 'NIA0'),
    (0.62, 'NEA0 can be used'),
    (0.60, 'security mode'),
    (0.52, 'nas-path.c'),
    (0.57, 'amf-sm'),
    (0.55, 'context.c'),
    (0.48, 'GUTI has already been allocated'),
    (0.53, 'Failed to find'),
    (0.50, 'ngap-handler'),
    (0.48, 'No AMF-UE-NGAP-ID'),
    (0.48, 'No RAN_UE_NGAP_ID'),
    (0.47, 'No NAS_PDU'),
    (0.47, 'No UserLocationInformation'),
    (0.46, 'Invalid AMF_UE_NGAP_ID'),
    (0.45, 'Registration reject'),
    (0.45, 'amf_sbi_send_deactivate_all_ue_in_gnb'),
    (0.45, 'UE context not found'),
    (0.43, 'no_ue_context'),
    (0.42, 'No RAN UE Context'),
    (0.42, 'ran-ue'),
    (0.40, 'AMF-UE'),
    (0.38, 'Cannot find AMF-UE'),
    (0.37, 'Cannot find Served TAI'),
    (0.35, 'Cannot find S_NSSAI'),
    (0.35, 'No TAI'),
    (0.33, 'No PLMN'),
    (0.33, 'No SupportedTAList'),
    (0.31, 'No globalGNB_ID'),
    (0.30, 'No GlobalRANNodeID'),
    (0.29, 'NG-Setup failure'),
    (0.28, 'association'),
    (0.25, 'N2'),
    (0.22, 'SCTP'),
    (0.20, 'ngap-sm.c'),
    (0.15, 'Not implemented'),
    (0.10, 'timer'),
    (0.08, 'sbi-path.c'),
    (0.05, 'nf-sm.c'),
    (0.08, 'sbi'),
    (0.08, 'SBI'),
    # Component fallbacks
    (0.88, '[tlv]'),
    (0.82, '[nas]'),
    (0.72, '[gmm]'),
    (0.50, '[ngap]'),
    (0.42, '[amf]'),
    (0.30, '[mem]'),
    (0.25, '[event]'),
    (0.20, '[sctp]'),
    (0.15, '[sock]'),
    (0.08, '[sbi]'),
    (0.05, '[app]'),
]

# ---------------------------------------------------------------------------
# Depth patterns — open5GS SBI
# (copied from protocols/sbi/open5gs_sbi_monitor.py _DEPTH_PATTERNS)
# ---------------------------------------------------------------------------

_OPEN5GS_SBI_DEPTH: List[Tuple[float, str]] = [
    (0.95, 'ogs_json_'),
    (0.93, 'json_parse'),
    (0.93, 'ogs_yaml_'),
    (0.92, 'cJSON_Parse'),
    (0.90, 'ogs_sbi_body_'),
    (0.90, 'sbi_message'),
    (0.88, 'OpenAPI_'),
    (0.87, 'ogs_sbi_response_'),
    (0.86, 'ogs_sbi_request_'),
    (0.85, 'ogs_sbi_header_'),
    (0.84, 'MandatoryIeMissing'),
    (0.83, 'MandatoryFieldMissing'),
    (0.82, 'InvalidMandatoryParameter'),
    (0.88, 'ogs_nas_5gs_decode'),
    (0.87, 'nas-5gs-plain'),
    (0.86, 'ogs_nas_5gmm_decode'),
    (0.85, 'nas-decoder'),
    (0.80, 'nrf-handler'),
    (0.78, 'nrf-sm'),
    (0.76, 'amf-handler'),
    (0.75, 'smf-handler'),
    (0.74, 'udm-handler'),
    (0.72, 'sbi-handler'),
    (0.70, 'gmm-handler'),
    (0.68, 'gmm-sm'),
    (0.66, 'smf-sm'),
    (0.64, 'nrf-context'),
    (0.62, 'smf-context'),
    (0.60, 'amf-context'),
    (0.75, 'HTTP2_PROTOCOL_ERROR'),
    (0.73, 'h2_error'),
    (0.72, 'nghttp2_'),
    (0.70, 'GOAWAY'),
    (0.68, 'RST_STREAM'),
    (0.57, 'nf-instance'),
    (0.55, 'sbi-path'),
    (0.53, 'nf-type'),
    (0.52, 'PLMN mismatch'),
    (0.50, 'S-NSSAI mismatch'),
    (0.50, 'DNN'),
    (0.48, 'PDU Session'),
    (0.47, 'UE context'),
    (0.47, 'SUPI'),
    (0.45, 'subscription'),
    (0.43, 'Invalid nfType'),
    (0.35, 'sbi connect'),
    (0.33, 'sbi server'),
    (0.31, 'HTTP/2 connection'),
    (0.30, 'TLS'),
    (0.28, 'TCP'),
    (0.20, 'nf-sm.c'),
    (0.15, 'Not implemented'),
    (0.10, 'timer'),
    (0.08, 'heartbeat'),
    (0.05, 'health-check'),
    # Component fallbacks
    (0.90, '[sbi]'),
    (0.85, '[nas]'),
    (0.80, '[smf]'),
    (0.80, '[nrf]'),
    (0.78, '[amf]'),
    (0.75, '[udm]'),
    (0.72, '[pcf]'),
    (0.70, '[ausf]'),
    (0.60, '[ngap]'),
    (0.55, '[gmm]'),
    (0.45, '[tlv]'),
    (0.35, '[mem]'),
    (0.25, '[event]'),
    (0.20, '[sock]'),
    (0.15, '[app]'),
]

# ---------------------------------------------------------------------------
# Depth patterns — free5GC NGAP
# ---------------------------------------------------------------------------

_FREE5GC_NGAP_DEPTH: List[Tuple[float, str]] = [
    # Go runtime crash
    (0.97, 'panic:'),
    (0.96, 'runtime error:'),
    (0.95, 'nil pointer dereference'),
    (0.94, 'index out of range'),
    (0.93, 'slice bounds out of range'),
    (0.90, 'goroutine'),
    # APER / ASN.1 decode
    (0.90, '[Aper]'),
    (0.88, 'aper'),
    # NAS layer
    (0.86, '[Nas5GS]'),
    (0.84, '[Nas]'),
    (0.82, 'NAS'),
    # GMM handler
    (0.78, '[Gmm]'),
    (0.76, 'GMM'),
    (0.74, 'HandleRegistrationRequest'),
    (0.72, 'HandleAuthenticationResponse'),
    (0.70, 'HandleSecurityModeComplete'),
    (0.68, 'HandleDeregistrationRequest'),
    (0.66, 'HandleServiceRequest'),
    # NGAP handler
    (0.62, '[Ngap]'),
    (0.60, 'NGAP'),
    (0.58, 'HandleNGSetupRequest'),
    (0.56, 'HandleInitialUEMessage'),
    (0.54, 'HandleUplinkNASTransport'),
    (0.52, 'HandleUEContextReleaseRequest'),
    (0.50, 'HandlePDUSessionResourceSetupResponse'),
    # AMF context / UE context
    (0.50, 'UE Context'),
    (0.48, 'AmfUe'),
    (0.46, 'RanUe'),
    (0.45, 'SUPI'),
    (0.44, 'PDU Session'),
    (0.42, 'FindAmfUe'),
    (0.40, 'FindRanUe'),
    # AMF general
    (0.38, '[AMF]'),
    (0.36, '[Amf]'),
    # Consumer / SBI calls from AMF
    (0.30, '[Consumer]'),
    # Connection / transport
    (0.25, 'Association'),
    (0.22, 'SCTP'),
    (0.22, 'SCTPConn'),
    (0.20, 'N2'),
    # Background
    (0.10, 'NRF'),
    (0.08, 'Failed to connect'),
]

# ---------------------------------------------------------------------------
# Depth patterns — free5GC SBI
# ---------------------------------------------------------------------------

_FREE5GC_SBI_DEPTH: List[Tuple[float, str]] = [
    # Go runtime crash
    (0.97, 'panic:'),
    (0.96, 'runtime error:'),
    (0.95, 'nil pointer dereference'),
    (0.94, 'index out of range'),
    (0.93, 'slice bounds out of range'),
    (0.90, 'goroutine'),
    # SBI / JSON deep paths
    (0.88, 'json'),
    (0.86, 'unmarshal'),
    (0.85, 'Marshal'),
    (0.84, 'OpenAPI'),
    (0.82, 'MandatoryFieldMissing'),
    (0.80, 'InvalidFormat'),
    (0.78, 'InvalidParam'),
    # NF-specific handlers
    (0.76, '[NRF]'),
    (0.75, '[Nrf]'),
    (0.72, '[SMF]'),
    (0.72, '[Smf]'),
    (0.70, '[AMF]'),
    (0.70, '[Amf]'),
    (0.68, '[UDM]'),
    (0.66, '[UDR]'),
    (0.65, '[PCF]'),
    (0.64, '[AUSF]'),
    # Application-level errors
    (0.60, 'SUPI'),
    (0.58, 'NF Instance'),
    (0.56, 'PDU Session'),
    (0.54, 'PLMN'),
    (0.52, 'S-NSSAI'),
    (0.50, 'subscription'),
    # SBI routing / HTTP
    (0.45, 'ResourceNotFound'),
    (0.42, 'MethodNotAllowed'),
    (0.40, 'UnsupportedMediaType'),
    # Transport
    (0.30, 'http2'),
    (0.28, 'GOAWAY'),
    (0.25, 'RST_STREAM'),
    (0.20, 'TLS'),
    # Background
    (0.10, 'Failed to connect'),
    (0.08, 'heartbeat'),
]

_DEPTH_PATTERNS: Dict[str, Dict[str, List[Tuple[float, str]]]] = {
    'open5gs': {'ngap': _OPEN5GS_NGAP_DEPTH, 'sbi': _OPEN5GS_SBI_DEPTH},
    'free5gc':  {'ngap': _FREE5GC_NGAP_DEPTH, 'sbi': _FREE5GC_SBI_DEPTH},
}

# ---------------------------------------------------------------------------
# Crash-signature regexes per core
# ---------------------------------------------------------------------------

_ANSI_ESC = re.compile(r'\x1b\[[0-9;]*m')

# File:line extraction regexes for AFL-style source coverage tracking.
# open5GS: "message.c:1381" or "(../lib/sbi/message.c:1381)"
_OPEN5GS_FILE_LINE_RE = re.compile(r'([a-zA-Z0-9_-]+\.c):(\d+)')
# free5GC: "[handler/management.go:87]" or "consumer/nf_management.go:87"
_FREE5GC_FILE_LINE_RE = re.compile(r'([a-zA-Z0-9_/.-]+\.go):(\d+)')

_FATAL_SKIP: Dict[str, re.Pattern] = {
    'open5gs': re.compile(r'backtrace\(\) returned|ogs_abort\b', re.IGNORECASE),
    'free5gc':  re.compile(r'^$'),  # nothing to skip in free5GC goroutine dumps
}

_FATAL_RE: Dict[str, re.Pattern] = {
    'open5gs': re.compile(
        r'FATAL[:\s]+(.+?)\s*$|'
        r'(Assertion.+?failed[^)]*\))|'
        r'(Segmentation fault|SIGSEGV|SIGABRT|Aborted|core dumped)',
        re.IGNORECASE,
    ),
    'free5gc': re.compile(
        r'panic:\s*(.+?)\s*$|'
        r'(runtime error:\s*.+?)\s*$|'
        r'(nil pointer dereference|index out of range|slice bounds out of range)|'
        r'(Segmentation fault|SIGSEGV|SIGABRT)',
        re.IGNORECASE,
    ),
}


# ---------------------------------------------------------------------------
# NfMonitor
# ---------------------------------------------------------------------------

class NfMonitor:
    """Unified 5G NF process and log monitor for open5GS and free5GC.

    Presents the same interface as the legacy Open5GSMonitor /
    Open5GsSbiMonitor classes so adapters can use it without changes to
    their call sites.
    """

    OPEN5GS = 'open5gs'
    FREE5GC  = 'free5gc'

    def __init__(self,
                 core:        str = 'open5gs',
                 primary_nf:  str = 'AMF',
                 log_path:    Optional[str] = None,
                 extra_nfs:   Optional[List[str]] = None,
                 protocol:    str = 'ngap',
                 bin_dir:     Optional[str] = None,
                 gcov_gcda_dir: Optional[str] = None,
                 gcov_src_dir:  Optional[str] = None):
        if core not in (self.OPEN5GS, self.FREE5GC):
            raise ValueError(f"Unknown core '{core}'. Use 'open5gs' or 'free5gc'.")
        if protocol not in ('ngap', 'sbi'):
            raise ValueError(f"Unknown protocol '{protocol}'. Use 'ngap' or 'sbi'.")

        self._core       = core
        self._primary_nf = primary_nf.upper()
        self._extra_nfs  = [n.upper() for n in (extra_nfs or [])]
        self._all_nfs    = [self._primary_nf] + self._extra_nfs
        self._protocol   = protocol
        self._bin_dir    = bin_dir  # free5GC bin/ path for specific pgrep

        # gcov coverage mode (open5GS only, requires --gcov build + gcov_ctrl.so)
        # gcov_gcda_dir: BUILD_DIR/src (where .gcda files are written at runtime)
        # gcov_src_dir:  open5GS source root (for gcovr --root)
        self._gcov_gcda_dir = gcov_gcda_dir
        self._gcov_src_dir  = gcov_src_dir
        # Per-episode gcov coverage set (file, lineno) — cleared in reset_episode()
        self._gcov_line_coverage: Set[Tuple[str, int]] = set()

        # Select per-core tables
        self._error_kw    = _ERROR_KEYWORDS[core]
        self._noise       = _NOISE_PATTERNS[core]
        self._severity    = _LEVEL_SEVERITY[core]
        self._depth_pats  = _DEPTH_PATTERNS[core][protocol]
        self._fatal_skip  = _FATAL_SKIP[core]
        self._fatal_re    = _FATAL_RE[core]

        # Log path: caller-supplied > default derivation
        if log_path:
            self._log_path = log_path
        elif core == self.OPEN5GS:
            self._log_path = f'/var/log/open5gs/{primary_nf.lower()}.log'
        else:
            self._log_path = f'/tmp/free5gc-logs/{primary_nf.lower()}.log'

        # Novelty / frequency tracking for anomaly_score.
        # Both are per-episode: reset at each episode boundary so the reward
        # signal stays stationary across training.  Persisting them across
        # episodes causes freq_factor to collapse to ~0 after hundreds of
        # episodes of the same WARN lines, killing the learning signal.
        self._seen_errors: Set[str] = set()
        self._error_freq:  Dict[str, int] = {}
        # AFL-style source coverage: (basename, lineno) pairs seen this episode.
        # Cleared each episode so the coverage bonus stays informative throughout training.
        self._file_line_coverage: Set[Tuple[str, int]] = set()
        # RSS baseline per NF for memory growth detection (key=NF name, val=MB)
        self._rss_baseline_mb: Dict[str, Optional[float]] = {}

    # ── Process name lookup ───────────────────────────────────────────────

    def _proc_name(self, nf: Optional[str] = None) -> str:
        nf = (nf or self._primary_nf).upper()
        return _PROC_NAMES[self._core].get(nf, nf.lower())

    # ── Process alive checks ──────────────────────────────────────────────

    def _pgrep_alive(self, nf: str) -> bool:
        """Return True if the NF process is running."""
        nf_up = nf.upper()
        try:
            if self._core == self.FREE5GC and self._bin_dir:
                bin_path = os.path.join(self._bin_dir, nf_up.lower())
                r = subprocess.run(
                    ['pgrep', '-f', bin_path],
                    capture_output=True, timeout=2,
                )
            else:
                proc = self._proc_name(nf_up)
                r = subprocess.run(
                    ['pgrep', '-x', proc],
                    capture_output=True, timeout=2,
                )
            return r.returncode == 0
        except Exception:
            return False

    def is_alive(self, nf: Optional[str] = None) -> bool:
        return self._pgrep_alive(nf or self._primary_nf)

    # Aliases used by NGAP adapter
    def is_amf_alive(self) -> bool:
        return self.is_alive(self._primary_nf)

    # Aliases used by SBI adapter
    def is_nf_alive(self, nf: Optional[str] = None) -> bool:
        return self.is_alive(nf or self._primary_nf)

    def detect_crash(self) -> bool:
        """True if any monitored NF process has stopped."""
        return any(not self.is_alive(nf) for nf in self._all_nfs)

    # ── Process termination ───────────────────────────────────────────────

    def kill(self, nf: Optional[str] = None,
             grace_seconds: float = 3.0) -> bool:
        nf = (nf or self._primary_nf).upper()
        if not self.is_alive(nf):
            return True
        proc = self._proc_name(nf)
        try:
            if self._core == self.FREE5GC and self._bin_dir:
                bin_path = os.path.join(self._bin_dir, nf.lower())
                subprocess.run(['pkill', '-TERM', '-f', bin_path],
                               capture_output=True, timeout=5)
            else:
                subprocess.run(['pkill', '-TERM', '-x', proc],
                               capture_output=True, timeout=5)
        except Exception:
            pass
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            time.sleep(0.5)
            if not self.is_alive(nf):
                return True
        try:
            if self._core == self.FREE5GC and self._bin_dir:
                subprocess.run(['pkill', '-KILL', '-f',
                                os.path.join(self._bin_dir, nf.lower())],
                               capture_output=True, timeout=5)
            else:
                subprocess.run(['pkill', '-KILL', '-x', proc],
                               capture_output=True, timeout=5)
            time.sleep(1.0)
        except Exception:
            pass
        return not self.is_alive(nf)

    # Aliases
    def kill_amf(self, grace_seconds: float = 3.0) -> bool:
        return self.kill(self._primary_nf, grace_seconds)

    def kill_nf(self, nf: Optional[str] = None,
                grace_seconds: float = 3.0) -> bool:
        return self.kill(nf, grace_seconds)

    def reset_episode(self) -> None:
        """Reset per-episode novelty and frequency counters.

        Must be called at each RL episode boundary (env.reset()).  Without
        this, freq_factor collapses to ~0 after hundreds of episodes of the
        same WARN lines, making the anomaly_score near-zero and killing the
        learning signal.
        """
        self._seen_errors.clear()
        self._error_freq.clear()
        self._file_line_coverage.clear()
        # _gcov_line_coverage intentionally NOT cleared here — it is campaign-scoped,
        # not episode-scoped.  Clearing it every episode makes every episode "discover"
        # the same ~576 lines and the campaign total never grows.
        # It is reset only in gcov_campaign_reset() at the start of a new campaign.

    # ── Resource monitoring ───────────────────────────────────────────────

    def _get_nf_pid(self, nf: Optional[str] = None) -> Optional[int]:
        """Return the PID of the NF process, or None if not running."""
        nf = (nf or self._primary_nf).upper()
        try:
            if self._core == self.FREE5GC and self._bin_dir:
                bin_path = os.path.join(self._bin_dir, nf.lower())
                r = subprocess.run(['pgrep', '-f', bin_path],
                                   capture_output=True, text=True, timeout=2)
            else:
                proc = self._proc_name(nf)
                r = subprocess.run(['pgrep', '-x', proc],
                                   capture_output=True, text=True, timeout=2)
            if r.returncode == 0:
                return int(r.stdout.strip().split('\n')[0])
        except Exception:
            pass
        return None

    def get_nf_rss_mb(self, nf: Optional[str] = None) -> Optional[float]:
        """Return resident set size in MB for the NF process, or None."""
        pid = self._get_nf_pid(nf)
        if pid is None:
            return None
        try:
            with open(f'/proc/{pid}/status') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        return int(line.split()[1]) / 1024.0
        except Exception:
            pass
        return None

    def get_nf_fd_count(self, nf: Optional[str] = None) -> Optional[int]:
        """Return open file-descriptor count for the NF process, or None."""
        pid = self._get_nf_pid(nf)
        if pid is None:
            return None
        try:
            return len(os.listdir(f'/proc/{pid}/fd'))
        except Exception:
            return None

    def check_resource_growth(self, nf: Optional[str] = None,
                               rss_warn_mb: float = 200.0,
                               rss_restart_mb: float = 500.0) -> Optional[str]:
        """Return a message if RSS has grown beyond a threshold since baseline.

        First call sets the baseline; subsequent calls compare against it.
        Returns None when growth is within rss_warn_mb.
        Returns a string starting with "CRITICAL: " when growth exceeds
        rss_restart_mb — the caller should treat this as a restart trigger.
        """
        nf = (nf or self._primary_nf).upper()
        rss = self.get_nf_rss_mb(nf)
        if rss is None:
            return None
        baseline = self._rss_baseline_mb.get(nf)
        if baseline is None:
            self._rss_baseline_mb[nf] = rss
            return None
        growth = rss - baseline
        if growth <= rss_warn_mb:
            return None
        fds = self.get_nf_fd_count(nf)
        fd_str = f', {fds} open fds' if fds is not None else ''
        msg = (f'{nf} RSS grew {growth:.0f} MB '
               f'({baseline:.0f} → {rss:.0f} MB{fd_str})')
        if growth > rss_restart_mb:
            # Reset baseline so the next restart gets a fresh reference point.
            self._rss_baseline_mb[nf] = None
            return f'CRITICAL: {msg}'
        return msg

    # ── Log helpers ───────────────────────────────────────────────────────

    def _tail_log(self, n: int, log_path: Optional[str] = None) -> List[str]:
        path = log_path or self._log_path
        if not os.path.exists(path):
            return []
        try:
            r = subprocess.run(
                ['tail', '-n', str(n), path],
                capture_output=True, text=True, timeout=2,
            )
            return r.stdout.splitlines()
        except Exception:
            return []

    def _is_error_line(self, line: str) -> bool:
        return (any(k in line for k in self._error_kw)
                and not any(p in line for p in self._noise))

    def recent_errors(self, n: int = 30) -> List[str]:
        return [l for l in self._tail_log(n) if self._is_error_line(l)]

    def recent_logs_by_level(self, n: int = 30) -> Dict[str, List[str]]:
        buckets: Dict[str, List[str]] = {'fatal': [], 'error': [], 'warn': []}
        if self._core == self.OPEN5GS:
            fatal_kw = {'FATAL', 'assert', 'Segmentation fault', 'core dumped',
                        'SIGSEGV', 'SIGABRT', 'Aborted'}
            for line in self._tail_log(n):
                if any(k in line for k in fatal_kw):
                    buckets['fatal'].append(line)
                elif 'ERROR' in line:
                    buckets['error'].append(line)
                elif 'WARNING' in line or 'WARN' in line:
                    buckets['warn'].append(line)
        else:  # free5GC
            for line in self._tail_log(n):
                if any(k in line for k in ('[FATA]', 'panic:', 'runtime error:',
                                            'nil pointer', 'SIGSEGV', 'SIGABRT')):
                    buckets['fatal'].append(line)
                elif '[ERRO]' in line:
                    buckets['error'].append(line)
                elif '[WARN]' in line:
                    buckets['warn'].append(line)
        return buckets

    def snapshot_log_position(self) -> int:
        if not os.path.exists(self._log_path):
            return 0
        try:
            return os.path.getsize(self._log_path)
        except OSError:
            return 0

    def lines_since_snapshot(self, offset: int) -> List[str]:
        if not os.path.exists(self._log_path):
            return []
        try:
            with open(self._log_path, 'rb') as f:
                f.seek(offset)
                raw = f.read()
            lines = raw.decode('utf-8', errors='replace').splitlines()
            # free5GC writes each event twice: structured (time="...") then bracket
            # ([WARN][AMF][Ngap]...).  Drop the structured duplicates so depth
            # patterns (which match bracket tokens like [Ngap]) work on all lines.
            if self._core == self.FREE5GC:
                lines = [l for l in lines if not l.startswith('time="')]
            return lines
        except OSError:
            return []

    def get_crash_signature(self, n: int = 150) -> str:
        for line in reversed(self._tail_log(n)):
            clean = _ANSI_ESC.sub('', line)
            if self._fatal_skip.search(clean):
                continue
            m = self._fatal_re.search(clean)
            if m:
                sig = next(g for g in m.groups() if g)
                return sig.strip()
        return 'unknown'

    def get_stack_trace(self, n: int = 150) -> List[str]:
        if self._core == self.OPEN5GS:
            fatal_kw = ('FATAL', 'Assertion', 'SIGSEGV', 'SIGABRT', 'Aborted',
                        'Segmentation fault', 'core dumped', 'ERROR')
        else:
            fatal_kw = ('[FATA]', '[ERRO]', 'panic:', 'runtime error:',
                        'goroutine', 'SIGSEGV', 'SIGABRT')
        lines = []
        for line in self._tail_log(n):
            clean = _ANSI_ESC.sub('', line)
            if any(k in clean for k in fatal_kw):
                lines.append(clean.strip())
        return lines[-30:]

    # ── Depth / severity scoring ──────────────────────────────────────────

    def _line_depth(self, line: str) -> float:
        for score, pattern in self._depth_pats:
            if pattern in line:
                return score
        return 0.05

    def max_depth_reached(self, lines: Optional[List[str]] = None) -> float:
        """Return the highest depth score seen across ALL log lines (INFO + WARN + ERRO).

        Unlike anomaly_score, this does not filter to error lines — it scans every
        line so that successful protocol progression logged at INFO level is visible.
        Use this as the 'how deep did we get' signal; use anomaly_score for 'how
        broken was it at that depth'.
        """
        if lines is None:
            lines = self._tail_log(50)
        best = 0.05
        for line in lines:
            # Skip structured-format duplicate lines (free5GC logs each event twice)
            if self._core == self.FREE5GC and line.startswith('time="'):
                continue
            d = self._line_depth(_ANSI_ESC.sub('', line))
            if d > best:
                best = d
        return best

    def _line_severity(self, line: str) -> float:
        """Return severity weight for one log line."""
        if self._core == self.OPEN5GS:
            for kw in ('Segmentation fault', 'core dumped', 'SIGSEGV', 'SIGABRT',
                       'Aborted', 'assert', 'FATAL'):
                if kw in line:
                    return self._severity.get(kw, 1.0)
            for kw in ('ERROR', 'WARNING'):
                if f'] {kw}:' in line:
                    return self._severity.get(kw, 0.50)
            return 0.40
        else:  # free5GC
            for kw in ('panic:', 'runtime error:', 'nil pointer', 'SIGSEGV', 'SIGABRT'):
                if kw in line:
                    return self._severity.get(kw, 1.0)
            for token in ('[FATA]', '[ERRO]', '[WARN]'):
                if token in line:
                    return self._severity.get(token, 0.50)
            return 0.40

    # ── Composite anomaly score ───────────────────────────────────────────

    def anomaly_score(self, lines: Optional[List[str]] = None) -> float:
        """Return composite anomaly score [0.0, 1.0].

        Algorithm (same as Open5GsSbiMonitor):
          1. depth × severity × freq_factor per error line
          2. Sum top-3 distinct depth buckets (weights 1.0, 0.5, 0.25)
          3. +0.15 novelty bonus for any first-ever unique error signature
          4. Capped at 0.95 (1.0 reserved for process crash)
        """
        if self.detect_crash():
            return 1.0

        if lines is None:
            errors = self.recent_errors()
        else:
            errors = [l for l in lines if self._is_error_line(l)]

        if not errors:
            return 0.0

        bucket_scores: Dict[float, float] = {}
        novel = False
        for line in errors:
            depth    = self._line_depth(line)
            severity = self._line_severity(line)
            sig      = line[-80:].strip()

            freq = self._error_freq.get(sig, 0)
            self._error_freq[sig] = freq + 1
            freq_factor = 1.0 / (1.0 + freq * 0.4)

            weighted = depth * severity * freq_factor
            bucket   = round(depth, 1)
            if weighted > bucket_scores.get(bucket, 0.0):
                bucket_scores[bucket] = weighted

            if sig not in self._seen_errors:
                novel = True
                self._seen_errors.add(sig)

        top3    = sorted(bucket_scores.values(), reverse=True)[:3]
        weights = [1.0, 0.5, 0.25]
        score   = sum(w * s for w, s in zip(weights, top3))
        score  += 0.15 if novel else 0.0
        return min(score, 0.95)

    # ── File:line coverage (AFL-style at log level) ───────────────────────

    def new_file_lines(self, lines: List[str]) -> List[Tuple[str, int]]:
        """Return (filename, lineno) pairs newly seen in *lines* this episode.

        Extracts source locations from NF log output using per-core patterns:
          open5GS: ``message.c:1381``  (C source file:line)
          free5GC: ``management.go:87``  (Go source file:line)

        Only locations not previously seen this episode are returned and added
        to the coverage set.  Call reset_episode() to clear between episodes.
        """
        newly_seen: List[Tuple[str, int]] = []
        pattern = (_OPEN5GS_FILE_LINE_RE if self._core == self.OPEN5GS
                   else _FREE5GC_FILE_LINE_RE)
        for line in lines:
            clean = _ANSI_ESC.sub('', line)
            for m in pattern.finditer(clean):
                # Normalise to basename so ../lib/sbi/message.c and message.c
                # map to the same coverage key.
                fname = os.path.basename(m.group(1))
                loc: Tuple[str, int] = (fname, int(m.group(2)))
                if loc not in self._file_line_coverage:
                    self._file_line_coverage.add(loc)
                    newly_seen.append(loc)
        return newly_seen

    @property
    def file_line_coverage_count(self) -> int:
        """Number of distinct (file, line) locations seen this episode."""
        return len(self._file_line_coverage)

    # ── gcov-based coverage (open5GS --gcov build + gcov_ctrl.so) ────────

    def gcov_campaign_reset(self, nf: Optional[str] = None) -> bool:
        """Initialise _gcov_line_coverage with the current on-disk baseline.

        Must be called at the START of each fuzzing campaign (not between episodes).

        Strategy — no file deletion or zeroing (avoids lcov version quirks and root
        permission issues).  Instead:
          1. Read whatever .gcda data exists from previous runs.
          2. Pre-populate _gcov_line_coverage with those lines so they are treated
             as "already seen" — only code paths newly reached DURING this campaign
             will earn gcov rewards.
          3. Send SIGUSR1 to clear in-memory counters so the first request starts clean.
        """
        if not self._gcov_gcda_dir:
            return False

        # Baseline: absorb all previously covered lines so they don't earn rewards
        baseline_path = self._gcov_src_dir or self._gcov_gcda_dir
        try:
            covered = self._gcov_read_covered_lines(baseline_path)
            self._gcov_line_coverage = set(covered)
        except Exception:
            self._gcov_line_coverage.clear()

        # Clear in-memory counters so the first request's dump is clean
        self.gcov_reset(nf)
        return True

    # Path to the dedicated gcov signal wrapper installed via:
    #   sudo install -m 755 scripts/gcov_signal.sh /usr/local/bin/open5gs-gcov-signal
    #   echo "$USER ALL=(root) NOPASSWD: /usr/local/bin/open5gs-gcov-signal" \
    #     | sudo tee /etc/sudoers.d/open5gs-gcov
    _GCOV_SIGNAL_HELPER = '/usr/local/bin/open5gs-gcov-signal'

    def _send_signal(self, pid: int, sig: int) -> bool:
        """Send *sig* to *pid*, with two privilege-escalation fallbacks.

        NF processes run as root (started via ``sudo open5gs.sh start --gcov``).
        When the fuzzer runs as a regular user, ``os.kill`` raises PermissionError.

        Fallback order:
          1. os.kill (works when fuzzer runs as root or same user as NF)
          2. sudo -n open5gs-gcov-signal <sig> <pid>  (requires sudoers entry)
          3. sudo -n kill -<sig> <pid>                (requires broad sudo kill)
        """
        try:
            os.kill(pid, sig)
            return True
        except PermissionError:
            pass
        except OSError:
            return False

        # Fallback 1: dedicated gcov signal helper (narrow sudoers rule)
        if os.path.exists(self._GCOV_SIGNAL_HELPER):
            try:
                r = subprocess.run(
                    ['sudo', '-n', self._GCOV_SIGNAL_HELPER, str(sig), str(pid)],
                    capture_output=True, timeout=3,
                )
                if r.returncode == 0:
                    return True
            except Exception:
                pass

        # Fallback 2: generic sudo kill (works if user has broad passwordless sudo)
        try:
            r = subprocess.run(
                ['sudo', '-n', 'kill', f'-{sig}', str(pid)],
                capture_output=True, timeout=3,
            )
            return r.returncode == 0
        except Exception:
            return False

    def gcov_reset(self, nf: Optional[str] = None) -> bool:
        """Send SIGUSR1 → __gcov_reset() clears in-memory gcov counters.

        Call immediately BEFORE a fuzz request for per-request coverage isolation.
        Requires the NF to have been started with LD_PRELOAD=gcov_ctrl.so.
        """
        import signal as _signal
        pid = self._get_nf_pid(nf)
        if pid is None:
            return False
        return self._send_signal(pid, _signal.SIGUSR1)

    def gcov_dump(self, nf: Optional[str] = None) -> bool:
        """Send SIGUSR2 → __gcov_dump() flushes gcov counters to .gcda files.

        Call immediately AFTER a fuzz request, then gcov_new_lines() to read coverage.
        """
        import signal as _signal
        pid = self._get_nf_pid(nf)
        if pid is None:
            return False
        return self._send_signal(pid, _signal.SIGUSR2)

    def gcov_new_lines(self,
                       nf_filter: Optional[str] = None,
                       dump_first: bool = False,
                       wait_ms: int = 80,
                       eval_every: int = 1) -> List[Tuple[str, int]]:
        """Return (filename, lineno) pairs newly covered since campaign start.

        _gcov_line_coverage is campaign-scoped (not episode-scoped) — it grows
        monotonically until gcov_campaign_reset() is called at the next campaign start.

        Args:
            nf_filter:   Source subdirectory to restrict coverage to, e.g. "src/nrf".
            dump_first:  If True, send SIGUSR2 before reading (always done so .gcda
                         stays current even on skipped lcov steps).
            wait_ms:     Milliseconds to wait after dump before reading .gcda files.
            eval_every:  Run the expensive lcov capture only every N calls.
                         On skipped calls SIGUSR2 is still sent so .gcda accumulates,
                         but lcov is not invoked.  Use 5–10 to reduce overhead ~5–10×
                         with minimal loss of signal resolution.
        """
        if not self._gcov_gcda_dir or not self._gcov_src_dir:
            return []

        # Always dump so .gcda stays current, even when we skip the lcov read.
        if dump_first:
            self.gcov_dump()

        # Rate-limit the expensive lcov capture.
        self._gcov_eval_counter = getattr(self, '_gcov_eval_counter', 0) + 1
        if self._gcov_eval_counter % eval_every != 0:
            return []

        if wait_ms > 0:
            time.sleep(wait_ms / 1000.0)

        filter_path = (os.path.join(self._gcov_src_dir, nf_filter)
                       if nf_filter else self._gcov_src_dir)

        try:
            covered = self._gcov_read_covered_lines(filter_path)
        except Exception:
            return []

        newly_seen: List[Tuple[str, int]] = []
        for fname, lineno in covered:
            loc = (fname, lineno)
            if loc not in self._gcov_line_coverage:
                self._gcov_line_coverage.add(loc)
                newly_seen.append(loc)
        return newly_seen

    def _gcov_read_covered_lines(self, filter_path: str) -> List[Tuple[str, int]]:
        """Run lcov and return all (basename, lineno) with execution count > 0."""
        import tempfile
        fd, info_file = tempfile.mkstemp(suffix='.info', prefix='nf_gcov_')
        os.close(fd)
        try:
            r = subprocess.run(
                [
                    'lcov', '--capture',
                    '--directory',      self._gcov_gcda_dir,
                    '--base-directory', self._gcov_src_dir,
                    '--output-file',    info_file,
                    '--gcov-tool',      'gcov',
                    '--ignore-errors',  'source,gcov',
                    '--parallel',       # lcov 2.x: run gcov instances concurrently
                ],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                return []

            # Filter to NF-specific source directory when requested
            if filter_path != self._gcov_src_dir:
                rel = os.path.relpath(filter_path, self._gcov_src_dir)
                subprocess.run(
                    ['lcov', '--extract', info_file, f'*/{rel}/*',
                     '--output-file', info_file],
                    capture_output=True, text=True, timeout=10,
                )

            return self._parse_lcov_info(info_file)
        finally:
            try:
                os.unlink(info_file)
            except OSError:
                pass

    def _parse_lcov_info(self, info_file: str) -> List[Tuple[str, int]]:
        """Parse lcov .info file; return (basename, lineno) pairs with count > 0."""
        covered: List[Tuple[str, int]] = []
        current_file = ''
        try:
            with open(info_file) as f:
                for raw in f:
                    line = raw.rstrip()
                    if line.startswith('SF:'):
                        current_file = os.path.basename(line[3:])
                    elif line.startswith('DA:') and current_file:
                        parts = line[3:].split(',')
                        if len(parts) >= 2:
                            try:
                                lineno = int(parts[0])
                                count  = int(parts[1])
                                if count > 0:
                                    covered.append((current_file, lineno))
                            except ValueError:
                                pass
        except OSError:
            pass
        return covered

    @property
    def gcov_coverage_count(self) -> int:
        """Number of distinct (file, line) locations covered by gcov this episode."""
        return len(self._gcov_line_coverage)
