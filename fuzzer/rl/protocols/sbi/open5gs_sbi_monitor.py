#!/usr/bin/env python3
"""
open5GS SBI NF process monitor.

Monitors AMF, SMF, NRF, UDM and other NF processes and their log files
during SBI fuzzing.  Follows the same pattern as ngap/open5gs_monitor.py
but targets the SBI / HTTP2 code paths instead of NGAP / N2.

Log format: "MM/DD HH:MM:SS.mmm: [domain] LEVEL: message (file.c:N)"
"""

import os
import re
import subprocess
import time
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# NF process table  (maps NF type → process name + default log path)
# ---------------------------------------------------------------------------

NF_PROCESSES: Dict[str, Dict[str, str]] = {
    'NRF':  {'proc': 'open5gs-nrfd',  'log': '/var/log/open5gs/nrf.log'},
    'AMF':  {'proc': 'open5gs-amfd',  'log': '/var/log/open5gs/amf.log'},
    'SMF':  {'proc': 'open5gs-smfd',  'log': '/var/log/open5gs/smf.log'},
    'UDM':  {'proc': 'open5gs-udmd',  'log': '/var/log/open5gs/udm.log'},
    'UDR':  {'proc': 'open5gs-udrd',  'log': '/var/log/open5gs/udr.log'},
    'PCF':  {'proc': 'open5gs-pcfd',  'log': '/var/log/open5gs/pcf.log'},
    'AUSF': {'proc': 'open5gs-ausfd', 'log': '/var/log/open5gs/ausf.log'},
}

# All keywords that flag a line as worth collecting from any NF log.
ERROR_KEYWORDS = (
    # OS-level crash signals
    'Segmentation fault', 'core dumped', 'SIGSEGV', 'SIGABRT', 'Aborted',
    # open5GS internal assertions
    'assert', 'FATAL',
    # open5GS structured log levels
    'ERROR', 'WARNING',
)

# Lines that are constant background noise when NRF is not running.
# Filtered before scoring so they don't fill the tail window.
_NOISE_PATTERNS = (
    'Retry registration with NRF',
    "Couldn't connect to server",
    'ogs_sbi_client_handler() failed',
    'nf-sm.c',
)

# Severity weights per log-level keyword
_LEVEL_SEVERITY: Dict[str, float] = {
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
}

# ---------------------------------------------------------------------------
# Depth patterns for SBI code paths
#
# Calibrated against open5GS NRF / AMF / SMF log output during SBI fuzzing.
# Two classes:
#   Content patterns — specific message text / source-file name (placed first)
#   Component fallbacks — open5GS [domain] tags
#
# Higher score = deeper code path reached = more interesting for fuzzing.
# ---------------------------------------------------------------------------

_DEPTH_PATTERNS: List[Tuple[float, str]] = [
    # ── Level 5 — JSON / YAML decode internals ───────────────────────────
    (0.95, 'ogs_json_'),         # OGS JSON parsing function failure
    (0.93, 'json_parse'),        # JSON parse error deep in body handling
    (0.93, 'ogs_yaml_'),         # YAML config parsing (startup only, very deep)
    (0.92, 'cJSON_Parse'),       # cJSON library call failure

    # ── Level 4 — SBI message body / IE validation ───────────────────────
    (0.90, 'ogs_sbi_body_'),     # SBI body encode/decode function
    (0.90, 'sbi_message'),       # SBI message structure error
    (0.88, 'OpenAPI_'),          # OpenAPI model decode failure
    (0.87, 'ogs_sbi_response_'),
    (0.86, 'ogs_sbi_request_'),
    (0.85, 'ogs_sbi_header_'),
    (0.84, 'MandatoryIeMissing'),  # 3GPP mandatory IE missing in SBI body
    (0.83, 'MandatoryFieldMissing'),
    (0.82, 'InvalidMandatoryParameter'),

    # ── Level 4 — NAS / 5GMM inside AMF SBI paths ────────────────────────
    # AMF forwards N1 messages to SMF over SBI; NAS decode errors here are deep
    (0.88, 'ogs_nas_5gs_decode'),
    (0.87, 'nas-5gs-plain'),
    (0.86, 'ogs_nas_5gmm_decode'),
    (0.85, 'nas-decoder'),

    # ── Level 3 — NF-specific handler failures ───────────────────────────
    (0.80, 'nrf-handler'),       # NRF request handler
    (0.78, 'nrf-sm'),            # NRF state machine error
    (0.76, 'amf-handler'),       # AMF SBI request handler
    (0.75, 'smf-handler'),       # SMF SBI request handler
    (0.74, 'udm-handler'),
    (0.72, 'sbi-handler'),       # Generic SBI handler
    (0.70, 'gmm-handler'),       # AMF GMM handler (reached via N1 in SBI)
    (0.68, 'gmm-sm'),
    (0.66, 'smf-sm'),
    (0.64, 'nrf-context'),       # NRF context management error
    (0.62, 'smf-context'),       # SMF PDU session context error
    (0.60, 'amf-context'),

    # ── Level 3 — HTTP/2 framing errors ──────────────────────────────────
    (0.75, 'HTTP2_PROTOCOL_ERROR'),
    (0.73, 'h2_error'),
    (0.72, 'nghttp2_'),          # nghttp2 library error (used by open5GS SBI)
    (0.70, 'GOAWAY'),            # Server sending GOAWAY — connection-level error
    (0.68, 'RST_STREAM'),        # Stream reset — individual request error

    # ── Level 2 — SBI routing / NF discovery failures ────────────────────
    (0.57, 'nf-instance'),       # NF instance lookup failure
    (0.55, 'sbi-path'),          # SBI path routing error
    (0.53, 'nf-type'),           # NF type mismatch
    (0.52, 'PLMN mismatch'),     # PLMN validation failure
    (0.50, 'S-NSSAI mismatch'),  # Slice mismatch
    (0.50, 'DNN'),               # DNN not configured
    (0.48, 'PDU Session'),       # PDU session error
    (0.47, 'UE context'),        # UE context not found
    (0.47, 'SUPI'),              # SUPI format / lookup error
    (0.45, 'subscription'),      # Subscription not found
    (0.43, 'Invalid nfType'),

    # ── Level 1 — SBI transport / connection ─────────────────────────────
    (0.35, 'sbi connect'),
    (0.33, 'sbi server'),
    (0.31, 'HTTP/2 connection'),
    (0.30, 'TLS'),
    (0.28, 'TCP'),

    # ── Level 0 — shallow / background ───────────────────────────────────
    (0.20, 'nf-sm.c'),           # NRF NF state machine (frequent background noise)
    (0.15, 'Not implemented'),
    (0.10, 'timer'),
    (0.08, 'heartbeat'),
    (0.05, 'health-check'),

    # ── Component fallbacks: [domain] tag ────────────────────────────────
    (0.90, '[sbi]'),    # SBI core library — very deep for SBI fuzzing
    (0.85, '[nas]'),    # NAS layer (reached via N1 messages in SBI)
    (0.80, '[smf]'),    # SMF application
    (0.80, '[nrf]'),    # NRF application
    (0.78, '[amf]'),    # AMF application
    (0.75, '[udm]'),    # UDM application
    (0.72, '[pcf]'),    # PCF application
    (0.70, '[ausf]'),   # AUSF application
    (0.60, '[ngap]'),   # NGAP (reached via AMF SBI paths)
    (0.55, '[gmm]'),    # GMM (reached via N1 inside SBI)
    (0.45, '[tlv]'),    # TLV core
    (0.35, '[mem]'),    # Memory pool errors
    (0.25, '[event]'),  # Event loop
    (0.20, '[sock]'),   # Socket
    (0.15, '[app]'),    # App startup
]


class Open5GsSbiMonitor:
    """Monitor open5GS NF processes and log files during SBI fuzzing.

    Follows the same interface as ngap/open5gs_monitor.Open5GSMonitor so that
    SbiAdapter.compute_reward() can use it identically.
    """

    def __init__(self,
                 primary_nf: str = 'NRF',
                 extra_nfs: Optional[List[str]] = None,
                 log_path: Optional[str] = None):
        """
        primary_nf:  the NF being directly targeted (default: 'NRF')
        extra_nfs:   additional NFs whose processes to check for crashes
        log_path:    override log file path (defaults to NF_PROCESSES[primary_nf]['log'])
        """
        self.primary_nf  = primary_nf.upper()
        self.extra_nfs   = [n.upper() for n in (extra_nfs or [])]
        self._all_nfs    = [self.primary_nf] + self.extra_nfs

        if log_path:
            self.log_path = log_path
        else:
            self.log_path = NF_PROCESSES.get(self.primary_nf, {}).get(
                'log', f'/var/log/open5gs/{self.primary_nf.lower()}.log'
            )

        self._seen_errors: Set[str] = set()
        self._error_freq:  Dict[str, int] = {}

    # ── Process health ────────────────────────────────────────────────────

    def _proc_name(self, nf: str) -> str:
        return NF_PROCESSES.get(nf, {}).get('proc', f'open5gs-{nf.lower()}d')

    def is_nf_alive(self, nf: Optional[str] = None) -> bool:
        """Return True if the NF process is running."""
        proc = self._proc_name(nf or self.primary_nf)
        try:
            r = subprocess.run(['pgrep', '-x', proc],
                               capture_output=True, timeout=2)
            return r.returncode == 0
        except Exception:
            return False

    # Alias used by generic_env.py's _check_server_state()
    def is_amf_alive(self) -> bool:
        """Check the primary NF process (name matches Open5GSMonitor API)."""
        return self.is_nf_alive(self.primary_nf)

    def kill_nf(self, nf: Optional[str] = None,
                grace_seconds: float = 3.0) -> bool:
        """Terminate NF process (SIGTERM → SIGKILL)."""
        nf = nf or self.primary_nf
        if not self.is_nf_alive(nf):
            return True
        proc = self._proc_name(nf)
        try:
            subprocess.run(['pkill', '-TERM', '-x', proc],
                           capture_output=True, timeout=5)
        except Exception:
            pass
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            time.sleep(0.5)
            if not self.is_nf_alive(nf):
                return True
        try:
            subprocess.run(['pkill', '-KILL', '-x', proc],
                           capture_output=True, timeout=5)
            time.sleep(1.0)
        except Exception:
            pass
        return not self.is_nf_alive(nf)

    # Alias used by generic_env.py
    def kill_amf(self, grace_seconds: float = 3.0) -> bool:
        return self.kill_nf(self.primary_nf, grace_seconds)

    def detect_crash(self) -> bool:
        """Return True if any monitored NF process has crashed."""
        for nf in self._all_nfs:
            if not self.is_nf_alive(nf):
                return True
        return False

    # ── Log reading ───────────────────────────────────────────────────────

    def _tail_log(self, n: int, log_path: Optional[str] = None) -> List[str]:
        path = log_path or self.log_path
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

    def recent_errors(self, n: int = 30) -> List[str]:
        """Return error/warning lines from the primary NF log.

        Filters _NOISE_PATTERNS that fire when NRF is not reachable.
        """
        return [
            line for line in self._tail_log(n)
            if any(k in line for k in ERROR_KEYWORDS)
            and not any(p in line for p in _NOISE_PATTERNS)
        ]

    def recent_logs_by_level(self, n: int = 30) -> Dict[str, List[str]]:
        """Return log lines bucketed by severity (fatal/error/warn)."""
        fatal_kw = {'FATAL', 'assert', 'Segmentation fault', 'core dumped',
                    'SIGSEGV', 'SIGABRT', 'Aborted'}
        warn_kw  = {'WARN', 'WARNING'}
        buckets: Dict[str, List[str]] = {'fatal': [], 'error': [], 'warn': []}
        for line in self._tail_log(n):
            if any(k in line for k in fatal_kw):
                buckets['fatal'].append(line)
            elif 'ERROR' in line:
                buckets['error'].append(line)
            elif any(k in line for k in warn_kw):
                buckets['warn'].append(line)
        return buckets

    _ANSI_ESC = re.compile(r'\x1b\[[0-9;]*m')

    # FATAL lines to skip: generic/uninformative lines that appear after every crash
    _FATAL_SKIP = re.compile(r'backtrace\(\) returned|ogs_abort\b', re.IGNORECASE)

    # Prefer lines with specific assertion text or signal name
    _FATAL_RE = re.compile(
        r'FATAL[:\s]+(.+?)\s*$|'
        r'(Assertion.+?failed[^)]*\))|'
        r'(Segmentation fault|SIGSEGV|SIGABRT|Aborted|core dumped)',
        re.IGNORECASE,
    )

    def get_crash_signature(self, n: int = 150) -> str:
        """Return a stable crash signature extracted from the most recent FATAL line.

        Reads the last *n* lines of the NF log, strips ANSI colour codes, and
        returns the first meaningful FATAL/Assertion/signal line found (scanning
        from the end, skipping generic `backtrace()` noise).  Used as a dedup
        key — identical root-causes produce identical signatures.

        Returns 'unknown' when no fatal indicator is found.
        """
        for line in reversed(self._tail_log(n)):
            clean = self._ANSI_ESC.sub('', line)
            if self._FATAL_SKIP.search(clean):
                continue
            m = self._FATAL_RE.search(clean)
            if m:
                sig = next(g for g in m.groups() if g)
                return sig.strip()
        return 'unknown'

    def get_stack_trace(self, n: int = 150) -> List[str]:
        """Return recent FATAL + ERROR lines from the NF log, ANSI-stripped.

        Useful for embedding a human-readable crash summary in the corpus JSON.
        """
        fatal_kw = ('FATAL', 'Assertion', 'SIGSEGV', 'SIGABRT', 'Aborted',
                    'Segmentation fault', 'core dumped', 'ERROR')
        lines = []
        for line in self._tail_log(n):
            clean = self._ANSI_ESC.sub('', line)
            if any(k in clean for k in fatal_kw):
                lines.append(clean.strip())
        return lines[-30:]  # cap at 30 lines

    # ── Depth / severity scoring ──────────────────────────────────────────

    def _line_depth(self, line: str) -> float:
        for score, pattern in _DEPTH_PATTERNS:
            if pattern in line:
                return score
        return 0.05

    def _line_severity(self, line: str) -> float:
        for kw in ('Segmentation fault', 'core dumped', 'SIGSEGV', 'SIGABRT',
                   'Aborted', 'assert', 'FATAL'):
            if kw in line:
                return _LEVEL_SEVERITY[kw]
        for kw in ('ERROR', 'WARNING'):
            if f'] {kw}:' in line:
                return _LEVEL_SEVERITY.get(kw, 0.50)
        return 0.40

    def snapshot_log_position(self) -> int:
        """Return current byte offset at end of the log file.

        Call this BEFORE sending a request so that score_since_snapshot()
        only scores log lines caused by THAT request, eliminating lag from
        previous steps contaminating the reward signal.
        """
        if not os.path.exists(self.log_path):
            return 0
        try:
            return os.path.getsize(self.log_path)
        except OSError:
            return 0

    def lines_since_snapshot(self, offset: int) -> List[str]:
        """Return new log lines written after byte *offset*."""
        if not os.path.exists(self.log_path):
            return []
        try:
            with open(self.log_path, 'rb') as f:
                f.seek(offset)
                raw = f.read()
            return raw.decode('utf-8', errors='replace').splitlines()
        except OSError:
            return []

    def anomaly_score(self, lines: Optional[List[str]] = None) -> float:
        """Composite anomaly score [0.0, 1.0] for *lines* (or last log tail).

        Algorithm:
          1. Weighted depth  = depth × severity per new error line
          2. Diminishing returns: freq_factor = 1 / (1 + freq × 0.15)
          3. Score = sum of top-3 distinct depth buckets (not just max),
             so hitting multiple deep code paths in one step is rewarded more
          4. Novelty bonus +0.15 for first-ever unique error signature
          5. Capped at 0.95 (1.0 reserved for process crash)
        """
        if self.detect_crash():
            return 1.0

        if lines is None:
            errors = self.recent_errors()
        else:
            errors = [
                l for l in lines
                if any(k in l for k in ERROR_KEYWORDS)
                and not any(p in l for p in _NOISE_PATTERNS)
            ]
        if not errors:
            return 0.0

        # Collect per-depth-bucket best score (sum top-3 buckets)
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
            # Keep best score per depth bucket (rounded to 0.1) so different
            # code paths at similar depth don't inflate the score unfairly.
            bucket = round(depth, 1)
            if weighted > bucket_scores.get(bucket, 0.0):
                bucket_scores[bucket] = weighted

            if sig not in self._seen_errors:
                novel = True
                self._seen_errors.add(sig)

        # Sum the top-3 bucket scores with diminishing weights (1.0, 0.5, 0.25)
        top3 = sorted(bucket_scores.values(), reverse=True)[:3]
        weights = [1.0, 0.5, 0.25]
        score = sum(w * s for w, s in zip(weights, top3))
        score += 0.15 if novel else 0.0
        return min(score, 0.95)

