#!/usr/bin/env python3
"""
open5GS AMF process monitor.

Checks whether the AMF is alive and inspects its log for anomalies.
Used by NgapAdapter.check_health() and compute_reward().
"""

import os
import subprocess
import time
from typing import Dict, List, Set, Tuple


AMF_PROCESS_NAME = 'open5gs-amfd'
DEFAULT_LOG_PATH = '/var/log/open5gs/amf.log'

# All keywords that flag a line as worth collecting from the AMF log.
#
# open5GS log format: "MM/DD HH:MM:SS.mmm: [domain] LEVEL: message (file.c:N)"
# Level strings (from ogs-log.c): FATAL, ERROR, WARNING, INFO, DEBUG, TRACE
# Note: open5GS emits "WARNING" for the warn level, never bare "WARN".
#
# WARNING is included because open5GS logs many protocol-rejection events
# (missing IEs, unexpected state, context not found) at WARNING level, which
# are exactly the deep code paths we want to reward in fuzzing.
ERROR_KEYWORDS = (
    # Process-kill / OS-level crash signals (no log-level prefix)
    'Segmentation fault', 'core dumped', 'SIGSEGV', 'SIGABRT', 'Aborted',
    # open5GS ogs_assert() / ogs_fatal() internal failures
    'assert', 'FATAL',
    # open5GS structured log levels (WARNING is the actual string, not WARN)
    'ERROR', 'WARNING',
)

# Log lines that are constant background noise when NRF / SBI services are not
# running.  They fill the tail window but carry no fuzzing signal.  Filtered
# out in recent_errors() before depth/severity scoring.
_SBI_NOISE_PATTERNS = (
    'Retry registration with NRF',
    "Couldn't connect to server",
    'ogs_sbi_client_handler() failed',
    'nf-sm.c',
)

# Severity weight for each log-level keyword found in a line.
# Applied as a multiplier against the depth score so that the same code path
# reached via ERROR is worth more than via WARN.
_LEVEL_SEVERITY: Dict[str, float] = {
    # Crash / OS signals
    'Segmentation fault': 1.00,
    'core dumped':        1.00,
    'SIGSEGV':            1.00,
    'SIGABRT':            1.00,
    'Aborted':            0.95,
    # open5GS internal
    'assert':             0.90,
    'FATAL':              1.00,
    # Structured log levels
    'ERROR':              0.85,
    'WARN':               0.50,
    'WARNING':            0.50,
}

# Depth scores for AMF log lines (higher = deeper code path reached by the fuzzer).
# Each tuple is (depth_score 0.0–1.0, substring to match).
# Lines are checked in order; the first match wins.
#
# Two classes of pattern:
#   Content patterns  — match message text or source-file name (more specific,
#                       placed first so they take priority).
#   Component patterns — match the open5GS domain tag "[domain] " that prefixes
#                       every log line.  Format: "[ngap] WARNING: ..." etc.
#                       These act as fallbacks: any line whose content does not
#                       match a specific pattern is still scored by which
#                       component emitted it.
#
# Calibrated against open5GS-2.7 log output during NGAP fuzzing.
_DEPTH_PATTERNS: List[Tuple[float, str]] = [
    # ── Content: Level 5 — ASN.1 / TLV / APER decode internals ──────────
    (0.95, 'aper_decode'),
    (0.93, 'tlv_decode'),
    (0.92, 'tlv_build'),

    # ── Content: Level 4 — NAS IE / pkbuf internals ──────────────────────
    (0.90, 'Not enough pkbuf'),
    (0.90, 'pkbuf'),
    (0.88, 'ies.c'),
    (0.88, 'decoder.c'),
    (0.87, 'nas-5gs-plain'),
    # Specific NAS 5GS decode function chains observed during fuzzing:
    # "ogs_nas_5gs_decode_registration_request() failed" at decoder.c:4467
    # "ogs_nas_5gs_decode_5gs_mobile_identity() failed" at decoder.c:96
    (0.86, 'ogs_nas_5gs_decode_registration_request'),
    (0.84, 'ogs_nas_5gs_decode_5gs_mobile_identity'),
    (0.85, 'nas-decoder'),
    (0.85, 'nas_5gs_decode'),
    # "ogs_nas_5gmm_decode() failed" at amf-sm.c:1098 — NAS GMM decode failed
    # inside the AMF state machine; the fuzzer's NAS payload reached the full
    # 5GMM decoder before the error was returned.
    (0.83, 'ogs_nas_5gmm_decode'),

    # ── Content: Level 3 — Security / integrity / NAS GMM layer ──────────
    (0.80, 'Integrity check'),
    (0.78, 'MAC failure'),
    (0.75, 'integrity'),
    (0.73, 'ciphering'),
    (0.70, 'gmm-handler'),
    (0.70, '5gmm-handler'),
    # GMM state machine — "gmm_handle_registration_request() failed [23]"
    # at gmm-sm.c:3468.  Deeper than the handler itself since it involves
    # registration logic, security algorithm selection, and cause mapping.
    (0.68, 'gmm-sm.c'),
    (0.66, 'gmm_handle_registration_request'),
    (0.68, 'ngap-path'),
    (0.66, 'authentication'),
    (0.65, 'Invalid 5GMM message type'),
    # NIA0/NEA0 — null integrity / null ciphering rejection at gmm-handler.c:351
    # Triggered when UE security caps offer only NIA0.  Already in patterns.
    (0.63, 'NIA0'),
    (0.62, 'NEA0 can be used'),   # full message: "NEA0 can be used in Encrypt[x], but Integrity cannot be bypassed"
    (0.60, 'security mode'),
    # NAS path — "Registration reject [cause]" at nas-path.c:213
    # Means the registration was processed far enough to build a reject response.
    (0.52, 'nas-path.c'),

    # ── Content: Level 2 — NGAP handler / AMF state machine / UE context ─
    (0.57, 'amf-sm'),
    (0.55, 'context.c'),
    # "GUTI has already been allocated" at context.c:1488 — repeated
    # registration without UE context cleanup; interesting AMF state reached.
    (0.48, 'GUTI has already been allocated'),
    (0.53, 'Failed to find'),
    (0.50, 'ngap-handler'),
    (0.48, 'No AMF-UE-NGAP-ID'),
    (0.48, 'No RAN_UE_NGAP_ID'),
    (0.47, 'No NAS_PDU'),
    (0.47, 'No UserLocationInformation'),
    (0.46, 'Invalid AMF_UE_NGAP_ID'),
    (0.45, 'Registration reject'),  # procedure reached NAS-path response building
    # "amf_sbi_send_deactivate_all_ue_in_gnb()" at sbi-path.c:654 — WARNING
    # emitted when the AMF cannot cleanly release a UE and deactivates all UEs
    # on the gNB.  Indicates the fuzzer disrupted AMF-wide UE state.
    (0.45, 'amf_sbi_send_deactivate_all_ue_in_gnb'),
    (0.45, 'UE context not found'),
    (0.43, 'no_ue_context'),
    # "No RAN UE Context : AMF_UE_NGAP_ID[N]" at ngap-handler.c:1617 —
    # differs from 'ran-ue' substring; explicit pattern needed.
    (0.42, 'No RAN UE Context'),
    (0.42, 'ran-ue'),
    (0.40, 'AMF-UE'),
    (0.38, 'Cannot find AMF-UE'),
    (0.37, 'Cannot find Served TAI'),
    (0.35, 'Cannot find S_NSSAI'),

    # ── Content: Level 1 — NGAP connection / gNB / association ───────────
    (0.35, 'No TAI'),
    (0.33, 'No PLMN'),
    (0.33, 'No SupportedTAList'),
    (0.31, 'No globalGNB_ID'),
    (0.30, 'No GlobalRANNodeID'),
    (0.29, 'NG-Setup failure'),
    (0.28, 'association'),
    (0.25, 'N2'),
    (0.22, 'SCTP'),

    # ── Content: Level 0 — Shallow proc dispatch / timers / SBI ──────────
    # "Not implemented(choice:X, proc:Y)" at ngap-sm.c — shallow PDU-choice
    # dispatch in the NGAP state machine.  Low score: the agent must not
    # exploit this path repeatedly (diminishing returns handles the rest).
    (0.20, 'ngap-sm.c'),
    (0.15, 'Not implemented'),
    (0.10, 'timer'),
    (0.08, 'sbi-path.c'),    # SBI path — unrelated to N2 fuzzing
    (0.05, 'nf-sm.c'),       # NRF NF state machine — background noise
    (0.08, 'sbi'),
    (0.08, 'SBI'),

    # ── Component fallbacks: [domain] tag in every open5GS log line ───────
    # Applied when no content pattern matched above.
    # Domain tag format: "[domain] " — e.g. "[nas] ERROR: ..."
    # Ordered high→low so the first bracketed tag match wins.
    #
    # [tlv]   — TLV/pkbuf core library; reaching it means deep parse reached
    (0.88, '[tlv]'),
    # [nas]   — 5GS NAS layer (ogs_nas_5gs_*); very deep for NGAP fuzzing
    (0.82, '[nas]'),
    # [gmm]   — GMM / 5GMM mobility management handler
    (0.72, '[gmm]'),
    # [ngap]  — NGAP procedure / message handling in open5GS lib
    (0.50, '[ngap]'),
    # [amf]   — AMF application-level logic (context, state machine)
    (0.42, '[amf]'),
    # [mem]   — memory pool errors; usually come from deep allocation paths
    (0.30, '[mem]'),
    # [event] — event-loop errors; moderate depth
    (0.25, '[event]'),
    # [sctp]  — SCTP transport layer
    (0.20, '[sctp]'),
    # [sock]  — raw socket errors
    (0.15, '[sock]'),
    # [sbi]   — Service Based Interface (HTTP2/REST), unrelated to N2 fuzzing
    (0.08, '[sbi]'),
    # [app]   — application startup / config parsing
    (0.05, '[app]'),
]


class Open5GSMonitor:
    """Monitor open5GS AMF process health and log anomalies."""

    def __init__(self, log_path: str = DEFAULT_LOG_PATH):
        self.log_path = log_path
        # Set of error line signatures seen across all episodes.
        # Gives a novelty bonus the first time a new deep error appears.
        self._seen_errors: Set[str] = set()
        # Per-signature frequency counter used for diminishing returns.
        # Each repeated occurrence of the same error is worth less, forcing
        # the RL agent to explore new paths rather than exploiting a known
        # shallow one (e.g. repeated "Not implemented(choice:3, proc:42)").
        self._error_freq: Dict[str, int] = {}

    # ── Process health ────────────────────────────────────────────────────

    def is_amf_alive(self) -> bool:
        """Return True if the open5gs-amfd process is running."""
        try:
            r = subprocess.run(
                ['pgrep', '-x', AMF_PROCESS_NAME],
                capture_output=True,
                timeout=2,
            )
            return r.returncode == 0
        except Exception:
            return False

    def kill_amf(self, grace_seconds: float = 3.0) -> bool:
        """
        Terminate the AMF process gracefully (SIGTERM), then SIGKILL if needed.
        Returns True if the process is gone after the call.
        """
        if not self.is_amf_alive():
            return True

        try:
            subprocess.run(['pkill', '-TERM', '-x', AMF_PROCESS_NAME],
                           capture_output=True, timeout=5)
        except Exception:
            pass

        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            time.sleep(0.5)
            if not self.is_amf_alive():
                return True

        try:
            subprocess.run(['pkill', '-KILL', '-x', AMF_PROCESS_NAME],
                           capture_output=True, timeout=5)
            time.sleep(1.0)
        except Exception:
            pass

        return not self.is_amf_alive()

    def detect_crash(self) -> bool:
        """Return True if the AMF process has crashed."""
        return not self.is_amf_alive()

    # ── Log reading ───────────────────────────────────────────────────────

    def _tail_log(self, n: int) -> List[str]:
        """Return the last *n* lines of the AMF log, or [] on any error."""
        if not os.path.exists(self.log_path):
            return []
        try:
            r = subprocess.run(
                ['tail', '-n', str(n), self.log_path],
                capture_output=True, text=True, timeout=2,
            )
            return r.stdout.splitlines()
        except Exception:
            return []

    def recent_errors(self, n: int = 30) -> List[str]:
        """Return lines from the AMF log that contain any ERROR_KEYWORDS.

        Includes WARNING lines in addition to ERROR/FATAL and crash signals,
        so the depth scoring in anomaly_score() can reward protocol-rejection
        warnings (missing IEs, context not found, etc.) that open5GS logs at
        WARNING level.

        SBI/NRF noise lines (_SBI_NOISE_PATTERNS) are filtered out because
        they fire constantly when NRF is not running and would otherwise fill
        the 30-line window, displacing genuine AMF/NAS errors.

        Terminal grep equivalent:
            ... 2>&1 | grep --line-buffered -E \
                "ERROR|WARNING|FATAL|assert|Segmentation fault|core dumped|SIGSEGV|SIGABRT|Aborted"
        """
        return [
            line for line in self._tail_log(n)
            if any(k in line for k in ERROR_KEYWORDS)
            and not any(p in line for p in _SBI_NOISE_PATTERNS)
        ]

    def recent_logs_by_level(self, n: int = 30) -> Dict[str, List[str]]:
        """Return log lines bucketed by severity level.

        Returns a dict with keys:
          'fatal'  — FATAL / ogs_assert / crash-signal lines
          'error'  — ERROR lines
          'warn'   — WARN / WARNING lines

        Useful for tiered reward bonuses in compute_reward().
        """
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

    # ── Depth / severity scoring ──────────────────────────────────────────

    def _line_depth(self, line: str) -> float:
        """Return the depth score [0.0, 1.0] for one AMF log line.

        Checks _DEPTH_PATTERNS in order (most specific first) and returns the
        score of the first match, or 0.05 for any unrecognised keyword line.
        """
        for score, pattern in _DEPTH_PATTERNS:
            if pattern in line:
                return score
        return 0.05

    def _line_severity(self, line: str) -> float:
        """Return the severity weight [0.0, 1.0] for one AMF log line.

        open5GS log format: "MM/DD HH:MM:SS.mmm: [domain] LEVEL: message (file.c:N)"
        Level strings from ogs-log.c level_strings[]: FATAL, ERROR, WARNING, INFO, …
        Note: open5GS emits "WARNING" (not "WARN") for the warn level.

        Crash / OS signals are detected by substring (no structured prefix).
        """
        # Crash and ogs_assert signals — appear without a structured log prefix
        for kw in ('Segmentation fault', 'core dumped', 'SIGSEGV', 'SIGABRT',
                   'Aborted', 'assert', 'FATAL'):
            if kw in line:
                return _LEVEL_SEVERITY[kw]
        # open5GS structured levels — pattern is "] LEVEL: " after the domain tag
        # open5GS uses "WARNING" (not "WARN") per level_strings[] in ogs-log.c
        for kw in ('ERROR', 'WARNING'):
            if f'] {kw}:' in line:
                return _LEVEL_SEVERITY.get(kw, 0.50)
        return 0.40   # matched a keyword but no recognisable level prefix

    # ── Composite anomaly score ───────────────────────────────────────────

    def anomaly_score(self) -> float:
        """
        Return a float in [0.0, 1.0] indicating AMF anomaly severity.

        Combines four signals:
          1. **Weighted depth** — depth_score × severity_weight for each line.
             Severity: FATAL=1.0, ERROR=0.85, WARNING=0.50.
             Depth: aper_decode=0.95, pkbuf=0.90, gmm-sm.c=0.68,
                    ngap-handler=0.50, ngap-sm.c=0.20 (shallow dispatch).
          2. **Diminishing returns** — each repeated occurrence of the same
             error signature is worth less: factor = 1/(1 + freq × 0.15).
               freq=0 → 1.00 (first time, full reward)
               freq=5 → 0.57 (6th repetition)
               freq=10 → 0.40 (11th repetition)
               freq=20 → 0.25 (21st repetition)
             This prevents the RL agent from getting stuck exploiting a
             single shallow path like "Not implemented(choice:3, proc:42)".
          3. **Novelty** — 0.15 bonus if any line is one never seen before
             across the entire training run (first-ever unique error).
          4. Capped at 0.95 (1.0 is reserved for process crash).

        Combined example — first-time ERROR in pkbuf (very deep):
            depth=0.90, severity=0.85, freq=0 → 0.90×0.85×1.0 + 0.15 = 0.915 → capped 0.95

        Combined example — 10th repetition of "Not implemented" (shallow):
            depth=0.15, severity=0.85, freq=10 → 0.15×0.85×0.40 = 0.051
        """
        if self.detect_crash():
            return 1.0

        errors = self.recent_errors()
        if not errors:
            return 0.0

        max_weighted = 0.0
        novel = False
        for line in errors:
            depth    = self._line_depth(line)
            severity = self._line_severity(line)
            # Short signature (last 80 chars) strips timestamp noise
            sig = line[-80:].strip()

            # Diminishing returns: repeated errors are worth less
            freq = self._error_freq.get(sig, 0)
            self._error_freq[sig] = freq + 1
            freq_factor = 1.0 / (1.0 + freq * 0.15)

            weighted = depth * severity * freq_factor
            if weighted > max_weighted:
                max_weighted = weighted

            if sig not in self._seen_errors:
                novel = True
                self._seen_errors.add(sig)

        score = max_weighted + (0.15 if novel else 0.0)
        return min(score, 0.95)
