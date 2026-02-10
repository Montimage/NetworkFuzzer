#!/usr/bin/env python3
"""
Server Log Monitor for RL Fuzzing.

Parses server logs to extract:
1. Error levels (Error, Warning, Info)
2. Error messages and their frequency
3. Source code locations (file:line)
4. Novel/rare messages for reward bonuses

Supports:
- Orthanc log format
- DCMTK log format
- Generic syslog format
"""

import re
import os
import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
import threading

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Parsed log entry."""
    timestamp: str
    level: str          # 'E' (error), 'W' (warning), 'I' (info), 'D' (debug)
    source_file: str
    source_line: int
    message: str
    raw_line: str


@dataclass
class LogStats:
    """Statistics from log monitoring."""
    total_entries: int = 0
    errors: int = 0
    warnings: int = 0
    infos: int = 0

    unique_messages: Set[str] = field(default_factory=set)
    unique_locations: Set[str] = field(default_factory=set)  # "file:line" or "func:error_code"

    message_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    location_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Error code tracking (DCMTK specific)
    error_codes: Set[str] = field(default_factory=set)
    error_code_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    new_error_codes_session: Set[str] = field(default_factory=set)

    # For novelty detection
    new_messages_this_session: Set[str] = field(default_factory=set)
    new_locations_this_session: Set[str] = field(default_factory=set)

    # Severity scores
    severity_scores: Dict[str, float] = field(default_factory=lambda: {
        'E': 3.0,   # Error - most interesting
        'W': 2.0,   # Warning
        'I': 1.0,   # Info
        'D': 0.5,   # Debug
    })


class LogParser:
    """Parser for different server log formats."""

    # Orthanc format: E0206 13:37:03.468989 CommandDispatcher.cpp:676] message
    ORTHANC_PATTERN = re.compile(
        r'^([EWID])(\d{4})\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+'
        r'(\w+\.cpp):(\d+)\]\s*(.*)$'
    )

    # DCMTK simple format: E: message or I: message
    # Example: E: DIMSE failure (aborting association): 0006:020b DIMSE_parseCmdObject: Missing CommandField
    DCMTK_SIMPLE_PATTERN = re.compile(
        r'^([EWID]):\s*(.*)$'
    )

    # DCMTK format with source: E: file.cc(123): message
    DCMTK_SOURCE_PATTERN = re.compile(
        r'^([EWID]):\s*(\w+\.\w+)\((\d+)\):\s*(.*)$'
    )

    # DCMTK error code pattern: 0006:020b (module:error)
    DCMTK_ERROR_CODE = re.compile(r'([0-9a-fA-F]{4}):([0-9a-fA-F]{4})')

    # DCMTK function name pattern: DIMSE_xxx or DUL_xxx
    DCMTK_FUNC_PATTERN = re.compile(r'(DIMSE_\w+|DUL_\w+|ASC_\w+)')

    # Generic syslog: timestamp level [source] message
    SYSLOG_PATTERN = re.compile(
        r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'\[?(ERROR|WARN|INFO|DEBUG)\]?\s*'
        r'(?:\[([^\]]+)\])?\s*(.*)$',
        re.IGNORECASE
    )

    # DCMTK error code meanings (for semantic understanding)
    DCMTK_ERROR_MEANINGS = {
        # DIMSE module (0006)
        "0006:0001": "DIMSE_BADCOMMANDTYPE",
        "0006:0002": "DIMSE_BADDATA",
        "0006:0003": "DIMSE_BADMESSAGE",
        "0006:020b": "DIMSE_PARSEERROR_MISSING_COMMANDFIELD",
        "0006:020c": "DIMSE_READPDV_FAILED",
        "0006:020d": "DIMSE_RECEIVEMESSAGE_FAILED",
        "0006:0308": "DIMSE_PDV_INVALID_LENGTH",
        "0006:0110": "DIMSE_ILLEGALRESPONSE",
        # DUL module (0005)
        "0005:0001": "DUL_ASSOCIATIONREJECTED",
        "0005:0002": "DUL_NOASSOCIATIONREQUEST",
        "0005:0305": "DUL_ILLEGAL_PDU_LENGTH",
        "0005:0306": "DUL_PROTOCOL_ERROR",
        # ASC module (0004)
        "0004:0001": "ASC_BADPRESENTATIONCONTEXT",
        "0004:0002": "ASC_MISSINGPRESENTATIONCONTEXT",
    }

    @classmethod
    def extract_error_info(cls, message: str) -> Dict[str, str]:
        """Extract structured info from DCMTK error message."""
        info = {}

        # Extract error code
        code_match = cls.DCMTK_ERROR_CODE.search(message)
        if code_match:
            error_code = f"{code_match.group(1)}:{code_match.group(2)}"
            info["error_code"] = error_code
            info["error_meaning"] = cls.DCMTK_ERROR_MEANINGS.get(error_code.lower(), "unknown")

        # Extract function name
        func_match = cls.DCMTK_FUNC_PATTERN.search(message)
        if func_match:
            info["function"] = func_match.group(1)

        return info

    @classmethod
    def parse_line(cls, line: str) -> Optional[LogEntry]:
        """Parse a log line into a LogEntry."""
        line = line.strip()
        if not line:
            return None

        # Try Orthanc format first
        match = cls.ORTHANC_PATTERN.match(line)
        if match:
            return LogEntry(
                timestamp=match.group(3),
                level=match.group(1),
                source_file=match.group(4),
                source_line=int(match.group(5)),
                message=match.group(6),
                raw_line=line,
            )

        # Try DCMTK format with source file
        match = cls.DCMTK_SOURCE_PATTERN.match(line)
        if match:
            return LogEntry(
                timestamp="",
                level=match.group(1),
                source_file=match.group(2),
                source_line=int(match.group(3)),
                message=match.group(4),
                raw_line=line,
            )

        # Try DCMTK simple format (E: message)
        match = cls.DCMTK_SIMPLE_PATTERN.match(line)
        if match:
            level = match.group(1)
            message = match.group(2)

            # Extract error code as pseudo source location
            error_info = cls.extract_error_info(message)
            source = error_info.get("function", "DCMTK")
            if error_info.get("error_code"):
                source = f"{source}:{error_info['error_code']}"

            return LogEntry(
                timestamp="",
                level=level,
                source_file=source,
                source_line=0,
                message=message,
                raw_line=line,
            )

        # Try syslog format
        match = cls.SYSLOG_PATTERN.match(line)
        if match:
            level_map = {'ERROR': 'E', 'WARN': 'W', 'INFO': 'I', 'DEBUG': 'D'}
            return LogEntry(
                timestamp=match.group(1),
                level=level_map.get(match.group(2).upper(), 'I'),
                source_file=match.group(3) or "unknown",
                source_line=0,
                message=match.group(4),
                raw_line=line,
            )

        # Check for simple error indicators
        if line.startswith('E') or 'error' in line.lower():
            return LogEntry(
                timestamp="",
                level='E',
                source_file="unknown",
                source_line=0,
                message=line,
                raw_line=line,
            )

        return None


class ServerLogMonitor:
    """
    Monitors server logs for fuzzing feedback.

    Can monitor:
    1. Local log file (tail -f style)
    2. SSH remote log
    3. Docker container logs
    """

    def __init__(self,
                 log_path: Optional[str] = None,
                 ssh_host: Optional[str] = None,
                 ssh_log_path: Optional[str] = None,
                 docker_container: Optional[str] = None,
                 baseline_messages: Optional[Set[str]] = None,
                 min_level: str = 'I'):
        """
        Initialize log monitor.

        Args:
            log_path: Local path to log file
            ssh_host: SSH host for remote log monitoring
            ssh_log_path: Path to log on remote host
            docker_container: Docker container name for log monitoring
            baseline_messages: Known messages to not reward as novel
            min_level: Minimum log level to process ('E', 'W', 'I', 'D')
        """
        self.log_path = log_path
        self.ssh_host = ssh_host
        self.ssh_log_path = ssh_log_path
        self.docker_container = docker_container
        self.min_level = min_level  # Filter out debug by default

        self.stats = LogStats()
        self.baseline_messages = baseline_messages or set()

        # Level priority for filtering
        self._level_priority = {'E': 4, 'W': 3, 'I': 2, 'D': 1}

        # For file monitoring
        self._last_position = 0
        self._last_inode = None

        # Thread safety
        self._lock = threading.Lock()

        # Recent entries buffer
        self._recent_entries: List[LogEntry] = []
        self._max_recent = 100

        # Track processed lines to avoid duplicates (for SSH tail -n mode)
        self._processed_lines: Set[str] = set()
        self._max_processed = 1000  # Keep last N to avoid memory growth

    def _read_new_lines(self) -> List[str]:
        """Read new lines from log source."""
        lines = []

        # SSH remote log reading
        if self.ssh_host and self.ssh_log_path:
            try:
                import subprocess
                # Always get last N lines (simpler and more reliable than position tracking)
                # This may re-read some lines but the deduplication in check_logs handles it
                use_sudo = getattr(self, '_ssh_use_sudo', False)
                tail_cmd = f'sudo tail -n 50 {self.ssh_log_path}' if use_sudo \
                    else f'tail -n 50 {self.ssh_log_path}'
                cmd = f'ssh {self.ssh_host} "{tail_cmd}"'

                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.splitlines()
                    if lines:
                        logger.debug(f"SSH: read {len(lines)} lines from {self.ssh_host}:{self.ssh_log_path}")
                elif not use_sudo and result.returncode in (1, 2):
                    # Permission denied or file access error — retry with sudo
                    logger.info(f"SSH log read failed without sudo (rc={result.returncode}), retrying with sudo")
                    self._ssh_use_sudo = True
                    cmd_sudo = f'ssh {self.ssh_host} "sudo tail -n 50 {self.ssh_log_path}"'
                    result2 = subprocess.run(cmd_sudo, shell=True, capture_output=True, text=True, timeout=10)
                    if result2.returncode == 0:
                        lines = result2.stdout.splitlines()
                        if lines:
                            logger.info(f"SSH sudo: read {len(lines)} lines (sudo mode enabled)")
                    else:
                        logger.warning(f"SSH log read failed even with sudo (rc={result2.returncode}): "
                                     f"{result2.stderr[:100]}")
                else:
                    logger.warning(f"SSH log read failed (rc={result.returncode}): {result.stderr[:100]}")
            except subprocess.TimeoutExpired:
                logger.warning("SSH log read timed out")
            except Exception as e:
                logger.warning(f"Error reading SSH logs: {e}")

        # Local log file
        elif self.log_path and os.path.exists(self.log_path):
            try:
                stat = os.stat(self.log_path)
                current_inode = stat.st_ino

                # Check if file was rotated
                if self._last_inode and current_inode != self._last_inode:
                    self._last_position = 0

                self._last_inode = current_inode

                with open(self.log_path, 'r', errors='ignore') as f:
                    f.seek(self._last_position)
                    lines = f.readlines()
                    self._last_position = f.tell()
            except Exception as e:
                logger.warning(f"Error reading log file: {e}")

        # Docker container logs
        elif self.docker_container:
            try:
                import subprocess
                result = subprocess.run(
                    ['docker', 'logs', '--tail', '50', self.docker_container],
                    capture_output=True, text=True, timeout=5
                )
                lines = result.stdout.splitlines() + result.stderr.splitlines()
            except Exception as e:
                logger.warning(f"Error reading docker logs: {e}")

        return lines

    def check_logs(self) -> Tuple[List[LogEntry], Dict[str, float]]:
        """
        Check for new log entries and compute rewards.

        Returns:
            (new_entries, reward_info)
        """
        lines = self._read_new_lines()
        new_entries = []
        reward_info = {
            'log_reward': 0.0,
            'new_errors': 0,
            'new_warnings': 0,
            'new_messages': 0,
            'new_locations': 0,
            'new_error_codes': 0,
            'depth_score': 0.0,
            'error_codes_found': [],
            'lines_read': len(lines),
        }

        min_priority = self._level_priority.get(self.min_level, 2)

        with self._lock:
            for line in lines:
                # Skip already processed lines (for SSH tail -n mode which re-reads)
                line_hash = hash(line.strip())
                if line_hash in self._processed_lines:
                    continue
                self._processed_lines.add(line_hash)

                # Limit memory usage
                if len(self._processed_lines) > self._max_processed:
                    # Remove oldest half
                    to_remove = list(self._processed_lines)[:self._max_processed // 2]
                    for h in to_remove:
                        self._processed_lines.discard(h)

                entry = LogParser.parse_line(line)
                if not entry:
                    continue

                # Filter by minimum log level (skip Debug by default)
                entry_priority = self._level_priority.get(entry.level, 1)
                if entry_priority < min_priority:
                    continue

                new_entries.append(entry)
                self._recent_entries.append(entry)
                if len(self._recent_entries) > self._max_recent:
                    self._recent_entries.pop(0)

                # Update stats
                self.stats.total_entries += 1
                if entry.level == 'E':
                    self.stats.errors += 1
                    reward_info['new_errors'] += 1
                elif entry.level == 'W':
                    self.stats.warnings += 1
                    reward_info['new_warnings'] += 1
                else:
                    self.stats.infos += 1

                # Extract and track error codes (DCMTK specific)
                error_info = LogParser.extract_error_info(entry.message)
                if error_info.get("error_code"):
                    error_code = error_info["error_code"].lower()
                    self.stats.error_code_counts[error_code] += 1
                    reward_info['error_codes_found'].append(error_code)

                    if error_code not in self.stats.error_codes:
                        self.stats.error_codes.add(error_code)
                        self.stats.new_error_codes_session.add(error_code)
                        reward_info['new_error_codes'] += 1

                        # Bonus reward for high-value error codes
                        bonus = HIGH_VALUE_ERROR_CODES.get(error_code, 1.0)
                        reward_info['log_reward'] += 25.0 * bonus
                        logger.info(f"NEW ERROR CODE: {error_code} ({error_info.get('error_meaning', 'unknown')}) bonus={bonus}")

                # Check for novel message (skip baseline/common messages)
                msg_key = self._normalize_message(entry.message)
                is_baseline = any(base in msg_key for base in self.baseline_messages)
                if msg_key not in self.stats.unique_messages:
                    if not is_baseline:
                        self.stats.new_messages_this_session.add(msg_key)
                        reward_info['new_messages'] += 1
                        # Novel message reward based on severity
                        reward_info['log_reward'] += 15.0 * self.stats.severity_scores.get(entry.level, 1.0)
                    self.stats.unique_messages.add(msg_key)

                self.stats.message_counts[msg_key] += 1

                # Check for novel source location (or function:error_code for DCMTK)
                loc_key = None
                if entry.source_file != "unknown":
                    if entry.source_line > 0:
                        loc_key = f"{entry.source_file}:{entry.source_line}"
                    elif ":" in entry.source_file:  # function:error_code format
                        loc_key = entry.source_file

                if loc_key and loc_key not in self.stats.unique_locations:
                    self.stats.new_locations_this_session.add(loc_key)
                    self.stats.unique_locations.add(loc_key)
                    self.stats.location_counts[loc_key] += 1
                    reward_info['new_locations'] += 1
                    # Novel location = new code path!
                    reward_info['log_reward'] += 20.0
                elif loc_key:
                    self.stats.location_counts[loc_key] += 1

                # Base reward for any error/warning (but not for baseline messages)
                if not is_baseline:
                    reward_info['log_reward'] += self.stats.severity_scores.get(entry.level, 0.5)

            # Compute depth score (how many unique code paths + error codes)
            reward_info['depth_score'] = len(self.stats.unique_locations) + len(self.stats.error_codes)

        return new_entries, reward_info

    def _normalize_message(self, message: str) -> str:
        """Normalize message for comparison (remove variable parts)."""
        # Remove numbers (likely IDs, lengths, etc.)
        normalized = re.sub(r'\b\d+\b', '<N>', message)
        # Remove hex values
        normalized = re.sub(r'0x[0-9a-fA-F]+', '<HEX>', normalized)
        # Remove quoted strings
        normalized = re.sub(r'"[^"]*"', '<STR>', normalized)
        # Remove UUIDs
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<UUID>', normalized)
        return normalized.strip()

    def get_stats(self) -> Dict:
        """Get current statistics."""
        with self._lock:
            return {
                'total_entries': self.stats.total_entries,
                'errors': self.stats.errors,
                'warnings': self.stats.warnings,
                'unique_messages': len(self.stats.unique_messages),
                'unique_locations': len(self.stats.unique_locations),
                'unique_error_codes': len(self.stats.error_codes),
                'new_messages_session': len(self.stats.new_messages_this_session),
                'new_locations_session': len(self.stats.new_locations_this_session),
                'new_error_codes_session': len(self.stats.new_error_codes_session),
                'error_codes': list(self.stats.error_codes),
                'top_messages': sorted(
                    self.stats.message_counts.items(),
                    key=lambda x: x[1], reverse=True
                )[:10],
                'top_locations': sorted(
                    self.stats.location_counts.items(),
                    key=lambda x: x[1], reverse=True
                )[:10],
                'top_error_codes': sorted(
                    self.stats.error_code_counts.items(),
                    key=lambda x: x[1], reverse=True
                )[:10],
            }

    def get_recent_entries(self, n: int = 10) -> List[LogEntry]:
        """Get recent log entries."""
        with self._lock:
            return self._recent_entries[-n:]

    def reset_session_stats(self):
        """Reset session-specific stats (for new training run)."""
        with self._lock:
            self.stats.new_messages_this_session.clear()
            self.stats.new_locations_this_session.clear()


# Predefined error message patterns for common DICOM servers
ORTHANC_BASELINE_MESSAGES = {
    "Illegal service parameter: Called AP Title",
    "Receiving Association failed: DUL illegal subitem length <N>",
    "Protocol version not supported",
    "Application context not supported",
}

DCMTK_BASELINE_MESSAGES = {
    # Common association messages (not interesting for fuzzing)
    "Association Received",
    "Association Acknowledged",
    "Association Aborted",
    "Association Rejected",
    "Association Released",
    # Normal operations
    "Received Echo Request",
    "Sending Echo Response",
}

# High-value error codes that indicate interesting fuzzing behavior
HIGH_VALUE_ERROR_CODES = {
    "0006:020b": 3.0,  # Missing CommandField - parser confusion
    "0006:020c": 2.5,  # Read PDV failed - protocol error
    "0006:020d": 2.0,  # Receive message failed
    "0006:0308": 4.0,  # PDV invalid length 0 - memory/buffer issue
    "0006:0110": 2.5,  # Illegal response
    "0005:0305": 3.0,  # Illegal PDU length
    "0005:0306": 2.5,  # Protocol error
}


def create_log_monitor(server_type: str = "orthanc", **kwargs) -> ServerLogMonitor:
    """Create a log monitor for a specific server type."""
    if server_type.lower() == "orthanc":
        baseline = ORTHANC_BASELINE_MESSAGES
    elif server_type.lower() == "dcmtk":
        baseline = DCMTK_BASELINE_MESSAGES
    else:
        baseline = set()

    return ServerLogMonitor(baseline_messages=baseline, **kwargs)
