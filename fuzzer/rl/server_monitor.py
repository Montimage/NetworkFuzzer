#!/usr/bin/env python3
"""
Server health monitor for RL-guided DICOM fuzzing.

Collects server-side metrics observable over the network:
  1. DICOM Echo health: C-ECHO latency as primary health indicator
  2. Connection availability: can we open new DICOM connections?
  3. Recovery time: how long until server returns to normal after fuzz?
  4. Concurrent connections: thread exhaustion detection
  5. Baseline comparison: delta from pre-fuzz health snapshot

The Orthanc REST API (port 8042) requires authentication, so all metrics
are measured via DICOM protocol-level probes on the DICOM port itself.
This is actually more useful — it tests the same code paths the fuzzer targets.
"""

import re
import socket
import struct
import time
import logging
import threading
from collections import deque

logger = logging.getLogger(__name__)

# Valid ASSOC_RQ for C-ECHO (Verification SOP Class)
def _build_echo_assoc_rq(called_ae="ORTHANC", calling_ae="MONITOR"):
    """Build a minimal valid ASSOC_RQ for C-ECHO."""
    called = called_ae.ljust(16).encode('ascii')[:16]
    calling = calling_ae.ljust(16).encode('ascii')[:16]

    app_ctx_uid = b'1.2.840.10008.3.1.1.1'
    app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

    abstract_uid = b'1.2.840.10008.1.1'
    abstract = struct.pack('>BBH', 0x30, 0, len(abstract_uid)) + abstract_uid
    transfer_uid = b'1.2.840.10008.1.2'
    transfer = struct.pack('>BBH', 0x40, 0, len(transfer_uid)) + transfer_uid
    pres_ctx_data = struct.pack('>BBBB', 1, 0, 0, 0) + abstract + transfer
    pres_ctx = struct.pack('>BBH', 0x20, 0, len(pres_ctx_data)) + pres_ctx_data

    max_pdu = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', 16382)
    impl_uid_data = b'1.2.826.0.1.3680043.9.3811.2.0.2'
    impl_uid = struct.pack('>BBH', 0x52, 0, len(impl_uid_data)) + impl_uid_data
    impl_name_data = b'MONITOR'
    impl_name = struct.pack('>BBH', 0x55, 0, len(impl_name_data)) + impl_name_data
    user_info_data = max_pdu + impl_uid + impl_name
    user_info = struct.pack('>BBH', 0x50, 0, len(user_info_data)) + user_info_data

    variable = app_ctx + pres_ctx + user_info
    reserved32 = b'\x00' * 32
    pdu_data = struct.pack('>H', 1) + b'\x00\x00' + called + calling + reserved32 + variable
    pdu = struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data
    return pdu


def _build_cecho_rq():
    """Build a C-ECHO-RQ PDATA PDU."""
    uid = b'1.2.840.10008.1.1'
    if len(uid) % 2:
        uid += b'\x00'
    elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid
    elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)
    elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, 1)
    elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0101)
    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0800
    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set

    pdv_data = struct.pack('>B', 1) + struct.pack('>B', 0x03) + command_set
    pdv_item = struct.pack('>I', len(pdv_data)) + pdv_data
    pdata = struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item
    return pdata


def _build_release_rq():
    """Build A-RELEASE-RQ PDU."""
    return struct.pack('>BBi', 0x05, 0, 4) + b'\x00' * 4


class HealthSnapshot:
    """A snapshot of server health at a point in time."""

    def __init__(self):
        self.timestamp = 0.0
        self.echo_latency_ms = -1.0        # C-ECHO round-trip latency (-1 = failed)
        self.connect_latency_ms = -1.0      # TCP connect time
        self.assoc_accepted = False          # Did ASSOC_RQ get accepted?
        self.assoc_latency_ms = -1.0        # Time to get ASSOC_AC
        self.echo_success = False            # Did C-ECHO complete?
        self.concurrent_connections = 0      # How many parallel connections succeed
        self.max_concurrent_tested = 0       # How many we tested
        self.error = ""                      # Error message if any

    def to_dict(self):
        return {
            "echo_latency_ms": round(self.echo_latency_ms, 1),
            "connect_latency_ms": round(self.connect_latency_ms, 1),
            "assoc_accepted": self.assoc_accepted,
            "assoc_latency_ms": round(self.assoc_latency_ms, 1),
            "echo_success": self.echo_success,
            "concurrent_connections": self.concurrent_connections,
            "max_concurrent_tested": self.max_concurrent_tested,
            "error": self.error,
        }

    def health_score(self):
        """Compute a 0-100 health score.

        100 = fully healthy, 0 = completely unresponsive.
        """
        score = 0.0

        # TCP connection (0-20)
        if self.connect_latency_ms >= 0:
            if self.connect_latency_ms < 50:
                score += 20.0
            elif self.connect_latency_ms < 200:
                score += 15.0
            elif self.connect_latency_ms < 1000:
                score += 10.0
            else:
                score += 5.0
        # else: can't connect → 0

        # Association accepted (0-20)
        if self.assoc_accepted:
            score += 20.0

        # C-ECHO success (0-30)
        if self.echo_success:
            score += 30.0
            # Bonus for fast echo
            if self.echo_latency_ms < 10:
                score += 0  # Normal
            elif self.echo_latency_ms < 50:
                score -= 5  # Slightly degraded
            elif self.echo_latency_ms < 200:
                score -= 10  # Noticeably degraded

        # Concurrent connections (0-30)
        if self.max_concurrent_tested > 0:
            ratio = self.concurrent_connections / self.max_concurrent_tested
            score += 30.0 * ratio

        return max(0.0, min(100.0, score))


class ServerMonitor:
    """
    Monitors a DICOM server's health via network probes.

    Usage:
        monitor = ServerMonitor("152.228.175.65", 4242)

        # Take baseline before fuzzing
        baseline = monitor.check_health()

        # ... send fuzzed PDU ...

        # Take post-fuzz snapshot
        post_fuzz = monitor.check_health()

        # Compare
        degradation = monitor.compute_degradation(baseline, post_fuzz)
    """

    def __init__(self, target_host, target_port=4242, called_ae="ORTHANC",
                 concurrent_test_count=5, connect_timeout=3.0):
        self.target_host = target_host
        self.target_port = target_port
        self.called_ae = called_ae
        self.concurrent_test_count = concurrent_test_count
        self.connect_timeout = connect_timeout

        # Cache the probe PDUs
        self._assoc_rq = _build_echo_assoc_rq(called_ae=called_ae)
        self._cecho_rq = _build_cecho_rq()
        self._release_rq = _build_release_rq()

        # Baseline history for trend detection
        self._baseline_echo_times = deque(maxlen=20)
        self._baseline_connect_times = deque(maxlen=20)

    def check_health(self, full=True):
        """
        Take a health snapshot of the server.

        Args:
            full: if True, also run concurrent connection test (slower).
                  if False, just do echo check (faster, for per-episode use).
        """
        snap = HealthSnapshot()
        snap.timestamp = time.monotonic()

        # 1. TCP connect + DICOM association + C-ECHO
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)

            t0 = time.monotonic()
            sock.connect((self.target_host, self.target_port))
            t_connect = time.monotonic()
            snap.connect_latency_ms = (t_connect - t0) * 1000.0
            self._baseline_connect_times.append(snap.connect_latency_ms)

            # Send ASSOC_RQ
            sock.sendall(self._assoc_rq)
            sock.settimeout(3.0)
            assoc_resp = sock.recv(4096)
            t_assoc = time.monotonic()
            snap.assoc_latency_ms = (t_assoc - t_connect) * 1000.0

            if assoc_resp and assoc_resp[0] == 0x02:
                snap.assoc_accepted = True

                # Send C-ECHO
                t_echo_start = time.monotonic()
                sock.sendall(self._cecho_rq)
                sock.settimeout(3.0)
                echo_resp = sock.recv(4096)
                t_echo_end = time.monotonic()

                if echo_resp and echo_resp[0] == 0x04:
                    snap.echo_success = True
                    snap.echo_latency_ms = (t_echo_end - t_echo_start) * 1000.0
                    self._baseline_echo_times.append(snap.echo_latency_ms)

                # Clean disconnect
                try:
                    sock.sendall(self._release_rq)
                    sock.settimeout(1.0)
                    sock.recv(1024)
                except Exception:
                    pass

            sock.close()

        except socket.timeout:
            snap.error = "connect_timeout"
        except ConnectionRefusedError:
            snap.error = "refused"
        except ConnectionResetError:
            snap.error = "reset"
        except Exception as e:
            snap.error = str(e)

        # 2. Concurrent connection test (only on full check)
        if full and not snap.error:
            snap.max_concurrent_tested = self.concurrent_test_count
            snap.concurrent_connections = self._test_concurrent()

        return snap

    def check_health_quick(self):
        """Fast health check — just TCP connect + ASSOC_RQ."""
        snap = HealthSnapshot()
        snap.timestamp = time.monotonic()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)

            t0 = time.monotonic()
            sock.connect((self.target_host, self.target_port))
            t_connect = time.monotonic()
            snap.connect_latency_ms = (t_connect - t0) * 1000.0

            sock.sendall(self._assoc_rq)
            sock.settimeout(3.0)
            resp = sock.recv(4096)
            t_assoc = time.monotonic()
            snap.assoc_latency_ms = (t_assoc - t_connect) * 1000.0

            if resp and resp[0] == 0x02:
                snap.assoc_accepted = True
            sock.close()

        except socket.timeout:
            snap.error = "timeout"
        except ConnectionRefusedError:
            snap.error = "refused"
        except Exception as e:
            snap.error = str(e)

        return snap

    def _test_concurrent(self):
        """Test how many concurrent DICOM connections the server accepts."""
        results = [False] * self.concurrent_test_count
        sockets = [None] * self.concurrent_test_count

        def try_connect(idx):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.connect_timeout)
                s.connect((self.target_host, self.target_port))
                s.sendall(self._assoc_rq)
                s.settimeout(3.0)
                resp = s.recv(4096)
                if resp and resp[0] == 0x02:
                    results[idx] = True
                sockets[idx] = s
            except Exception:
                if sockets[idx]:
                    try:
                        sockets[idx].close()
                    except Exception:
                        pass

        threads = []
        for i in range(self.concurrent_test_count):
            t = threading.Thread(target=try_connect, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=self.connect_timeout + 2)

        # Count successes
        success_count = sum(1 for r in results if r)

        # Clean up: release and close all connections
        for s in sockets:
            if s:
                try:
                    s.sendall(self._release_rq)
                    s.settimeout(0.5)
                    s.recv(256)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass

        return success_count

    def measure_recovery(self, max_wait=10.0, poll_interval=0.5):
        """
        After a fuzz PDU, measure how long until the server recovers.

        Returns:
            recovery_ms: time until server accepts a new association (-1 if didn't recover)
            recovered: True if server recovered within max_wait
        """
        t_start = time.monotonic()

        while (time.monotonic() - t_start) < max_wait:
            snap = self.check_health_quick()
            if snap.assoc_accepted:
                return (time.monotonic() - t_start) * 1000.0, True
            time.sleep(poll_interval)

        return max_wait * 1000.0, False

    def compute_degradation(self, before, after):
        """
        Compute server health degradation from before/after snapshots.

        Returns a dict with:
            health_before: 0-100 score
            health_after: 0-100 score
            health_delta: negative = degradation
            echo_latency_delta_ms: increase in echo latency
            connect_latency_delta_ms: increase in connect latency
            connections_lost: decrease in concurrent connection count
            echo_lost: True if echo worked before but not after
            assoc_lost: True if association worked before but not after
            impact_score: 0-100 composite impact score (higher = more impact)
        """
        h_before = before.health_score()
        h_after = after.health_score()
        delta = h_after - h_before

        echo_delta = 0.0
        if before.echo_latency_ms > 0 and after.echo_latency_ms > 0:
            echo_delta = after.echo_latency_ms - before.echo_latency_ms
        elif before.echo_latency_ms > 0 and after.echo_latency_ms < 0:
            echo_delta = 5000.0  # Echo failed → assume 5s latency

        connect_delta = 0.0
        if before.connect_latency_ms > 0 and after.connect_latency_ms > 0:
            connect_delta = after.connect_latency_ms - before.connect_latency_ms
        elif before.connect_latency_ms > 0 and after.connect_latency_ms < 0:
            connect_delta = 5000.0

        conn_lost = 0
        if before.concurrent_connections > 0:
            conn_lost = before.concurrent_connections - after.concurrent_connections

        echo_lost = before.echo_success and not after.echo_success
        assoc_lost = before.assoc_accepted and not after.assoc_accepted

        # Composite impact score (0-100)
        impact = 0.0

        # Health drop (0-40)
        if delta < 0:
            impact += min(abs(delta) * 0.4, 40.0)

        # Echo latency increase (0-20)
        if echo_delta > 0:
            if echo_delta > 1000:
                impact += 20.0
            elif echo_delta > 100:
                impact += 15.0
            elif echo_delta > 20:
                impact += 10.0
            elif echo_delta > 5:
                impact += 5.0

        # Connection loss (0-20)
        if conn_lost > 0:
            impact += min(conn_lost * 5.0, 20.0)

        # Service loss (0-20)
        if assoc_lost:
            impact += 10.0
        if echo_lost:
            impact += 10.0

        return {
            "health_before": round(h_before, 1),
            "health_after": round(h_after, 1),
            "health_delta": round(delta, 1),
            "echo_latency_delta_ms": round(echo_delta, 1),
            "connect_latency_delta_ms": round(connect_delta, 1),
            "connections_lost": conn_lost,
            "echo_lost": echo_lost,
            "assoc_lost": assoc_lost,
            "impact_score": round(min(impact, 100.0), 1),
        }

    def get_baseline_stats(self):
        """Get statistics from baseline history."""
        stats = {
            "avg_echo_ms": 0.0,
            "avg_connect_ms": 0.0,
            "echo_samples": len(self._baseline_echo_times),
            "connect_samples": len(self._baseline_connect_times),
        }
        if self._baseline_echo_times:
            stats["avg_echo_ms"] = round(
                sum(self._baseline_echo_times) / len(self._baseline_echo_times), 1)
        if self._baseline_connect_times:
            stats["avg_connect_ms"] = round(
                sum(self._baseline_connect_times) / len(self._baseline_connect_times), 1)
        return stats


class ProcessMonitor:
    """
    Monitors a remote process's resource usage via SSH.

    Tracks RSS memory, FD count, CPU%, and thread count to detect
    memory leaks, FD leaks, and CPU anomalies on the target server.

    Usage:
        monitor = ProcessMonitor(ssh_host="user@host", process_name="storescp")
        monitor.take_baseline()
        # ... fuzzing ...
        monitor.sample()  # Call periodically (e.g., every 10 steps)
        metrics = monitor.get_latest_metrics()
        summary = monitor.get_summary()
    """

    def __init__(self, ssh_host, process_name, sample_interval=10):
        """
        Args:
            ssh_host: SSH host string (e.g., "user@192.168.1.100")
            process_name: Process name to monitor (e.g., "storescp")
            sample_interval: Minimum steps between samples
        """
        self.ssh_host = ssh_host
        self.process_name = process_name
        self.sample_interval = sample_interval

        # Baseline values
        self.baseline_rss_kb = 0
        self.baseline_vsz_kb = 0
        self.baseline_fd_count = 0
        self.baseline_cpu = 0.0
        self.baseline_threads = 0
        self.baseline_taken = False

        # Current/latest values
        self._latest = {}
        self._prev = {}  # Previous sample for delta computation
        self._history = []  # List of metric snapshots
        self._step_counter = 0
        self._pid = None
        self._last_reported_anomaly = 0.0  # For visibility logging

        self._lock = threading.Lock()

    def _ssh_command(self, cmd):
        """Run a command via SSH and return stdout."""
        import subprocess
        full_cmd = f'ssh -o BatchMode=yes -o ConnectTimeout=5 {self.ssh_host} "{cmd}" 2>/dev/null'
        try:
            result = subprocess.run(
                full_cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.debug(f"SSH command rc={result.returncode}: {cmd[:50]}")
        except subprocess.TimeoutExpired:
            logger.warning(f"SSH command timed out: {cmd[:50]}")
        except Exception as e:
            logger.debug(f"SSH command failed: {e}")
        return None

    def _find_pid(self):
        """Find the PID of the target process."""
        output = self._ssh_command(f"pgrep -x {self.process_name} | head -1")
        if output:
            try:
                self._pid = int(output.strip())
                return self._pid
            except ValueError:
                pass
        # Fallback: try pidof
        output = self._ssh_command(f"pidof {self.process_name} | awk '{{print $1}}'")
        if output:
            try:
                self._pid = int(output.strip().split()[0])
                return self._pid
            except (ValueError, IndexError):
                pass
        return None

    def _collect_metrics(self):
        """Collect process metrics via SSH."""
        if not self._pid:
            self._find_pid()
        if not self._pid:
            return None

        # Get RSS, VSZ, CPU%, thread count in one call
        output = self._ssh_command(
            f"ps -p {self._pid} -o rss=,vsz=,%cpu=,nlwp= 2>/dev/null"
        )
        if not output:
            # Process may have died, try to find it again
            self._pid = None
            self._find_pid()
            if not self._pid:
                return None
            output = self._ssh_command(
                f"ps -p {self._pid} -o rss=,vsz=,%cpu=,nlwp= 2>/dev/null"
            )
            if not output:
                return None

        try:
            parts = output.strip().split()
            rss_kb = int(parts[0])
            vsz_kb = int(parts[1])
            cpu_pct = float(parts[2])
            threads = int(parts[3])
        except (ValueError, IndexError):
            return None

        # Get FD count
        fd_count = 0
        fd_output = self._ssh_command(
            f"ls /proc/{self._pid}/fd 2>/dev/null | wc -l"
        )
        if fd_output:
            try:
                fd_count = int(fd_output.strip())
            except ValueError:
                pass

        metrics = {
            'rss_kb': rss_kb,
            'vsz_kb': vsz_kb,
            'cpu_percent': cpu_pct,
            'threads': threads,
            'fd_count': fd_count,
            'timestamp': time.monotonic(),
        }

        # Compute deltas from baseline
        if self.baseline_taken:
            metrics['rss_growth_kb'] = rss_kb - self.baseline_rss_kb
            metrics['rss_growth_mb'] = (rss_kb - self.baseline_rss_kb) / 1024.0
            metrics['fd_growth'] = fd_count - self.baseline_fd_count
            metrics['thread_growth'] = threads - self.baseline_threads

            # Per-sample delta (rate of change since last sample)
            rss_delta_mb = 0.0
            fd_delta = 0
            if self._prev:
                rss_delta_mb = (rss_kb - self._prev.get('rss_kb', rss_kb)) / 1024.0
                fd_delta = fd_count - self._prev.get('fd_count', fd_count)
            metrics['rss_delta_mb'] = rss_delta_mb
            metrics['fd_delta'] = fd_delta

            # Anomaly score (0-100) based on rate of change, not total growth
            anomaly = 0.0
            # RSS spike (0-40): sudden growth between samples indicates leak
            if rss_delta_mb > 10:
                anomaly += 40.0
            elif rss_delta_mb > 2:
                anomaly += 25.0
            elif rss_delta_mb > 0.5:
                anomaly += 10.0
            # FD spike (0-30): sudden FD increase between samples
            if fd_delta > 20:
                anomaly += 30.0
            elif fd_delta > 5:
                anomaly += 20.0
            elif fd_delta > 1:
                anomaly += 10.0
            # CPU (0-30): sustained high CPU
            if cpu_pct > 90:
                anomaly += 30.0
            elif cpu_pct > 50:
                anomaly += 15.0
            elif cpu_pct > 20:
                anomaly += 5.0
            metrics['anomaly_score'] = min(anomaly, 100.0)
        else:
            metrics['rss_growth_kb'] = 0
            metrics['rss_growth_mb'] = 0.0
            metrics['rss_delta_mb'] = 0.0
            metrics['fd_growth'] = 0
            metrics['fd_delta'] = 0
            metrics['thread_growth'] = 0
            metrics['anomaly_score'] = 0.0

        return metrics

    def take_baseline(self):
        """Take baseline measurements before fuzzing starts."""
        # First verify SSH connectivity
        test = self._ssh_command("echo ok")
        if not test:
            logger.warning(f"SSH connection to {self.ssh_host} failed. "
                          f"Check SSH key auth (BatchMode=yes).")
            return False

        if not self._find_pid():
            logger.warning(f"Process '{self.process_name}' not found on {self.ssh_host}. "
                          f"Check process name or if it's running.")
            return False

        metrics = self._collect_metrics()
        if metrics:
            self.baseline_rss_kb = metrics['rss_kb']
            self.baseline_vsz_kb = metrics['vsz_kb']
            self.baseline_fd_count = metrics['fd_count']
            self.baseline_cpu = metrics['cpu_percent']
            self.baseline_threads = metrics['threads']
            self.baseline_taken = True
            logger.info(f"Process baseline: RSS={self.baseline_rss_kb}KB "
                       f"FDs={self.baseline_fd_count} CPU={self.baseline_cpu}% "
                       f"Threads={self.baseline_threads} PID={self._pid}")
            return True
        logger.warning(f"Failed to collect metrics for '{self.process_name}' (PID={self._pid})")
        return False

    def sample(self, force=False):
        """
        Collect a sample if enough steps have passed.

        Args:
            force: If True, sample regardless of interval.

        Returns:
            metrics dict or None if skipped/failed
        """
        self._step_counter += 1
        if not force and self._step_counter % self.sample_interval != 0:
            return None

        metrics = self._collect_metrics()
        if metrics:
            with self._lock:
                self._prev = dict(self._latest) if self._latest else {}
                self._latest = metrics
                self._history.append(metrics)

            # Periodic visibility: log when anomaly_score changes significantly
            anomaly = metrics.get('anomaly_score', 0)
            if abs(anomaly - self._last_reported_anomaly) > 10:
                logger.info(
                    f"PROCESS [{self.process_name}]: anomaly={anomaly:.0f}/100 "
                    f"RSS={metrics['rss_kb']}KB({metrics['rss_growth_mb']:+.1f}MB) "
                    f"delta={metrics['rss_delta_mb']:+.1f}MB "
                    f"FDs={metrics['fd_count']}({metrics['fd_growth']:+d}) "
                    f"CPU={metrics['cpu_percent']:.1f}%"
                )
                self._last_reported_anomaly = anomaly

        return metrics

    def get_latest_metrics(self):
        """Return the most recent metrics snapshot."""
        with self._lock:
            return dict(self._latest) if self._latest else None

    def get_anomaly_reward(self):
        """Return bonus reward based on anomaly score (0-50)."""
        with self._lock:
            if not self._latest:
                return 0.0
            score = self._latest.get('anomaly_score', 0)
            return min(score * 0.5, 50.0)  # Up to +50 reward

    def get_summary(self):
        """Return a summary of all collected metrics."""
        with self._lock:
            if not self._history:
                return None

            rss_values = [m['rss_kb'] for m in self._history]
            fd_values = [m['fd_count'] for m in self._history]
            cpu_values = [m['cpu_percent'] for m in self._history]

            return {
                'samples': len(self._history),
                'baseline_rss_kb': self.baseline_rss_kb,
                'baseline_fd_count': self.baseline_fd_count,
                'baseline_cpu': self.baseline_cpu,
                'baseline_threads': self.baseline_threads,
                'current_rss_kb': rss_values[-1] if rss_values else 0,
                'max_rss_kb': max(rss_values) if rss_values else 0,
                'rss_growth_kb': (rss_values[-1] - self.baseline_rss_kb) if rss_values else 0,
                'rss_growth_mb': (rss_values[-1] - self.baseline_rss_kb) / 1024.0 if rss_values else 0,
                'current_fd_count': fd_values[-1] if fd_values else 0,
                'max_fd_count': max(fd_values) if fd_values else 0,
                'fd_growth': (fd_values[-1] - self.baseline_fd_count) if fd_values else 0,
                'avg_cpu': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
                'max_cpu': max(cpu_values) if cpu_values else 0,
                'final_anomaly_score': self._history[-1].get('anomaly_score', 0) if self._history else 0,
                'max_anomaly_score': max(m.get('anomaly_score', 0) for m in self._history) if self._history else 0,
                'pid': self._pid,
            }


class AsanMonitor:
    """
    Monitors AddressSanitizer (ASAN) log files on a remote server via SSH.

    DCMTK (or any target) should be compiled with -fsanitize=address and run with:
        ASAN_OPTIONS="log_path=/tmp/asan_storescp:halt_on_error=0:detect_leaks=1"

    This makes ASAN write report files like /tmp/asan_storescp.<pid>.<seq> for each
    bug found, while allowing the process to continue running.

    Usage:
        monitor = AsanMonitor(ssh_host="root@host", asan_log_pattern="/tmp/asan_storescp.*")
        monitor.take_baseline()
        # ... fuzzing ...
        new_bugs = monitor.sample()
        reward = monitor.get_bug_reward()
        summary = monitor.get_summary()
    """

    # ASAN error types and their severity
    SEVERITY_MAP = {
        # Critical: memory corruption bugs
        'heap-buffer-overflow': 'critical',
        'heap-use-after-free': 'critical',
        'stack-buffer-overflow': 'critical',
        'global-buffer-overflow': 'critical',
        'stack-use-after-return': 'critical',
        # High: memory management bugs
        'double-free': 'high',
        'alloc-dealloc-mismatch': 'high',
        'stack-overflow': 'high',
        # Medium: leaks
        'memory-leak': 'medium',
        'detected memory leaks': 'medium',
    }

    SEVERITY_REWARDS = {
        'critical': 300.0,
        'high': 150.0,
        'medium': 50.0,
        'unknown': 25.0,
    }

    # Regex for ASAN error lines
    _RE_ERROR = re.compile(
        r'==\d+==ERROR: AddressSanitizer: (\S+)'
    )
    # Regex for stack frame lines
    _RE_FRAME = re.compile(
        r'#(\d+)\s+\S+\s+in\s+(\S+)\s+(\S+)'
    )
    # Regex for leak summary
    _RE_LEAK = re.compile(
        r'==\d+==ERROR: LeakSanitizer: (detected memory leaks)'
    )

    def __init__(self, ssh_host, asan_log_pattern="/tmp/asan_storescp.*",
                 sample_interval=5):
        """
        Args:
            ssh_host: SSH host string (e.g., "root@192.168.1.100")
            asan_log_pattern: Glob pattern for ASAN log files on remote host
            sample_interval: Minimum steps between samples
        """
        self.ssh_host = ssh_host
        self.asan_log_pattern = asan_log_pattern
        self.sample_interval = sample_interval

        # Tracking
        self._seen_files = set()       # Files already processed
        self._seen_fingerprints = set()  # Deduplicated bug fingerprints
        self._bugs = []                # All unique bugs found
        self._step_counter = 0
        self._last_reward = 0.0
        self._lock = threading.Lock()

    def _ssh_command(self, cmd):
        """Run a command via SSH and return stdout."""
        import subprocess
        full_cmd = f'ssh -o BatchMode=yes -o ConnectTimeout=5 {self.ssh_host} "{cmd}" 2>/dev/null'
        try:
            result = subprocess.run(
                full_cmd, shell=True, capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.debug(f"ASAN SSH command rc={result.returncode}: {cmd[:60]}")
        except subprocess.TimeoutExpired:
            logger.warning(f"ASAN SSH command timed out: {cmd[:60]}")
        except Exception as e:
            logger.debug(f"ASAN SSH command failed: {e}")
        return None

    def _parse_asan_report(self, text):
        """Parse an ASAN report and extract error type, severity, and stack frames.

        Returns:
            dict with error_type, severity, stack_frames list, or None if unparseable
        """
        error_type = None
        stack_frames = []

        # Check for error type
        match = self._RE_ERROR.search(text)
        if match:
            error_type = match.group(1)
        else:
            # Check for leak report
            match = self._RE_LEAK.search(text)
            if match:
                error_type = 'memory-leak'

        if not error_type:
            return None

        # Extract stack frames
        for m in self._RE_FRAME.finditer(text):
            frame_num = int(m.group(1))
            function = m.group(2)
            location = m.group(3)
            stack_frames.append({
                'frame': frame_num,
                'function': function,
                'location': location,
            })

        severity = self.SEVERITY_MAP.get(error_type, 'unknown')

        return {
            'error_type': error_type,
            'severity': severity,
            'stack_frames': stack_frames,
        }

    def _get_fingerprint(self, report):
        """Generate a deduplication fingerprint for a bug report.

        Fingerprint = error_type + first stack frame's function + file.
        """
        fp_parts = [report['error_type']]
        if report['stack_frames']:
            frame = report['stack_frames'][0]
            fp_parts.append(frame['function'])
            fp_parts.append(frame['location'])
        return '|'.join(fp_parts)

    def take_baseline(self):
        """Scan existing ASAN log files and mark them as already seen."""
        test = self._ssh_command("echo ok")
        if not test:
            logger.warning(f"ASAN monitor: SSH to {self.ssh_host} failed")
            return False

        output = self._ssh_command(f"ls -1 {self.asan_log_pattern} 2>/dev/null")
        if output:
            for line in output.strip().split('\n'):
                line = line.strip()
                if line:
                    self._seen_files.add(line)
            logger.info(f"ASAN baseline: {len(self._seen_files)} existing log files marked as seen")
        else:
            logger.info("ASAN baseline: no existing log files found (clean start)")
        return True

    def sample(self, force=False):
        """Check for new ASAN log files, parse and deduplicate.

        Returns:
            list of new unique bug reports (may be empty)
        """
        self._step_counter += 1
        if not force and self._step_counter % self.sample_interval != 0:
            return []

        output = self._ssh_command(f"ls -1 {self.asan_log_pattern} 2>/dev/null")
        if not output:
            return []

        new_files = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if line and line not in self._seen_files:
                new_files.append(line)
                self._seen_files.add(line)

        if not new_files:
            return []

        new_bugs = []
        for filepath in new_files:
            content = self._ssh_command(f"cat {filepath}")
            if not content:
                continue

            report = self._parse_asan_report(content)
            if not report:
                continue

            report['file'] = filepath
            fingerprint = self._get_fingerprint(report)

            if fingerprint not in self._seen_fingerprints:
                self._seen_fingerprints.add(fingerprint)
                report['fingerprint'] = fingerprint
                with self._lock:
                    self._bugs.append(report)
                new_bugs.append(report)

                logger.critical(
                    f"ASAN BUG [{report['severity'].upper()}]: {report['error_type']} "
                    f"in {report['stack_frames'][0]['function'] if report['stack_frames'] else '?'} "
                    f"({filepath})"
                )

        self._last_reward = 0.0
        for bug in new_bugs:
            self._last_reward += self.SEVERITY_REWARDS.get(bug['severity'], 25.0)

        return new_bugs

    def get_bug_reward(self):
        """Return the reward accumulated from the last sample() call."""
        return self._last_reward

    def get_bug_counts(self):
        """Return bug counts by severity."""
        with self._lock:
            counts = {'critical': 0, 'high': 0, 'medium': 0, 'unknown': 0, 'total': 0}
            for bug in self._bugs:
                counts[bug['severity']] = counts.get(bug['severity'], 0) + 1
                counts['total'] += 1
            return counts

    def get_summary(self):
        """Return a summary of all ASAN bugs found."""
        with self._lock:
            if not self._bugs:
                return None

            counts = {'critical': 0, 'high': 0, 'medium': 0, 'unknown': 0}
            error_types = {}
            top_frames = {}

            for bug in self._bugs:
                counts[bug['severity']] = counts.get(bug['severity'], 0) + 1
                error_types[bug['error_type']] = error_types.get(bug['error_type'], 0) + 1
                if bug['stack_frames']:
                    frame_key = f"{bug['stack_frames'][0]['function']} ({bug['stack_frames'][0]['location']})"
                    top_frames[frame_key] = top_frames.get(frame_key, 0) + 1

            return {
                'total_unique_bugs': len(self._bugs),
                'total_files_seen': len(self._seen_files),
                'severity_counts': counts,
                'error_types': error_types,
                'top_stack_frames': sorted(top_frames.items(), key=lambda x: -x[1])[:10],
            }


class CoverageMonitor:
    """
    Monitors code coverage growth on a remote server via SSH + lcov.

    DCMTK (or any target) should be compiled with --coverage:
        cmake -DCMAKE_C_FLAGS="--coverage" -DCMAKE_CXX_FLAGS="--coverage" ...

    .gcda files accumulate coverage data at runtime. This monitor periodically
    runs lcov to measure line and function coverage, rewarding the RL agent
    for reaching new code.

    Usage:
        monitor = CoverageMonitor(ssh_host="root@host", coverage_dir="/opt/dcmtk/build")
        monitor.take_baseline()
        # ... fuzzing ...
        delta = monitor.sample()
        reward = monitor.get_coverage_reward()
        summary = monitor.get_summary()
    """

    def __init__(self, ssh_host, coverage_dir, sample_interval=20, process_name=None):
        """
        Args:
            ssh_host: SSH host string (e.g., "root@192.168.1.100")
            coverage_dir: Build directory with .gcda coverage files on remote host
            sample_interval: Minimum steps between samples (lcov is slow)
            process_name: Process name to flush gcov data from (e.g., "storescp")
        """
        self.ssh_host = ssh_host
        self.coverage_dir = coverage_dir
        self.sample_interval = sample_interval
        self.process_name = process_name
        self._flush_method = None  # auto-detected: "dump", "flush", or None

        # Baseline and current coverage
        self.baseline_lines = 0
        self.baseline_functions = 0
        self.baseline_line_pct = 0.0
        self.baseline_func_pct = 0.0
        self.baseline_taken = False

        self.current_lines = 0
        self.current_functions = 0
        self.current_line_pct = 0.0
        self.current_func_pct = 0.0

        # Peak tracking
        self.peak_lines = 0
        self.peak_functions = 0

        # Sampling
        self._step_counter = 0
        self._last_reward = 0.0
        self._prev_lines = 0
        self._prev_functions = 0
        self._history = []
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._failure_warned = False

    # Regex for lcov summary output
    _RE_LINES = re.compile(r'lines\.*:\s*([\d.]+)%\s*\((\d+)\s+of\s+(\d+)')
    _RE_FUNCS = re.compile(r'functions\.*:\s*([\d.]+)%\s*\((\d+)\s+of\s+(\d+)')

    def _ssh_command(self, cmd):
        """Run a command via SSH and return stdout."""
        import subprocess
        full_cmd = f'ssh -o BatchMode=yes -o ConnectTimeout=5 {self.ssh_host} "{cmd}"'
        try:
            result = subprocess.run(
                full_cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                stderr_snippet = result.stderr.strip()[:120] if result.stderr else ""
                logger.debug(f"Coverage SSH rc={result.returncode}: {cmd[:60]} | {stderr_snippet}")
        except subprocess.TimeoutExpired:
            logger.warning(f"Coverage SSH command timed out: {cmd[:60]}")
        except Exception as e:
            logger.debug(f"Coverage SSH command failed: {e}")
        return None

    def _ssh_command_raw(self, cmd, timeout=30):
        """Run SSH command and return (stdout, stderr, returncode) regardless of exit code."""
        import subprocess
        full_cmd = f'ssh -o BatchMode=yes -o ConnectTimeout=5 {self.ssh_host} "{cmd}"'
        try:
            result = subprocess.run(
                full_cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", "timeout", -1
        except Exception as e:
            return "", str(e), -1

    def _flush_gcov(self):
        """Flush gcov data from the running process so .gcda files are up-to-date.

        Long-running processes only write .gcda on exit. We try (in order):
        1. SIGUSR1: requires coverage_handler.so LD_PRELOAD (works with ASAN)
        2. GDB: call __gcov_dump() (fails with ASAN, works without)
        3. SIGPROF: some GCC runtimes flush on SIGPROF
        4. None: coverage data will be stale until process restart
        """
        if not self.process_name:
            return

        # Auto-detect flush method on first call
        if self._flush_method is None:
            pid = self._ssh_command(f"pgrep -x {self.process_name} | head -1")
            if not pid:
                logger.debug(f"Coverage flush: process {self.process_name} not found")
                self._flush_method = "none"
                return

            # Try SIGUSR1 first (works with ASAN via coverage_handler.so LD_PRELOAD)
            logger.info("Coverage flush: trying SIGUSR1 (coverage_handler.so)...")
            # Remove stale marker
            self._ssh_command("rm -f /tmp/.gcov_dumped")
            pre_cov = self._read_coverage_raw()
            self._ssh_command(f"kill -SIGUSR1 {pid}")
            time.sleep(0.3)
            # Check if the handler wrote a marker file
            marker = self._ssh_command("cat /tmp/.gcov_dumped 2>/dev/null")
            if marker and marker.strip() == "1":
                self._flush_method = "sigusr1"
                self._ssh_command("rm -f /tmp/.gcov_dumped")
                logger.info(f"Coverage flush: SIGUSR1 works (coverage_handler.so detected)")
                return  # first call already flushed

            # SIGUSR1 sent but no marker — check if coverage changed anyway
            post_cov = self._read_coverage_raw()
            if pre_cov and post_cov and \
               post_cov.get('lines_covered', 0) > pre_cov.get('lines_covered', 0):
                self._flush_method = "sigusr1"
                logger.info(f"Coverage flush: SIGUSR1 works (coverage increased: "
                           f"{pre_cov['lines_covered']} -> {post_cov['lines_covered']})")
                return

            # Try GDB (may fail with ASAN)
            gdb_check = self._ssh_command("which gdb")
            if gdb_check:
                stdout, stderr, rc = self._ssh_command_raw(
                    f"gdb -batch -p {pid} -ex 'info proc' 2>&1"
                )
                attach_output = stdout + " " + stderr
                if "ptrace: operation not permitted" not in attach_output.lower():
                    gdb_prefix = (
                        f"gdb -batch -p {pid} "
                        f"-ex 'set env ASAN_OPTIONS=detect_leaks=0' "
                        f"-ex 'set unwindonsignal on' "
                    )
                    for func_name in ("__gcov_dump", "__gcov_flush"):
                        gdb_cmd = f"{gdb_prefix}-ex 'call (void){func_name}()' 2>&1"
                        stdout, stderr, rc = self._ssh_command_raw(gdb_cmd)
                        output = stdout + " " + stderr
                        if "no symbol" not in output.lower() and "cannot" not in output.lower() \
                           and "signal" not in output.lower():
                            method = "dump" if func_name == "__gcov_dump" else "flush"
                            self._flush_method = method
                            logger.info(f"Coverage flush: using {func_name}() via GDB (pid={pid})")
                            return

            # Fallback: try SIGPROF
            logger.info("Coverage flush: trying kill -SIGPROF...")
            pre_cov = self._read_coverage_raw()
            self._ssh_command(f"kill -SIGPROF {pid}")
            time.sleep(0.5)
            post_cov = self._read_coverage_raw()
            if pre_cov and post_cov and \
               post_cov.get('lines_covered', 0) > pre_cov.get('lines_covered', 0):
                self._flush_method = "sigprof"
                logger.info(f"Coverage flush: kill -SIGPROF works "
                           f"({pre_cov['lines_covered']} -> {post_cov['lines_covered']} lines)")
                return

            # Nothing worked
            binary_path = self._ssh_command(f"readlink -f /proc/{pid}/exe 2>/dev/null") or "?"
            logger.warning(
                f"Coverage flush: no working method found for {self.process_name} (pid={pid})\n"
                f"  Binary: {binary_path}\n"
                f"  To fix: start server with LD_PRELOAD=coverage_handler.so\n"
                f"  Build coverage_handler.so: gcc -shared -fPIC -o coverage_handler.so coverage_handler.c"
            )
            self._flush_method = "none"
            return

        if self._flush_method == "none":
            return

        pid = self._ssh_command(f"pgrep -x {self.process_name} | head -1")
        if not pid:
            return

        if self._flush_method == "sigusr1":
            self._ssh_command(f"kill -SIGUSR1 {pid}")
            time.sleep(0.2)
        elif self._flush_method == "sigprof":
            self._ssh_command(f"kill -SIGPROF {pid}")
            time.sleep(0.3)
        else:
            func = "__gcov_dump" if self._flush_method == "dump" else "__gcov_flush"
            self._ssh_command(f"gdb -batch -p {pid} -ex 'call (void){func}()' 2>&1")

    def _read_coverage_raw(self):
        """Run lcov and parse coverage without flushing first.

        Returns:
            dict with lines_covered, functions_covered, line_pct, func_pct, or None
        """
        capture_cmd = (
            f"lcov --capture --directory {self.coverage_dir} "
            f"--output-file /tmp/coverage_fuzzer.info --quiet && "
            f"lcov --summary /tmp/coverage_fuzzer.info 2>&1"
        )
        output = self._ssh_command(capture_cmd)
        if not output:
            return None

        result = {}

        line_match = self._RE_LINES.search(output)
        if line_match:
            result['line_pct'] = float(line_match.group(1))
            result['lines_covered'] = int(line_match.group(2))
            result['lines_total'] = int(line_match.group(3))
        else:
            return None

        func_match = self._RE_FUNCS.search(output)
        if func_match:
            result['func_pct'] = float(func_match.group(1))
            result['functions_covered'] = int(func_match.group(2))
            result['functions_total'] = int(func_match.group(3))
        else:
            result['func_pct'] = 0.0
            result['functions_covered'] = 0
            result['functions_total'] = 0

        return result

    def _read_coverage(self):
        """Flush gcov data then run lcov and parse coverage.

        Returns:
            dict with lines_covered, functions_covered, line_pct, func_pct, or None
        """
        self._flush_gcov()
        return self._read_coverage_raw()

    def take_baseline(self):
        """Measure initial coverage before fuzzing starts."""
        test = self._ssh_command("echo ok")
        if not test:
            logger.warning(f"Coverage monitor: SSH to {self.ssh_host} failed")
            return False

        # Check that lcov is available
        lcov_check = self._ssh_command("which lcov")
        if not lcov_check:
            logger.warning("Coverage monitor: lcov not found on remote host")
            return False

        cov = self._read_coverage()
        if cov:
            self.baseline_lines = cov['lines_covered']
            self.baseline_functions = cov['functions_covered']
            self.baseline_line_pct = cov['line_pct']
            self.baseline_func_pct = cov['func_pct']
            self.baseline_taken = True

            self.current_lines = self.baseline_lines
            self.current_functions = self.baseline_functions
            self._prev_lines = self.baseline_lines
            self._prev_functions = self.baseline_functions
            self.peak_lines = self.baseline_lines
            self.peak_functions = self.baseline_functions

            logger.info(
                f"Coverage baseline: {cov['lines_covered']}/{cov.get('lines_total', '?')} lines "
                f"({cov['line_pct']:.1f}%), "
                f"{cov['functions_covered']}/{cov.get('functions_total', '?')} functions "
                f"({cov['func_pct']:.1f}%)"
            )
            return True

        logger.warning("Coverage monitor: failed to read initial coverage")
        return False

    def sample(self, force=False):
        """Read coverage and compute delta from previous sample.

        Returns:
            dict with 'lines' and 'functions' delta, or None if skipped/failed
        """
        self._step_counter += 1
        if not force and self._step_counter % self.sample_interval != 0:
            return None

        cov = self._read_coverage()
        if not cov:
            self._consecutive_failures += 1
            if self._consecutive_failures >= 3 and not self._failure_warned:
                logger.warning(
                    f"Coverage monitor: {self._consecutive_failures} consecutive lcov failures. "
                    f"Check that {self.coverage_dir} contains .gcda files and lcov works on {self.ssh_host}"
                )
                self._failure_warned = True
            return None

        self._consecutive_failures = 0
        with self._lock:
            self.current_lines = cov['lines_covered']
            self.current_functions = cov['functions_covered']
            self.current_line_pct = cov['line_pct']
            self.current_func_pct = cov['func_pct']

            line_delta = self.current_lines - self._prev_lines
            func_delta = self.current_functions - self._prev_functions

            self._prev_lines = self.current_lines
            self._prev_functions = self.current_functions

            if self.current_lines > self.peak_lines:
                self.peak_lines = self.current_lines
            if self.current_functions > self.peak_functions:
                self.peak_functions = self.current_functions

            self._history.append({
                'lines': self.current_lines,
                'functions': self.current_functions,
                'line_pct': self.current_line_pct,
                'func_pct': self.current_func_pct,
                'timestamp': time.monotonic(),
            })

        delta = {'lines': line_delta, 'functions': func_delta}

        # Compute reward
        self._last_reward = 0.0
        if line_delta > 0:
            self._last_reward += min(line_delta * 5.0, 100.0)
            logger.info(
                f"COVERAGE: +{line_delta} lines (total: {self.current_lines}, "
                f"{self.current_line_pct:.1f}%)"
            )
        if func_delta > 0:
            self._last_reward += min(func_delta * 20.0, 100.0)
            logger.info(
                f"COVERAGE: +{func_delta} functions (total: {self.current_functions}, "
                f"{self.current_func_pct:.1f}%)"
            )

        return delta

    def get_coverage_reward(self):
        """Return the reward accumulated from the last sample() call."""
        return self._last_reward

    def get_current_coverage(self):
        """Return current coverage metrics."""
        with self._lock:
            return {
                'lines': self.current_lines,
                'functions': self.current_functions,
                'line_pct': self.current_line_pct,
                'func_pct': self.current_func_pct,
                'lines_from_baseline': self.current_lines - self.baseline_lines,
                'functions_from_baseline': self.current_functions - self.baseline_functions,
            }

    def get_summary(self):
        """Return a summary of coverage growth."""
        with self._lock:
            return {
                'baseline_lines': self.baseline_lines,
                'baseline_functions': self.baseline_functions,
                'baseline_line_pct': self.baseline_line_pct,
                'baseline_func_pct': self.baseline_func_pct,
                'final_lines': self.current_lines,
                'final_functions': self.current_functions,
                'final_line_pct': self.current_line_pct,
                'final_func_pct': self.current_func_pct,
                'lines_growth': self.current_lines - self.baseline_lines,
                'functions_growth': self.current_functions - self.baseline_functions,
                'peak_lines': self.peak_lines,
                'peak_functions': self.peak_functions,
                'samples': len(self._history),
            }