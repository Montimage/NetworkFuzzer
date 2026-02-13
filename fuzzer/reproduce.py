#!/usr/bin/env python3
"""
PDU Replay & Response Classifier for NetworkFuzzer.

Replays raw .bin PDU files against a DICOM server and classifies responses:
  CRASH  — Server unresponsive after send (health check fails)
  HANG   — No response after timeout + retry
  ABORT  — Server sent A-ABORT (PDU type 0x07)
  ACCEPT — Server accepted association (PDU type 0x02)
  REJECT — Server rejected association (PDU type 0x03)
  ERROR  — Connection reset, refused, or other socket exception
  CLOSED — Server closed connection silently (0 bytes)

Usage:
  python3 -m fuzzer.reproduce --input-dir fuzzer/data/pcap_output/rl_generated \\
      --target-host 192.168.1.200 --target-port 4242

  python3 -m fuzzer.reproduce --input rl_fuzzed_0005.bin \\
      --target-host localhost --target-port 4242 --associate --health-check
"""

import argparse
import csv
import glob
import os
import select
import socket
import struct
import sys
import time

# ---------------------------------------------------------------------------
# Verdict severity order (higher = more interesting)
# ---------------------------------------------------------------------------
VERDICT_SEVERITY = {
    "CRASH": 0,
    "HANG": 1,
    "ABORT": 2,
    "ACCEPT": 3,
    "REJECT": 4,
    "REJECTED": 5,  # Server closed connection after parsing
    "ERROR": 6,
    "CLOSED": 7,
}

# PDU type byte → name
PDU_TYPE_NAMES = {
    0x01: "ASSOC_RQ",
    0x02: "ASSOC_AC",
    0x03: "ASSOC_RJ",
    0x04: "PDATA",
    0x05: "REL_RQ",
    0x06: "REL_RP",
    0x07: "ABORT",
}

# A-ASSOCIATE-RJ rejection sources and reasons (from reward.py)
RJ_SOURCES = {
    1: "DUL-service-user",
    2: "DUL-service-provider-ACSE",
    3: "DUL-service-provider-presentation",
}
RJ_REASONS_USER = {
    1: "no-reason", 2: "application-context-unsupported",
    3: "calling-AE-not-recognized", 7: "called-AE-not-recognized",
}
RJ_REASONS_ACSE = {1: "no-reason", 2: "protocol-version-not-supported"}
RJ_REASONS_PRES = {0: "no-reason", 1: "temporary-congestion", 2: "local-limit-exceeded"}

# A-ABORT sources and reasons (DICOM PS3.8 Table 9-26)
ABORT_SOURCES = {0: "DUL-service-user", 2: "DUL-service-provider"}
ABORT_REASONS = {
    0: "reason-not-specified",
    1: "unrecognized-PDU",
    2: "unexpected-PDU",
    4: "unrecognized-PDU-parameter",
    5: "unexpected-PDU-parameter",
    6: "invalid-PDU-parameter-value",
}


def is_socket_alive(sock):
    """Check if socket is still connected without blocking."""
    try:
        # Use select with 0 timeout to check if socket is readable
        readable, _, exceptional = select.select([sock], [], [sock], 0)
        if exceptional:
            return False
        if readable:
            # Socket is readable - peek to see if it's EOF
            try:
                data = sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                return len(data) > 0
            except (BlockingIOError, socket.error):
                return True  # No data yet, but socket alive
        
        # Additional check: try to get socket error status
        try:
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err != 0:
                return False
        except Exception:
            pass
            
        return True  # Not readable yet, still alive
    except Exception:
        return False


def wait_for_response_or_closure(sock, timeout_ms):
    """
    Wait for either data or socket closure, with fine-grained polling.
    Returns (data: bytes, closed: bool, elapsed_ms: float)
    """
    start = time.monotonic()
    timeout_s = timeout_ms / 1000.0
    poll_interval = 0.05  # 50ms polling
    
    while (time.monotonic() - start) < timeout_s:
        # Check if data is available
        readable, _, exceptional = select.select([sock], [], [sock], poll_interval)
        
        if exceptional:
            elapsed = (time.monotonic() - start) * 1000.0
            return b"", True, elapsed
            
        if readable:
            try:
                data = sock.recv(4096)
                elapsed = (time.monotonic() - start) * 1000.0
                if len(data) == 0:
                    # EOF - server closed connection
                    return b"", True, elapsed
                return data, False, elapsed
            except Exception:
                elapsed = (time.monotonic() - start) * 1000.0
                return b"", True, elapsed
    
    # Timeout - check if socket is still alive
    elapsed = (time.monotonic() - start) * 1000.0
    alive = is_socket_alive(sock)
    return b"", not alive, elapsed


def parse_reject_pdu(response):
    """Parse A-ASSOCIATE-RJ (bytes 7=result, 8=source, 9=reason)."""
    source_name = "unknown"
    reason_name = "unknown"
    if len(response) >= 10:
        src = response[8]
        reason = response[9]
        source_name = RJ_SOURCES.get(src, f"unknown-{src}")
        if src == 1:
            reason_name = RJ_REASONS_USER.get(reason, f"code-{reason}")
        elif src == 2:
            reason_name = RJ_REASONS_ACSE.get(reason, f"code-{reason}")
        elif src == 3:
            reason_name = RJ_REASONS_PRES.get(reason, f"code-{reason}")
    return source_name, reason_name


def parse_abort_pdu(response):
    """Parse A-ABORT (bytes 8=source, 9=reason)."""
    source_name = "unknown"
    reason_name = "unknown"
    if len(response) >= 10:
        source_name = ABORT_SOURCES.get(response[8], f"unknown-{response[8]}")
        reason_name = ABORT_REASONS.get(response[9], f"code-{response[9]}")
    return source_name, reason_name


# ---------------------------------------------------------------------------
# Association builder (minimal, stdlib-only version from server_monitor.py)
# ---------------------------------------------------------------------------

def _build_assoc_rq(called_ae="ORTHANC", calling_ae="REPRO"):
    """Build a minimal valid ASSOC_RQ for Verification SOP (C-ECHO)."""
    called = called_ae.ljust(16).encode('ascii')[:16]
    calling = calling_ae.ljust(16).encode('ascii')[:16]

    app_ctx_uid = b'1.2.840.10008.3.1.1.1'
    app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

    abstract_uid = b'1.2.840.10008.1.1'  # Verification SOP
    abstract = struct.pack('>BBH', 0x30, 0, len(abstract_uid)) + abstract_uid
    transfer_uid = b'1.2.840.10008.1.2'  # Implicit VR LE
    transfer = struct.pack('>BBH', 0x40, 0, len(transfer_uid)) + transfer_uid
    pres_ctx_data = struct.pack('>BBBB', 1, 0, 0, 0) + abstract + transfer
    pres_ctx = struct.pack('>BBH', 0x20, 0, len(pres_ctx_data)) + pres_ctx_data

    max_pdu = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', 16384)
    impl_uid_data = b'1.2.826.0.1.3680043.9.3811.2.0.2'
    impl_uid = struct.pack('>BBH', 0x52, 0, len(impl_uid_data)) + impl_uid_data
    impl_name_data = b'REPRO'
    impl_name = struct.pack('>BBH', 0x55, 0, len(impl_name_data)) + impl_name_data
    user_info_data = max_pdu + impl_uid + impl_name
    user_info = struct.pack('>BBH', 0x50, 0, len(user_info_data)) + user_info_data

    variable = app_ctx + pres_ctx + user_info
    reserved32 = b'\x00' * 32
    pdu_data = struct.pack('>H', 1) + b'\x00\x00' + called + calling + reserved32 + variable
    pdu = struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data
    return pdu


def _build_release_rq():
    """Build A-RELEASE-RQ PDU."""
    return struct.pack('>BBi', 0x05, 0, 4) + b'\x00' * 4


# ---------------------------------------------------------------------------
# Health check (C-ECHO probe, reuses server_monitor.py pattern)
# ---------------------------------------------------------------------------

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
    return struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item


def health_check(host, port, called_ae="ORTHANC", timeout=3.0):
    """
    C-ECHO based health check.

    Returns (ok: bool, latency_ms: float, error: str).
    """
    assoc_rq = _build_assoc_rq(called_ae=called_ae, calling_ae="HCHECK")
    cecho_rq = _build_cecho_rq()
    release_rq = _build_release_rq()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t0 = time.monotonic()
        sock.connect((host, port))

        sock.sendall(assoc_rq)
        resp = sock.recv(4096)
        if not resp or resp[0] != 0x02:
            sock.close()
            return False, -1.0, "association-rejected"

        sock.sendall(cecho_rq)
        sock.settimeout(timeout)
        echo_resp = sock.recv(4096)
        t1 = time.monotonic()

        ok = bool(echo_resp and echo_resp[0] == 0x04)

        try:
            sock.sendall(release_rq)
            sock.settimeout(1.0)
            sock.recv(1024)
        except Exception:
            pass
        sock.close()

        return ok, (t1 - t0) * 1000.0, ""

    except socket.timeout:
        return False, -1.0, "timeout"
    except ConnectionRefusedError:
        return False, -1.0, "refused"
    except ConnectionResetError:
        return False, -1.0, "reset"
    except Exception as e:
        return False, -1.0, str(e)


# ---------------------------------------------------------------------------
# Core replay logic
# ---------------------------------------------------------------------------

def replay_pdu(pdu_bytes, host, port, called_ae="ORTHANC", calling_ae="REPRO",
               associate=False, timeout=3.0, retry_timeout=5.0):
    """
    Send a single PDU to the target server and classify the response.

    Returns a dict with:
      verdict, response_time_ms, response_type, details,
      reject_source, reject_reason, bytes_received
    """
    result = {
        "verdict": "ERROR",
        "response_time_ms": 0.0,
        "response_type": "",
        "details": "",
        "reject_source": "",
        "reject_reason": "",
        "bytes_received": 0,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(5.0)
        sock.connect((host, port))
    except ConnectionRefusedError:
        result["details"] = "Connection refused"
        return result
    except socket.timeout:
        result["details"] = "Connect timeout"
        return result
    except Exception as e:
        result["details"] = str(e)
        return result

    try:
        # Optionally send a valid association first
        if associate:
            assoc_rq = _build_assoc_rq(called_ae=called_ae, calling_ae=calling_ae)
            sock.sendall(assoc_rq)
            sock.settimeout(timeout)
            assoc_resp = sock.recv(4096)
            if not assoc_resp or assoc_resp[0] != 0x02:
                # Association itself was rejected — still send the PDU anyway
                pass

        # Send the fuzzed PDU
        t_start = time.monotonic()
        sock.sendall(pdu_bytes)

        # Use fine-grained polling to detect closures quickly
        # First try: quick response (timeout ms)
        response, closed, elapsed = wait_for_response_or_closure(sock, timeout * 1000)
        result["response_time_ms"] = round(elapsed, 1)
        
        if closed:
            # Server closed connection without sending response
            result["verdict"] = "REJECTED"
            result["details"] = f"Server closed connection silently after {result['response_time_ms']:.0f}ms"
        elif response:
            # Got a response - process it below
            pass
        else:
            # Timeout with no response and socket still alive - retry with longer timeout
            response, closed, elapsed = wait_for_response_or_closure(sock, retry_timeout * 1000)
            result["response_time_ms"] = round(elapsed, 1)
            
            if closed:
                result["verdict"] = "REJECTED"
                result["details"] = f"Server closed connection (detected after {result['response_time_ms']:.0f}ms)"
            elif response:
                # Got a late response
                pass
            else:
                # True hang: no response and socket still alive after full timeout
                result["verdict"] = "HANG"
                result["details"] = f"True hang: no response or closure after {result['response_time_ms']:.0f}ms"

        # Process response if we got one
        if response:
            result["bytes_received"] = len(response)
            
            if len(response) == 0:
                result["verdict"] = "CLOSED"
                result["details"] = "Server closed connection (0 bytes)"
            else:
                resp_type = response[0]
                result["response_type"] = PDU_TYPE_NAMES.get(resp_type, f"0x{resp_type:02x}")

                if resp_type == 0x07:  # A-ABORT
                    result["verdict"] = "ABORT"
                    src, reason = parse_abort_pdu(response)
                    result["reject_source"] = src
                    result["reject_reason"] = reason
                    # Full reason without truncation
                    result["details"] = f"Source={src}, Reason={reason}"

                elif resp_type == 0x03:  # A-ASSOCIATE-RJ
                    result["verdict"] = "REJECT"
                    src, reason = parse_reject_pdu(response)
                    result["reject_source"] = src
                    result["reject_reason"] = reason
                    # Full reason without truncation
                    result["details"] = f"Source={src}, Reason={reason}"

                elif resp_type == 0x02:  # A-ASSOCIATE-AC
                    result["verdict"] = "ACCEPT"
                    result["details"] = "Association accepted"

                elif resp_type == 0x04:  # P-DATA-TF
                    result["verdict"] = "ACCEPT"
                    result["details"] = f"P-DATA response ({len(response)} bytes)"

                elif resp_type == 0x06:  # A-RELEASE-RP
                    result["verdict"] = "ACCEPT"
                    result["details"] = "Release response"

                else:
                    result["verdict"] = "ACCEPT"
                    result["details"] = f"Response type 0x{resp_type:02x} ({len(response)} bytes)"

    except ConnectionResetError:
        t_end = time.monotonic()
        result["response_time_ms"] = round((t_end - t_start) * 1000.0, 1)
        result["verdict"] = "REJECTED"
        result["details"] = "Connection reset by server (rejected malformed PDU)"
    except BrokenPipeError:
        t_end = time.monotonic()
        result["response_time_ms"] = round((t_end - t_start) * 1000.0, 1)
        result["verdict"] = "REJECTED"
        result["details"] = "Broken pipe (server closed connection)"
    except OSError as e:
        t_end = time.monotonic()
        result["response_time_ms"] = round((t_end - t_start) * 1000.0, 1)
        if e.errno in (104, 32):  # ECONNRESET, EPIPE
            result["verdict"] = "REJECTED"
            result["details"] = f"Connection closed by server (errno {e.errno})"
        else:
            result["verdict"] = "ERROR"
            result["details"] = str(e)
    except Exception as e:
        result["verdict"] = "ERROR"
        result["details"] = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def collect_files(input_path=None, input_dir=None, pcap_mode=False):
    """Collect .bin (or .pcap in pcap-mode) files to replay."""
    files = []

    if input_path:
        if os.path.isfile(input_path):
            files.append(input_path)
        else:
            print(f"Error: file not found: {input_path}", file=sys.stderr)

    if input_dir:
        if not os.path.isdir(input_dir):
            print(f"Error: directory not found: {input_dir}", file=sys.stderr)
        else:
            if pcap_mode:
                patterns = ["*.pcap", "*.bin"]
            else:
                patterns = ["*.bin"]
            for pat in patterns:
                found = sorted(glob.glob(os.path.join(input_dir, pat)))
                files.extend(found)

    return files


def load_pdu_from_file(filepath, pcap_mode=False):
    """Load raw PDU bytes from a .bin file (or extract from .pcap)."""
    if pcap_mode and filepath.endswith(".pcap"):
        try:
            from scapy.all import rdpcap, Raw
            packets = rdpcap(filepath)
            # Extract payload from first packet with Raw layer
            for pkt in packets:
                if pkt.haslayer(Raw):
                    return bytes(pkt[Raw].load)
            return None
        except Exception:
            return None
    else:
        with open(filepath, "rb") as f:
            return f.read()


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def format_table(results, target_host, target_port, duration_s):
    """Format results as a console table sorted by severity."""
    # Sort: primary by severity (CRASH first), secondary by response time (desc)
    results.sort(key=lambda r: (
        VERDICT_SEVERITY.get(r["verdict"], 99),
        -r["response_time_ms"],
    ))

    total = len(results)
    dur_min = int(duration_s // 60)
    dur_sec = int(duration_s % 60)

    lines = []
    lines.append("")
    lines.append("=== PDU REPLAY RESULTS ===")
    lines.append(f"Target: {target_host}:{target_port}  |  "
                 f"PDUs tested: {total}  |  "
                 f"Duration: {dur_min}m {dur_sec:02d}s")
    lines.append("")
    lines.append(f" {'#':>3}  {'File':<30} {'Verdict':<10} {'Time':>10}  {'Details'}")
    lines.append(f" {'---':>3}  {'-'*30} {'-'*9} {'-'*10}  {'-'*50}")

    for i, r in enumerate(results, 1):
        fname = os.path.basename(r["file"])
        if len(fname) > 30:
            fname = fname[:27] + "..."
        verdict = r["verdict"]
        if verdict == "CRASH":
            verdict = "CRASH!"
        time_str = f"{r['response_time_ms']:.0f}ms"
        details = r["details"]
        # Don't truncate details for ABORT/REJECT - show full reason
        if verdict not in ["ABORT", "REJECT"] and len(details) > 50:
            details = details[:47] + "..."
        lines.append(f" {i:>3}  {fname:<30} {verdict:<10} {time_str:>10}  {details}")

    # Summary
    counts = {}
    for r in results:
        v = r["verdict"]
        counts[v] = counts.get(v, 0) + 1

    lines.append("")
    lines.append("=== SUMMARY ===")
    for verdict in ["CRASH", "HANG", "ABORT", "ACCEPT", "REJECT", "REJECTED", "ERROR", "CLOSED"]:
        count = counts.get(verdict, 0)
        if count > 0 or verdict in ("CRASH", "HANG"):
            pct = 100.0 * count / total if total > 0 else 0
            marker = ""
            if verdict == "CRASH" and count > 0:
                crash_files = [os.path.basename(r["file"])
                               for r in results if r["verdict"] == "CRASH"]
                marker = f"  <- {', '.join(crash_files[:3])}"
            lines.append(f"  {verdict:<8} {count:>3} ({pct:>5.1f}%){marker}")

    lines.append("")
    return "\n".join(lines)


def write_csv(results, output_path):
    """Write results to a CSV file."""
    fieldnames = [
        "file", "verdict", "response_time_ms", "pdu_type_sent", "pdu_size",
        "response_type", "reject_source", "reject_reason", "bytes_received",
        "health_before", "health_after", "health_delta", "details",
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print(f"CSV report written to: {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Replay .bin PDU files against a DICOM server and classify responses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Replay all .bin files in a directory
  python3 -m fuzzer.reproduce --input-dir fuzzer/data/pcap_output/rl_generated \\
      --target-host 192.168.1.200 --target-port 4242

  # Single file with association wrapper
  python3 -m fuzzer.reproduce --input rl_fuzzed_0005.bin \\
      --target-host localhost --target-port 4242 --associate

  # With health checks and CSV output
  python3 -m fuzzer.reproduce --input-dir ... --target-host ... \\
      --health-check --output report.csv
        """,
    )

    parser.add_argument("--input", "-i", help="Single .bin file to replay")
    parser.add_argument("--input-dir", "-d", help="Directory of .bin files to replay")
    parser.add_argument("--target-host", "-H", required=True, help="Target DICOM server host")
    parser.add_argument("--target-port", "-P", type=int, default=4242,
                        help="Target DICOM server port (default: 4242)")
    parser.add_argument("--associate", "-a", action="store_true",
                        help="Send valid ASSOC_RQ before each PDU")
    parser.add_argument("--health-check", action="store_true",
                        help="Run C-ECHO health checks before/after each PDU (slower)")
    parser.add_argument("--timeout", "-t", type=float, default=3.0,
                        help="Response timeout in seconds (default: 3.0)")
    parser.add_argument("--retry-timeout", type=float, default=5.0,
                        help="Retry timeout to confirm hangs (default: 5.0)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay between PDUs in seconds (default: 0.5)")
    parser.add_argument("--called-ae", default="ORTHANC",
                        help="Called AE title (default: ORTHANC)")
    parser.add_argument("--calling-ae", default="REPRO",
                        help="Calling AE title (default: REPRO)")
    parser.add_argument("--output", "-o", help="CSV output file path")
    parser.add_argument("--pcap-mode", action="store_true",
                        help="Also scan for .pcap files and extract payloads")
    parser.add_argument("--crash-wait", type=float, default=30.0,
                        help="Max seconds to wait for server recovery after crash (default: 30)")
    parser.add_argument("--crash-poll", type=float, default=2.0,
                        help="Polling interval during crash recovery (default: 2.0)")

    args = parser.parse_args()

    if not args.input and not args.input_dir:
        parser.error("At least one of --input or --input-dir is required")

    # Collect files
    files = collect_files(args.input, args.input_dir, args.pcap_mode)
    if not files:
        print("No files found to replay.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(files)} PDU file(s) to replay against "
          f"{args.target_host}:{args.target_port}")
    if args.associate:
        print("  Mode: sending ASSOC_RQ before each PDU")
    if args.health_check:
        print("  Mode: C-ECHO health checks enabled")
    print()

    results = []
    t_session_start = time.monotonic()

    for idx, filepath in enumerate(files):
        fname = os.path.basename(filepath)
        progress = f"[{idx+1}/{len(files)}]"

        # Load PDU bytes
        pdu_bytes = load_pdu_from_file(filepath, args.pcap_mode)
        if pdu_bytes is None or len(pdu_bytes) == 0:
            print(f"  {progress} {fname}: SKIP (empty or unreadable)")
            continue

        # Detect PDU type from first byte
        pdu_type_byte = pdu_bytes[0] if pdu_bytes else 0
        pdu_type_name = PDU_TYPE_NAMES.get(pdu_type_byte, f"0x{pdu_type_byte:02x}")

        # Pre-health check
        health_before_ok = None
        health_before_ms = -1.0
        if args.health_check:
            health_before_ok, health_before_ms, _ = health_check(
                args.target_host, args.target_port, args.called_ae)

        # Replay
        r = replay_pdu(
            pdu_bytes, args.target_host, args.target_port,
            called_ae=args.called_ae, calling_ae=args.calling_ae,
            associate=args.associate,
            timeout=args.timeout, retry_timeout=args.retry_timeout,
        )

        # Post-health check → detect CRASH
        health_after_ok = None
        health_after_ms = -1.0
        health_delta = 0.0
        if args.health_check:
            time.sleep(0.1)
            health_after_ok, health_after_ms, health_err = health_check(
                args.target_host, args.target_port, args.called_ae)

            if health_before_ok and not health_after_ok:
                r["verdict"] = "CRASH"
                r["details"] = f"Server unresponsive after send ({health_err})"

            if health_before_ms > 0 and health_after_ms > 0:
                health_delta = health_after_ms - health_before_ms

        # Enrich result
        r["file"] = filepath
        r["pdu_type_sent"] = pdu_type_name
        r["pdu_size"] = len(pdu_bytes)
        r["health_before"] = health_before_ok if health_before_ok is not None else ""
        r["health_after"] = health_after_ok if health_after_ok is not None else ""
        r["health_delta"] = round(health_delta, 1) if args.health_check else ""

        results.append(r)

        # Print progress
        verdict_display = r["verdict"]
        if verdict_display == "CRASH":
            verdict_display = "CRASH!"
        print(f"  {progress} {fname:<30} {verdict_display:<8} "
              f"{r['response_time_ms']:>7.0f}ms  {r['details'][:40]}")

        # Crash recovery: wait for server to come back
        if r["verdict"] == "CRASH":
            print(f"        >> Server crashed! Waiting up to {args.crash_wait:.0f}s for recovery...")
            recovered = False
            t_wait_start = time.monotonic()
            while (time.monotonic() - t_wait_start) < args.crash_wait:
                time.sleep(args.crash_poll)
                ok, _, _ = health_check(args.target_host, args.target_port, args.called_ae)
                if ok:
                    elapsed = time.monotonic() - t_wait_start
                    print(f"        >> Server recovered after {elapsed:.1f}s")
                    recovered = True
                    break
            if not recovered:
                print(f"        >> Server did NOT recover within {args.crash_wait:.0f}s!")
                print(f"        >> Stopping replay. Remaining PDUs skipped.")
                break

        # Delay between PDUs
        if idx < len(files) - 1 and r["verdict"] != "CRASH":
            time.sleep(args.delay)

    t_session_end = time.monotonic()
    duration_s = t_session_end - t_session_start

    # Print table
    print(format_table(results, args.target_host, args.target_port, duration_s))

    # Write CSV
    if args.output:
        write_csv(results, args.output)

    # Exit code: 1 if any crashes found
    crashes = sum(1 for r in results if r["verdict"] == "CRASH")
    if crashes > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
