#!/usr/bin/env python3
"""
Crash reproducer for RL fuzzing corpus.

Replays the exact PDU bytes saved by the fuzzer when a crash was detected,
sending them over the same transport (SCTP/TCP) to confirm the crash is
reproducible.

Supports both old (flat) and new (crash_trigger-nested) corpus file formats.
Supports NGAP/SCTP (AMF) and SBI/HTTP2-over-TCP (NRF, SMF, UDM, ...) protocols.

Usage:
    # Replay a single crash file (protocol/host/port auto-detected from file)
    python -m fuzzer.rl.replay_crash fuzzer/data/crashes/crash_<ts>.json --repeat 5

    # Replay all crash files in the corpus directory
    python -m fuzzer.rl.replay_crash fuzzer/data/crashes/

    # Override host/port (default: taken from crash file's 'target' field)
    python -m fuzzer.rl.replay_crash crash.json --host 127.0.0.5 --port 38412

    # Verbose: show raw bytes for each message
    python -m fuzzer.rl.replay_crash crash.json --verbose
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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


_IPPROTO_SCTP = 132
_SCTP_SNDINFO = 2
_SCTP_NODELAY = getattr(socket, 'SCTP_NODELAY', 3)
_NGAP_PPID    = 60

# Known open5GS NF IP → process name mapping (open5GS sample.yaml defaults)
_IP_TO_NF: dict[str, str] = {
    '127.0.0.5':  'amf',
    '127.0.0.4':  'smf',
    '127.0.0.10': 'nrf',
    '127.0.0.12': 'udm',
    '127.0.0.20': 'udr',
    '127.0.0.11': 'ausf',
    '127.0.0.13': 'pcf',
}
_PROC_NAMES: dict[str, str] = {
    'amf':  'open5gs-amfd',
    'smf':  'open5gs-smfd',
    'nrf':  'open5gs-nrfd',
    'udm':  'open5gs-udmd',
    'udr':  'open5gs-udrd',
    'ausf': 'open5gs-ausfd',
    'pcf':  'open5gs-pcfd',
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_nf_alive(nf_key: str) -> bool:
    proc = _PROC_NAMES.get(nf_key, f'open5gs-{nf_key}d')
    try:
        out = subprocess.check_output(['pgrep', '-x', proc], stderr=subprocess.DEVNULL)
        return bool(out.strip())
    except subprocess.CalledProcessError:
        return False


def _nf_from_target(target: str) -> str:
    """Guess NF key from 'host:port' string, defaulting to 'amf'."""
    host = target.split(':')[0] if ':' in target else target
    return _IP_TO_NF.get(host, 'amf')


def _extract_messages_fields(record: dict) -> tuple[list, dict]:
    """Return (messages, fields) from either old (flat) or new (crash_trigger) format."""
    if 'crash_trigger' in record:
        trig = record['crash_trigger']
        return trig.get('messages', []), trig.get('fields', {})
    return record.get('messages', []), record.get('fields', {})


# ---------------------------------------------------------------------------
# SCTP transport (NGAP)
# ---------------------------------------------------------------------------

def _send_sctp(host: str, port: int, messages: list[tuple[str, bytes]],
               connect_timeout: float, recv_timeout: float,
               verbose: bool) -> dict:
    """Open one SCTP association, send all messages, collect responses."""
    result = {"connected": False, "responses": [], "crash": False, "hang": False, "error": None}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, _IPPROTO_SCTP)
    sock.setsockopt(_IPPROTO_SCTP, _SCTP_NODELAY, 1)
    sock.settimeout(connect_timeout)

    try:
        sock.connect((host, port))
    except socket.timeout:
        result["hang"] = True
        result["error"] = f"connect timeout after {connect_timeout}s"
        sock.close()
        return result
    except ConnectionRefusedError:
        result["crash"] = True
        result["error"] = "connection refused (process not listening)"
        sock.close()
        return result
    except OSError as e:
        result["error"] = str(e)
        sock.close()
        return result

    result["connected"] = True

    for msg_type, data in messages:
        if verbose:
            print(f"  -> Sending {msg_type} ({len(data)} bytes): {data.hex()}")

        sndinfo = struct.pack('=HHIIi', 0, 0, socket.htonl(_NGAP_PPID), 0, 0)
        try:
            sock.sendmsg([data], [(_IPPROTO_SCTP, _SCTP_SNDINFO, sndinfo)])
        except OSError as e:
            result["error"] = f"send error on {msg_type}: {e}"
            break

        sock.settimeout(recv_timeout)
        try:
            resp = sock.recv(4096)
            if resp:
                rtype = _parse_ngap_type(resp)
                result["responses"].append({"msg_type": msg_type, "response": rtype,
                                            "hex": resp.hex(), "len": len(resp)})
                if verbose:
                    print(f"  <- Response ({len(resp)} bytes, {rtype}): {resp.hex()}")
            else:
                result["responses"].append({"msg_type": msg_type, "response": "closed"})
        except socket.timeout:
            result["responses"].append({"msg_type": msg_type, "response": "recv_timeout"})
            result["hang"] = True
            if verbose:
                print(f"  <- recv timeout on {msg_type}")

    try:
        sock.close()
    except OSError:
        pass

    return result


def _parse_ngap_type(data: bytes) -> str:
    """Return a human-readable NGAP PDU type from raw bytes."""
    _NAMES = {
        (0x20, 21): 'NGSetupResponse',
        (0x40, 21): 'NGSetupFailure',
        (0x00, 15): 'InitialContextSetup',
        (0x00, 46): 'DownlinkNASTransport',
        (0x00,  9): 'ErrorIndication',
        (0x20, 41): 'UEContextReleaseCommand',
        (0x20, 25): 'UEContextReleaseComplete',
        (0x00, 14): 'Paging',
    }
    if len(data) < 2:
        return 'too_short'
    return _NAMES.get((data[0], data[1]), f'ngap_0x{data[0]:02x}_proc{data[1]}')


# ---------------------------------------------------------------------------
# TCP transport (SBI / HTTP2)
# ---------------------------------------------------------------------------

def _send_tcp_sbi(host: str, port: int, messages: list[tuple[str, bytes]],
                  connect_timeout: float, recv_timeout: float,
                  verbose: bool) -> dict:
    """
    Replay SBI messages over TCP.

    Each message in the corpus is a complete HTTP/2 frame sequence (including
    the client preface), so each is sent on its own fresh TCP connection,
    mirroring the ephemeral-connection model used by the fuzzer.
    """
    result = {"connected": False, "responses": [], "crash": False, "hang": False, "error": None}

    for msg_type, data in messages:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(connect_timeout)

        try:
            sock.connect((host, port))
        except socket.timeout:
            result["hang"] = True
            result["error"] = f"connect timeout on {msg_type} after {connect_timeout}s"
            sock.close()
            return result
        except ConnectionRefusedError:
            result["crash"] = True
            result["error"] = f"connection refused on {msg_type} (process not listening)"
            sock.close()
            return result
        except OSError as e:
            result["error"] = f"connect error on {msg_type}: {e}"
            sock.close()
            return result

        result["connected"] = True

        if verbose:
            print(f"  -> Sending {msg_type} ({len(data)} bytes): {data[:64].hex()}...")

        try:
            sock.sendall(data)
        except (ConnectionResetError, BrokenPipeError) as e:
            result["responses"].append({"msg_type": msg_type, "response": "reset"})
            result["crash"] = True
            result["error"] = f"send reset on {msg_type}: {e}"
            sock.close()
            return result
        except OSError as e:
            result["error"] = f"send error on {msg_type}: {e}"
            sock.close()
            return result

        sock.settimeout(recv_timeout)
        try:
            resp = sock.recv(65536)
            if resp:
                rtype = _classify_h2_response(resp)
            else:
                rtype = "closed"
            result["responses"].append({"msg_type": msg_type, "response": rtype,
                                        "len": len(resp) if resp else 0})
            if verbose:
                print(f"  <- Response ({len(resp) if resp else 0} bytes, {rtype})")
        except socket.timeout:
            result["responses"].append({"msg_type": msg_type, "response": "recv_timeout"})
            result["hang"] = True
            if verbose:
                print(f"  <- recv timeout on {msg_type}")
        except ConnectionResetError:
            result["responses"].append({"msg_type": msg_type, "response": "reset"})
            result["crash"] = True
            if verbose:
                print(f"  <- connection reset on {msg_type}")

        try:
            sock.close()
        except OSError:
            pass

    return result


def _classify_h2_response(data: bytes) -> str:
    """Rough classification of an HTTP/2 response frame."""
    if not data:
        return "closed"
    # GOAWAY frame type = 0x7
    if len(data) >= 4 and data[3] == 0x7:
        return "goaway"
    # RST_STREAM frame type = 0x3
    if len(data) >= 4 and data[3] == 0x3:
        return "rst_stream"
    # SETTINGS frame type = 0x4
    if len(data) >= 4 and data[3] == 0x4:
        return "settings"
    # HTTP/2 response headers usually start with a HEADERS frame (type=0x1)
    if len(data) >= 4 and data[3] == 0x1:
        return "headers"
    return f"h2_type0x{data[3]:02x}" if len(data) >= 4 else "too_short"


# ---------------------------------------------------------------------------
# Core replay logic
# ---------------------------------------------------------------------------

def _restart_nf(restart_cmd: str, nf_key: str, wait: float = 4.0) -> bool:
    """Run restart_cmd and wait for the NF to come up. Returns True if alive."""
    try:
        subprocess.run(restart_cmd, shell=True, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"  restart_cmd failed: {e}")
        return False
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if _is_nf_alive(nf_key):
            return True
        time.sleep(0.5)
    return _is_nf_alive(nf_key)


def replay_file(path: str, host: str | None, port: int | None, repeat: int,
                connect_timeout: float, recv_timeout: float,
                verbose: bool, flood: int = 0, restart_cmd: str = "") -> int:
    """Replay one crash corpus file. Returns number of confirmed crashes.

    flood > 0: keep sending the saved messages in a loop up to `flood` total
    sends, checking after each batch whether the NF died.  Use this for
    state-dependent crashes where a single replay of the saved sequence is not
    enough — e.g. subscription-pool exhaustion needs ~1024 sends to trigger.
    """
    with open(path) as f:
        record = json.load(f)

    protocol = record.get('protocol', 'ngap')
    target_str = record.get('target', '')

    # Derive host/port from crash file when not overridden on CLI
    file_host, file_port = None, None
    if ':' in target_str:
        file_host, _p = target_str.rsplit(':', 1)
        try:
            file_port = int(_p)
        except ValueError:
            pass
    effective_host = host or file_host or ('127.0.0.5' if protocol == 'ngap' else '127.0.0.10')
    effective_port = port or file_port or (38412 if protocol == 'ngap' else 7777)

    raw_messages, fields = _extract_messages_fields(record)
    messages = [(mt, bytes.fromhex(hx)) for mt, hx in raw_messages]

    # Detection mode from crash file (old: 'response', new: 'detection')
    detection = record.get('detection') or record.get('response', 'unknown')

    print(f"\n{'=' * 60}")
    print(f"File:      {path}")
    print(f"Protocol:  {protocol}")
    print(f"Target:    {effective_host}:{effective_port}  (recorded: {target_str})")
    print(f"Detection: {detection}")
    print(f"Fields:    {fields}")
    print(f"Messages:  {[m[0] for m in raw_messages]}")
    if flood:
        print(f"Mode:      FLOOD (up to {flood} total message sends)")
    print(f"{'=' * 60}")

    if not messages:
        print("No messages in corpus file — skipping.")
        return 0

    nf_key = _nf_from_target(target_str or f"{effective_host}:{effective_port}")

    # ── Flood mode ────────────────────────────────────────────────────────────
    # For state-dependent crashes the corpus only captures the final trigger,
    # not the full history that built up the server state.  Flood mode replays
    # the saved messages repeatedly until the NF crashes or the send limit is
    # reached, printing progress every 50 sends.
    if flood:
        total_sends = 0
        print(f"  Flooding {nf_key} — watching for crash (Ctrl+C to stop)...")
        while total_sends < flood:
            nf_before = _is_nf_alive(nf_key)
            if not nf_before:
                print(f"  {nf_key} already down before send #{total_sends + 1}")
                break

            if protocol == 'sbi':
                result = _send_tcp_sbi(effective_host, effective_port, messages,
                                       connect_timeout, recv_timeout, False)
            else:
                result = _send_sctp(effective_host, effective_port, messages,
                                    connect_timeout, recv_timeout, False)

            total_sends += len(messages)

            crashed = result["crash"] or (nf_before and not _is_nf_alive(nf_key))
            if crashed:
                print(f"\n  *** CRASH CONFIRMED after {total_sends} total message sends ***")
                print(f"  Root cause: check NF log for FATAL/assert lines near this timestamp")
                print(f"    sudo scripts/open5gs.sh watch v2.7.7 --errors")
                return 1

            if total_sends % 50 == 0:
                responses = ", ".join(r["response"] for r in result["responses"]) or "none"
                print(f"  {total_sends:5d} sends  |  last responses=[{responses}]  |  "
                      f"{nf_key} alive=True")

        print(f"\n  No crash after {total_sends} sends — NF survived.")
        return 0

    # ── Normal repeat mode ────────────────────────────────────────────────────
    confirmed = 0
    for i in range(repeat):
        if restart_cmd:
            if not _is_nf_alive(nf_key):
                print(f"  Restarting {nf_key} before run {i+1}/{repeat}...")
                if not _restart_nf(restart_cmd, nf_key):
                    print(f"  WARNING: {nf_key} still down after restart — run {i+1} skipped")
                    continue
            else:
                # NF alive; still restart to get a clean slate between runs
                _restart_nf(restart_cmd, nf_key)

        nf_before = _is_nf_alive(nf_key)

        if protocol == 'sbi':
            result = _send_tcp_sbi(effective_host, effective_port, messages,
                                   connect_timeout, recv_timeout, verbose)
        else:
            result = _send_sctp(effective_host, effective_port, messages,
                                connect_timeout, recv_timeout, verbose)

        time.sleep(0.3)
        nf_after = _is_nf_alive(nf_key)

        status = "OK"
        if result["crash"] or (nf_before and not nf_after):
            status = "CRASH CONFIRMED"
            confirmed += 1
        elif result["hang"]:
            status = "HANG"
        elif not result["connected"]:
            status = f"NO CONNECTION ({result['error']})"

        responses = ", ".join(r["response"] for r in result["responses"]) or "none"
        print(f"  Run {i+1}/{repeat}: {status}  |  responses=[{responses}]  |  "
              f"{nf_key}_before={nf_before} after={nf_after}")

        if status == "CRASH CONFIRMED":
            print(f"  *** TRUE POSITIVE — {nf_key} process died after replaying this sequence ***")
            print(f"  Root cause: check NF log for FATAL/assert lines near this timestamp")
            print(f"    sudo scripts/open5gs.sh watch v2.7.7 --errors")
            time.sleep(2.0)

    return confirmed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Replay crash corpus files to confirm RL fuzzer findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("path", help="Path to a crash JSON file or a directory of crash files")
    parser.add_argument("--host", default=None,
                        help="Override target host (default: taken from crash file)")
    parser.add_argument("--port", type=int, default=None,
                        help="Override target port (default: taken from crash file)")
    parser.add_argument("--repeat", type=int, default=3,
                        help="How many times to replay each crash (default: 3)")
    parser.add_argument("--flood", type=int, default=0,
                        help="Flood mode: keep sending saved messages up to N total sends "
                             "until NF crashes. Use for state-dependent crashes that require "
                             "accumulated server state (e.g. --flood 1500 for pool exhaustion).")
    parser.add_argument("--restart-cmd", default="",
                        metavar="CMD",
                        help="Shell command to restart NFs between replay runs "
                             "(e.g. 'sudo scripts/open5gs.sh restart v2.7.7'). "
                             "Ensures each run starts with a live NF for clean confirmation.")
    parser.add_argument("--connect-timeout", type=float, default=3.0)
    parser.add_argument("--recv-timeout", type=float, default=2.0)
    parser.add_argument("--verbose", action="store_true",
                        help="Print raw hex bytes for each message")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: path not found: {args.path}")
        return 1

    if os.path.isdir(args.path):
        files = sorted(
            f for f in (os.path.join(args.path, n) for n in os.listdir(args.path))
            if f.endswith('.json')
        )
        if not files:
            print(f"No .json files found in {args.path}")
            return 1
    else:
        files = [args.path]

    print(f"Replaying {len(files)} crash file(s)")

    total_confirmed = 0
    for path in files:
        total_confirmed += replay_file(
            path, args.host, args.port, args.repeat,
            args.connect_timeout, args.recv_timeout, args.verbose,
            flood=args.flood, restart_cmd=args.restart_cmd,
        )

    print(f"\n{'=' * 60}")
    print(f"RESULT: {total_confirmed}/{len(files)} crash(es) confirmed as TRUE POSITIVES")
    print(f"{'=' * 60}")
    return 0 if total_confirmed > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
