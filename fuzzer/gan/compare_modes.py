#!/usr/bin/env python3
"""
Compare GAN modes: old pipeline (protocol/attack) vs smart mode.

Sends generated PCAPs to a live DICOM server and measures:
  - Early rejection rate (DUL layer rejects)
  - Association acceptance rate
  - Average parser depth reached
  - Response type diversity
  - PDATA response rate (deep parsing)
  - Crash/hang detection

Usage:
    python3 -m fuzzer.gan.compare_modes \
        --target-host 192.168.1.100 --target-port 4242 \
        --old-pcap-dir fuzzer/data/pcap_output/old \
        --smart-pcap-dir fuzzer/data/pcap_output/smart

Or generate + compare in one step:
    python3 -m fuzzer.gan.compare_modes \
        --target-host 192.168.1.100 --target-port 4242 \
        --generate --samples 100
"""

import os
import sys
import time
import socket
import struct
import argparse
import logging
from glob import glob
from collections import Counter

from scapy.all import rdpcap, Raw

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ============================================================================
# PCAP Replay + Scoring
# ============================================================================

def extract_pdus_from_pcap(pcap_path):
    """Extract raw DICOM PDU bytes from a PCAP file."""
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        logger.debug(f"Failed to read {pcap_path}: {e}")
        return []

    pdus = []
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if len(payload) >= 6:
                pdus.append(payload)
    return pdus


def send_session_to_server(pdu_list, host, port, timeout=3.0):
    """
    Send a list of PDUs as a single TCP session to the server.

    Returns dict with depth, response types, timing, and crash info.
    """
    result = {
        "depth": 0.0,
        "responses": [],
        "accepted": False,
        "pdata_response": False,
        "crash": False,
        "hang": False,
        "early_reject": False,
        "total_time_ms": 0.0,
    }

    if not pdu_list:
        return result

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(5.0)

        t_start = time.monotonic()
        sock.connect((host, port))

        for pdu in pdu_list:
            try:
                sock.sendall(pdu)
            except (BrokenPipeError, ConnectionResetError):
                result["responses"].append("pipe_broken")
                break

            try:
                sock.settimeout(timeout)
                resp = sock.recv(4096)

                if not resp:
                    result["responses"].append("closed")
                    result["depth"] = max(result["depth"], 0.5)
                    break

                resp_type = resp[0]
                if resp_type == 0x02:  # ASSOC-AC
                    result["responses"].append("accept")
                    result["accepted"] = True
                    result["depth"] = max(result["depth"], 4.0)
                elif resp_type == 0x03:  # ASSOC-RJ
                    result["responses"].append("reject")
                    if len(resp) >= 10:
                        source = resp[8]
                        result["depth"] = max(result["depth"],
                                              {1: 1.0, 2: 2.0, 3: 3.0}.get(source, 1.0))
                    else:
                        result["depth"] = max(result["depth"], 1.0)
                    if not result["accepted"]:
                        result["early_reject"] = True
                elif resp_type == 0x04:  # P-DATA response
                    result["responses"].append("pdata_resp")
                    result["pdata_response"] = True
                    result["depth"] = max(result["depth"], 5.0)
                elif resp_type == 0x06:  # RELEASE-RP
                    result["responses"].append("release_rp")
                    result["depth"] = max(result["depth"], 3.0)
                elif resp_type == 0x07:  # ABORT
                    result["responses"].append("abort")
                    result["depth"] = max(result["depth"], 3.0)
                else:
                    result["responses"].append(f"type_0x{resp_type:02x}")
                    result["depth"] = max(result["depth"], 2.0)

            except socket.timeout:
                result["responses"].append("timeout")
                result["hang"] = True
                result["depth"] = max(result["depth"], 2.0)
                break
            except ConnectionResetError:
                result["responses"].append("reset")
                result["depth"] = max(result["depth"], 0.5)
                break

        t_end = time.monotonic()
        result["total_time_ms"] = (t_end - t_start) * 1000.0
        sock.close()

    except ConnectionRefusedError:
        result["responses"].append("refused")
        # Check crash
        time.sleep(0.5)
        try:
            check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            check.settimeout(2.0)
            check.connect((host, port))
            check.close()
        except Exception:
            result["crash"] = True

    except ConnectionResetError:
        result["responses"].append("reset")
        result["depth"] = max(result["depth"], 0.5)

    except socket.timeout:
        result["responses"].append("connect_timeout")
        result["hang"] = True

    except Exception as e:
        result["responses"].append(f"error:{e}")

    return result


def score_pcap_dir(pcap_dir, host, port, delay=0.1, max_pcaps=None):
    """
    Score all PCAPs in a directory against a live server.

    Returns list of per-session result dicts.
    """
    pcap_files = sorted(glob(os.path.join(pcap_dir, "*.pcap")))
    if max_pcaps:
        pcap_files = pcap_files[:max_pcaps]

    if not pcap_files:
        logger.warning(f"No PCAP files found in {pcap_dir}")
        return []

    results = []
    for i, pcap_path in enumerate(pcap_files):
        pdus = extract_pdus_from_pcap(pcap_path)
        if not pdus:
            continue

        result = send_session_to_server(pdus, host, port)
        result["pcap"] = os.path.basename(pcap_path)
        results.append(result)

        if delay > 0:
            time.sleep(delay)

        if (i + 1) % 25 == 0:
            logger.info(f"  Scored {i+1}/{len(pcap_files)} PCAPs...")

    return results


# ============================================================================
# Metrics Computation
# ============================================================================

def compute_metrics(results, label=""):
    """Compute comparison metrics from scoring results."""
    if not results:
        return {"label": label, "total": 0}

    n = len(results)
    metrics = {
        "label": label,
        "total": n,
        "accepted": sum(1 for r in results if r["accepted"]),
        "pdata_response": sum(1 for r in results if r["pdata_response"]),
        "early_reject": sum(1 for r in results if r["early_reject"]),
        "crash": sum(1 for r in results if r["crash"]),
        "hang": sum(1 for r in results if r["hang"]),
        "avg_depth": sum(r["depth"] for r in results) / n,
        "max_depth": max(r["depth"] for r in results),
        "avg_time_ms": sum(r["total_time_ms"] for r in results) / n,
    }

    # Acceptance rate
    metrics["accept_rate"] = metrics["accepted"] / n * 100
    # Early rejection rate (rejected at DUL layer before any processing)
    metrics["early_reject_rate"] = metrics["early_reject"] / n * 100
    # Deep parsing rate (got PDATA response = server processed our command)
    metrics["deep_parse_rate"] = metrics["pdata_response"] / n * 100

    # Response diversity
    all_responses = []
    for r in results:
        all_responses.extend(r["responses"])
    response_counts = Counter(all_responses)
    metrics["unique_response_types"] = len(response_counts)
    metrics["response_distribution"] = dict(response_counts)

    # Depth distribution
    depth_buckets = {"none (0)": 0, "shallow (0-1)": 0, "medium (1-3)": 0,
                     "deep (3-5)": 0, "very_deep (5+)": 0}
    for r in results:
        d = r["depth"]
        if d == 0:
            depth_buckets["none (0)"] += 1
        elif d <= 1:
            depth_buckets["shallow (0-1)"] += 1
        elif d <= 3:
            depth_buckets["medium (1-3)"] += 1
        elif d <= 5:
            depth_buckets["deep (3-5)"] += 1
        else:
            depth_buckets["very_deep (5+)"] += 1
    metrics["depth_distribution"] = depth_buckets

    return metrics


def print_comparison(metrics_old, metrics_smart):
    """Pretty-print comparison between two mode results."""
    print("\n" + "=" * 78)
    print("  GAN MODE COMPARISON: Old Pipeline vs Smart Mode")
    print("=" * 78)

    def row(label, old_val, smart_val, fmt="{}", better="higher"):
        old_s = fmt.format(old_val)
        smart_s = fmt.format(smart_val)
        # Determine winner
        if better == "higher":
            winner = "<<" if smart_val > old_val else (">>" if old_val > smart_val else "==")
        else:
            winner = "<<" if smart_val < old_val else (">>" if old_val < smart_val else "==")
        print(f"  {label:<30s}  {old_s:>12s}  {smart_s:>12s}  {winner}")

    print(f"\n  {'Metric':<30s}  {'Old Pipeline':>12s}  {'Smart Mode':>12s}  Winner")
    print("  " + "-" * 72)

    row("Total sessions",
        metrics_old["total"], metrics_smart["total"], "{}")
    row("Avg parser depth",
        metrics_old.get("avg_depth", 0), metrics_smart.get("avg_depth", 0),
        "{:.2f}", "higher")
    row("Max parser depth",
        metrics_old.get("max_depth", 0), metrics_smart.get("max_depth", 0),
        "{:.1f}", "higher")
    row("Association accepted",
        metrics_old.get("accept_rate", 0), metrics_smart.get("accept_rate", 0),
        "{:.1f}%", "higher")
    row("Early rejection rate",
        metrics_old.get("early_reject_rate", 0), metrics_smart.get("early_reject_rate", 0),
        "{:.1f}%", "lower")
    row("Deep parse rate (PDATA resp)",
        metrics_old.get("deep_parse_rate", 0), metrics_smart.get("deep_parse_rate", 0),
        "{:.1f}%", "higher")
    row("Unique response types",
        metrics_old.get("unique_response_types", 0), metrics_smart.get("unique_response_types", 0),
        "{}", "higher")
    row("Crashes detected",
        metrics_old.get("crash", 0), metrics_smart.get("crash", 0),
        "{}", "higher")
    row("Hangs detected",
        metrics_old.get("hang", 0), metrics_smart.get("hang", 0),
        "{}", "higher")
    row("Avg response time (ms)",
        metrics_old.get("avg_time_ms", 0), metrics_smart.get("avg_time_ms", 0),
        "{:.1f}", "higher")

    print("\n  Depth Distribution:")
    for bucket in ["none (0)", "shallow (0-1)", "medium (1-3)", "deep (3-5)", "very_deep (5+)"]:
        old_v = metrics_old.get("depth_distribution", {}).get(bucket, 0)
        smart_v = metrics_smart.get("depth_distribution", {}).get(bucket, 0)
        print(f"    {bucket:<20s}  {old_v:>8d}  {smart_v:>8d}")

    print(f"\n  Response Distribution (Old Pipeline):")
    for resp, count in sorted(metrics_old.get("response_distribution", {}).items(),
                               key=lambda x: -x[1]):
        print(f"    {resp:<25s}  {count:>5d}")

    print(f"\n  Response Distribution (Smart Mode):")
    for resp, count in sorted(metrics_smart.get("response_distribution", {}).items(),
                               key=lambda x: -x[1]):
        print(f"    {resp:<25s}  {count:>5d}")

    print("\n" + "=" * 78)


def print_single_mode(metrics):
    """Print results for a single mode (when old pipeline is unavailable)."""
    print("\n" + "=" * 60)
    print(f"  SMART MODE RESULTS")
    print("=" * 60)

    n = metrics["total"]
    if n == 0:
        print("  No sessions scored.")
        print("=" * 60)
        return

    print(f"\n  Sessions scored:            {n}")
    print(f"  Avg parser depth:           {metrics['avg_depth']:.2f}")
    print(f"  Max parser depth:           {metrics['max_depth']:.1f}")
    print(f"  Association accepted:       {metrics['accept_rate']:.1f}%")
    print(f"  Early rejection rate:       {metrics['early_reject_rate']:.1f}%")
    print(f"  Deep parse rate (PDATA):    {metrics['deep_parse_rate']:.1f}%")
    print(f"  Unique response types:      {metrics['unique_response_types']}")
    print(f"  Crashes detected:           {metrics['crash']}")
    print(f"  Hangs detected:             {metrics['hang']}")
    print(f"  Avg response time:          {metrics['avg_time_ms']:.1f} ms")

    print(f"\n  Depth Distribution:")
    for bucket, count in metrics["depth_distribution"].items():
        bar = "#" * min(count, 40)
        print(f"    {bucket:<20s}  {count:>4d}  {bar}")

    print(f"\n  Response Distribution:")
    for resp, count in sorted(metrics.get("response_distribution", {}).items(),
                               key=lambda x: -x[1]):
        print(f"    {resp:<25s}  {count:>5d}")

    print("\n  (Run with --old-pcap-dir to compare against old pipeline)")
    print("=" * 60)


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Compare old GAN pipeline vs smart mode against live server")
    parser.add_argument("--target-host", required=True,
                        help="Target DICOM server host")
    parser.add_argument("--target-port", type=int, default=4242,
                        help="Target DICOM port (default: 4242)")
    parser.add_argument("--old-pcap-dir", type=str, default=None,
                        help="Directory with PCAPs from old pipeline")
    parser.add_argument("--smart-pcap-dir", type=str, default=None,
                        help="Directory with PCAPs from smart mode")
    parser.add_argument("--generate", action="store_true",
                        help="Generate PCAPs for both modes before comparing")
    parser.add_argument("--samples", type=int, default=100,
                        help="Number of samples per mode (with --generate)")
    parser.add_argument("--feedback-rounds", type=int, default=2,
                        help="Feedback rounds for smart mode (with --generate)")
    parser.add_argument("--max-pcaps", type=int, default=None,
                        help="Max PCAPs to score per mode")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between sessions in seconds (default: 0.1)")
    args = parser.parse_args()

    if args.generate:
        base_dir = "fuzzer/data/pcap_output"
        old_dir = os.path.join(base_dir, "compare_old")
        old_pcap_dir = os.path.join(old_dir, "pcaps")
        smart_dir = os.path.join(base_dir, "compare_smart")

        python = os.environ.get("PYTHON", sys.executable)

        # --- Step 1: Generate old pipeline PCAPs ---
        print(f"\n[1/4] Generating old pipeline PCAPs (--mode protocol)...")
        print(f"  Using python: {python}")
        os.makedirs(old_dir, exist_ok=True)

        # Use minimal epochs (10) to keep it fast — CTGAN quality barely improves after that
        old_cmd = (
            f"{python} -m fuzzer.gan.gan --mode protocol "
            f"--samples {args.samples} --epochs 10 --batch-size 500 "
            f"fuzzer/data/normal_filtered_labeled.csv "
            f"fuzzer/data/abnormal_filtered_labeled.csv "
            f"{old_dir}"
        )
        print(f"  Running: {old_cmd}")
        ret = os.system(old_cmd)

        old_pipeline_ok = False
        if ret != 0:
            print("  WARNING: Old pipeline GAN generation failed (needs pandas+ctgan)")
        else:
            # Find the generated CSV and convert to PCAPs
            import glob as _glob
            csvs = sorted(_glob.glob(os.path.join(old_dir, "*dicom_*flows_*.csv")))
            if csvs:
                pcap_cmd = (
                    f"{python} -m fuzzer.gan.synthetic_to_pcap "
                    f"{csvs[-1]} {old_pcap_dir}"
                )
                print(f"  Converting to PCAPs: {pcap_cmd}")
                ret2 = os.system(pcap_cmd)
                if ret2 == 0:
                    old_pipeline_ok = True
                else:
                    print("  WARNING: CSV-to-PCAP conversion failed")
            else:
                print(f"  WARNING: No CSV found in {old_dir}")

        if not old_pipeline_ok:
            print("  Skipping old pipeline — will only show smart mode results")
            old_pcap_dir = None

        # --- Step 2: Generate smart mode PCAPs ---
        print(f"\n[2/4] Generating smart mode PCAPs (--mode smart)...")
        smart_cmd = (
            f"{python} -m fuzzer.gan.gan --mode smart "
            f"--samples {args.samples} "
            f"--target-host {args.target_host} --target-port {args.target_port} "
            f"--feedback-rounds {args.feedback_rounds} "
            f"--pcap-output {smart_dir}"
        )
        print(f"  Running: {smart_cmd}")
        ret = os.system(smart_cmd)
        if ret != 0:
            print("  ERROR: Smart mode generation failed")
            sys.exit(1)

        args.old_pcap_dir = old_pcap_dir
        args.smart_pcap_dir = smart_dir

    # At least smart mode PCAPs are required
    if not args.smart_pcap_dir:
        print("ERROR: Provide --smart-pcap-dir or use --generate")
        sys.exit(1)

    step = 3 if args.generate else 1
    total_steps = (3 if args.old_pcap_dir else 2) if args.generate else (2 if args.old_pcap_dir else 1)

    # Score old pipeline (if available)
    old_metrics = None
    if args.old_pcap_dir:
        print(f"\n[{step}/{step + total_steps - 1}] Scoring old pipeline PCAPs against "
              f"{args.target_host}:{args.target_port}...")
        old_results = score_pcap_dir(
            args.old_pcap_dir, args.target_host, args.target_port,
            delay=args.delay, max_pcaps=args.max_pcaps)
        old_metrics = compute_metrics(old_results, "Old Pipeline")
        print(f"  Scored {len(old_results)} sessions")
        step += 1

    # Score smart mode
    print(f"\n[{step}/{step + total_steps - step}] Scoring smart mode PCAPs against "
          f"{args.target_host}:{args.target_port}...")
    smart_results = score_pcap_dir(
        args.smart_pcap_dir, args.target_host, args.target_port,
        delay=args.delay, max_pcaps=args.max_pcaps)
    smart_metrics = compute_metrics(smart_results, "Smart Mode")
    print(f"  Scored {len(smart_results)} sessions")

    # Print results
    if old_metrics and old_metrics["total"] > 0:
        print_comparison(old_metrics, smart_metrics)
    else:
        print_single_mode(smart_metrics)


if __name__ == "__main__":
    main()
