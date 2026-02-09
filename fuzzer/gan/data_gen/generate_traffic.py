#!/usr/bin/env python3
"""
Generate DICOM network traffic by replaying downloaded DICOM files against
a DICOM SCP (local pynetdicom or remote Orthanc), capturing all traffic as
PCAP files.

Two modes:
  --mode local   Start an in-process pynetdicom SCP on localhost (default)
  --mode remote  Send to an existing remote PACS (e.g. Orthanc)

Usage:
    # Against remote Orthanc
    python generate_traffic.py --dicom-dir fuzzer/data/training_data/dicom_files \\
        --output-dir fuzzer/data/training_data/pcaps --mode remote \\
        --host 152.228.175.65 --port 4242 --called-ae ORTHANC

    # Against local pynetdicom SCP (no external server needed)
    python generate_traffic.py --dicom-dir fuzzer/data/training_data/dicom_files \\
        --output-dir fuzzer/data/training_data/pcaps --mode local --port 11112

    # Extract PDUs only from existing pcap/ directory (no SCP needed)
    # Use extract_pdus.py instead for that workflow.
"""

import os
import sys
import argparse
import logging
import subprocess
import signal
import time
import threading
import glob
import random
import tempfile

import pydicom
from pydicom.uid import (
    ImplicitVRLittleEndian,
    ExplicitVRLittleEndian,
)
from pynetdicom import AE, evt, StoragePresentationContexts
from pynetdicom.sop_class import (
    Verification,
    PatientRootQueryRetrieveInformationModelFind,
    StudyRootQueryRetrieveInformationModelFind,
)
from pydicom.dataset import Dataset

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("traffic_generation.log"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)

# Default network parameters
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 4242
DEFAULT_CALLED_AE = "ORTHANC"
DEFAULT_CALLING_AE = "NETWORKFUZZER"

# Alternative AE titles for traffic diversity
ALT_AE_TITLES = [
    "STORESCP", "FINDSCP", "PACS_SRV",
    "MODALITY1", "WORKSTATION", "VIEWER", "ARCHIVE",
    "CT_SCANNER", "MR_SCANNER", "US_SCANNER",
]

# Transfer syntaxes to negotiate
TRANSFER_SYNTAXES = [
    ImplicitVRLittleEndian,
    ExplicitVRLittleEndian,
]


# ============================================================================
# Local SCP (for --mode local)
# ============================================================================

def handle_store(event):
    """Handle a C-STORE request (accept everything)."""
    return 0x0000  # Success


def handle_find(event):
    """Handle a C-FIND request (return empty)."""
    yield 0x0000, None


def start_scp(host, port, ae_title):
    """Start a pynetdicom SCP that accepts all storage and query requests."""
    ae = AE(ae_title=ae_title)
    for cx in StoragePresentationContexts:
        ae.add_supported_context(cx.abstract_syntax, TRANSFER_SYNTAXES)
    ae.add_supported_context(Verification, TRANSFER_SYNTAXES)
    ae.add_supported_context(
        PatientRootQueryRetrieveInformationModelFind, TRANSFER_SYNTAXES
    )
    ae.add_supported_context(
        StudyRootQueryRetrieveInformationModelFind, TRANSFER_SYNTAXES
    )
    handlers = [
        (evt.EVT_C_STORE, handle_store),
        (evt.EVT_C_FIND, handle_find),
    ]
    logger.info(f"Starting local SCP on {host}:{port} (AE: {ae_title})")
    scp = ae.start_server((host, port), evt_handlers=handlers, block=False)
    return scp


# ============================================================================
# Packet Capture
# ============================================================================

def detect_capture_interface(host):
    """Auto-detect the network interface to capture on."""
    if host in ("127.0.0.1", "localhost", "::1"):
        return "lo"
    try:
        result = subprocess.run(
            ["ip", "route", "get", host],
            capture_output=True, text=True, timeout=5,
        )
        # Parse: "1.2.3.4 via X.X.X.X dev <iface> ..."
        for token_idx, token in enumerate(result.stdout.split()):
            if token == "dev" and token_idx + 1 < len(result.stdout.split()):
                return result.stdout.split()[token_idx + 1]
    except Exception:
        pass
    return "any"


def start_tcpdump(output_pcap, host, port, interface=None):
    """Start tcpdump to capture traffic to/from the target host:port."""
    if interface is None:
        interface = detect_capture_interface(host)

    # Build filter: capture traffic on the DICOM port to/from the host
    if host in ("127.0.0.1", "localhost"):
        bpf_filter = f"port {port}"
    else:
        bpf_filter = f"host {host} and port {port}"

    cmd = [
        "tcpdump", "-i", interface, "-w", output_pcap,
        "-s", "0", bpf_filter,
    ]
    logger.info(f"Starting capture: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        time.sleep(1.0)  # Let tcpdump initialize and start capturing
        # Check it didn't die immediately
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode(errors='replace')
            logger.error(f"tcpdump exited immediately: {stderr}")
            return None
        return proc
    except FileNotFoundError:
        logger.error("tcpdump not found. Install with: sudo apt install tcpdump")
        return None


def stop_tcpdump(proc):
    """Stop tcpdump process gracefully."""
    if proc is None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ============================================================================
# DICOM Operations
# ============================================================================

def find_dicom_files(dicom_dir, max_files=None):
    """Find all DICOM files in the directory tree."""
    dcm_files = []
    for root, dirs, files in os.walk(dicom_dir):
        for f in files:
            fpath = os.path.join(root, f)
            if f.lower().endswith(('.dcm', '.ima', '.dicom')):
                dcm_files.append(fpath)
            elif '.' not in f:
                # Files without extension are often DICOM
                dcm_files.append(fpath)

    if max_files and len(dcm_files) > max_files:
        dcm_files = random.sample(dcm_files, max_files)

    return sorted(dcm_files)


def perform_cecho(host, port, calling_ae, called_ae):
    """Perform a C-ECHO verification."""
    ae = AE(ae_title=calling_ae)
    ae.add_requested_context(Verification, TRANSFER_SYNTAXES)
    assoc = ae.associate(host, port, ae_title=called_ae)
    if assoc.is_established:
        status = assoc.send_c_echo()
        assoc.release()
        return True
    return False


def perform_cstore(host, port, dicom_file, calling_ae, called_ae):
    """Perform a C-STORE for a single DICOM file."""
    try:
        ds = pydicom.dcmread(dicom_file, force=True)
    except Exception as e:
        logger.debug(f"Cannot read {dicom_file}: {e}")
        return False

    ae = AE(ae_title=calling_ae)
    if hasattr(ds, 'SOPClassUID'):
        ae.add_requested_context(ds.SOPClassUID, TRANSFER_SYNTAXES)
    else:
        for cx in StoragePresentationContexts[:10]:
            ae.add_requested_context(cx.abstract_syntax, TRANSFER_SYNTAXES)

    assoc = ae.associate(host, port, ae_title=called_ae)
    if assoc.is_established:
        status = assoc.send_c_store(ds)
        assoc.release()
        return status is not None
    return False


def perform_cfind(host, port, calling_ae, called_ae, patient_name="*"):
    """Perform a C-FIND query."""
    ae = AE(ae_title=calling_ae)
    ae.add_requested_context(
        PatientRootQueryRetrieveInformationModelFind, TRANSFER_SYNTAXES
    )
    ds = Dataset()
    ds.PatientName = patient_name
    ds.QueryRetrieveLevel = "PATIENT"

    assoc = ae.associate(host, port, ae_title=called_ae)
    if assoc.is_established:
        responses = assoc.send_c_find(ds, PatientRootQueryRetrieveInformationModelFind)
        for status, identifier in responses:
            pass
        assoc.release()
        return True
    return False


def perform_association_variants(host, port, calling_ae, called_ae):
    """
    Perform various association patterns for traffic diversity:
    - Association + release (no data)
    - Association + abort
    - Multi-context association
    """
    # Normal association + release
    ae = AE(ae_title=calling_ae)
    ae.add_requested_context(Verification, TRANSFER_SYNTAXES)
    assoc = ae.associate(host, port, ae_title=called_ae)
    if assoc.is_established:
        assoc.release()

    # Association + abort
    ae2 = AE(ae_title=calling_ae)
    ae2.add_requested_context(Verification, TRANSFER_SYNTAXES)
    for cx in StoragePresentationContexts[:5]:
        ae2.add_requested_context(cx.abstract_syntax, TRANSFER_SYNTAXES)
    assoc = ae2.associate(host, port, ae_title=called_ae)
    if assoc.is_established:
        assoc.abort()


# ============================================================================
# Batch Traffic Generation
# ============================================================================

def generate_traffic_batch(dicom_files, host, port, called_ae,
                           output_pcap, interface=None, batch_idx=0):
    """
    Generate one batch of DICOM traffic and capture to a single PCAP.
    """
    tcpdump_proc = start_tcpdump(output_pcap, host, port, interface)
    if tcpdump_proc is None:
        logger.error(f"Skipping batch {batch_idx}: cannot start packet capture")
        return 0

    operations = 0

    try:
        # C-ECHO with various AE titles
        for ae_title in random.sample(ALT_AE_TITLES, min(3, len(ALT_AE_TITLES))):
            try:
                if perform_cecho(host, port, ae_title, called_ae):
                    operations += 1
                    logger.debug(f"C-ECHO OK (ae={ae_title})")
            except Exception as e:
                logger.debug(f"C-ECHO failed ({ae_title}): {e}")

        # C-STORE for each DICOM file
        for dcm_file in dicom_files:
            calling = random.choice(ALT_AE_TITLES)
            try:
                if perform_cstore(host, port, dcm_file, calling, called_ae):
                    operations += 1
                    logger.debug(f"C-STORE OK: {os.path.basename(dcm_file)}")
                else:
                    logger.debug(f"C-STORE rejected: {os.path.basename(dcm_file)}")
            except Exception as e:
                logger.debug(f"C-STORE error ({dcm_file}): {e}")

        # C-FIND queries with various patterns
        for pn in ["*", "A*", "SMITH*", "DOE*", "?"]:
            calling = random.choice(ALT_AE_TITLES)
            try:
                if perform_cfind(host, port, calling, called_ae, pn):
                    operations += 1
            except Exception as e:
                logger.debug(f"C-FIND failed ({pn}): {e}")

        # Association variants (release, abort, multi-context)
        try:
            perform_association_variants(host, port, "VARIANT_SCU", called_ae)
            operations += 2
        except Exception as e:
            logger.debug(f"Association variants failed: {e}")

        # Let final packets flush
        time.sleep(1.5)

    finally:
        stop_tcpdump(tcpdump_proc)

    return operations


def generate_all_traffic(dicom_dir, output_dir, host, port, called_ae,
                         mode="remote", batch_size=50, interface=None,
                         max_files=None):
    """
    Main entry point: replay DICOM files against a PACS, capture traffic.
    """
    os.makedirs(output_dir, exist_ok=True)

    dicom_files = find_dicom_files(dicom_dir, max_files=max_files)
    if not dicom_files:
        logger.error(f"No DICOM files found in {dicom_dir}")
        return 0

    logger.info(f"Found {len(dicom_files)} DICOM files")
    logger.info(f"Target: {host}:{port} (AE: {called_ae}, mode: {mode})")

    # Start local SCP if needed
    scp = None
    if mode == "local":
        scp = start_scp("127.0.0.1", port, called_ae)
        time.sleep(1.0)

    total_ops = 0
    total_pcaps = 0

    try:
        for i in range(0, len(dicom_files), batch_size):
            batch = dicom_files[i:i + batch_size]
            batch_idx = i // batch_size
            output_pcap = os.path.join(
                output_dir, f"traffic_batch_{batch_idx:04d}.pcap"
            )

            logger.info(
                f"Batch {batch_idx}: {len(batch)} files -> {output_pcap}"
            )

            ops = generate_traffic_batch(
                batch, host, port, called_ae,
                output_pcap, interface, batch_idx,
            )
            total_ops += ops
            if ops > 0 and os.path.exists(output_pcap):
                fsize = os.path.getsize(output_pcap)
                total_pcaps += 1
                logger.info(
                    f"  Batch {batch_idx}: {ops} operations, "
                    f"PCAP size: {fsize / 1024:.1f} KB"
                )
            else:
                logger.warning(f"  Batch {batch_idx}: {ops} operations, no PCAP")

    finally:
        if scp is not None:
            scp.shutdown()
            logger.info("Local SCP shutdown")

    logger.info(
        f"Traffic generation complete: {total_pcaps} PCAPs, "
        f"{total_ops} operations from {len(dicom_files)} files"
    )
    return total_pcaps


def main():
    parser = argparse.ArgumentParser(
        description="Generate DICOM traffic by replaying files against a PACS server"
    )
    parser.add_argument(
        "--dicom-dir", type=str, required=True,
        help="Directory containing DICOM files to replay",
    )
    parser.add_argument(
        "--output-dir", type=str, default="fuzzer/data/training_data/pcaps",
        help="Output directory for captured PCAP files",
    )
    parser.add_argument(
        "--mode", choices=["local", "remote"], default="remote",
        help="local = start pynetdicom SCP; remote = use existing PACS (default: remote)",
    )
    parser.add_argument(
        "--host", type=str, default=DEFAULT_HOST,
        help=f"Target PACS host (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Target DICOM port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--called-ae", type=str, default=DEFAULT_CALLED_AE,
        help=f"Called AE title of target SCP (default: {DEFAULT_CALLED_AE})",
    )
    parser.add_argument(
        "--interface", type=str, default=None,
        help="Network interface for tcpdump (auto-detected if omitted)",
    )
    parser.add_argument(
        "--batch-size", type=int, default=50,
        help="Number of DICOM files per PCAP batch (default: 50)",
    )
    parser.add_argument(
        "--max-files", type=int, default=None,
        help="Limit total number of DICOM files to send (default: all)",
    )

    args = parser.parse_args()

    if args.mode == "local":
        args.host = "127.0.0.1"

    print("\n" + "=" * 70)
    print("DICOM TRAFFIC GENERATOR")
    print("=" * 70)
    print(f"Mode:         {args.mode}")
    print(f"Target:       {args.host}:{args.port} (AE: {args.called_ae})")
    print(f"DICOM files:  {args.dicom_dir}")
    print(f"Output PCAPs: {args.output_dir}")
    print(f"Batch size:   {args.batch_size}")
    iface = args.interface or detect_capture_interface(args.host)
    print(f"Capture intf: {iface}")
    print("=" * 70 + "\n")

    n_pcaps = generate_all_traffic(
        args.dicom_dir, args.output_dir,
        host=args.host, port=args.port,
        called_ae=args.called_ae,
        mode=args.mode,
        batch_size=args.batch_size,
        interface=args.interface,
        max_files=args.max_files,
    )

    print(f"\nDone: {n_pcaps} PCAP files generated")
    print(f"Output: {args.output_dir}\n")


if __name__ == "__main__":
    main()
