#!/usr/bin/env python3
"""
Convert generated PDU byte sequences into valid PCAP files.

Wraps raw PDU bytes in complete DICOM sessions (assoc_rq + assoc_ac +
pdata + release) and encapsulates in Ether/IP/TCP using the existing
wrap_tcp_ip() function from synthetic_to_pcap.py.

Usage:
    python -m fuzzer.models.byte_model.to_pcap --pdu-dir fuzzer/data/pcap_output/ml_generated --output-dir fuzzer/data/pcap_output/ml_pcaps
"""

import os
import sys
import argparse
import glob
import logging
import struct

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from fuzzer.common.pcap_utils import (
    wrap_tcp_ip, build_associate_rq, build_associate_ac,
    build_release_rq, build_release_rp,
)
from scapy.all import wrpcap

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# DICOM PDU type byte values
PDU_TYPES = {
    0x01: "assoc_rq",
    0x02: "assoc_ac",
    0x03: "assoc_rj",
    0x04: "pdata",
    0x05: "release_rq",
    0x06: "release_rp",
    0x07: "abort",
}


def classify_pdu(pdu_bytes):
    """Classify a PDU by its type byte."""
    if not pdu_bytes:
        return "unknown"
    return PDU_TYPES.get(pdu_bytes[0], "unknown")


def build_session_around_pdu(pdu_bytes):
    """
    Build a complete DICOM session around a generated PDU.

    If the PDU is an assoc_rq, build: [pdu, assoc_ac, release_rq, release_rp]
    If the PDU is pdata, build: [assoc_rq, assoc_ac, pdu, release_rq, release_rp]
    Otherwise, wrap in a standard session.
    """
    pdu_type = classify_pdu(pdu_bytes)

    if pdu_type == "assoc_rq":
        # Use generated assoc_rq, add matching assoc_ac + release
        return [
            pdu_bytes,
            build_associate_ac(),
            build_release_rq(),
            build_release_rp(),
        ]
    elif pdu_type == "assoc_ac":
        return [
            build_associate_rq(),
            pdu_bytes,
            build_release_rq(),
            build_release_rp(),
        ]
    elif pdu_type == "pdata":
        return [
            build_associate_rq(),
            build_associate_ac(),
            pdu_bytes,
            build_release_rq(),
            build_release_rp(),
        ]
    elif pdu_type in ("release_rq", "release_rp", "abort"):
        return [
            build_associate_rq(),
            build_associate_ac(),
            pdu_bytes,
        ]
    else:
        # Unknown type — send as raw pdata within a session
        return [
            build_associate_rq(),
            build_associate_ac(),
            pdu_bytes,
            build_release_rq(),
            build_release_rp(),
        ]


def pdus_to_pcap(pdu_list, output_dir, src_port_base=50000):
    """
    Convert a list of raw PDU byte sequences to PCAP files.

    Each PDU is wrapped in a complete DICOM session and TCP/IP encapsulation.
    """
    os.makedirs(output_dir, exist_ok=True)
    count = 0

    for i, pdu_bytes in enumerate(pdu_list):
        if not pdu_bytes:
            continue

        try:
            session_pdus = build_session_around_pdu(pdu_bytes)
            packets = wrap_tcp_ip(
                session_pdus,
                src_port=src_port_base + (i % 10000),
            )

            pcap_path = os.path.join(output_dir, f"ml_session_{i:06d}.pcap")
            wrpcap(pcap_path, packets)
            count += 1
        except Exception as e:
            logger.debug(f"Failed to create PCAP for PDU {i}: {e}")

    logger.info(f"Created {count} PCAP files in {output_dir}")
    return count


def main():
    parser = argparse.ArgumentParser(
        description="Convert generated PDU bytes to PCAP files"
    )
    parser.add_argument("--pdu-dir", type=str, required=True,
                        help="Directory containing .bin PDU files")
    parser.add_argument("--output-dir", type=str, default="fuzzer/data/pcap_output/ml_pcaps",
                        help="Output directory for PCAP files")

    args = parser.parse_args()

    # Load PDUs
    pdu_files = sorted(glob.glob(os.path.join(args.pdu_dir, "*.bin")))
    if not pdu_files:
        print(f"No .bin files found in {args.pdu_dir}")
        sys.exit(1)

    pdus = []
    for f in pdu_files:
        with open(f, 'rb') as fh:
            pdus.append(fh.read())

    print(f"Loaded {len(pdus)} PDUs from {args.pdu_dir}")

    count = pdus_to_pcap(pdus, args.output_dir)
    print(f"Created {count} PCAP files in {args.output_dir}")


if __name__ == "__main__":
    main()
