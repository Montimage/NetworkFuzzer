#!/usr/bin/env python3
"""
Extract individual DICOM PDU byte sequences from PCAP files.

Reads PCAP files, reassembles TCP streams on DICOM ports, parses PDU
boundaries, and saves each PDU as a raw binary file organized by type.

Usage:
    python extract_pdus.py --pcap-dir fuzzer/data/training_data/pcaps --output-dir fuzzer/data/training_data/pdus
    python extract_pdus.py --pcap-dir pcap/ --output-dir /tmp/pdus  # Bootstrap from existing PCAPs
"""

import os
import sys
import argparse
import logging
import struct
import csv
from collections import defaultdict

import numpy as np
from scapy.all import rdpcap, TCP, Raw, conf

# Suppress scapy warnings
conf.verb = 0

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("pdu_extraction.log"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)

# DICOM PDU type mapping (PS3.8 Table 9-1)
PDU_TYPE_NAMES = {
    0x01: "assoc_rq",
    0x02: "assoc_ac",
    0x03: "assoc_rj",
    0x04: "pdata",
    0x05: "release_rq",
    0x06: "release_rp",
    0x07: "abort",
}

# Standard DICOM ports
DICOM_PORTS = {104, 4006, 11112, 11113, 4242}

# Maximum PDU size to accept (avoid memory issues with corrupt length fields)
MAX_PDU_SIZE = 4 * 1024 * 1024  # 4 MB

# Minimum PDU size (type + reserved + length = 6 bytes)
MIN_PDU_HEADER = 6


def is_dicom_port(sport, dport):
    """Check if either port is a known DICOM port."""
    return sport in DICOM_PORTS or dport in DICOM_PORTS


def reassemble_tcp_streams(packets):
    """
    Reassemble TCP streams from scapy packets.

    Returns dict mapping (src_ip, src_port, dst_ip, dst_port) -> bytearray of payload.
    """
    streams = defaultdict(bytearray)

    for pkt in packets:
        if TCP not in pkt or Raw not in pkt:
            continue

        ip_layer = pkt.getlayer("IP")
        if ip_layer is None:
            continue

        tcp = pkt[TCP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        sport = tcp.sport
        dport = tcp.dport

        # Only process DICOM-port traffic
        if not is_dicom_port(sport, dport):
            continue

        stream_key = (src_ip, sport, dst_ip, dport)
        streams[stream_key].extend(bytes(pkt[Raw].load))

    return streams


def parse_pdus_from_stream(stream_bytes, source_label=""):
    """
    Parse DICOM PDU boundaries from a reassembled TCP stream.

    PDU format: type(1 byte) + reserved(1 byte) + length(4 bytes, big-endian) + data

    Returns list of (pdu_type_code, pdu_bytes) tuples.
    """
    pdus = []
    offset = 0
    data = bytes(stream_bytes)

    while offset + MIN_PDU_HEADER <= len(data):
        pdu_type = data[offset]

        # Validate PDU type
        if pdu_type not in PDU_TYPE_NAMES:
            # Not a valid PDU type; try next byte
            offset += 1
            continue

        # Parse PDU length (bytes 2-5, big-endian)
        pdu_length = struct.unpack('!I', data[offset + 2:offset + 6])[0]

        # Total PDU size = header(6) + payload(pdu_length)
        total_size = MIN_PDU_HEADER + pdu_length

        # Sanity checks
        if pdu_length > MAX_PDU_SIZE:
            logger.debug(
                f"Skipping PDU at offset {offset}: length {pdu_length} exceeds max "
                f"({source_label})"
            )
            offset += 1
            continue

        if offset + total_size > len(data):
            # PDU extends beyond available data — likely truncated
            # Still extract what we have if it's at least header + some data
            if pdu_length > 0 and offset + MIN_PDU_HEADER < len(data):
                available = len(data) - offset
                logger.debug(
                    f"Truncated PDU at offset {offset}: expected {total_size}, "
                    f"have {available} ({source_label})"
                )
            break

        pdu_bytes = data[offset:offset + total_size]
        pdus.append((pdu_type, pdu_bytes))
        offset += total_size

    return pdus


def extract_pdus_from_pcap(pcap_path):
    """
    Extract all DICOM PDUs from a single PCAP file.

    Returns list of (pdu_type_code, pdu_bytes, pcap_path) tuples.
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        logger.error(f"Failed to read {pcap_path}: {e}")
        return []

    streams = reassemble_tcp_streams(packets)
    all_pdus = []

    for stream_key, stream_data in streams.items():
        if len(stream_data) < MIN_PDU_HEADER:
            continue

        label = f"{pcap_path}:{stream_key[0]}:{stream_key[1]}->{stream_key[2]}:{stream_key[3]}"
        pdus = parse_pdus_from_stream(stream_data, label)

        for pdu_type, pdu_bytes in pdus:
            all_pdus.append((pdu_type, pdu_bytes, pcap_path))

    return all_pdus


def save_pdus(pdus, output_dir):
    """
    Save extracted PDUs organized by type.

    Creates:
        output_dir/assoc_rq/   — A-ASSOCIATE-RQ PDUs
        output_dir/assoc_ac/   — A-ASSOCIATE-AC PDUs
        output_dir/pdata/      — P-DATA-TF PDUs
        ...
        output_dir/metadata.csv — PDU metadata
    """
    os.makedirs(output_dir, exist_ok=True)

    # Create subdirectories for each PDU type
    type_dirs = {}
    for type_code, type_name in PDU_TYPE_NAMES.items():
        type_dir = os.path.join(output_dir, type_name)
        os.makedirs(type_dir, exist_ok=True)
        type_dirs[type_code] = type_dir

    # Counters per type
    counters = defaultdict(int)
    metadata_rows = []

    for pdu_type, pdu_bytes, source_file in pdus:
        type_name = PDU_TYPE_NAMES.get(pdu_type, f"unknown_{pdu_type:02x}")
        idx = counters[pdu_type]
        counters[pdu_type] += 1

        # Save raw binary
        if pdu_type in type_dirs:
            out_path = os.path.join(type_dirs[pdu_type], f"{type_name}_{idx:06d}.bin")
            with open(out_path, 'wb') as f:
                f.write(pdu_bytes)

        # Metadata
        metadata_rows.append({
            "pdu_type": type_name,
            "pdu_type_code": f"0x{pdu_type:02x}",
            "length": len(pdu_bytes),
            "source_file": os.path.basename(source_file),
            "file_index": idx,
        })

    # Write metadata CSV
    csv_path = os.path.join(output_dir, "metadata.csv")
    if metadata_rows:
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=metadata_rows[0].keys())
            writer.writeheader()
            writer.writerows(metadata_rows)

    # Also save as numpy arrays for efficient model loading
    for pdu_type, type_dir in type_dirs.items():
        type_name = PDU_TYPE_NAMES[pdu_type]
        type_pdus = [
            pdu_bytes for pt, pdu_bytes, _ in pdus if pt == pdu_type
        ]
        if type_pdus:
            # Save lengths separately (variable-length sequences)
            lengths = np.array([len(p) for p in type_pdus], dtype=np.int32)
            np.save(os.path.join(type_dir, "lengths.npy"), lengths)

            # Save concatenated bytes + offsets for efficient loading
            all_bytes = b''.join(type_pdus)
            np.save(
                os.path.join(type_dir, "bytes.npy"),
                np.frombuffer(all_bytes, dtype=np.uint8),
            )
            offsets = np.zeros(len(type_pdus) + 1, dtype=np.int64)
            for i, p in enumerate(type_pdus):
                offsets[i + 1] = offsets[i] + len(p)
            np.save(os.path.join(type_dir, "offsets.npy"), offsets)

    return counters


def extract_all(pcap_dir, output_dir):
    """
    Extract PDUs from all PCAP files in a directory.
    """
    pcap_files = []
    for root, dirs, files in os.walk(pcap_dir):
        for f in files:
            if f.lower().endswith(('.pcap', '.pcapng', '.cap')):
                pcap_files.append(os.path.join(root, f))

    if not pcap_files:
        logger.error(f"No PCAP files found in {pcap_dir}")
        return {}

    pcap_files.sort()
    logger.info(f"Found {len(pcap_files)} PCAP files")

    all_pdus = []
    for i, pcap_path in enumerate(pcap_files):
        logger.info(f"[{i+1}/{len(pcap_files)}] Processing {pcap_path}...")
        pdus = extract_pdus_from_pcap(pcap_path)
        all_pdus.extend(pdus)
        logger.info(f"  Extracted {len(pdus)} PDUs")

    logger.info(f"Total PDUs extracted: {len(all_pdus)}")

    # Save organized by type
    counters = save_pdus(all_pdus, output_dir)

    # Report
    for type_code, count in sorted(counters.items()):
        type_name = PDU_TYPE_NAMES.get(type_code, f"0x{type_code:02x}")
        logger.info(f"  {type_name}: {count} PDUs")

    return counters


def main():
    parser = argparse.ArgumentParser(
        description="Extract DICOM PDU byte sequences from PCAP files"
    )
    parser.add_argument(
        "--pcap-dir", type=str, required=True,
        help="Directory containing PCAP files",
    )
    parser.add_argument(
        "--output-dir", type=str, default="fuzzer/data/training_data/pdus",
        help="Output directory for extracted PDUs",
    )

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("DICOM PDU EXTRACTOR")
    print("=" * 70)
    print(f"PCAP source: {args.pcap_dir}")
    print(f"Output: {args.output_dir}")
    print("=" * 70 + "\n")

    counters = extract_all(args.pcap_dir, args.output_dir)

    total = sum(counters.values())
    print(f"\nDone: {total} PDUs extracted")
    for type_code, count in sorted(counters.items()):
        type_name = PDU_TYPE_NAMES.get(type_code, f"0x{type_code:02x}")
        print(f"  {type_name}: {count}")
    print(f"Output: {args.output_dir}\n")


if __name__ == "__main__":
    main()
