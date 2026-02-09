#!/usr/bin/env python3
"""
Targeted PDU generator that specifically crafts packets to trigger
known mmt-security DICOM rules.

Generates PDATA PDUs with deliberately malformed DICOM command fields
to exercise detection rules for:
  - Invalid PDU types (outside 1-7)
  - Unrecognized command field values
  - Anomalous DICOM status codes
  - Invalid message IDs (0, 0xFFFF)
  - Invalid data set types
  - PDU length anomalies (0, >16MB)
  - Invalid protocol version

Usage:
    python -m fuzzer.gan.targeted_gen --output-dir fuzzer/data/pcap_output/targeted --count 20 --to-pcap
"""

import os
import sys
import struct
import random
import argparse
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fuzzer.models.byte_model.to_pcap import pdus_to_pcap

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def build_assoc_rq(called_ae="ORTHANC", calling_ae="ATTACKER", abstract_syntax=None,
                   protocol_version=1, pdu_length_override=None):
    """Build A-ASSOCIATE-RQ with configurable fields."""
    called = called_ae.ljust(16).encode('ascii')[:16]
    calling = calling_ae.ljust(16).encode('ascii')[:16]

    app_ctx_uid = b'1.2.840.10008.3.1.1.1'
    app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

    if abstract_syntax is None:
        abstract_syntax = b'1.2.840.10008.1.1'
    abstract = struct.pack('>BBH', 0x30, 0, len(abstract_syntax)) + abstract_syntax
    transfer_uid = b'1.2.840.10008.1.2'
    transfer = struct.pack('>BBH', 0x40, 0, len(transfer_uid)) + transfer_uid
    pres_ctx_data = struct.pack('>BBBB', 1, 0, 0, 0) + abstract + transfer
    pres_ctx = struct.pack('>BBH', 0x20, 0, len(pres_ctx_data)) + pres_ctx_data

    max_pdu = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', 16382)
    impl_uid = struct.pack('>BBH', 0x52, 0, 11) + b'1.2.3.4.5.6'
    user_info = struct.pack('>BBH', 0x50, 0, len(max_pdu + impl_uid)) + max_pdu + impl_uid

    variable = app_ctx + pres_ctx + user_info
    reserved32 = b'\x00' * 32
    pdu_data = struct.pack('>H', protocol_version) + b'\x00\x00' + called + calling + reserved32 + variable

    if pdu_length_override is not None:
        pdu = struct.pack('>BBi', 0x01, 0, pdu_length_override) + pdu_data
    else:
        pdu = struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data
    return pdu


def build_pdata(command_field=0x0030, message_id=1, data_set_type=0x0101,
                affected_sop_uid=b'1.2.840.10008.1.1', status=None,
                extra_data=b''):
    """Build a PDATA PDU with configurable DICOM command elements."""
    # Affected SOP Class UID
    uid = affected_sop_uid
    if len(uid) % 2: uid += b'\x00'
    elem_0002 = struct.pack('<HHI', 0x0000, 0x0002, len(uid)) + uid

    # Command Field
    elem_0100 = struct.pack('<HHI H', 0x0000, 0x0100, 2, command_field)

    # Message ID
    elem_0110 = struct.pack('<HHI H', 0x0000, 0x0110, 2, message_id)

    # Data Set Type
    elem_0800 = struct.pack('<HHI H', 0x0000, 0x0800, 2, data_set_type)

    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0800

    # Optional: Status field (for response-like PDUs)
    if status is not None:
        elem_0900 = struct.pack('<HHI H', 0x0000, 0x0900, 2, status)
        command_set += elem_0900

    # Command Group Length
    elem_0000 = struct.pack('<HHI I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set + extra_data

    # PDV Item
    pdv_data = struct.pack('>BB', 1, 0x03) + command_set
    pdv_item = struct.pack('>I', len(pdv_data)) + pdv_data

    # PDATA PDU
    pdata = struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item
    return pdata


def build_raw_pdu(pdu_type, data):
    """Build a raw PDU with arbitrary type byte."""
    return struct.pack('>BBi', pdu_type, 0, len(data)) + data


# ============================================================
# Rule-targeted generators
# ============================================================

def gen_invalid_pdu_types(count):
    """Rule: Detect invalid DICOM PDU type (outside 1-7)."""
    pdus = []
    invalid_types = [0x00, 0x08, 0x09, 0x0A, 0x10, 0x20, 0x50, 0x80, 0xFE, 0xFF]
    for i in range(count):
        ptype = random.choice(invalid_types)
        # Fill with plausible ASSOC_RQ-like data so it reaches the parser
        data = build_assoc_rq()[6:]  # Everything after the header
        pdu = build_raw_pdu(ptype, data)
        pdus.append(("invalid_pdu_type", ptype, pdu))
    return pdus


def gen_invalid_command_fields(count):
    """Rule: Detect unrecognized DICOM command field value."""
    pdus = []
    # Valid command fields: 0x0001 (C-STORE-RQ), 0x8001 (C-STORE-RSP),
    # 0x0020 (C-FIND-RQ), 0x0030 (C-ECHO-RQ), etc.
    invalid_cmds = [0x0000, 0x0002, 0x0003, 0x0099, 0x00FF, 0x1234,
                    0x7FFF, 0x8000, 0xDEAD, 0xFFFF, 0xBEEF, 0xCAFE]
    for i in range(count):
        cmd = random.choice(invalid_cmds)
        pdu = build_pdata(command_field=cmd)
        pdus.append(("invalid_command_field", cmd, pdu))
    return pdus


def gen_anomalous_status(count):
    """Rule: Detect anomalous DICOM status (non-success, non-pending)."""
    pdus = []
    # 0x0000=success, 0xFF00/0xFF01=pending. Others are anomalous.
    anomalous = [0x0001, 0x0100, 0x0110, 0x0120, 0x0122, 0x0124,
                 0x0210, 0x0211, 0x0212, 0xA700, 0xA900, 0xB000,
                 0xC000, 0xC100, 0xDEAD, 0xFE00, 0xFFFF]
    for i in range(count):
        status = random.choice(anomalous)
        # Use a response-like command (C-ECHO-RSP = 0x8030)
        pdu = build_pdata(command_field=0x8030, status=status, message_id=1)
        pdus.append(("anomalous_status", status, pdu))
    return pdus


def gen_status_0xDEAD(count):
    """Rule: Detect specific invalid DICOM status 0xDEAD."""
    pdus = []
    for i in range(count):
        pdu = build_pdata(command_field=0x8030, status=0xDEAD, message_id=i + 1)
        pdus.append(("status_0xDEAD", 0xDEAD, pdu))
    return pdus


def gen_message_id_zero(count):
    """Rule: Detect DICOM message ID equal to zero."""
    pdus = []
    for i in range(count):
        cmd = random.choice([0x0030, 0x0020, 0x0001, 0x0010])
        pdu = build_pdata(command_field=cmd, message_id=0)
        pdus.append(("message_id_zero", 0, pdu))
    return pdus


def gen_message_id_max(count):
    """Rule: Detect DICOM message ID at maximum value 0xFFFF."""
    pdus = []
    for i in range(count):
        cmd = random.choice([0x0030, 0x0020, 0x0001, 0x0010])
        pdu = build_pdata(command_field=cmd, message_id=0xFFFF)
        pdus.append(("message_id_max", 0xFFFF, pdu))
    return pdus


def gen_invalid_data_set_type(count):
    """Rule: Detect invalid DICOM data set type."""
    pdus = []
    # Valid: 0x0001 (dataset present), 0x0101 (no dataset)
    invalid = [0x0000, 0x0002, 0x00FF, 0x0100, 0x0102, 0x0200,
               0x1234, 0x7FFF, 0xFEFE, 0xFFFF]
    for i in range(count):
        dst = random.choice(invalid)
        pdu = build_pdata(data_set_type=dst)
        pdus.append(("invalid_data_set_type", dst, pdu))
    return pdus


def gen_pdu_length_over_16mb(count):
    """Rule: Detect DICOM PDU length exceeding 16MB."""
    pdus = []
    huge_lengths = [16 * 1024 * 1024 + 1, 0x01000001, 0x02000000, 0x7FFFFFFF]
    for i in range(count):
        length = random.choice(huge_lengths)
        # Build ASSOC_RQ with inflated length field (actual data is short)
        data = build_assoc_rq()[6:]
        pdu = struct.pack('>BBi', 0x01, 0, length) + data
        pdus.append(("pdu_length_over_16mb", length, pdu))
    return pdus


def gen_pdu_length_zero(count):
    """Rule: Detect DICOM PDU length of zero."""
    pdus = []
    for i in range(count):
        ptype = random.choice([0x01, 0x04, 0x05, 0x06])
        pdu = struct.pack('>BBi', ptype, 0, 0)
        pdus.append(("pdu_length_zero", 0, pdu))
    return pdus


def gen_invalid_protocol_version(count):
    """Rule: Detect invalid DICOM protocol version."""
    pdus = []
    invalid_versions = [0, 2, 3, 0x00FF, 0x0100, 0xFF01, 0xFFFF]
    for i in range(count):
        version = random.choice(invalid_versions)
        pdu = build_assoc_rq(protocol_version=version)
        pdus.append(("invalid_protocol_version", version, pdu))
    return pdus


# All generators
GENERATORS = [
    ("invalid_pdu_type", gen_invalid_pdu_types),
    ("invalid_command_field", gen_invalid_command_fields),
    ("anomalous_status", gen_anomalous_status),
    ("status_0xDEAD", gen_status_0xDEAD),
    ("message_id_zero", gen_message_id_zero),
    ("message_id_max", gen_message_id_max),
    ("invalid_data_set_type", gen_invalid_data_set_type),
    ("pdu_length_over_16mb", gen_pdu_length_over_16mb),
    ("pdu_length_zero", gen_pdu_length_zero),
    ("invalid_protocol_version", gen_invalid_protocol_version),
]


def main():
    parser = argparse.ArgumentParser(description="Targeted DICOM PDU generator for mmt-security rules")
    parser.add_argument("--output-dir", type=str, default="fuzzer/data/pcap_output/targeted")
    parser.add_argument("--count", type=int, default=5, help="PDUs per rule category")
    parser.add_argument("--to-pcap", action="store_true", help="Also generate PCAPs")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    all_pdus = []
    for name, gen_func in GENERATORS:
        pdus = gen_func(args.count)
        category_dir = os.path.join(args.output_dir, name)
        os.makedirs(category_dir, exist_ok=True)

        for i, (cat, value, pdu_bytes) in enumerate(pdus):
            out_path = os.path.join(category_dir, f"{cat}_{i:04d}.bin")
            with open(out_path, 'wb') as f:
                f.write(pdu_bytes)
            all_pdus.append(pdu_bytes)

        logger.info(f"{name}: generated {len(pdus)} PDUs (value examples: "
                     f"{[p[1] for p in pdus[:3]]})")

    logger.info(f"\nTotal: {len(all_pdus)} targeted PDUs in {args.output_dir}")

    if args.to_pcap:
        pcap_dir = os.path.join(args.output_dir, "pcap")
        # Group by category for separate PCAPs
        for name, gen_func in GENERATORS:
            category_dir = os.path.join(args.output_dir, name)
            cat_pdus = []
            for f in sorted(os.listdir(category_dir)):
                if f.endswith('.bin'):
                    cat_pdus.append(open(os.path.join(category_dir, f), 'rb').read())
            if cat_pdus:
                cat_pcap_dir = os.path.join(pcap_dir, name)
                pdus_to_pcap(cat_pdus, cat_pcap_dir)
                logger.info(f"  {name}: PCAPs in {cat_pcap_dir}")


if __name__ == "__main__":
    main()
