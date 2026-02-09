#!/usr/bin/env python3
"""
DICOM Session PCAP Generator

Builds complete DICOM sessions from synthetic CSV parameters and writes them
as PCAP files. Constructs raw DICOM PDU bytes following PS3.8, wraps them in
TCP/IP packets using scapy.

Supports:
  - Valid DICOM sessions with GAN-generated parameters
  - Attack-specific sessions (from attack profiles)
  - Malformed packet generation (post-generation mutations)

Usage:
  python synthetic_to_pcap.py <synthetic_csv> <output_dir> [options]
  python synthetic_to_pcap.py <synthetic_csv> <output_dir> --attack-type ae_manipulation
  python synthetic_to_pcap.py <synthetic_csv> <output_dir> --malformed
"""

import os
import sys
import argparse
import struct
import random
import logging
import pandas as pd
import numpy as np
from datetime import datetime

from scapy.all import IP, TCP, Raw, Ether, wrpcap, conf

from fuzzer.gan.attack_profiles import (
    ATTACK_PROFILES, MALFORMATION_MUTATIONS, PDU_TYPE_MAP,
    get_attack_profile, get_malformation_list,
    VERIFICATION_SOP, IMPLICIT_VR_LE, DICOM_APP_CONTEXT,
)

# Suppress scapy warnings
conf.verb = 0

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("synthetic_conversion.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Default network parameters
DEFAULT_SRC_IP = "192.168.1.100"
DEFAULT_DST_IP = "192.168.1.200"
DEFAULT_SRC_PORT = 50000
DEFAULT_DST_PORT = 4006  # DICOM port (4006 used by many PACS; 104 is also standard)


# =============================================================================
# DICOM PDU Builders (raw bytes, per PS3.8)
# =============================================================================

def _pad_ae_title(ae_title, length=16):
    """Pad AE title to 16 bytes with spaces (DICOM PS3.8 requirement)."""
    if isinstance(ae_title, str):
        ae_bytes = ae_title.encode('latin-1', errors='replace')
    else:
        ae_bytes = ae_title
    # Truncate if too long, pad with spaces if too short
    ae_bytes = ae_bytes[:length]
    ae_bytes = ae_bytes + b' ' * (length - len(ae_bytes))
    return ae_bytes


def _encode_uid(uid_str):
    """Encode a UID string to bytes, with odd-length padding."""
    if isinstance(uid_str, str):
        uid_bytes = uid_str.encode('ascii', errors='replace')
    else:
        uid_bytes = uid_str
    # UIDs must have even length per DICOM
    if len(uid_bytes) % 2 != 0:
        uid_bytes += b'\x00'
    return uid_bytes


def _build_item(item_type, data):
    """Build a generic DICOM association item: type(1) + reserved(1) + length(2) + data."""
    return struct.pack('!BBH', item_type, 0x00, len(data)) + data


def _build_sub_item(item_type, data):
    """Build a sub-item: type(1) + reserved(1) + length(2) + data."""
    return struct.pack('!BBH', item_type, 0x00, len(data)) + data


def build_application_context_item(app_context=None):
    """Build Application Context Item (type 0x10)."""
    if app_context is None:
        app_context = DICOM_APP_CONTEXT
    uid = _encode_uid(app_context)
    return _build_item(0x10, uid)


def build_presentation_context_rq(ctx_id, abstract_syntax, transfer_syntaxes):
    """
    Build Presentation Context Item for A-ASSOCIATE-RQ (type 0x20).
    Contains abstract syntax sub-item (0x30) and transfer syntax sub-items (0x40).
    """
    # Abstract Syntax sub-item (type 0x30)
    abs_uid = _encode_uid(abstract_syntax)
    abs_item = _build_sub_item(0x30, abs_uid)

    # Transfer Syntax sub-items (type 0x40)
    xfer_items = b''
    if isinstance(transfer_syntaxes, str):
        transfer_syntaxes = [transfer_syntaxes]
    for ts in transfer_syntaxes:
        ts_uid = _encode_uid(ts)
        xfer_items += _build_sub_item(0x40, ts_uid)

    # Presentation Context: ctx_id(1) + reserved(3) + items
    pctx_data = struct.pack('!B3x', ctx_id) + abs_item + xfer_items
    return _build_item(0x20, pctx_data)


def build_presentation_context_ac(ctx_id, result, transfer_syntax):
    """
    Build Presentation Context Item for A-ASSOCIATE-AC (type 0x21).
    result: 0=accept, 1=user-reject, 2=no-reason, 3=abstract-syntax-not-supported,
            4=transfer-syntax-not-supported
    """
    ts_uid = _encode_uid(transfer_syntax)
    ts_item = _build_sub_item(0x40, ts_uid)

    # ctx_id(1) + reserved(1) + result(1) + reserved(1) + transfer syntax item
    pctx_data = struct.pack('!BBBB', ctx_id, 0x00, result, 0x00) + ts_item
    return _build_item(0x21, pctx_data)


def build_user_info_item(max_pdu_len=16384, impl_uid=None, impl_version=None):
    """Build User Information Item (type 0x50) with sub-items."""
    sub_items = b''

    # Maximum Length sub-item (type 0x51)
    max_len_data = struct.pack('!I', max_pdu_len)
    sub_items += _build_sub_item(0x51, max_len_data)

    # Implementation Class UID sub-item (type 0x52)
    if impl_uid is None:
        impl_uid = "1.2.826.0.1.3680043.9.3811.2.1.0"
    uid_data = _encode_uid(impl_uid)
    sub_items += _build_sub_item(0x52, uid_data)

    # Implementation Version Name sub-item (type 0x55)
    if impl_version is None:
        impl_version = "NETWORKFUZZER"
    ver_data = impl_version.encode('ascii', errors='replace')
    sub_items += _build_sub_item(0x55, ver_data)

    return _build_item(0x50, sub_items)


def build_associate_rq(called_ae="ANY-SCP", calling_ae="PYNETDICOM",
                       abstract_syntaxes=None, transfer_syntaxes=None,
                       max_pdu_len=16384, app_context=None):
    """
    Build A-ASSOCIATE-RQ PDU (type 0x01) per DICOM PS3.8 Section 9.3.2.

    Format:
      PDU type (1) + reserved (1) + PDU length (4) +
      protocol version (2) + reserved (2) +
      called AE (16) + calling AE (16) + reserved (32) +
      variable items
    """
    if abstract_syntaxes is None:
        abstract_syntaxes = [VERIFICATION_SOP]
    if transfer_syntaxes is None:
        transfer_syntaxes = [IMPLICIT_VR_LE]

    # Variable items
    variable_items = b''

    # Application Context
    variable_items += build_application_context_item(app_context)

    # Presentation Contexts (one per abstract syntax)
    for i, abs_syn in enumerate(abstract_syntaxes if isinstance(abstract_syntaxes, list) else [abstract_syntaxes]):
        ctx_id = 2 * i + 1  # odd IDs: 1, 3, 5, ...
        variable_items += build_presentation_context_rq(ctx_id, abs_syn, transfer_syntaxes)

    # User Information
    variable_items += build_user_info_item(max_pdu_len)

    # Fixed fields
    protocol_version = 0x0001
    called = _pad_ae_title(called_ae)
    calling = _pad_ae_title(calling_ae)
    reserved_32 = b'\x00' * 32

    pdu_data = struct.pack('!HH', protocol_version, 0x0000) + \
               called + calling + reserved_32 + variable_items

    # PDU header: type(1) + reserved(1) + length(4)
    pdu_header = struct.pack('!BBI', 0x01, 0x00, len(pdu_data))
    return pdu_header + pdu_data


def build_associate_ac(called_ae="ANY-SCP", calling_ae="PYNETDICOM",
                       abstract_syntaxes=None, transfer_syntaxes=None,
                       max_pdu_len=16384, app_context=None):
    """
    Build A-ASSOCIATE-AC PDU (type 0x02) per DICOM PS3.8 Section 9.3.3.
    Same structure as A-ASSOCIATE-RQ but with acceptance results.
    """
    if abstract_syntaxes is None:
        abstract_syntaxes = [VERIFICATION_SOP]
    if transfer_syntaxes is None:
        transfer_syntaxes = [IMPLICIT_VR_LE]

    variable_items = b''
    variable_items += build_application_context_item(app_context)

    # Presentation Context results (accept all)
    for i, _ in enumerate(abstract_syntaxes if isinstance(abstract_syntaxes, list) else [abstract_syntaxes]):
        ctx_id = 2 * i + 1
        ts = transfer_syntaxes[0] if isinstance(transfer_syntaxes, list) else transfer_syntaxes
        variable_items += build_presentation_context_ac(ctx_id, 0, ts)  # 0 = accept

    variable_items += build_user_info_item(max_pdu_len)

    protocol_version = 0x0001
    called = _pad_ae_title(called_ae)
    calling = _pad_ae_title(calling_ae)
    reserved_32 = b'\x00' * 32

    pdu_data = struct.pack('!HH', protocol_version, 0x0000) + \
               called + calling + reserved_32 + variable_items

    pdu_header = struct.pack('!BBI', 0x02, 0x00, len(pdu_data))
    return pdu_header + pdu_data


def build_associate_rj(result=1, source=1, reason=1):
    """
    Build A-ASSOCIATE-RJ PDU (type 0x03).
    Fixed 10 bytes: type(1) + reserved(1) + length(4) + reserved(1) + result(1) + source(1) + reason(1)
    """
    return struct.pack('!BBIBBB B', 0x03, 0x00, 4, 0x00, result, source, reason)


def build_pdata_tf(pdv_context_id=1, pdv_flags=0x03, command_data=None, dataset_data=None):
    """
    Build P-DATA-TF PDU (type 0x04) per DICOM PS3.8 Section 9.3.5.

    Each P-DATA-TF contains one or more PDV items:
      PDV length (4) + presentation context ID (1) + message control header (1) + data

    pdv_flags (Message Control Header):
      bit 0: 0=command, 1=dataset
      bit 1: 0=not last, 1=last fragment
      So: 0x01=dataset-not-last, 0x02=command-last, 0x03=dataset-last
    """
    pdv_items = b''

    if command_data is not None:
        # Command PDV (flags: 0x03 = command + last fragment)
        pdv_payload = struct.pack('!BB', pdv_context_id, 0x03) + command_data
        pdv_items += struct.pack('!I', len(pdv_payload)) + pdv_payload

    if dataset_data is not None:
        # Dataset PDV
        pdv_payload = struct.pack('!BB', pdv_context_id, pdv_flags) + dataset_data
        pdv_items += struct.pack('!I', len(pdv_payload)) + pdv_payload

    if not pdv_items:
        # Generate minimal command (C-ECHO-RQ)
        cmd = _build_cecho_rq()
        pdv_payload = struct.pack('!BB', pdv_context_id, 0x03) + cmd
        pdv_items = struct.pack('!I', len(pdv_payload)) + pdv_payload

    pdu_header = struct.pack('!BBI', 0x04, 0x00, len(pdv_items))
    return pdu_header + pdv_items


def build_cfind_rq(pdv_context_id=1, patient_name="*", patient_id=None):
    """Build P-DATA-TF containing a C-FIND-RQ command + query dataset."""
    # C-FIND-RQ command (Implicit VR LE)
    cmd_elements = b''
    # (0000,0002) Affected SOP Class UID
    affected_uid = VERIFICATION_SOP.encode('ascii')
    if len(affected_uid) % 2:
        affected_uid += b'\x00'
    cmd_elements += _dicom_element(0x0000, 0x0002, affected_uid)
    # (0000,0100) Command Field = 0x0020 (C-FIND-RQ)
    cmd_elements += _dicom_element(0x0000, 0x0100, struct.pack('<H', 0x0020))
    # (0000,0110) Message ID
    cmd_elements += _dicom_element(0x0000, 0x0110, struct.pack('<H', 1))
    # (0000,0800) Command Data Set Type = 0x0001 (has dataset)
    cmd_elements += _dicom_element(0x0000, 0x0800, struct.pack('<H', 0x0001))
    # (0000,0000) Command Group Length
    group_len = struct.pack('<I', len(cmd_elements))
    cmd_data = _dicom_element(0x0000, 0x0000, group_len) + cmd_elements

    # Query dataset
    ds_elements = b''
    # (0010,0010) Patient's Name
    pn_val = patient_name.encode('ascii', errors='replace')
    if len(pn_val) % 2:
        pn_val += b' '
    ds_elements += _dicom_element(0x0010, 0x0010, pn_val)
    # (0010,0020) Patient ID
    if patient_id:
        pid_val = patient_id.encode('ascii', errors='replace')
        if len(pid_val) % 2:
            pid_val += b' '
        ds_elements += _dicom_element(0x0010, 0x0020, pid_val)

    # Build command PDV
    cmd_pdv = struct.pack('!BB', pdv_context_id, 0x03) + cmd_data
    # Build dataset PDV
    ds_pdv = struct.pack('!BB', pdv_context_id, 0x02) + ds_elements

    pdv_items = struct.pack('!I', len(cmd_pdv)) + cmd_pdv + \
                struct.pack('!I', len(ds_pdv)) + ds_pdv

    pdu_header = struct.pack('!BBI', 0x04, 0x00, len(pdv_items))
    return pdu_header + pdv_items


def build_release_rq():
    """Build A-RELEASE-RQ PDU (type 0x05). Fixed 10 bytes."""
    return struct.pack('!BBI', 0x05, 0x00, 4) + b'\x00' * 4


def build_release_rp():
    """Build A-RELEASE-RP PDU (type 0x06). Fixed 10 bytes."""
    return struct.pack('!BBI', 0x06, 0x00, 4) + b'\x00' * 4


def build_abort(source=0, reason=0):
    """
    Build A-ABORT PDU (type 0x07). Fixed 10 bytes.
    source: 0=UL service user, 2=UL service provider
    reason: 0-6 (only meaningful when source=2)
    """
    return struct.pack('!BBI', 0x07, 0x00, 4) + struct.pack('!BBBB', 0x00, 0x00, source, reason)


def _build_cecho_rq():
    """Build a minimal C-ECHO-RQ DIMSE command (Implicit VR Little Endian)."""
    elements = b''
    # (0000,0002) Affected SOP Class UID = Verification SOP Class
    uid_val = VERIFICATION_SOP.encode('ascii')
    if len(uid_val) % 2:
        uid_val += b'\x00'
    elements += _dicom_element(0x0000, 0x0002, uid_val)
    # (0000,0100) Command Field = 0x0030 (C-ECHO-RQ)
    elements += _dicom_element(0x0000, 0x0100, struct.pack('<H', 0x0030))
    # (0000,0110) Message ID = 1
    elements += _dicom_element(0x0000, 0x0110, struct.pack('<H', 1))
    # (0000,0800) Command Data Set Type = 0x0101 (no dataset)
    elements += _dicom_element(0x0000, 0x0800, struct.pack('<H', 0x0101))

    # Prepend group length
    group_len = struct.pack('<I', len(elements))
    return _dicom_element(0x0000, 0x0000, group_len) + elements


def _build_cecho_rsp():
    """Build a minimal C-ECHO-RSP DIMSE command."""
    elements = b''
    uid_val = VERIFICATION_SOP.encode('ascii')
    if len(uid_val) % 2:
        uid_val += b'\x00'
    elements += _dicom_element(0x0000, 0x0002, uid_val)
    # Command Field = 0x8030 (C-ECHO-RSP)
    elements += _dicom_element(0x0000, 0x0100, struct.pack('<H', 0x8030))
    # Message ID Being Responded To
    elements += _dicom_element(0x0000, 0x0120, struct.pack('<H', 1))
    # Command Data Set Type = 0x0101 (no dataset)
    elements += _dicom_element(0x0000, 0x0800, struct.pack('<H', 0x0101))
    # Status = 0x0000 (Success)
    elements += _dicom_element(0x0000, 0x0900, struct.pack('<H', 0x0000))

    group_len = struct.pack('<I', len(elements))
    return _dicom_element(0x0000, 0x0000, group_len) + elements


def _dicom_element(group, element, value):
    """Encode a single DICOM data element in Implicit VR Little Endian."""
    return struct.pack('<HHI', group, element, len(value)) + value


def _build_cstore_rq(abstract_syntax, patient_name=None, dataset_tags=None):
    """Build a C-STORE-RQ command + dataset."""
    # Command
    elements = b''
    uid_val = abstract_syntax.encode('ascii', errors='replace')
    if len(uid_val) % 2:
        uid_val += b'\x00'
    elements += _dicom_element(0x0000, 0x0002, uid_val)
    # Command Field = 0x0001 (C-STORE-RQ)
    elements += _dicom_element(0x0000, 0x0100, struct.pack('<H', 0x0001))
    elements += _dicom_element(0x0000, 0x0110, struct.pack('<H', 1))
    # Affected SOP Instance UID
    inst_uid = f"1.2.3.4.5.{random.randint(1000,9999)}.{random.randint(1,100)}"
    inst_val = inst_uid.encode('ascii')
    if len(inst_val) % 2:
        inst_val += b'\x00'
    elements += _dicom_element(0x0000, 0x1000, inst_val)
    # Command Data Set Type = 0x0001 (has dataset)
    elements += _dicom_element(0x0000, 0x0800, struct.pack('<H', 0x0001))

    group_len = struct.pack('<I', len(elements))
    cmd_data = _dicom_element(0x0000, 0x0000, group_len) + elements

    # Dataset
    ds = b''
    if patient_name:
        pn = patient_name.encode('latin-1', errors='replace')
        if len(pn) % 2:
            pn += b' '
        ds += _dicom_element(0x0010, 0x0010, pn)

    if dataset_tags:
        for tag, value in dataset_tags.items():
            g, e = tag
            if isinstance(value, bytes):
                val = value
            elif isinstance(value, int):
                val = struct.pack('<H', value & 0xFFFF)
            else:
                val = str(value).encode('latin-1', errors='replace')
            if len(val) % 2:
                val += b'\x00'
            ds += _dicom_element(g, e, val)

    return cmd_data, ds


# =============================================================================
# Session Builder
# =============================================================================

def build_session_pdus(params):
    """
    Build a complete DICOM session as a list of raw PDU bytes,
    based on session parameters from the synthetic CSV.

    Args:
        params: dict with session parameters (one row from synthetic CSV)

    Returns:
        list of bytes objects, each being one DICOM PDU
    """
    pdus = []

    # Parse parameters
    called_ae = str(params.get("called_ae", "ANY-SCP"))
    calling_ae = str(params.get("calling_ae", "PYNETDICOM"))
    abstract_syntax = str(params.get("abstract_syntax", VERIFICATION_SOP))
    transfer_syntax = str(params.get("transfer_syntax", IMPLICIT_VR_LE))
    max_pdu_len = int(params.get("max_pdu_len", 16384))
    attack_type = str(params.get("attack_type", ""))
    patient_name = str(params.get("patient_name", ""))

    # Extract abstract syntax UID from display string if needed
    abstract_syntax = _extract_uid(abstract_syntax)
    transfer_syntax = _extract_uid(transfer_syntax)

    abstract_syntaxes = [abstract_syntax]
    transfer_syntaxes = [transfer_syntax]

    # App context override for CVE payloads
    app_context = params.get("app_context", None)
    if app_context and str(app_context) not in ("", "nan"):
        app_context = str(app_context)
    else:
        app_context = None

    # Parse PDU sequence
    pdu_seq_str = str(params.get("pdu_sequence", "assoc_rq,assoc_ac,pdata,release_rq,release_rp"))
    pdu_sequence = [s.strip() for s in pdu_seq_str.split(",") if s.strip()]

    # PDU length override for length attacks
    pdu_len_override = params.get("pdu_len_override", None)

    # Abort parameters
    abort_source = int(params.get("abort_source", 0))
    abort_reason = int(params.get("abort_reason", 0))

    # Build each PDU in sequence
    for pdu_name in pdu_sequence:
        pdu_bytes = _build_single_pdu(
            pdu_name, called_ae, calling_ae, abstract_syntaxes, transfer_syntaxes,
            max_pdu_len, app_context, patient_name, attack_type, params,
            abort_source, abort_reason,
        )
        if pdu_bytes:
            if pdu_len_override is not None and pdu_name in ("assoc_rq", "pdata"):
                pdu_bytes = _override_pdu_length(pdu_bytes, int(pdu_len_override))
            pdus.append(pdu_bytes)

    return pdus


def _build_single_pdu(pdu_name, called_ae, calling_ae, abstract_syntaxes,
                      transfer_syntaxes, max_pdu_len, app_context,
                      patient_name, attack_type, params,
                      abort_source, abort_reason):
    """Build a single PDU by name."""
    if pdu_name == "assoc_rq":
        return build_associate_rq(called_ae, calling_ae, abstract_syntaxes,
                                  transfer_syntaxes, max_pdu_len, app_context)
    elif pdu_name == "assoc_ac":
        return build_associate_ac(called_ae, calling_ae, abstract_syntaxes,
                                  transfer_syntaxes, max_pdu_len, app_context)
    elif pdu_name == "assoc_rj":
        return build_associate_rj()
    elif pdu_name == "pdata":
        return _build_pdata_for_attack(abstract_syntaxes[0], patient_name,
                                       attack_type, params)
    elif pdu_name == "cfind_rq":
        pid = params.get("patient_id", None)
        if pid and str(pid) not in ("", "nan"):
            pid = str(pid)
        else:
            pid = None
        return build_cfind_rq(1, patient_name or "*", pid)
    elif pdu_name == "release_rq":
        return build_release_rq()
    elif pdu_name == "release_rp":
        return build_release_rp()
    elif pdu_name == "abort":
        return build_abort(abort_source, abort_reason)
    else:
        logger.warning(f"Unknown PDU name: {pdu_name}")
        return None


def _build_pdata_for_attack(abstract_syntax, patient_name, attack_type, params):
    """Build P-DATA-TF PDU appropriate for the attack type."""
    if attack_type in ("patient_data_injection", "imaging_manipulation"):
        # Build C-STORE-RQ with patient data or imaging parameters
        dataset_tags = {}
        if attack_type == "imaging_manipulation":
            wc = params.get("window_center", None)
            ww = params.get("window_width", None)
            if wc is not None and str(wc) not in ("", "nan"):
                dataset_tags[(0x0028, 0x1050)] = str(int(float(wc)))
            if ww is not None and str(ww) not in ("", "nan"):
                dataset_tags[(0x0028, 0x1051)] = str(int(float(ww)))

        cmd_data, ds_data = _build_cstore_rq(
            abstract_syntax, patient_name if patient_name else None, dataset_tags or None
        )
        return build_pdata_tf(1, 0x02, cmd_data, ds_data if ds_data else None)
    else:
        # Default: C-ECHO
        return build_pdata_tf(1, 0x03)


def _override_pdu_length(pdu_bytes, new_length):
    """Override the PDU length field (bytes 2-5) with a custom value."""
    if len(pdu_bytes) < 6:
        return pdu_bytes
    return pdu_bytes[:2] + struct.pack('!I', new_length) + pdu_bytes[6:]


def _extract_uid(value):
    """Extract a UID from a display string like 'Name (1.2.3.4.5)'."""
    if '(' in value and ')' in value:
        start = value.rfind('(') + 1
        end = value.rfind(')')
        return value[start:end]
    return value


# =============================================================================
# TCP/IP Wrapping
# =============================================================================

def wrap_tcp_ip(pdu_list, src_ip=DEFAULT_SRC_IP, dst_ip=DEFAULT_DST_IP,
                src_port=DEFAULT_SRC_PORT, dst_port=DEFAULT_DST_PORT):
    """
    Wrap a list of DICOM PDU byte sequences in TCP/IP packets using scapy.
    Builds a proper TCP handshake, data transfer, and teardown.

    Returns a list of scapy packets ready for wrpcap.
    """
    packets = []
    seq_client = 1000
    seq_server = 2000

    # Ethernet layer (required by MMT-DPI for protocol detection)
    ether_c2s = Ether(src="00:11:22:33:44:55", dst="00:66:77:88:99:aa")
    ether_s2c = Ether(src="00:66:77:88:99:aa", dst="00:11:22:33:44:55")

    # TCP 3-way handshake
    syn = ether_c2s / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=src_port, dport=dst_port,
        flags='S', seq=seq_client
    )
    packets.append(syn)
    seq_client += 1

    syn_ack = ether_s2c / IP(src=dst_ip, dst=src_ip) / TCP(
        sport=dst_port, dport=src_port,
        flags='SA', seq=seq_server, ack=seq_client
    )
    packets.append(syn_ack)
    seq_server += 1

    ack = ether_c2s / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=src_port, dport=dst_port,
        flags='A', seq=seq_client, ack=seq_server
    )
    packets.append(ack)

    # Send PDUs alternating client/server
    is_client = True  # first PDU is from client (A-ASSOCIATE-RQ)
    for pdu_bytes in pdu_list:
        if is_client:
            pkt = ether_c2s / IP(src=src_ip, dst=dst_ip) / TCP(
                sport=src_port, dport=dst_port,
                flags='PA', seq=seq_client, ack=seq_server
            ) / Raw(load=pdu_bytes)
            seq_client += len(pdu_bytes)
        else:
            pkt = ether_s2c / IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dst_port, dport=src_port,
                flags='PA', seq=seq_server, ack=seq_client
            ) / Raw(load=pdu_bytes)
            seq_server += len(pdu_bytes)

        packets.append(pkt)

        # ACK from the other side
        if is_client:
            ack_pkt = ether_s2c / IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dst_port, dport=src_port,
                flags='A', seq=seq_server, ack=seq_client
            )
        else:
            ack_pkt = ether_c2s / IP(src=src_ip, dst=dst_ip) / TCP(
                sport=src_port, dport=dst_port,
                flags='A', seq=seq_client, ack=seq_server
            )
        packets.append(ack_pkt)
        is_client = not is_client

    # TCP teardown (FIN)
    fin = ether_c2s / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=src_port, dport=dst_port,
        flags='FA', seq=seq_client, ack=seq_server
    )
    packets.append(fin)
    seq_client += 1

    fin_ack = ether_s2c / IP(src=dst_ip, dst=src_ip) / TCP(
        sport=dst_port, dport=src_port,
        flags='FA', seq=seq_server, ack=seq_client
    )
    packets.append(fin_ack)
    seq_server += 1

    last_ack = ether_c2s / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=src_port, dport=dst_port,
        flags='A', seq=seq_client, ack=seq_server
    )
    packets.append(last_ack)

    return packets


# =============================================================================
# Malformation Mutations
# =============================================================================

def apply_malformations(packets, mutations=None):
    """
    Apply malformation mutations to a list of scapy packets.
    Randomly selects and applies mutations from MALFORMATION_MUTATIONS.
    """
    if mutations is None:
        # Select 1-3 random mutations
        available = list(MALFORMATION_MUTATIONS.keys())
        n_mutations = random.randint(1, min(3, len(available)))
        mutations = random.sample(available, n_mutations)

    logger.info(f"Applying malformations: {mutations}")

    for mutation_name in mutations:
        mutation = MALFORMATION_MUTATIONS.get(mutation_name)
        if not mutation:
            continue

        if mutation_name == "truncate_mid_pdu":
            packets = _mutate_truncate(packets, mutation)
        elif mutation_name == "reserved_bytes_nonzero":
            packets = _mutate_reserved_bytes(packets, mutation)
        elif mutation_name == "random_byte_insertion":
            packets = _mutate_insert_bytes(packets, mutation)
        elif mutation_name == "pdu_reorder":
            packets = _mutate_reorder(packets, mutation)
        elif mutation_name == "length_mismatch":
            packets = _mutate_length_mismatch(packets, mutation)
        elif mutation_name == "pdu_type_invalid":
            packets = _mutate_pdu_type(packets, mutation)
        elif mutation_name == "item_type_invalid":
            packets = _mutate_item_type(packets, mutation)

    return packets


def _get_data_packets(packets):
    """Return indices of packets that contain Raw payload (DICOM data)."""
    return [i for i, pkt in enumerate(packets) if Raw in pkt]


def _mutate_truncate(packets, mutation):
    """Truncate a random data packet's payload."""
    data_idxs = _get_data_packets(packets)
    if not data_idxs:
        return packets
    idx = random.choice(data_idxs)
    ratio = random.choice(mutation.get("truncate_ratios", [0.5]))
    raw = packets[idx][Raw].load
    new_len = max(1, int(len(raw) * ratio))
    packets[idx][Raw].load = raw[:new_len]
    return packets


def _mutate_reserved_bytes(packets, mutation):
    """Set reserved bytes to non-zero in DICOM PDU headers."""
    data_idxs = _get_data_packets(packets)
    if not data_idxs:
        return packets
    idx = random.choice(data_idxs)
    raw = bytearray(packets[idx][Raw].load)
    byte_val = random.choice(mutation.get("byte_values", [0xFF]))
    # Byte 1 is reserved in all DICOM PDUs
    if len(raw) > 1:
        raw[1] = byte_val
    packets[idx][Raw].load = bytes(raw)
    return packets


def _mutate_insert_bytes(packets, mutation):
    """Insert random bytes into a data packet payload."""
    data_idxs = _get_data_packets(packets)
    if not data_idxs:
        return packets
    idx = random.choice(data_idxs)
    raw = packets[idx][Raw].load
    insert_size = random.choice(mutation.get("insertion_sizes", [4]))
    insert_pos = random.randint(0, max(0, len(raw) - 1))
    insert_data = bytes(random.getrandbits(8) for _ in range(insert_size))
    packets[idx][Raw].load = raw[:insert_pos] + insert_data + raw[insert_pos:]
    return packets


def _mutate_reorder(packets, mutation):
    """Reorder data packets (not TCP handshake/teardown)."""
    data_idxs = _get_data_packets(packets)
    if len(data_idxs) < 2:
        return packets
    strategy = random.choice(mutation.get("strategies", ["shuffle"]))

    data_pkts = [packets[i] for i in data_idxs]
    if strategy == "reverse":
        data_pkts.reverse()
    elif strategy == "shuffle":
        random.shuffle(data_pkts)
    elif strategy == "duplicate_first":
        data_pkts.insert(1, data_pkts[0])
    elif strategy == "duplicate_last":
        data_pkts.append(data_pkts[-1])

    # Replace data packets in order
    result = list(packets)
    for j, orig_idx in enumerate(data_idxs):
        if j < len(data_pkts):
            result[orig_idx] = data_pkts[j]
    # Handle extra packets from duplication
    if len(data_pkts) > len(data_idxs):
        for extra in data_pkts[len(data_idxs):]:
            # Insert before teardown (last 3 packets)
            result.insert(max(0, len(result) - 3), extra)
    return result


def _mutate_length_mismatch(packets, mutation):
    """Set PDU length to mismatch actual data length."""
    data_idxs = _get_data_packets(packets)
    if not data_idxs:
        return packets
    idx = random.choice(data_idxs)
    raw = bytearray(packets[idx][Raw].load)
    if len(raw) < 6:
        return packets

    strategy = random.choice(mutation.get("strategies", ["zero"]))
    if strategy == "shorter_by_10":
        actual_len = struct.unpack('!I', bytes(raw[2:6]))[0]
        new_len = max(0, actual_len - 10)
    elif strategy == "longer_by_100":
        actual_len = struct.unpack('!I', bytes(raw[2:6]))[0]
        new_len = actual_len + 100
    elif strategy == "zero":
        new_len = 0
    elif strategy == "max_uint32":
        new_len = 0xFFFFFFFF
    else:
        return packets

    raw[2:6] = struct.pack('!I', new_len)
    packets[idx][Raw].load = bytes(raw)
    return packets


def _mutate_pdu_type(packets, mutation):
    """Set PDU type byte to invalid value."""
    data_idxs = _get_data_packets(packets)
    if not data_idxs:
        return packets
    idx = random.choice(data_idxs)
    raw = bytearray(packets[idx][Raw].load)
    if len(raw) > 0:
        raw[0] = random.choice(mutation.get("invalid_types", [0xFF]))
    packets[idx][Raw].load = bytes(raw)
    return packets


def _mutate_item_type(packets, mutation):
    """Set association item type bytes to invalid values in assoc PDUs."""
    data_idxs = _get_data_packets(packets)
    if not data_idxs:
        return packets
    # Find an association PDU (type 0x01 or 0x02)
    for idx in data_idxs:
        raw = bytearray(packets[idx][Raw].load)
        if len(raw) > 74 and raw[0] in (0x01, 0x02):
            # Variable items start at offset 74 in A-ASSOCIATE PDUs
            pos = 74
            if pos < len(raw):
                raw[pos] = random.choice(mutation.get("invalid_item_types", [0xFF]))
                packets[idx][Raw].load = bytes(raw)
            break
    return packets


# =============================================================================
# PCAP Generation
# =============================================================================

def generate_pcap(synthetic_csv, output_dir, attack_type=None, malformed=False,
                  num_flows=None):
    """
    Main entry point: read synthetic CSV, generate PCAPs.

    Args:
        synthetic_csv: Path to CSV with session parameters
        output_dir: Directory to write PCAP files
        attack_type: Optional attack type for profile-specific behavior
        malformed: If True, apply malformation mutations
        num_flows: Max number of flows to generate (None = all)
    """
    os.makedirs(output_dir, exist_ok=True)

    logger.info(f"Loading synthetic data from {synthetic_csv}")
    df = pd.read_csv(synthetic_csv)
    logger.info(f"Loaded {len(df)} sessions")

    if num_flows and num_flows < len(df):
        df = df.sample(num_flows)
        logger.info(f"Selected {num_flows} sessions")

    success_count = 0
    error_count = 0

    for idx, row in df.iterrows():
        try:
            params = row.to_dict()
            session_id = params.get("session_id", idx)

            # Generate randomized network parameters per session
            src_port = random.randint(49152, 65535)

            # Build DICOM PDUs
            pdus = build_session_pdus(params)
            if not pdus:
                logger.warning(f"Session {session_id}: no PDUs generated, skipping")
                continue

            # Wrap in TCP/IP
            packets = wrap_tcp_ip(pdus, src_port=src_port)

            # Apply malformations if requested
            if malformed:
                packets = apply_malformations(packets)

            # Write PCAP
            at = params.get("attack_type", attack_type or "")
            if at and str(at) not in ("", "nan"):
                filename = f"{at}_session_{session_id}.pcap"
            else:
                filename = f"session_{session_id}.pcap"
            output_file = os.path.join(output_dir, filename)
            wrpcap(output_file, packets)
            success_count += 1

        except Exception as e:
            logger.error(f"Error generating PCAP for session {idx}: {e}")
            error_count += 1
            continue

    logger.info(f"Generated {success_count} PCAPs, {error_count} errors in {output_dir}")
    return success_count, error_count


def main():
    parser = argparse.ArgumentParser(
        description="Generate DICOM session PCAPs from synthetic CSV data")
    parser.add_argument("synthetic_csv",
                        help="Path to synthetic CSV with session parameters")
    parser.add_argument("output_dir",
                        help="Directory to save PCAP files")
    parser.add_argument("--attack-type", type=str, default=None,
                        help="Attack profile name")
    parser.add_argument("--malformed", action="store_true",
                        help="Apply malformation mutations to generated packets")
    parser.add_argument("--num-flows", type=int, default=None,
                        help="Maximum number of flows to generate")

    args = parser.parse_args()

    print("\n" + "=" * 80)
    print("DICOM SESSION PCAP GENERATOR")
    if args.attack_type:
        print(f"Attack Type: {args.attack_type}")
    if args.malformed:
        print("Mode: MALFORMED")
    print("=" * 80 + "\n")

    success, errors = generate_pcap(
        args.synthetic_csv, args.output_dir,
        attack_type=args.attack_type,
        malformed=args.malformed,
        num_flows=args.num_flows,
    )

    print(f"\nDone: {success} PCAPs generated, {errors} errors")
    print(f"Output: {args.output_dir}\n")


if __name__ == "__main__":
    main()
