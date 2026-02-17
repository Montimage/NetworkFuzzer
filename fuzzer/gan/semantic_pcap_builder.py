#!/usr/bin/env python3
"""
Protocol-Aware PDU Construction for Smart GAN Pipeline.

Converts SessionPlans into valid DICOM PDU byte sequences using the proven
builders from dicom_semantics.py and pcap_utils.py. Payloads are injected
at the plan-specified injection target *before* length calculation, so PDU
length fields are always structurally correct.

Key functions:
  - build_session_from_plan(plan) -> List[bytes]
  - plans_to_pcap(plans, output_dir) -> (success_count, error_count)
  - validate_pdu(pdu_bytes) -> dict
"""

import os
import struct
import random
import logging
from datetime import datetime
from typing import List, Tuple, Dict, Optional

from scapy.all import wrpcap

from fuzzer.common.pcap_utils import wrap_tcp_ip, build_release_rq, build_release_rp
from fuzzer.rl.hybrid_env import (
    SEMANTIC_FIELDS,
    PAYLOAD_TYPES,
    INJECTION_TARGETS,
    STATE_SEQUENCES,
)
from fuzzer.rl.dicom_semantics import (
    build_smart_assoc_rq,
    build_smart_cecho_pdata,
    build_multi_context_assoc_rq,
    build_malformed_dimse_pdata,
    STORAGE_SOP_CLASSES,
    TRANSFER_SYNTAXES,
)
from fuzzer.gan.session_planner import SessionPlan

logger = logging.getLogger(__name__)


# ============================================================================
# PDU Builders (thin wrappers around dicom_semantics builders)
# ============================================================================

def _clamp_max_pdu(value):
    """Clamp max_pdu_length to valid range for struct.pack('>I')."""
    if value < 0:
        return 0
    if value > 0xFFFFFFFF:
        return 0xFFFFFFFF
    return value


def _build_assoc_rq(plan, payloads):
    """Build A-ASSOCIATE-RQ from plan with optional payload injection."""
    called_ae = payloads.get("called_ae", b"ORTHANC")
    calling_ae = payloads.get("calling_ae", b"FUZZER")
    abstract_syntax = payloads.get("abstract_syntax")
    transfer_syntax = payloads.get("transfer_syntax")

    return build_smart_assoc_rq(
        called_ae=called_ae,
        calling_ae=calling_ae,
        max_pdu_length=_clamp_max_pdu(plan.max_pdu_length),
        abstract_syntax=abstract_syntax,
        transfer_syntax=transfer_syntax,
    )


def _build_multi_context_assoc_rq(plan, payloads, sop_key="ct", xfer_key="implicit_vr_le"):
    """Build multi-context ASSOC_RQ for C-STORE/C-FIND/C-MOVE."""
    called_ae = payloads.get("called_ae", b"ORTHANC")
    calling_ae = payloads.get("calling_ae", b"FUZZER")

    sop_uid = STORAGE_SOP_CLASSES.get(sop_key, STORAGE_SOP_CLASSES["ct"])
    xfer = TRANSFER_SYNTAXES.get(xfer_key, TRANSFER_SYNTAXES["implicit_vr_le"])

    contexts = [
        (STORAGE_SOP_CLASSES["verification"], [TRANSFER_SYNTAXES["implicit_vr_le"]]),
        (sop_uid, [xfer]),
    ]

    # Inject abstract_syntax payload into an extra context
    abstract = payloads.get("abstract_syntax")
    if abstract:
        if isinstance(abstract, str):
            abstract = abstract.encode()
        contexts.append((abstract, [xfer]))

    return build_multi_context_assoc_rq(
        presentation_contexts=contexts,
        called_ae=called_ae,
        calling_ae=calling_ae,
        max_pdu_length=_clamp_max_pdu(plan.max_pdu_length),
    )


def _build_pdata(plan, fields):
    """Build PDATA (C-ECHO) with semantic field mutations."""
    return build_smart_cecho_pdata(
        context_id=fields.get("context_id"),
        msg_control=fields.get("msg_control"),
        command_field=fields.get("command_field"),
        message_id=fields.get("message_id"),
        data_set_type=fields.get("data_set_type"),
    )


def _build_cstore_pdata(plan, fields):
    """Build C-STORE-RQ PDATA with minimal dataset."""
    ctx_id = fields.get("context_id", 3)  # Context 3 for storage SOP class
    msg_id = fields.get("message_id", 1)

    sop_class = b'1.2.840.10008.5.1.4.1.1.2'  # CT Image Storage
    if len(sop_class) % 2:
        sop_class += b'\x00'
    sop_instance = b'1.2.3.4.5.6.7.8.9.0'
    if len(sop_instance) % 2:
        sop_instance += b'\x00'

    # Command set
    elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class)) + sop_class
    elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0001)  # C-STORE-RQ
    elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)
    elem_0700 = struct.pack('<HH I H', 0x0000, 0x0700, 2, 0)       # Priority medium
    elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0000)  # Dataset present
    elem_1000 = struct.pack('<HH I', 0x0000, 0x1000, len(sop_instance)) + sop_instance

    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0700 + elem_0800 + elem_1000
    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set

    # Command PDV
    cmd_pdv = struct.pack('>BB', ctx_id, 0x01) + command_set
    cmd_pdv_item = struct.pack('>I', len(cmd_pdv)) + cmd_pdv

    # Minimal dataset
    patient_name = b"FUZZPATIENT"
    if len(patient_name) % 2:
        patient_name += b' '
    ds_0010_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
    ds_0008_0018 = struct.pack('<HH I', 0x0008, 0x0018, len(sop_instance)) + sop_instance
    dataset = ds_0010_0010 + ds_0008_0018

    # Data PDV
    data_pdv = struct.pack('>BB', ctx_id, 0x02) + dataset
    data_pdv_item = struct.pack('>I', len(data_pdv)) + data_pdv

    pdu_data = cmd_pdv_item + data_pdv_item
    return struct.pack('>BBi', 0x04, 0, len(pdu_data)) + pdu_data


def _build_cfind_pdata(fields):
    """Build C-FIND-RQ PDATA."""
    ctx_id = fields.get("context_id", 3)
    msg_id = fields.get("message_id", 1)

    sop_class = STORAGE_SOP_CLASSES["patient_root_qr_find"]
    if len(sop_class) % 2:
        sop_class += b'\x00'

    elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class)) + sop_class
    elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0020)  # C-FIND-RQ
    elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)
    elem_0700 = struct.pack('<HH I H', 0x0000, 0x0700, 2, 0)
    elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0000)  # Dataset present

    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0700 + elem_0800
    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set

    cmd_pdv = struct.pack('>BB', ctx_id, 0x01) + command_set
    cmd_pdv_item = struct.pack('>I', len(cmd_pdv)) + cmd_pdv

    # Query dataset: patient name wildcard
    patient_name = b'*'
    if len(patient_name) % 2:
        patient_name += b' '
    ds_0010_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
    ds_0008_0052 = struct.pack('<HH I', 0x0008, 0x0052, 8) + b'PATIENT '  # Query level
    dataset = ds_0008_0052 + ds_0010_0010

    data_pdv = struct.pack('>BB', ctx_id, 0x02) + dataset
    data_pdv_item = struct.pack('>I', len(data_pdv)) + data_pdv

    pdu_data = cmd_pdv_item + data_pdv_item
    return struct.pack('>BBi', 0x04, 0, len(pdu_data)) + pdu_data


def _build_cmove_pdata(fields):
    """Build C-MOVE-RQ PDATA."""
    ctx_id = fields.get("context_id", 3)
    msg_id = fields.get("message_id", 1)

    sop_class = STORAGE_SOP_CLASSES["patient_root_qr_move"]
    if len(sop_class) % 2:
        sop_class += b'\x00'

    elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class)) + sop_class
    elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0021)  # C-MOVE-RQ
    elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)
    elem_0700 = struct.pack('<HH I H', 0x0000, 0x0700, 2, 0)
    elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0000)
    # Move destination (0000,0600)
    dest_ae = b'FUZZER          '[:16]
    elem_0600 = struct.pack('<HH I', 0x0000, 0x0600, len(dest_ae)) + dest_ae

    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0600 + elem_0700 + elem_0800
    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set

    cmd_pdv = struct.pack('>BB', ctx_id, 0x01) + command_set
    cmd_pdv_item = struct.pack('>I', len(cmd_pdv)) + cmd_pdv

    # Query dataset
    ds_0008_0052 = struct.pack('<HH I', 0x0008, 0x0052, 8) + b'PATIENT '
    patient_name = b'*'
    if len(patient_name) % 2:
        patient_name += b' '
    ds_0010_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
    dataset = ds_0008_0052 + ds_0010_0010

    data_pdv = struct.pack('>BB', ctx_id, 0x02) + dataset
    data_pdv_item = struct.pack('>I', len(data_pdv)) + data_pdv

    pdu_data = cmd_pdv_item + data_pdv_item
    return struct.pack('>BBi', 0x04, 0, len(pdu_data)) + pdu_data


def _build_cget_pdata(fields):
    """Build C-GET-RQ PDATA."""
    ctx_id = fields.get("context_id", 3)
    msg_id = fields.get("message_id", 1)

    sop_class = STORAGE_SOP_CLASSES["patient_root_qr_get"]
    if len(sop_class) % 2:
        sop_class += b'\x00'

    elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class)) + sop_class
    elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0010)  # C-GET-RQ
    elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)
    elem_0700 = struct.pack('<HH I H', 0x0000, 0x0700, 2, 0)
    elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0000)

    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0700 + elem_0800
    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set

    cmd_pdv = struct.pack('>BB', ctx_id, 0x01) + command_set
    cmd_pdv_item = struct.pack('>I', len(cmd_pdv)) + cmd_pdv

    ds_0008_0052 = struct.pack('<HH I', 0x0008, 0x0052, 8) + b'PATIENT '
    patient_name = b'*'
    if len(patient_name) % 2:
        patient_name += b' '
    ds_0010_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
    dataset = ds_0008_0052 + ds_0010_0010

    data_pdv = struct.pack('>BB', ctx_id, 0x02) + dataset
    data_pdv_item = struct.pack('>I', len(data_pdv)) + data_pdv

    pdu_data = cmd_pdv_item + data_pdv_item
    return struct.pack('>BBi', 0x04, 0, len(pdu_data)) + pdu_data


def _build_release_rq_pdu():
    return struct.pack('>BBi', 0x05, 0, 4) + b'\x00\x00\x00\x00'


def _build_release_rp_pdu():
    return struct.pack('>BBi', 0x06, 0, 4) + b'\x00\x00\x00\x00'


def _build_abort_pdu():
    return struct.pack('>BBi', 0x07, 0, 4) + b'\x00\x00\x00\x00'


def _build_assoc_ac_pdu():
    """Minimal A-ASSOCIATE-AC (client shouldn't send this)."""
    return struct.pack('>BBi', 0x02, 0, 4) + b'\x00\x00\x00\x00'


def _build_assoc_rj_pdu():
    """Minimal A-ASSOCIATE-RJ."""
    return struct.pack('>BBi', 0x03, 0, 4) + b'\x00\x01\x01\x01'


def _build_partial_pdu():
    """Build a truncated PDU (just the type byte + partial header)."""
    pdu_type = random.choice([0x01, 0x04])
    return struct.pack('>BB', pdu_type, 0) + b'\x00'


def _build_garbage_pdu():
    """Build random garbage bytes."""
    length = random.randint(10, 200)
    return os.urandom(length)


# ============================================================================
# Plan Resolver
# ============================================================================

def _resolve_semantic_fields(plan):
    """Resolve semantic field mutations from plan indices."""
    fields = {}
    if plan.semantic_field > 0:
        field_idx = plan.semantic_field - 1
        if field_idx < len(SEMANTIC_FIELDS):
            field_name, values = SEMANTIC_FIELDS[field_idx]
            value_idx = min(plan.semantic_value_idx, len(values) - 1)
            fields[field_name] = values[value_idx]
    return fields


def _resolve_payloads(plan):
    """Resolve payload injection from plan indices."""
    payloads = {}
    if plan.payload_type > 0 and plan.injection_target > 0:
        pay_idx = plan.payload_type - 1
        tgt_idx = plan.injection_target - 1

        if pay_idx < len(PAYLOAD_TYPES) and tgt_idx < len(INJECTION_TARGETS):
            _, payload_list = PAYLOAD_TYPES[pay_idx]
            target_name = INJECTION_TARGETS[tgt_idx]
            payload = random.choice(payload_list)

            # DICOM uses nested 2-byte length fields (item → sub-item).
            # Truncate oversized payloads so wrapping structures don't overflow.
            # 32000 is safe: leaves room for sub-item headers and presentation context wrapper.
            if target_name in ("abstract_syntax", "transfer_syntax", "impl_uid"):
                if len(payload) > 32000:
                    payload = payload[:32000]

            payloads[target_name] = payload

    return payloads


# ============================================================================
# Core Builder
# ============================================================================

# Map PDU type names to SOP class keys for multi-context ASSOC_RQ
_ASSOC_RQ_SOP_MAP = {
    "assoc_rq_ct": "ct",
    "assoc_rq_mr": "mr",
    "assoc_rq_us": "us",
    "assoc_rq_sc": "sc",
    "assoc_rq_ct_explicit": "ct",
}

# PDU types that need multi-context ASSOC_RQ
_MULTI_CONTEXT_PDUS = {
    "cstore_pdata", "cstore_rich_pdata", "cstore_mr_pdata", "cstore_us_pdata",
    "cstore_sc_pdata", "cstore_explicit_pdata",
    "cfind_pdata", "cmove_pdata", "cget_pdata",
    "assoc_rq_ct", "assoc_rq_mr", "assoc_rq_us", "assoc_rq_sc",
    "assoc_rq_ct_explicit",
}


def _build_single_pdu(pdu_type, plan, fields, payloads):
    """Build a single PDU of the given type."""
    if pdu_type == "assoc_rq":
        return _build_assoc_rq(plan, payloads)
    elif pdu_type in _ASSOC_RQ_SOP_MAP:
        sop_key = _ASSOC_RQ_SOP_MAP[pdu_type]
        xfer_key = "explicit_vr_le" if "explicit" in pdu_type else "implicit_vr_le"
        return _build_multi_context_assoc_rq(plan, payloads, sop_key, xfer_key)
    elif pdu_type == "pdata":
        return _build_pdata(plan, fields)
    elif pdu_type in ("cstore_pdata", "cstore_rich_pdata", "cstore_mr_pdata",
                       "cstore_us_pdata", "cstore_sc_pdata", "cstore_explicit_pdata"):
        return _build_cstore_pdata(plan, fields)
    elif pdu_type == "cfind_pdata":
        return _build_cfind_pdata(fields)
    elif pdu_type == "cmove_pdata":
        return _build_cmove_pdata(fields)
    elif pdu_type == "cget_pdata":
        return _build_cget_pdata(fields)
    elif pdu_type == "release_rq":
        return _build_release_rq_pdu()
    elif pdu_type == "release_rp":
        return _build_release_rp_pdu()
    elif pdu_type == "abort":
        return _build_abort_pdu()
    elif pdu_type == "assoc_ac":
        return _build_assoc_ac_pdu()
    elif pdu_type == "assoc_rj":
        return _build_assoc_rj_pdu()
    elif pdu_type == "partial_pdu":
        return _build_partial_pdu()
    elif pdu_type == "garbage":
        return _build_garbage_pdu()
    else:
        # Unknown type — build as C-ECHO PDATA
        logger.debug(f"Unknown PDU type '{pdu_type}', building as pdata")
        return _build_pdata(plan, fields)


def build_session_from_plan(plan):
    """
    Build a list of raw PDU byte sequences from a SessionPlan.

    1. Look up STATE_SEQUENCES[plan.pdu_sequence] for PDU ordering
    2. Resolve semantic fields and payloads from plan indices
    3. For each PDU type, call the appropriate builder
    4. Payloads injected before length calculation → lengths always correct

    Returns:
        List[bytes]: ordered list of PDU byte sequences for the session
    """
    # Get PDU sequence
    seq_idx = min(plan.pdu_sequence, len(STATE_SEQUENCES) - 1)
    seq_name, pdu_types = STATE_SEQUENCES[seq_idx]

    if not pdu_types:
        return []

    # Resolve plan fields
    fields = _resolve_semantic_fields(plan)
    payloads = _resolve_payloads(plan)

    # Check if any PDU in sequence needs multi-context association
    needs_multi_ctx = any(pt in _MULTI_CONTEXT_PDUS for pt in pdu_types)

    # If sequence starts with assoc_rq and we need multi-context, upgrade it
    pdus = []
    for pdu_type in pdu_types:
        if pdu_type == "assoc_rq" and needs_multi_ctx:
            # Use multi-context ASSOC_RQ to support C-STORE/C-FIND/C-MOVE
            pdu = _build_multi_context_assoc_rq(plan, payloads, "ct", "implicit_vr_le")
        else:
            pdu = _build_single_pdu(pdu_type, plan, fields, payloads)
        pdus.append(pdu)

    return pdus


# ============================================================================
# Batch PCAP Generation
# ============================================================================

def plans_to_pcap(plans, output_dir, dst_port=4242):
    """
    Convert a list of SessionPlans to PCAP files.

    For each plan:
      1. build_session_from_plan() → list of PDU bytes
      2. wrap_tcp_ip() → Scapy packets
      3. wrpcap() → PCAP file

    Args:
        plans: list of SessionPlan
        output_dir: directory to write PCAP files
        dst_port: destination port for TCP wrapper

    Returns:
        (success_count, error_count)
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    success = 0
    errors = 0

    for i, plan in enumerate(plans):
        try:
            pdu_list = build_session_from_plan(plan)
            if not pdu_list:
                continue

            packets = wrap_tcp_ip(pdu_list, dst_port=dst_port)
            pcap_path = os.path.join(
                output_dir,
                f"smart_{plan.attack_category}_{timestamp}_{i:04d}.pcap"
            )
            wrpcap(pcap_path, packets)
            success += 1

        except Exception as e:
            logger.warning(f"Failed to build PCAP for plan {i}: {e}")
            errors += 1

    logger.info(f"Generated {success} PCAPs ({errors} errors) in {output_dir}")
    return success, errors


# ============================================================================
# PDU Validation
# ============================================================================

VALID_PDU_TYPES = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}


def validate_pdu(pdu_bytes):
    """
    Structural validation of a DICOM PDU.

    Checks:
      - Type byte is 0x01-0x07
      - Length field matches actual data length
      - For PDATA: context ID is odd, within 1-255
      - For ASSOC_RQ: UIDs contain only valid characters

    Returns:
        dict with 'valid' (bool), 'errors' (list), 'pdu_type' (int), 'pdu_length' (int)
    """
    result = {"valid": True, "errors": [], "pdu_type": 0, "pdu_length": 0}

    if len(pdu_bytes) < 6:
        result["valid"] = False
        result["errors"].append(f"PDU too short: {len(pdu_bytes)} bytes (min 6)")
        return result

    pdu_type = pdu_bytes[0]
    result["pdu_type"] = pdu_type

    if pdu_type not in VALID_PDU_TYPES:
        result["valid"] = False
        result["errors"].append(f"Invalid PDU type: 0x{pdu_type:02x}")

    # Parse length (bytes 2-5, big-endian)
    pdu_length = struct.unpack('>I', pdu_bytes[2:6])[0]
    result["pdu_length"] = pdu_length

    actual_data_len = len(pdu_bytes) - 6
    if pdu_length != actual_data_len:
        result["valid"] = False
        result["errors"].append(
            f"Length mismatch: header says {pdu_length}, actual data is {actual_data_len}")

    # PDATA-specific checks
    if pdu_type == 0x04 and len(pdu_bytes) >= 11:
        context_id = pdu_bytes[10]
        if context_id == 0:
            result["valid"] = False
            result["errors"].append("Context ID is 0 (invalid)")
        elif context_id % 2 == 0:
            result["errors"].append(f"Context ID {context_id} is even (should be odd)")
            # Not necessarily invalid — some servers accept it

    # ASSOC_RQ UID check
    if pdu_type == 0x01 and len(pdu_bytes) > 74:
        # Variable items start at offset 74
        _validate_assoc_rq_items(pdu_bytes[74:], result)

    return result


def _validate_assoc_rq_items(item_data, result):
    """Validate variable items in ASSOC_RQ."""
    offset = 0
    while offset + 4 <= len(item_data):
        item_type = item_data[offset]
        # reserved byte at offset+1
        item_length = struct.unpack('>H', item_data[offset+2:offset+4])[0]

        if offset + 4 + item_length > len(item_data):
            break

        # Check UID format in Application Context (0x10), Abstract Syntax (0x30),
        # Transfer Syntax (0x40)
        if item_type in (0x10, 0x30, 0x40):
            uid = item_data[offset+4:offset+4+item_length]
            if not _is_valid_uid_format(uid):
                result["errors"].append(
                    f"Item 0x{item_type:02x}: UID contains invalid characters")

        offset += 4 + item_length


def _is_valid_uid_format(uid_bytes):
    """Check if bytes look like a valid DICOM UID (digits and dots)."""
    try:
        uid_str = uid_bytes.rstrip(b'\x00').decode('ascii')
        return all(c in '0123456789.' for c in uid_str)
    except (UnicodeDecodeError, ValueError):
        return False


def validate_session(pdu_list):
    """Validate all PDUs in a session. Returns summary dict."""
    results = []
    all_valid = True
    for pdu in pdu_list:
        v = validate_pdu(pdu)
        results.append(v)
        if not v["valid"]:
            all_valid = False

    return {
        "all_valid": all_valid,
        "pdu_count": len(pdu_list),
        "results": results,
    }
