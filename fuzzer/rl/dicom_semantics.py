#!/usr/bin/env python3
"""
DICOM Semantic Constraints for Smart Fuzzing.

Instead of random mutations that get rejected immediately, this module
provides semantically-aware mutations that:
1. Pass initial protocol validation
2. Reach deeper parsing code paths
3. Exploit edge cases within valid ranges

Key insight: Servers reject obviously invalid data early. Smart fuzzing
stays within "plausible" ranges to trigger deeper bugs.
"""

import struct
import random

# ============================================================================
# DICOM Value Constraints
# ============================================================================

# PDU Types (valid range: 1-7)
PDU_TYPES = {
    0x01: "A-ASSOCIATE-RQ",
    0x02: "A-ASSOCIATE-AC",
    0x03: "A-ASSOCIATE-RJ",
    0x04: "P-DATA-TF",
    0x05: "A-RELEASE-RQ",
    0x06: "A-RELEASE-RP",
    0x07: "A-ABORT",
}

# Boundary values for PDU type (to find off-by-one bugs)
PDU_TYPE_BOUNDARIES = [0x00, 0x01, 0x07, 0x08, 0xFF]

# DIMSE Command Fields (valid values)
DIMSE_COMMANDS = {
    0x0001: "C-STORE-RQ",
    0x8001: "C-STORE-RSP",
    0x0010: "C-GET-RQ",
    0x8010: "C-GET-RSP",
    0x0020: "C-FIND-RQ",
    0x8020: "C-FIND-RSP",
    0x0021: "C-MOVE-RQ",
    0x8021: "C-MOVE-RSP",
    0x0030: "C-ECHO-RQ",
    0x8030: "C-ECHO-RSP",
    0x0FFF: "C-CANCEL-RQ",
    # N-commands
    0x0100: "N-EVENT-REPORT-RQ",
    0x8100: "N-EVENT-REPORT-RSP",
    0x0110: "N-GET-RQ",
    0x8110: "N-GET-RSP",
    0x0120: "N-SET-RQ",
    0x8120: "N-SET-RSP",
    0x0130: "N-ACTION-RQ",
    0x8130: "N-ACTION-RSP",
    0x0140: "N-CREATE-RQ",
    0x8140: "N-CREATE-RSP",
    0x0150: "N-DELETE-RQ",
    0x8150: "N-DELETE-RSP",
}

# Smart mutation values for command field (valid + boundaries)
COMMAND_FIELD_MUTATIONS = [
    # Valid commands
    0x0001, 0x0010, 0x0020, 0x0021, 0x0030, 0x0FFF,
    0x0100, 0x0110, 0x0120, 0x0130, 0x0140, 0x0150,
    # Response commands
    0x8001, 0x8010, 0x8020, 0x8021, 0x8030,
    # Boundary/edge cases
    0x0000,  # Invalid but might be processed
    0x0002,  # Between valid values
    0x00FF,  # Just below N-commands
    0x7FFF,  # Max before response bit
    0x8000,  # Response bit only
    0xFFFF,  # Max value
]

# Message ID constraints (1-65535, 0 is invalid)
MESSAGE_ID_MUTATIONS = [
    1,      # Minimum valid
    2, 3, 4, 5, 6, 7,  # Common valid values
    255,    # Byte boundary
    256,    # Just over byte boundary
    32767,  # Max signed 16-bit
    32768,  # Min unsigned > max signed
    65534,  # Almost max
    65535,  # Max valid
    0,      # Invalid - should be rejected but might not be
]

# Data Set Type (0x0101 = no dataset, 0x0102 = dataset present, others invalid)
DATA_SET_TYPE_MUTATIONS = [
    0x0101,  # Valid: no dataset
    0x0102,  # Valid: dataset present (but we don't send one)
    0x0000,  # Invalid
    0x0100,  # Invalid but close
    0x0103,  # Invalid but close
    0x01FF,  # Invalid
    0xFFFF,  # Invalid max
]

# Status values for responses
STATUS_MUTATIONS = [
    0x0000,  # Success
    0x0001,  # Cancel
    0xFF00,  # Pending
    0xFF01,  # Pending with warning
    0xFE00,  # Cancel
    0xA700,  # Out of resources
    0xA900,  # Dataset does not match SOP class
    0xC000,  # Unable to process
    0xB000,  # Warning
    # Edge cases
    0xFFFF,
    0x0100,
    0x8000,
]

# Priority values (0=medium, 1=high, 2=low)
PRIORITY_MUTATIONS = [0, 1, 2, 3, 255]  # 3+ are invalid

# Presentation Context ID (odd numbers 1-255)
CONTEXT_ID_VALID = list(range(1, 256, 2))  # 1, 3, 5, ..., 255
CONTEXT_ID_MUTATIONS = [
    1, 3, 5,  # Common valid
    127, 129,  # Middle range
    253, 255,  # Max valid
    0,   # Invalid
    2,   # Invalid (even)
    254, # Invalid (even, near max)
]

# PDV Flags (message control header)
PDV_FLAGS = {
    0x00: "Not last fragment, command",
    0x01: "Not last fragment, data",
    0x02: "Last fragment, command",
    0x03: "Last fragment, data",  # Most common for C-ECHO
}
PDV_FLAGS_MUTATIONS = [0x00, 0x01, 0x02, 0x03, 0x04, 0x80, 0xFF]

# ============================================================================
# SOP Class and Transfer Syntax Constants (for multi-context association)
# ============================================================================

STORAGE_SOP_CLASSES = {
    "verification": b"1.2.840.10008.1.1",
    "ct": b"1.2.840.10008.5.1.4.1.1.2",
    "mr": b"1.2.840.10008.5.1.4.1.1.4",
    "us": b"1.2.840.10008.5.1.4.1.1.6.1",
    "cr": b"1.2.840.10008.5.1.4.1.1.1",
    "sc": b"1.2.840.10008.5.1.4.1.1.7",           # Secondary Capture
    "rt_struct": b"1.2.840.10008.5.1.4.1.1.481.3",
    "rt_plan": b"1.2.840.10008.5.1.4.1.1.481.5",
    "patient_root_qr_find": b"1.2.840.10008.5.1.4.1.2.1.1",
    "study_root_qr_find": b"1.2.840.10008.5.1.4.1.2.2.1",
    "patient_root_qr_move": b"1.2.840.10008.5.1.4.1.2.1.2",
    "patient_root_qr_get": b"1.2.840.10008.5.1.4.1.2.1.3",
}

TRANSFER_SYNTAXES = {
    "implicit_vr_le": b"1.2.840.10008.1.2",
    "explicit_vr_le": b"1.2.840.10008.1.2.1",
    "explicit_vr_be": b"1.2.840.10008.1.2.2",
    "jpeg_baseline": b"1.2.840.10008.1.2.4.50",
    "jpeg_lossless": b"1.2.840.10008.1.2.4.57",
    "jpeg2000": b"1.2.840.10008.1.2.4.90",
    "rle": b"1.2.840.10008.1.2.5",
}

# Maximum PDU Length values
MAX_PDU_LENGTH_MUTATIONS = [
    16384,   # Common default
    32768,   # Another common value
    65536,   # 64KB
    0,       # Invalid - might cause issues
    1,       # Too small
    100,     # Very small
    0x7FFFFFFF,  # Max signed 32-bit
    0xFFFFFFFF,  # Max unsigned
]

# ============================================================================
# Smart Mutation Functions
# ============================================================================

def mutate_message_id_smart():
    """Return a semantically valid or boundary message ID."""
    return random.choice(MESSAGE_ID_MUTATIONS)


def mutate_command_field_smart():
    """Return a semantically valid or boundary command field."""
    return random.choice(COMMAND_FIELD_MUTATIONS)


def mutate_data_set_type_smart():
    """Return a semantically valid or boundary data set type."""
    return random.choice(DATA_SET_TYPE_MUTATIONS)


def mutate_context_id_smart():
    """Return a semantically valid or boundary context ID."""
    if random.random() < 0.7:
        # 70% chance: valid odd number
        return random.choice(CONTEXT_ID_VALID)
    else:
        # 30% chance: boundary/invalid value
        return random.choice(CONTEXT_ID_MUTATIONS)


def mutate_pdu_type_smart():
    """Return a valid or boundary PDU type."""
    if random.random() < 0.5:
        return random.choice(list(PDU_TYPES.keys()))
    else:
        return random.choice(PDU_TYPE_BOUNDARIES)


def mutate_pdv_flags_smart():
    """Return a valid or boundary PDV flags value."""
    return random.choice(PDV_FLAGS_MUTATIONS)


def mutate_status_smart():
    """Return a valid or boundary status value."""
    return random.choice(STATUS_MUTATIONS)


def mutate_priority_smart():
    """Return a valid or boundary priority value."""
    return random.choice(PRIORITY_MUTATIONS)


def mutate_max_pdu_length_smart():
    """Return a valid or boundary max PDU length."""
    return random.choice(MAX_PDU_LENGTH_MUTATIONS)


# ============================================================================
# DICOM Element Offset Maps
# ============================================================================

# ASSOC_RQ PDU structure (offsets)
ASSOC_RQ_OFFSETS = {
    "pdu_type": (0, 1, "byte", mutate_pdu_type_smart),
    "reserved1": (1, 2, "byte", lambda: 0),
    "pdu_length": (2, 6, "uint32_be", None),  # Calculated
    "protocol_version": (6, 8, "uint16_be", lambda: random.choice([1, 0, 2, 0xFFFF])),
    "reserved2": (8, 10, "uint16_be", lambda: 0),
    "called_ae": (10, 26, "string16", None),  # AE title
    "calling_ae": (26, 42, "string16", None),  # AE title
    "reserved3": (42, 74, "bytes32", lambda: b'\x00' * 32),
    # Variable items start at 74
}

# PDATA PDU structure (offsets)
PDATA_OFFSETS = {
    "pdu_type": (0, 1, "byte", lambda: 0x04),
    "reserved": (1, 2, "byte", lambda: 0),
    "pdu_length": (2, 6, "uint32_be", None),
    "pdv_length": (6, 10, "uint32_be", None),
    "context_id": (10, 11, "byte", mutate_context_id_smart),
    "msg_control": (11, 12, "byte", mutate_pdv_flags_smart),
    # DIMSE command starts at 12 (implicit VR little-endian)
}

# DIMSE Command Set element offsets (within PDATA, after header)
# Format: (group, element) -> (offset_from_cmd_start, length, mutator)
DIMSE_COMMAND_OFFSETS = {
    # (0000,0000) Command Group Length - always first
    (0x0000, 0x0000): (0, 4, "uint32_le", None),  # Calculated
    # (0000,0002) Affected SOP Class UID
    (0x0000, 0x0002): (8, None, "ui", None),  # Variable length UID
    # (0000,0100) Command Field
    (0x0000, 0x0100): (None, 2, "uint16_le", mutate_command_field_smart),
    # (0000,0110) Message ID
    (0x0000, 0x0110): (None, 2, "uint16_le", mutate_message_id_smart),
    # (0000,0120) Message ID Being Responded To
    (0x0000, 0x0120): (None, 2, "uint16_le", mutate_message_id_smart),
    # (0000,0700) Priority
    (0x0000, 0x0700): (None, 2, "uint16_le", mutate_priority_smart),
    # (0000,0800) Data Set Type
    (0x0000, 0x0800): (None, 2, "uint16_le", mutate_data_set_type_smart),
    # (0000,0900) Status
    (0x0000, 0x0900): (None, 2, "uint16_le", mutate_status_smart),
}


# ============================================================================
# Smart PDU Builders
# ============================================================================

def build_smart_cecho_pdata(
    context_id=None,
    msg_control=None,
    command_field=None,
    message_id=None,
    data_set_type=None,
    affected_sop_uid=None,
):
    """
    Build a C-ECHO PDATA PDU with smart/semantic mutations.

    Parameters can be:
    - None: use valid default
    - "smart": use smart mutation (valid or boundary)
    - specific value: use that value
    """
    # Context ID
    if context_id == "smart":
        ctx_id = mutate_context_id_smart()
    elif context_id is not None:
        ctx_id = context_id
    else:
        ctx_id = 1  # Default valid

    # Message control
    if msg_control == "smart":
        msg_ctrl = mutate_pdv_flags_smart()
    elif msg_control is not None:
        msg_ctrl = msg_control
    else:
        msg_ctrl = 0x03  # Last fragment, command

    # Command field
    if command_field == "smart":
        cmd_field = mutate_command_field_smart()
    elif command_field is not None:
        cmd_field = command_field
    else:
        cmd_field = 0x0030  # C-ECHO-RQ

    # Message ID
    if message_id == "smart":
        msg_id = mutate_message_id_smart()
    elif message_id is not None:
        msg_id = message_id
    else:
        msg_id = 1  # Default valid

    # Data set type
    if data_set_type == "smart":
        ds_type = mutate_data_set_type_smart()
    elif data_set_type is not None:
        ds_type = data_set_type
    else:
        ds_type = 0x0101  # No dataset

    # Affected SOP Class UID
    if affected_sop_uid is not None:
        uid = affected_sop_uid
    else:
        uid = b'1.2.840.10008.1.1'  # Verification SOP Class

    if len(uid) % 2:
        uid += b'\x00'  # Pad to even length

    # Build DIMSE command set (implicit VR little-endian)
    # (0000,0002) Affected SOP Class UID
    elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid

    # (0000,0100) Command Field
    elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, cmd_field)

    # (0000,0110) Message ID
    elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id)

    # (0000,0800) Data Set Type
    elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, ds_type)

    command_set = elem_0002 + elem_0100 + elem_0110 + elem_0800

    # (0000,0000) Command Group Length (must be first)
    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set

    # Build PDV item
    pdv_data = struct.pack('>BB', ctx_id, msg_ctrl) + command_set
    pdv_item = struct.pack('>I', len(pdv_data)) + pdv_data

    # Build PDATA PDU
    pdata = struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item

    return pdata


def build_smart_assoc_rq(
    called_ae=b"ORTHANC",
    calling_ae=b"FUZZER",
    protocol_version=None,
    max_pdu_length=None,
    abstract_syntax=None,
    transfer_syntax=None,
):
    """
    Build an A-ASSOCIATE-RQ PDU with smart/semantic mutations.
    """
    # Pad AE titles
    called = called_ae.ljust(16)[:16] if isinstance(called_ae, bytes) else called_ae.encode().ljust(16)[:16]
    calling = calling_ae.ljust(16)[:16] if isinstance(calling_ae, bytes) else calling_ae.encode().ljust(16)[:16]

    # Protocol version
    if protocol_version == "smart":
        proto_ver = random.choice([1, 0, 2, 0xFFFF])
    elif protocol_version is not None:
        proto_ver = protocol_version
    else:
        proto_ver = 1

    # Application Context
    app_ctx_uid = b'1.2.840.10008.3.1.1.1'
    app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

    # Abstract Syntax (SOP Class)
    if abstract_syntax is not None:
        abs_uid = abstract_syntax
    else:
        abs_uid = b'1.2.840.10008.1.1'  # Verification
    abs_syn = struct.pack('>BBH', 0x30, 0, len(abs_uid)) + abs_uid

    # Transfer Syntax
    if transfer_syntax is not None:
        xfer_uid = transfer_syntax
    else:
        xfer_uid = b'1.2.840.10008.1.2'  # Implicit VR LE
    xfer_syn = struct.pack('>BBH', 0x40, 0, len(xfer_uid)) + xfer_uid

    # Presentation Context
    pres_ctx_data = struct.pack('>BBBB', 1, 0, 0, 0) + abs_syn + xfer_syn
    pres_ctx = struct.pack('>BBH', 0x20, 0, len(pres_ctx_data)) + pres_ctx_data

    # User Information
    if max_pdu_length == "smart":
        max_pdu = mutate_max_pdu_length_smart()
    elif max_pdu_length is not None:
        max_pdu = max_pdu_length
    else:
        max_pdu = 16382

    max_pdu_item = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', max_pdu)
    impl_uid = b'1.2.826.0.1.3680043.9.3811.2.0.2'
    impl_item = struct.pack('>BBH', 0x52, 0, len(impl_uid)) + impl_uid
    user_info = struct.pack('>BBH', 0x50, 0, len(max_pdu_item) + len(impl_item)) + max_pdu_item + impl_item

    # Build variable items
    variable = app_ctx + pres_ctx + user_info

    # Build PDU
    reserved32 = b'\x00' * 32
    pdu_data = struct.pack('>H', proto_ver) + b'\x00\x00' + called + calling + reserved32 + variable
    pdu = struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data

    return pdu


def build_multi_context_assoc_rq(
    presentation_contexts,
    called_ae=b"ORTHANC",
    calling_ae=b"FUZZER",
    protocol_version=None,
    max_pdu_length=None,
):
    """
    Build A-ASSOCIATE-RQ with multiple presentation contexts.

    Args:
        presentation_contexts: list of (abstract_syntax_bytes, [transfer_syntax_bytes, ...])
            e.g. [(STORAGE_SOP_CLASSES["ct"], [TRANSFER_SYNTAXES["implicit_vr_le"]])]
        called_ae: Called AE title
        calling_ae: Calling AE title
        protocol_version: Protocol version (default 1)
        max_pdu_length: Max PDU length (default 16382)
    """
    # Pad AE titles
    called = called_ae.ljust(16)[:16] if isinstance(called_ae, bytes) else called_ae.encode().ljust(16)[:16]
    calling = calling_ae.ljust(16)[:16] if isinstance(calling_ae, bytes) else calling_ae.encode().ljust(16)[:16]

    # Protocol version
    if protocol_version == "smart":
        proto_ver = random.choice([1, 0, 2, 0xFFFF])
    elif protocol_version is not None:
        proto_ver = protocol_version
    else:
        proto_ver = 1

    # Application Context
    app_ctx_uid = b'1.2.840.10008.3.1.1.1'
    app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

    # Build multiple presentation contexts (IDs must be odd: 1, 3, 5, ...)
    all_pres_ctx = b''
    for i, (abs_syntax, xfer_syntaxes) in enumerate(presentation_contexts):
        ctx_id = 2 * i + 1  # 1, 3, 5, 7, ...
        if ctx_id > 255:
            break

        # Abstract Syntax sub-item
        abs_syn = struct.pack('>BBH', 0x30, 0, len(abs_syntax)) + abs_syntax

        # Transfer Syntax sub-items (one or more)
        xfer_items = b''
        for xfer in xfer_syntaxes:
            xfer_items += struct.pack('>BBH', 0x40, 0, len(xfer)) + xfer

        # Presentation Context item
        pres_ctx_data = struct.pack('>BBBB', ctx_id, 0, 0, 0) + abs_syn + xfer_items
        all_pres_ctx += struct.pack('>BBH', 0x20, 0, len(pres_ctx_data)) + pres_ctx_data

    # User Information
    if max_pdu_length == "smart":
        max_pdu = mutate_max_pdu_length_smart()
    elif max_pdu_length is not None:
        max_pdu = max_pdu_length
    else:
        max_pdu = 16382

    max_pdu_item = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', max_pdu)
    impl_uid = b'1.2.826.0.1.3680043.9.3811.2.0.2'
    impl_item = struct.pack('>BBH', 0x52, 0, len(impl_uid)) + impl_uid
    user_info = struct.pack('>BBH', 0x50, 0, len(max_pdu_item) + len(impl_item)) + max_pdu_item + impl_item

    # Build variable items
    variable = app_ctx + all_pres_ctx + user_info

    # Build PDU
    reserved32 = b'\x00' * 32
    pdu_data = struct.pack('>H', proto_ver) + b'\x00\x00' + called + calling + reserved32 + variable
    pdu = struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data

    return pdu


# ============================================================================
# Semantic Mutation Strategies
# ============================================================================

SEMANTIC_MUTATION_STRATEGIES = [
    # (name, description, fields_to_mutate)
    ("valid_baseline", "Valid PDU for baseline comparison", {}),
    ("message_id_zero", "Message ID = 0 (invalid)", {"message_id": 0}),
    ("message_id_max", "Message ID = 65535 (max)", {"message_id": 65535}),
    ("command_field_invalid", "Invalid command field", {"command_field": 0x0002}),
    ("command_field_response", "Response command from client", {"command_field": 0x8030}),
    ("data_set_mismatch", "Data set type says present but none sent", {"data_set_type": 0x0102}),
    ("context_id_zero", "Context ID = 0 (invalid)", {"context_id": 0}),
    ("context_id_even", "Context ID = 2 (invalid, even)", {"context_id": 2}),
    ("msg_control_invalid", "Invalid message control flags", {"msg_control": 0x80}),
    ("all_smart", "All fields use smart mutations", {
        "context_id": "smart",
        "msg_control": "smart",
        "command_field": "smart",
        "message_id": "smart",
        "data_set_type": "smart",
    }),
]


def get_semantic_mutation_pdata(strategy_name):
    """Get a PDATA PDU with the specified semantic mutation strategy."""
    for name, desc, fields in SEMANTIC_MUTATION_STRATEGIES:
        if name == strategy_name:
            return build_smart_cecho_pdata(**fields)

    # Default to all smart
    return build_smart_cecho_pdata(
        context_id="smart",
        msg_control="smart",
        command_field="smart",
        message_id="smart",
        data_set_type="smart",
    )


# ============================================================================
# Aggressive DIMSE Attacks (bypass DUL, target DIMSE parser)
# ============================================================================

def build_malformed_dimse_pdata(attack_type="truncated_cmd"):
    """
    Build PDATA with malformed DIMSE command set.
    These bypass DUL validation and target the DIMSE parser.
    """
    ctx_id = 1
    msg_ctrl = 0x03

    if attack_type == "truncated_cmd":
        # Truncated command set - missing required elements
        uid = b'1.2.840.10008.1.1'
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid
        # Missing command field, message id, data set type
        command_set = elem_0002

    elif attack_type == "wrong_length":
        # Element with wrong length field
        uid = b'1.2.840.10008.1.1'
        # Claim length is 100 but only provide 18 bytes
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, 100) + uid
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)
        command_set = elem_0002 + elem_0100

    elif attack_type == "negative_length":
        # Element with "negative" length (large unsigned)
        uid = b'1.2.840.10008.1.1'
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, 0xFFFFFFFF) + uid
        command_set = elem_0002

    elif attack_type == "zero_length_uid":
        # Zero-length UID
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, 0)
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, 1)
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0101)
        command_set = elem_0002 + elem_0100 + elem_0110 + elem_0800

    elif attack_type == "duplicate_elements":
        # Duplicate DIMSE elements
        uid = b'1.2.840.10008.1.1\x00'
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)
        elem_0100_dup = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0001)  # Duplicate with different value
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, 1)
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0101)
        command_set = elem_0002 + elem_0100 + elem_0100_dup + elem_0110 + elem_0800

    elif attack_type == "out_of_order":
        # Elements in wrong order (group length should be first)
        uid = b'1.2.840.10008.1.1\x00'
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, 1)
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0101)
        command_set = elem_0100 + elem_0110 + elem_0800 + elem_0002  # No group length, wrong order

    elif attack_type == "invalid_group":
        # Use invalid group number
        uid = b'1.2.840.10008.1.1\x00'
        elem_bad = struct.pack('<HH I', 0xFFFF, 0x0002, len(uid)) + uid  # Group 0xFFFF
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)
        command_set = elem_bad + elem_0100

    elif attack_type == "oversized_group_length":
        # Group length claims much more data than present
        uid = b'1.2.840.10008.1.1\x00'
        elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, 0x7FFFFFFF)  # Huge length
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0030)
        command_set = elem_0000 + elem_0002 + elem_0100

    elif attack_type == "cstore_no_dataset":
        # C-STORE-RQ but with DataSetType = no dataset (inconsistent)
        uid = b'1.2.840.10008.5.1.4.1.1.2\x00'  # CT Image Storage
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, 0x0001)  # C-STORE-RQ
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, 1)
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, 0x0101)  # NO dataset (wrong!)
        instance_uid = b'1.2.3.4.5.6.7.8.9\x00'
        elem_1000 = struct.pack('<HH I', 0x0000, 0x1000, len(instance_uid)) + instance_uid
        command_set = elem_0002 + elem_0100 + elem_0110 + elem_0800 + elem_1000

    elif attack_type == "empty_pdata":
        # Empty PDATA (just header, no PDV)
        return struct.pack('>BBi', 0x04, 0, 0)

    elif attack_type == "pdv_length_zero":
        # PDV with zero length
        pdv_item = struct.pack('>I', 0)
        return struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item

    else:
        # Default: valid C-ECHO
        return build_smart_cecho_pdata()

    # Add group length
    elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
    command_set = elem_0000 + command_set

    # Build PDV
    pdv_data = struct.pack('>BB', ctx_id, msg_ctrl) + command_set
    pdv_item = struct.pack('>I', len(pdv_data)) + pdv_data

    # Build PDATA
    return struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item


MALFORMED_DIMSE_ATTACKS = [
    "truncated_cmd",
    "wrong_length",
    "negative_length",
    "zero_length_uid",
    "duplicate_elements",
    "out_of_order",
    "invalid_group",
    "oversized_group_length",
    "cstore_no_dataset",
    "empty_pdata",
    "pdv_length_zero",
]
