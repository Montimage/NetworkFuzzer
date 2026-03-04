#!/usr/bin/env python3
"""
DICOM Protocol Adapter.

Implements ProtocolAdapter for DICOM (Digital Imaging and Communications in Medicine).
Supports fuzzing of PACS servers like Orthanc, DCMTK, dcm4chee.
"""

import struct
import socket
import time
import random
from typing import List, Dict, Any, Tuple, Optional

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))

from fuzzer.rl.base.protocol_adapter import (
    ProtocolAdapter,
    FieldDefinition,
    StateTransition,
    PayloadTarget,
    HealthCheckResult,
    register_protocol,
)


# =============================================================================
# DICOM Constants
# =============================================================================

# PDU Types
PDU_TYPES = {
    0x01: "A-ASSOCIATE-RQ",
    0x02: "A-ASSOCIATE-AC",
    0x03: "A-ASSOCIATE-RJ",
    0x04: "P-DATA-TF",
    0x05: "A-RELEASE-RQ",
    0x06: "A-RELEASE-RP",
    0x07: "A-ABORT",
}

# DIMSE Commands
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
}

# Semantic mutation values
MESSAGE_ID_VALUES = [1, 2, 3, 4, 5, 6, 7, 255, 256, 32767, 32768, 65534, 65535, 0]
COMMAND_FIELD_VALUES = [
    0x0001, 0x0010, 0x0020, 0x0021, 0x0030, 0x0FFF,  # C-class requests
    0x0100, 0x0110, 0x0120, 0x0130, 0x0140, 0x0150,  # N-class requests
    0x8001, 0x8010, 0x8020, 0x8021, 0x8030,          # Valid responses
    0x0000, 0x0002, 0x00FF, 0x7FFF, 0x8000, 0xFFFF,  # Boundaries
]
DATA_SET_TYPE_VALUES = [0x0101, 0x0102, 0x0000, 0x0100, 0x0103, 0x01FF, 0xFFFF]
CONTEXT_ID_VALUES = [1, 3, 5, 127, 129, 253, 255, 0, 2, 254]  # Odd=valid, Even=invalid
PDV_FLAGS_VALUES = [0x00, 0x01, 0x02, 0x03, 0x04, 0x80, 0xFF]
MAX_PDU_LENGTH_VALUES = [16384, 32768, 65536, 0, 1, 100, 0x7FFFFFFF, 0xFFFFFFFF]


@register_protocol("dicom")
class DicomAdapter(ProtocolAdapter):
    """DICOM protocol adapter for RL fuzzing."""

    def __init__(self, called_ae: str = "ORTHANC", calling_ae: str = "FUZZER"):
        self.called_ae = called_ae.encode() if isinstance(called_ae, str) else called_ae
        self.calling_ae = calling_ae.encode() if isinstance(calling_ae, str) else calling_ae

    @property
    def protocol_name(self) -> str:
        return "dicom"

    @property
    def default_port(self) -> int:
        return 4242

    def get_semantic_fields(self) -> List[FieldDefinition]:
        return [
            FieldDefinition(
                name="message_id",
                offset=None,  # Variable position in DIMSE
                size=2,
                encoding="uint16_le",
                valid_values=[1, 2, 3, 4, 5, 6, 7],
                boundary_values=[0, 255, 256, 32767, 65535],
                description="DIMSE Message ID (1-65535, 0 is invalid)"
            ),
            FieldDefinition(
                name="command_field",
                offset=None,
                size=2,
                encoding="uint16_le",
                valid_values=[0x0030],  # C-ECHO-RQ
                boundary_values=[0x0000, 0x8030, 0xFFFF],
                description="DIMSE Command Field"
            ),
            FieldDefinition(
                name="data_set_type",
                offset=None,
                size=2,
                encoding="uint16_le",
                valid_values=[0x0101],  # No dataset
                boundary_values=[0x0102, 0x0000, 0xFFFF],
                description="Data Set Type (0x0101=none, 0x0102=present)"
            ),
            FieldDefinition(
                name="context_id",
                offset=10,  # In PDATA PDV
                size=1,
                encoding="uint8",
                valid_values=[1, 3, 5],  # Odd numbers
                boundary_values=[0, 2, 254, 255],
                description="Presentation Context ID (odd 1-255)"
            ),
            FieldDefinition(
                name="msg_control",
                offset=11,  # In PDATA PDV
                size=1,
                encoding="uint8",
                valid_values=[0x03],  # Last fragment, command
                boundary_values=[0x00, 0x80, 0xFF],
                description="PDV Message Control flags"
            ),
            FieldDefinition(
                name="max_pdu_length",
                offset=None,  # In User Info
                size=4,
                encoding="uint32_be",
                valid_values=[16384, 32768],
                boundary_values=[0, 1, 0xFFFFFFFF],
                description="Maximum PDU Length"
            ),
        ]

    def get_mutation_values(self, field_name: str) -> List[Any]:
        values_map = {
            "message_id": MESSAGE_ID_VALUES,
            "command_field": COMMAND_FIELD_VALUES,
            "data_set_type": DATA_SET_TYPE_VALUES,
            "context_id": CONTEXT_ID_VALUES,
            "msg_control": PDV_FLAGS_VALUES,
            "max_pdu_length": MAX_PDU_LENGTH_VALUES,
        }
        return values_map.get(field_name, [])

    def get_message_types(self) -> List[str]:
        return [
            "assoc_rq", "assoc_rq_multi",
            "pdata", "release_rq", "abort", "assoc_ac", "assoc_rj",
            "pdata_valid",
            "pdata_c_store", "pdata_c_store_partial",
            "pdata_c_store_ct",                          # CT Storage on negotiated ctx=3
            "pdata_c_find", "pdata_c_find_qr",          # C-FIND: generic vs negotiated ctx=5
            "pdata_c_find_study",                        # Study Root C-FIND
            "pdata_c_find_worklist",                     # Modality Worklist C-FIND
            "pdata_c_move", "pdata_c_move_qr",           # C-MOVE: generic vs negotiated ctx=7
            "pdata_c_get",
            "pdata_c_cancel",                            # C-CANCEL-RQ (cancel in-progress op)
            "pdata_n_get", "pdata_n_event",
            "pdata_n_action", "pdata_n_create",          # N-ACTION, N-CREATE
            "pdata_n_set", "pdata_n_delete",             # N-SET, N-DELETE
        ]

    def build_message(self, message_type: str, fields: Dict[str, Any],
                      payloads: Dict[str, bytes]) -> bytes:
        if message_type == "assoc_rq":
            return self._build_assoc_rq(fields, payloads)
        elif message_type == "assoc_rq_multi":
            return self._build_assoc_rq_multi(fields, payloads)
        elif message_type == "pdata":
            return self._build_pdata(fields)
        elif message_type == "pdata_valid":
            return self._build_pdata_valid(fields)
        elif message_type == "pdata_c_store":
            return self._build_pdata_c_store(fields, payloads)
        elif message_type == "pdata_c_store_partial":
            return self._build_pdata_c_store_partial(fields, payloads)
        elif message_type == "pdata_c_store_ct":
            return self._build_pdata_c_store_ct(fields, payloads)
        elif message_type == "pdata_c_find":
            return self._build_pdata_c_find(fields, payloads)
        elif message_type == "pdata_c_find_qr":
            return self._build_pdata_c_find_qr(fields, payloads)
        elif message_type == "pdata_c_find_study":
            return self._build_pdata_c_find_study(fields, payloads)
        elif message_type == "pdata_c_find_worklist":
            return self._build_pdata_c_find_worklist(fields, payloads)
        elif message_type == "pdata_c_move":
            return self._build_pdata_c_move(fields, payloads)
        elif message_type == "pdata_c_move_qr":
            return self._build_pdata_c_move_qr(fields, payloads)
        elif message_type == "pdata_c_get":
            return self._build_pdata_c_get(fields)
        elif message_type == "pdata_c_cancel":
            return self._build_pdata_c_cancel(fields)
        elif message_type == "pdata_n_get":
            return self._build_pdata_n_get(fields)
        elif message_type == "pdata_n_event":
            return self._build_pdata_n_event(fields)
        elif message_type == "pdata_n_action":
            return self._build_pdata_n_action(fields)
        elif message_type == "pdata_n_create":
            return self._build_pdata_n_create(fields)
        elif message_type == "pdata_n_set":
            return self._build_pdata_n_set(fields)
        elif message_type == "pdata_n_delete":
            return self._build_pdata_n_delete(fields)
        elif message_type == "release_rq":
            return struct.pack('>BBi', 0x05, 0, 4) + b'\x00\x00\x00\x00'
        elif message_type == "abort":
            return struct.pack('>BBi', 0x07, 0, 4) + b'\x00\x00\x00\x00'
        elif message_type == "assoc_ac":
            return struct.pack('>BBi', 0x02, 0, 4) + b'\x00\x00\x00\x00'
        elif message_type == "assoc_rj":
            return struct.pack('>BBi', 0x03, 0, 4) + b'\x00\x01\x01\x01'
        else:
            return self._build_pdata(fields)

    def _build_assoc_rq(self, fields: Dict[str, Any], payloads: Dict[str, bytes]) -> bytes:
        """Build A-ASSOCIATE-RQ PDU."""
        # Get AE titles (possibly from payloads for injection)
        called = payloads.get("called_ae", self.called_ae)
        calling = payloads.get("calling_ae", self.calling_ae)

        # Pad AE titles to 16 bytes
        if isinstance(called, str):
            called = called.encode()
        if isinstance(calling, str):
            calling = calling.encode()
        called = called.ljust(16)[:16]
        calling = calling.ljust(16)[:16]

        # Protocol version
        proto_ver = 1

        # Application Context
        app_ctx_uid = b'1.2.840.10008.3.1.1.1'
        app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

        # Abstract Syntax (possibly from payload)
        abs_uid = payloads.get("abstract_syntax", b'1.2.840.10008.1.1')  # Verification
        if isinstance(abs_uid, str):
            abs_uid = abs_uid.encode()
        abs_syn = struct.pack('>BBH', 0x30, 0, len(abs_uid)) + abs_uid

        # Transfer Syntax (possibly from payload)
        xfer_uid = payloads.get("transfer_syntax", b'1.2.840.10008.1.2')  # Implicit VR LE
        if isinstance(xfer_uid, str):
            xfer_uid = xfer_uid.encode()
        xfer_syn = struct.pack('>BBH', 0x40, 0, len(xfer_uid)) + xfer_uid

        # Presentation Context
        pres_ctx_data = struct.pack('>BBBB', 1, 0, 0, 0) + abs_syn + xfer_syn
        pres_ctx = struct.pack('>BBH', 0x20, 0, len(pres_ctx_data)) + pres_ctx_data

        # User Information
        max_pdu = fields.get("max_pdu_length", 16384)
        max_pdu_item = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', max_pdu & 0xFFFFFFFF)

        impl_uid = payloads.get("impl_uid", b'1.2.826.0.1.3680043.9.3811.2.0.2')
        if isinstance(impl_uid, str):
            impl_uid = impl_uid.encode()
        impl_item = struct.pack('>BBH', 0x52, 0, len(impl_uid)) + impl_uid

        user_info = struct.pack('>BBH', 0x50, 0, len(max_pdu_item) + len(impl_item)) + max_pdu_item + impl_item

        # Build variable items
        variable = app_ctx + pres_ctx + user_info

        # Build PDU
        reserved32 = b'\x00' * 32
        pdu_data = struct.pack('>H', proto_ver) + b'\x00\x00' + called + calling + reserved32 + variable
        pdu = struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data

        return pdu

    def _build_pdata(self, fields: Dict[str, Any]) -> bytes:
        """Build P-DATA-TF PDU with DIMSE command."""
        ctx_id = fields.get("context_id", 1)
        msg_ctrl = fields.get("msg_control", 0x03)
        cmd_field = fields.get("command_field", 0x0030)
        msg_id = fields.get("message_id", 1)
        ds_type = fields.get("data_set_type", 0x0101)

        # Affected SOP Class UID (Verification)
        uid = b'1.2.840.10008.1.1'
        if len(uid) % 2:
            uid += b'\x00'

        # Build DIMSE command set (implicit VR little-endian)
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(uid)) + uid
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, cmd_field & 0xFFFF)
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id & 0xFFFF)
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, ds_type & 0xFFFF)

        command_set = elem_0002 + elem_0100 + elem_0110 + elem_0800
        elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(command_set))
        command_set = elem_0000 + command_set

        # Build PDV
        pdv_data = struct.pack('>BB', ctx_id & 0xFF, msg_ctrl & 0xFF) + command_set
        pdv_item = struct.pack('>I', len(pdv_data)) + pdv_data

        # Build PDATA PDU
        pdata = struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item

        return pdata

    def _build_dimse_command(self, sop_class_uid: bytes, cmd_field: int, msg_id: int,
                              ds_type: int, extra_elements: bytes = b'') -> bytes:
        """Build a generic DIMSE command dataset (implicit VR little-endian)."""
        if len(sop_class_uid) % 2:
            sop_class_uid += b'\x00'
        elem_0002 = struct.pack('<HH I', 0x0000, 0x0002, len(sop_class_uid)) + sop_class_uid
        elem_0100 = struct.pack('<HH I H', 0x0000, 0x0100, 2, cmd_field & 0xFFFF)
        elem_0110 = struct.pack('<HH I H', 0x0000, 0x0110, 2, msg_id & 0xFFFF)
        elem_0800 = struct.pack('<HH I H', 0x0000, 0x0800, 2, ds_type & 0xFFFF)
        body = elem_0002 + elem_0100 + elem_0110 + extra_elements + elem_0800
        elem_0000 = struct.pack('<HH I I', 0x0000, 0x0000, 4, len(body))
        return elem_0000 + body

    def _build_pdata_pdv(self, ctx_id: int, msg_ctrl: int, command_set: bytes) -> bytes:
        """Wrap a command set in a PDV and PDATA PDU."""
        pdv_data = struct.pack('>BB', ctx_id & 0xFF, msg_ctrl & 0xFF) + command_set
        pdv_item = struct.pack('>I', len(pdv_data)) + pdv_data
        return struct.pack('>BBi', 0x04, 0, len(pdv_item)) + pdv_item

    def _build_pdata_valid(self, fields: Dict[str, Any]) -> bytes:
        """Build a valid C-ECHO-RQ P-DATA-TF that the server should respond to."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        uid = b'1.2.840.10008.1.1'
        command_set = self._build_dimse_command(uid, 0x0030, msg_id, 0x0101)
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def _build_pdata_c_store(self, fields: Dict[str, Any], payloads: Dict[str, bytes]) -> bytes:
        """Build C-STORE-RQ P-DATA-TF (DataSetType=0x0102, dataset present → server waits)."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)

        sop_class = b'1.2.840.10008.5.1.4.1.1.2'  # CT Image Storage
        sop_instance = payloads.get("sop_instance_uid", b'1.2.3.4.5.6.7.8.9.10.11')
        if isinstance(sop_instance, str):
            sop_instance = sop_instance.encode()
        if len(sop_instance) % 2:
            sop_instance += b'\x00'

        # (0000,0600) Move Destination / Priority / SOP Instance UID
        elem_0600 = struct.pack('<HH I', 0x0000, 0x0700, 2) + struct.pack('<H', 0x0000)  # Priority=MEDIUM
        elem_1000 = struct.pack('<HH I', 0x0000, 0x1000, len(sop_instance)) + sop_instance  # SOP Instance UID

        command_set = self._build_dimse_command(sop_class, 0x0001, msg_id, 0x0102,
                                                 extra_elements=elem_0600 + elem_1000)

        # Append a minimal dataset PDV (Patient Name + pixel placeholder)
        patient_name = payloads.get("patient_name", b'TEST^PATIENT')
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '
        # (0010,0010) Patient Name
        ds_elem_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
        # (7FE0,0010) Pixel Data (minimal, 8 bytes)
        pixel_data = b'\x00' * 8
        ds_elem_pixel = struct.pack('<HH I', 0x7FE0, 0x0010, len(pixel_data)) + pixel_data
        dataset = ds_elem_0010 + ds_elem_pixel

        cmd_pdu = self._build_pdata_pdv(ctx_id, 0x03, command_set)
        ds_pdv_data = struct.pack('>BB', ctx_id & 0xFF, 0x02) + dataset  # 0x02 = last fragment, data
        ds_pdv_item = struct.pack('>I', len(ds_pdv_data)) + ds_pdv_data
        ds_pdu = struct.pack('>BBi', 0x04, 0, len(ds_pdv_item)) + ds_pdv_item
        return cmd_pdu + ds_pdu

    def _build_pdata_c_find(self, fields: Dict[str, Any], payloads: Dict[str, bytes]) -> bytes:
        """Build C-FIND-RQ P-DATA-TF (Patient Root Q/R, DataSetType=0x0102)."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)

        sop_class = b'1.2.840.10008.5.1.4.1.2.1.1'  # Patient Root Q/R - FIND
        command_set = self._build_dimse_command(sop_class, 0x0020, msg_id, 0x0102)

        # Dataset: Patient Name wildcard + Query Retrieve Level
        patient_name = payloads.get("patient_name", b'*')
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '
        qr_level = b'PATIENT '  # 8 bytes (even)
        ds_elem_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
        ds_elem_0008 = struct.pack('<HH I', 0x0008, 0x0052, len(qr_level)) + qr_level
        dataset = ds_elem_0008 + ds_elem_0010

        cmd_pdu = self._build_pdata_pdv(ctx_id, 0x03, command_set)
        ds_pdv_data = struct.pack('>BB', ctx_id & 0xFF, 0x02) + dataset
        ds_pdv_item = struct.pack('>I', len(ds_pdv_data)) + ds_pdv_data
        ds_pdu = struct.pack('>BBi', 0x04, 0, len(ds_pdv_item)) + ds_pdv_item
        return cmd_pdu + ds_pdu

    def _build_pdata_c_move(self, fields: Dict[str, Any], payloads: Dict[str, bytes]) -> bytes:
        """Build C-MOVE-RQ P-DATA-TF (Study Root Q/R Move, DataSetType=0x0102)."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)

        sop_class = b'1.2.840.10008.5.1.4.1.2.2.2'  # Study Root Q/R - MOVE
        dest_ae = payloads.get("called_ae", self.called_ae)
        if isinstance(dest_ae, str):
            dest_ae = dest_ae.encode()
        dest_ae = dest_ae.ljust(16)[:16]
        elem_0600 = struct.pack('<HH I', 0x0000, 0x0600, len(dest_ae)) + dest_ae  # Move Destination

        command_set = self._build_dimse_command(sop_class, 0x0021, msg_id, 0x0102,
                                                 extra_elements=elem_0600)

        patient_name = payloads.get("patient_name", b'*')
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '
        qr_level = b'STUDY   '  # 8 bytes
        ds_elem_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
        ds_elem_0052 = struct.pack('<HH I', 0x0008, 0x0052, len(qr_level)) + qr_level
        dataset = ds_elem_0052 + ds_elem_0010

        cmd_pdu = self._build_pdata_pdv(ctx_id, 0x03, command_set)
        ds_pdv_data = struct.pack('>BB', ctx_id & 0xFF, 0x02) + dataset
        ds_pdv_item = struct.pack('>I', len(ds_pdv_data)) + ds_pdv_data
        ds_pdu = struct.pack('>BBi', 0x04, 0, len(ds_pdv_item)) + ds_pdv_item
        return cmd_pdu + ds_pdu

    def _build_pdata_c_get(self, fields: Dict[str, Any]) -> bytes:
        """Build C-GET-RQ P-DATA-TF (Patient Root Q/R Get, DataSetType=0x0102)."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)

        sop_class = b'1.2.840.10008.5.1.4.1.2.1.3'  # Patient Root Q/R - GET
        command_set = self._build_dimse_command(sop_class, 0x0010, msg_id, 0x0102)

        qr_level = b'PATIENT '
        ds_elem_0052 = struct.pack('<HH I', 0x0008, 0x0052, len(qr_level)) + qr_level
        dataset = ds_elem_0052

        cmd_pdu = self._build_pdata_pdv(ctx_id, 0x03, command_set)
        ds_pdv_data = struct.pack('>BB', ctx_id & 0xFF, 0x02) + dataset
        ds_pdv_item = struct.pack('>I', len(ds_pdv_data)) + ds_pdv_data
        ds_pdu = struct.pack('>BBi', 0x04, 0, len(ds_pdv_item)) + ds_pdv_item
        return cmd_pdu + ds_pdu

    def _build_pdata_c_store_partial(self, fields: Dict[str, Any],
                                      payloads: Dict[str, bytes]) -> bytes:
        """C-STORE command PDV only — DataSetType=0x0102 tells server dataset is coming,
        but no dataset PDV follows. Server blocks waiting for dataset PDVs → true hang."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        sop_class = b'1.2.840.10008.5.1.4.1.1.2'  # CT Image Storage

        sop_instance = payloads.get("sop_instance_uid", b'1.2.3.4.5.6.7.8.9.10.11')
        if isinstance(sop_instance, str):
            sop_instance = sop_instance.encode()
        if len(sop_instance) % 2:
            sop_instance += b'\x00'
        elem_1000 = struct.pack('<HH I', 0x0000, 0x1000, len(sop_instance)) + sop_instance

        # DataSetType=0x0102: dataset is present — server waits for dataset PDVs
        command_set = self._build_dimse_command(sop_class, 0x0001, msg_id, 0x0102,
                                                 extra_elements=elem_1000)
        # Return ONLY the command PDV — no dataset PDV intentionally omitted
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def _build_pdata_n_get(self, fields: Dict[str, Any]) -> bytes:
        """N-GET-RQ (CommandField=0x0110) — N-class commands are rarely fuzzed."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        # Modality Performed Procedure Step — common N-GET target in PACS workflows
        sop_class = b'1.2.840.10008.3.1.3.5'
        sop_instance = b'1.2.3.4.5.6.7.8.9.10.11'
        if len(sop_instance) % 2:
            sop_instance += b'\x00'
        elem_1001 = struct.pack('<HH I', 0x0000, 0x1001, len(sop_instance)) + sop_instance
        command_set = self._build_dimse_command(sop_class, 0x0110, msg_id, 0x0101,
                                                 extra_elements=elem_1001)
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def _build_pdata_n_event(self, fields: Dict[str, Any]) -> bytes:
        """N-EVENT-REPORT-RQ (CommandField=0x0100) — notification command."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        sop_class = b'1.2.840.10008.1.1'  # Verification SOP Class
        event_type_id = struct.pack('<HH I H', 0x0000, 0x1002, 2, 1)  # EventTypeID=1
        command_set = self._build_dimse_command(sop_class, 0x0100, msg_id, 0x0101,
                                                 extra_elements=event_type_id)
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def _build_assoc_rq_multi(self, fields: Dict[str, Any], payloads: Dict[str, bytes]) -> bytes:
        """Build A-ASSOCIATE-RQ offering multiple presentation contexts.

        ctx=1: Verification SOP (C-ECHO)
        ctx=3: CT Image Storage (C-STORE) — Explicit VR LE
        ctx=5: Patient Root Q/R Find (C-FIND)
        ctx=7: Patient Root Q/R Move (C-MOVE)
        ctx=9: Modality Worklist Find
        """
        called = payloads.get("called_ae", self.called_ae)
        calling = payloads.get("calling_ae", self.calling_ae)
        if isinstance(called, str):
            called = called.encode()
        if isinstance(calling, str):
            calling = calling.encode()
        called = called.ljust(16)[:16]
        calling = calling.ljust(16)[:16]

        app_ctx_uid = b'1.2.840.10008.3.1.1.1'
        app_ctx = struct.pack('>BBH', 0x10, 0, len(app_ctx_uid)) + app_ctx_uid

        xfer_implicit = b'1.2.840.10008.1.2'    # Implicit VR LE
        xfer_explicit = b'1.2.840.10008.1.2.1'  # Explicit VR LE

        def make_pres_ctx(ctx_id, abs_uid, xfer_uid=None):
            if xfer_uid is None:
                xfer_uid = xfer_implicit
            abs_syn = struct.pack('>BBH', 0x30, 0, len(abs_uid)) + abs_uid
            xfer_syn = struct.pack('>BBH', 0x40, 0, len(xfer_uid)) + xfer_uid
            data = struct.pack('>BBBB', ctx_id, 0, 0, 0) + abs_syn + xfer_syn
            return struct.pack('>BBH', 0x20, 0, len(data)) + data

        contexts = [
            make_pres_ctx(1, b'1.2.840.10008.1.1'),                       # Verification
            make_pres_ctx(3, b'1.2.840.10008.5.1.4.1.1.2', xfer_explicit), # CT Image Storage
            make_pres_ctx(5, b'1.2.840.10008.5.1.4.1.2.1.1'),              # Patient Root Find
            make_pres_ctx(7, b'1.2.840.10008.5.1.4.1.2.1.2'),              # Patient Root Move
            make_pres_ctx(9, b'1.2.840.10008.5.1.4.31'),                   # Modality Worklist
        ]
        all_pres_ctx = b''.join(contexts)

        max_pdu = fields.get("max_pdu_length", 16384)
        max_pdu_item = struct.pack('>BBH', 0x51, 0, 4) + struct.pack('>I', max_pdu & 0xFFFFFFFF)
        impl_uid = payloads.get("impl_uid", b'1.2.826.0.1.3680043.9.3811.2.0.2')
        if isinstance(impl_uid, str):
            impl_uid = impl_uid.encode()
        impl_item = struct.pack('>BBH', 0x52, 0, len(impl_uid)) + impl_uid
        user_info = struct.pack('>BBH', 0x50, 0, len(max_pdu_item) + len(impl_item)) + max_pdu_item + impl_item

        variable = app_ctx + all_pres_ctx + user_info
        reserved32 = b'\x00' * 32
        pdu_data = struct.pack('>H', 1) + b'\x00\x00' + called + calling + reserved32 + variable
        return struct.pack('>BBi', 0x01, 0, len(pdu_data)) + pdu_data

    def _build_pdata_c_find_qr(self, fields: Dict[str, Any], payloads: Dict[str, bytes]) -> bytes:
        """C-FIND-RQ on properly negotiated Patient Root Q/R Find context (ctx_id=5).

        Used with assoc_rq_multi which negotiates this context.
        """
        msg_id = fields.get("message_id", 1)
        ctx_id = 5  # Patient Root Q/R Find, negotiated in assoc_rq_multi
        sop_class = b'1.2.840.10008.5.1.4.1.2.1.1'
        command_set = self._build_dimse_command(sop_class, 0x0020, msg_id, 0x0102)

        patient_name = payloads.get("patient_name", b'*')
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '
        qr_level = b'PATIENT '
        ds_elem_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
        ds_elem_0008 = struct.pack('<HH I', 0x0008, 0x0052, len(qr_level)) + qr_level
        dataset = ds_elem_0008 + ds_elem_0010

        cmd_pdu = self._build_pdata_pdv(ctx_id, 0x03, command_set)
        ds_pdv_data = struct.pack('>BB', ctx_id & 0xFF, 0x02) + dataset
        ds_pdv_item = struct.pack('>I', len(ds_pdv_data)) + ds_pdv_data
        ds_pdu = struct.pack('>BBi', 0x04, 0, len(ds_pdv_item)) + ds_pdv_item
        return cmd_pdu + ds_pdu

    def _build_pdata_c_store_ct(self, fields: Dict[str, Any], payloads: Dict[str, bytes]) -> bytes:
        """C-STORE-RQ on properly negotiated CT Image Storage context (ctx_id=3).

        Used with assoc_rq_multi which negotiates this context.
        Dataset uses partial send (DataSetType=0x0102, no dataset PDV follows) → hang.
        """
        msg_id = fields.get("message_id", 1)
        ctx_id = 3  # CT Image Storage, negotiated in assoc_rq_multi
        sop_class = b'1.2.840.10008.5.1.4.1.1.2'

        sop_instance = payloads.get("sop_instance_uid", b'1.2.3.4.5.6.7.8.9.10.11')
        if isinstance(sop_instance, str):
            sop_instance = sop_instance.encode()
        if len(sop_instance) % 2:
            sop_instance += b'\x00'

        elem_0700 = struct.pack('<HH I', 0x0000, 0x0700, 2) + struct.pack('<H', 0x0000)  # Priority
        elem_1000 = struct.pack('<HH I', 0x0000, 0x1000, len(sop_instance)) + sop_instance

        # DataSetType=0x0102: dataset present — server waits for dataset PDVs
        command_set = self._build_dimse_command(sop_class, 0x0001, msg_id, 0x0102,
                                                 extra_elements=elem_0700 + elem_1000)
        # Send only the command PDV; omitting dataset PDV causes server to block waiting
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def _build_pdata_c_move_qr(self, fields: Dict[str, Any], payloads: Dict[str, bytes]) -> bytes:
        """C-MOVE-RQ on properly negotiated Patient Root Q/R Move context (ctx_id=7)."""
        msg_id = fields.get("message_id", 1)
        ctx_id = 7  # Patient Root Q/R Move, negotiated in assoc_rq_multi
        sop_class = b'1.2.840.10008.5.1.4.1.2.1.2'

        dest_ae = payloads.get("called_ae", self.called_ae)
        if isinstance(dest_ae, str):
            dest_ae = dest_ae.encode()
        dest_ae = dest_ae.ljust(16)[:16]
        elem_0600 = struct.pack('<HH I', 0x0000, 0x0600, len(dest_ae)) + dest_ae

        command_set = self._build_dimse_command(sop_class, 0x0021, msg_id, 0x0102,
                                                 extra_elements=elem_0600)
        patient_name = payloads.get("patient_name", b'*')
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '
        qr_level = b'PATIENT '
        ds_elem_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
        ds_elem_0052 = struct.pack('<HH I', 0x0008, 0x0052, len(qr_level)) + qr_level
        dataset = ds_elem_0052 + ds_elem_0010

        cmd_pdu = self._build_pdata_pdv(ctx_id, 0x03, command_set)
        ds_pdv_data = struct.pack('>BB', ctx_id & 0xFF, 0x02) + dataset
        ds_pdv_item = struct.pack('>I', len(ds_pdv_data)) + ds_pdv_data
        ds_pdu = struct.pack('>BBi', 0x04, 0, len(ds_pdv_item)) + ds_pdv_item
        return cmd_pdu + ds_pdu

    def _build_pdata_c_cancel(self, fields: Dict[str, Any]) -> bytes:
        """C-CANCEL-RQ (0x0FFF) — cancel a pending C-FIND or C-MOVE operation.

        The Message ID references the pending operation. For fuzzing we send
        arbitrary message IDs to test cancel handler robustness.
        """
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        uid = b'1.2.840.10008.1.1'
        command_set = self._build_dimse_command(uid, 0x0FFF, msg_id, 0x0101)
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def _build_pdata_c_find_study(self, fields: Dict[str, Any],
                                   payloads: Dict[str, bytes]) -> bytes:
        """C-FIND Study Root Q/R — study-level query (different SOP class and code path)."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        sop_class = b'1.2.840.10008.5.1.4.1.2.2.1'  # Study Root Q/R - FIND
        command_set = self._build_dimse_command(sop_class, 0x0020, msg_id, 0x0102)

        study_uid = payloads.get("study_uid", b'*')
        if isinstance(study_uid, str):
            study_uid = study_uid.encode()
        if len(study_uid) % 2:
            study_uid += b' '
        qr_level = b'STUDY   '
        ds_elem_000D = struct.pack('<HH I', 0x0020, 0x000D, len(study_uid)) + study_uid
        ds_elem_0052 = struct.pack('<HH I', 0x0008, 0x0052, len(qr_level)) + qr_level
        dataset = ds_elem_0052 + ds_elem_000D

        cmd_pdu = self._build_pdata_pdv(ctx_id, 0x03, command_set)
        ds_pdv_data = struct.pack('>BB', ctx_id & 0xFF, 0x02) + dataset
        ds_pdv_item = struct.pack('>I', len(ds_pdv_data)) + ds_pdv_data
        ds_pdu = struct.pack('>BBi', 0x04, 0, len(ds_pdv_item)) + ds_pdv_item
        return cmd_pdu + ds_pdu

    def _build_pdata_c_find_worklist(self, fields: Dict[str, Any],
                                      payloads: Dict[str, bytes]) -> bytes:
        """C-FIND Modality Worklist — exercises the worklist scheduling handler."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        sop_class = b'1.2.840.10008.5.1.4.31'  # Modality Worklist Information Model - FIND
        command_set = self._build_dimse_command(sop_class, 0x0020, msg_id, 0x0102)

        patient_name = payloads.get("patient_name", b'*')
        if isinstance(patient_name, str):
            patient_name = patient_name.encode()
        if len(patient_name) % 2:
            patient_name += b' '
        ds_elem_0010 = struct.pack('<HH I', 0x0010, 0x0010, len(patient_name)) + patient_name
        dataset = ds_elem_0010

        cmd_pdu = self._build_pdata_pdv(ctx_id, 0x03, command_set)
        ds_pdv_data = struct.pack('>BB', ctx_id & 0xFF, 0x02) + dataset
        ds_pdv_item = struct.pack('>I', len(ds_pdv_data)) + ds_pdv_data
        ds_pdu = struct.pack('>BBi', 0x04, 0, len(ds_pdv_item)) + ds_pdv_item
        return cmd_pdu + ds_pdu

    def _build_pdata_n_action(self, fields: Dict[str, Any]) -> bytes:
        """N-ACTION-RQ (0x0130) — Storage Commitment Push (or any N-ACTION service)."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        # Storage Commitment Push SOP Class
        sop_class = b'1.2.840.10008.1.9'
        sop_instance = b'1.2.3.4.5.6.7.8.9.10.11'
        if len(sop_instance) % 2:
            sop_instance += b'\x00'
        elem_1000 = struct.pack('<HH I', 0x0000, 0x1000, len(sop_instance)) + sop_instance
        elem_1008 = struct.pack('<HH I H', 0x0000, 0x1008, 2, 1)  # Action Type ID = 1
        command_set = self._build_dimse_command(sop_class, 0x0130, msg_id, 0x0102,
                                                 extra_elements=elem_1000 + elem_1008)
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def _build_pdata_n_create(self, fields: Dict[str, Any]) -> bytes:
        """N-CREATE-RQ (0x0140) — create a SOP instance (e.g. Modality Procedure Step)."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        # Modality Performed Procedure Step SOP Class
        sop_class = b'1.2.840.10008.3.1.2.3.3'
        sop_instance = b'1.2.3.4.5.9999'
        if len(sop_instance) % 2:
            sop_instance += b'\x00'
        elem_1000 = struct.pack('<HH I', 0x0000, 0x1000, len(sop_instance)) + sop_instance
        command_set = self._build_dimse_command(sop_class, 0x0140, msg_id, 0x0101,
                                                 extra_elements=elem_1000)
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def _build_pdata_n_set(self, fields: Dict[str, Any]) -> bytes:
        """N-SET-RQ (0x0120) — modify attributes of a SOP instance."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        sop_class = b'1.2.840.10008.3.1.2.3.3'  # Modality Performed Procedure Step
        sop_instance = b'1.2.3.4.5.9999'
        if len(sop_instance) % 2:
            sop_instance += b'\x00'
        # Requested SOP Instance UID (0000,1001)
        elem_1001 = struct.pack('<HH I', 0x0000, 0x1001, len(sop_instance)) + sop_instance
        command_set = self._build_dimse_command(sop_class, 0x0120, msg_id, 0x0102,
                                                 extra_elements=elem_1001)
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def _build_pdata_n_delete(self, fields: Dict[str, Any]) -> bytes:
        """N-DELETE-RQ (0x0150) — delete a SOP instance."""
        ctx_id = fields.get("context_id", 1)
        msg_id = fields.get("message_id", 1)
        sop_class = b'1.2.840.10008.3.1.2.3.3'
        sop_instance = b'1.2.3.4.5.9999'
        if len(sop_instance) % 2:
            sop_instance += b'\x00'
        elem_1001 = struct.pack('<HH I', 0x0000, 0x1001, len(sop_instance)) + sop_instance
        command_set = self._build_dimse_command(sop_class, 0x0150, msg_id, 0x0101,
                                                 extra_elements=elem_1001)
        return self._build_pdata_pdv(ctx_id, 0x03, command_set)

    def get_state_transitions(self) -> List[StateTransition]:
        return [
            # Valid sequences
            StateTransition("normal", ["assoc_rq", "pdata", "release_rq"],
                           "Normal association with C-ECHO", is_valid=True),
            StateTransition("normal_no_release", ["assoc_rq", "pdata"],
                           "Association without release", is_valid=True),

            # Invalid sequences (for fuzzing)
            StateTransition("pdata_first", ["pdata"],
                           "PDATA without association", is_valid=False),
            StateTransition("double_assoc", ["assoc_rq", "assoc_rq"],
                           "Two association requests", is_valid=False),
            StateTransition("pdata_flood", ["assoc_rq", "pdata", "pdata", "pdata", "pdata"],
                           "Multiple PDATA in sequence", is_valid=False, flood=True),
            StateTransition("abort_continue", ["assoc_rq", "abort", "pdata"],
                           "Continue after abort", is_valid=False),
            StateTransition("release_continue", ["assoc_rq", "release_rq", "pdata"],
                           "Continue after release", is_valid=False),
            StateTransition("immediate_abort", ["assoc_rq", "abort"],
                           "Immediate abort after association", is_valid=False),
            StateTransition("client_sends_ac", ["assoc_ac"],
                           "Client sends ASSOC-AC (server role)", is_valid=False),
            StateTransition("client_sends_rj", ["assoc_rj"],
                           "Client sends ASSOC-RJ (server role)", is_valid=False),

            # Multi-step sequences: valid echo first, then target command
            StateTransition("echo_then_store", ["assoc_rq", "pdata_valid", "pdata_c_store"],
                           "Valid C-ECHO then C-STORE hang", is_valid=False),
            StateTransition("echo_then_find", ["assoc_rq", "pdata_valid", "pdata_c_find"],
                           "Valid C-ECHO then C-FIND patient enum", is_valid=False),
            StateTransition("echo_then_move", ["assoc_rq", "pdata_valid", "pdata_c_move"],
                           "Valid C-ECHO then C-MOVE", is_valid=False),
            StateTransition("echo_then_get", ["assoc_rq", "pdata_valid", "pdata_c_get"],
                           "Valid C-ECHO then C-GET", is_valid=False),
            StateTransition("multi_command",
                           ["assoc_rq", "pdata_valid", "pdata_c_store", "pdata_c_find"],
                           "4-PDU deep chain: echo → store → find", is_valid=False),
            StateTransition("store_then_find", ["assoc_rq", "pdata_c_store", "pdata_c_find"],
                           "C-STORE then C-FIND", is_valid=False),
            StateTransition("cfind_flood",
                           ["assoc_rq", "pdata_c_find", "pdata_c_find", "pdata_c_find"],
                           "C-FIND flood", is_valid=False, flood=True),
            StateTransition("cstore_flood",
                           ["assoc_rq", "pdata_c_store", "pdata_c_store", "pdata_c_store"],
                           "C-STORE flood", is_valid=False, flood=True),
            StateTransition("echo_store_find",
                           ["assoc_rq", "pdata_valid", "pdata_c_store", "pdata_c_move"],
                           "4-PDU: echo → store → move", is_valid=False),

            # Partial dataset attacks: command PDV says dataset present, none follows
            StateTransition("partial_store",
                           ["assoc_rq", "pdata_c_store_partial"],
                           "C-STORE command only (no dataset PDV) → server blocks waiting",
                           is_valid=False),
            StateTransition("echo_partial_store",
                           ["assoc_rq", "pdata_valid", "pdata_c_store_partial"],
                           "Valid echo then partial C-STORE (no dataset)", is_valid=False),
            StateTransition("partial_store_then_find",
                           ["assoc_rq", "pdata_c_store_partial", "pdata_c_find"],
                           "Partial C-STORE then C-FIND", is_valid=False),
            StateTransition("partial_store_flood",
                           ["assoc_rq", "pdata_c_store_partial", "pdata_c_store_partial",
                            "pdata_c_store_partial"],
                           "Partial C-STORE flood", is_valid=False, flood=True),

            # N-class DIMSE commands (rarely fuzzed, potentially buggy handlers)
            StateTransition("n_get_attack",
                           ["assoc_rq", "pdata_n_get"],
                           "N-GET-RQ (0x0110) — N-class handler attack", is_valid=False),
            StateTransition("n_event_attack",
                           ["assoc_rq", "pdata_n_event"],
                           "N-EVENT-REPORT-RQ (0x0100) attack", is_valid=False),
            StateTransition("echo_n_get",
                           ["assoc_rq", "pdata_valid", "pdata_n_get"],
                           "Valid echo then N-GET", is_valid=False),
            StateTransition("n_get_then_find",
                           ["assoc_rq", "pdata_n_get", "pdata_c_find"],
                           "N-GET then C-FIND", is_valid=False),
            StateTransition("n_get_flood",
                           ["assoc_rq", "pdata_n_get", "pdata_n_get", "pdata_n_get"],
                           "N-GET flood", is_valid=False, flood=True),

            # 5-6 PDU deep chains
            StateTransition("echo_find_store",
                           ["assoc_rq", "pdata_valid", "pdata_c_find", "pdata_c_store"],
                           "5-PDU: echo → C-FIND → C-STORE", is_valid=False),
            StateTransition("echo_store_find_move",
                           ["assoc_rq", "pdata_valid", "pdata_c_store", "pdata_c_find",
                            "pdata_c_move"],
                           "5-PDU: echo → store → find → move", is_valid=False),
            StateTransition("echo_partial_find_move",
                           ["assoc_rq", "pdata_valid", "pdata_c_store_partial", "pdata_c_find",
                            "pdata_c_move"],
                           "5-PDU: echo → partial-store → find → move", is_valid=False),
            StateTransition("full_workflow",
                           ["assoc_rq", "pdata_valid", "pdata_c_store", "pdata_c_find",
                            "pdata_c_get", "pdata_c_move"],
                           "6-PDU full DICOM workflow", is_valid=False),

            # Multi-context sequences: properly negotiated SOP classes
            # These reach the real C-FIND/C-STORE handlers (different code path
            # from Verification SOP context attacks above).
            StateTransition("multi_ctx_find",
                           ["assoc_rq_multi", "pdata_c_find_qr"],
                           "Multi-ctx ASSOC + C-FIND on negotiated Q/R ctx=5", is_valid=False),
            StateTransition("multi_ctx_store",
                           ["assoc_rq_multi", "pdata_c_store_ct"],
                           "Multi-ctx ASSOC + C-STORE on negotiated CT ctx=3 (partial)", is_valid=False),
            StateTransition("multi_ctx_store_find",
                           ["assoc_rq_multi", "pdata_c_store_ct", "pdata_c_find_qr"],
                           "Multi-ctx: C-STORE then C-FIND on negotiated contexts", is_valid=False),
            StateTransition("multi_ctx_full",
                           ["assoc_rq_multi", "pdata_valid", "pdata_c_store_ct",
                            "pdata_c_find_qr", "pdata_c_move_qr"],
                           "5-PDU multi-context full workflow on negotiated contexts", is_valid=False),

            # C-CANCEL attacks — cancel in-progress C-FIND or C-MOVE
            StateTransition("find_then_cancel",
                           ["assoc_rq", "pdata_c_find", "pdata_c_cancel"],
                           "C-FIND then C-CANCEL — cancel handler robustness", is_valid=False),
            StateTransition("move_then_cancel",
                           ["assoc_rq", "pdata_c_move", "pdata_c_cancel"],
                           "C-MOVE then C-CANCEL", is_valid=False),
            StateTransition("multi_ctx_find_cancel",
                           ["assoc_rq_multi", "pdata_c_find_qr", "pdata_c_cancel"],
                           "Negotiated C-FIND then C-CANCEL", is_valid=False),

            # N-class DIMSE commands: N-ACTION, N-CREATE, N-SET, N-DELETE
            StateTransition("n_action_attack",
                           ["assoc_rq", "pdata_n_action"],
                           "N-ACTION-RQ (0x0130) storage commitment handler", is_valid=False),
            StateTransition("n_create_attack",
                           ["assoc_rq", "pdata_n_create"],
                           "N-CREATE-RQ (0x0140) modality procedure step creation", is_valid=False),
            StateTransition("n_set_attack",
                           ["assoc_rq", "pdata_n_set"],
                           "N-SET-RQ (0x0120) SOP instance attribute modification", is_valid=False),
            StateTransition("n_delete_attack",
                           ["assoc_rq", "pdata_n_delete"],
                           "N-DELETE-RQ (0x0150) SOP instance deletion", is_valid=False),
            StateTransition("echo_n_create",
                           ["assoc_rq", "pdata_valid", "pdata_n_create"],
                           "Valid C-ECHO then N-CREATE (create worklist entry)", is_valid=False),
            StateTransition("n_set_then_delete",
                           ["assoc_rq", "pdata_n_set", "pdata_n_delete"],
                           "N-SET then N-DELETE — modify then delete", is_valid=False),

            # Study and worklist queries: different SOP classes and code paths
            StateTransition("study_find",
                           ["assoc_rq", "pdata_c_find_study"],
                           "C-FIND Study Root Q/R — study-level query handler", is_valid=False),
            StateTransition("worklist_find",
                           ["assoc_rq", "pdata_c_find_worklist"],
                           "C-FIND Modality Worklist — scheduling handler", is_valid=False),
            StateTransition("worklist_then_store",
                           ["assoc_rq", "pdata_c_find_worklist", "pdata_c_store"],
                           "Worklist query then C-STORE chain", is_valid=False),
            StateTransition("echo_study_find",
                           ["assoc_rq", "pdata_valid", "pdata_c_find_study"],
                           "Valid C-ECHO then Study Root C-FIND", is_valid=False),
            StateTransition("multi_ctx_worklist",
                           ["assoc_rq_multi", "pdata_c_find_worklist"],
                           "Multi-ctx ASSOC then Modality Worklist C-FIND", is_valid=False),
        ]

    def get_payload_targets(self) -> List[PayloadTarget]:
        return [
            # ASSOC_RQ fields — injected in every sequence
            PayloadTarget("called_ae", "called_ae", max_size=16, encoding="string"),
            PayloadTarget("calling_ae", "calling_ae", max_size=16, encoding="string"),
            PayloadTarget("abstract_syntax", "abstract_syntax", max_size=64, encoding="bytes"),
            PayloadTarget("transfer_syntax", "transfer_syntax", max_size=64, encoding="bytes"),
            PayloadTarget("impl_uid", "impl_uid", max_size=64, encoding="bytes"),
            # Dataset fields — only reachable via specific DIMSE commands;
            # preferred_sequence routes the action to the right PDU type.
            PayloadTarget("patient_name", "patient_name", max_size=64, encoding="string",
                          preferred_sequence="echo_then_find"),
            PayloadTarget("sop_instance_uid", "sop_instance_uid", max_size=64, encoding="string",
                          preferred_sequence="echo_partial_store"),
            # Study Root query injection: injectable into Study Root C-FIND (0020,000D)
            PayloadTarget("study_uid", "study_uid", max_size=64, encoding="string",
                          preferred_sequence="study_find"),
            # Worklist patient name injection (same field name, different delivery path)
            PayloadTarget("worklist_patient", "patient_name", max_size=64, encoding="string",
                          preferred_sequence="worklist_find"),
        ]

    def parse_response(self, data: bytes) -> Dict[str, Any]:
        if not data:
            return {"type": "empty", "success": False}

        pdu_type = data[0]
        result = {
            "type": PDU_TYPES.get(pdu_type, f"type_{pdu_type:02x}"),
            "pdu_type": pdu_type,
            "success": False,
            "raw_length": len(data),
        }

        if pdu_type == 0x02:  # A-ASSOCIATE-AC
            result["success"] = True
            result["type"] = "accept"
        elif pdu_type == 0x03:  # A-ASSOCIATE-RJ
            result["type"] = "reject"
            if len(data) >= 10:
                result["reject_result"] = data[7]
                result["reject_source"] = data[8]
                result["reject_reason"] = data[9]
        elif pdu_type == 0x04:  # P-DATA-TF
            result["success"] = True
            result["type"] = "pdata"
        elif pdu_type == 0x06:  # A-RELEASE-RP
            result["success"] = True
            result["type"] = "release"
        elif pdu_type == 0x07:  # A-ABORT
            result["type"] = "abort"
            if len(data) >= 10:
                result["abort_source"] = data[8]
                result["abort_reason"] = data[9]

        return result

    def is_interesting_response(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        resp_type = response.get("type", "")

        # Response rewards (multipliers applied to 15.0 base).
        # Ordering matches "how deep into server code did we reach":
        #   pdata/type_xx > empty > accept > release > abort >> reject/reset
        #
        # IMPORTANT: abort is intentionally LOW (0.3) to prevent the RL from
        # exploiting fast abort-inducing actions.  At 500ms per step, abort
        # would otherwise beat hang (4.5s) on reward-per-second even though
        # hang is the actual DoS vulnerability we want to find.
        rewards = {
            "pdata":   (True, 5.0),   # Server processed DIMSE and returned data (deepest path)
            "empty":   (True, 2.5),   # Closed without response (unexpected state)
            "accept":  (True, 1.0),   # Association accepted
            "release": (True, 0.8),   # Normal release
            "abort":   (True, 0.3),   # Server rejected PDU — common, not interesting
            "reject":  (False, 0.2),  # Association rejected (very common)
            "reset":   (False, 0.1),  # TCP reset (very common)
            "timeout": (True, 0.0),   # Handled separately by _send_sequence hang logic
        }

        # Unknown response types are very interesting (undocumented server state)
        if resp_type.startswith("type_"):
            return (True, 5.0)

        return rewards.get(resp_type, (False, 0.5))

    def check_health(self, host: str, port: int, timeout: float = 5.0) -> HealthCheckResult:
        """Send C-ECHO to check server health."""
        result = HealthCheckResult(is_healthy=False)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            t_start = time.monotonic()
            sock.connect((host, port))

            # Send ASSOC_RQ
            assoc_rq = self._build_assoc_rq({}, {})
            sock.sendall(assoc_rq)

            # Get response
            resp = sock.recv(4096)
            t_end = time.monotonic()

            result.latency_ms = (t_end - t_start) * 1000

            if resp and resp[0] == 0x02:  # ASSOC_AC
                result.is_healthy = True
                result.details["association"] = "accepted"

                # Send C-ECHO
                pdata = self._build_pdata({"command_field": 0x0030, "message_id": 1})
                sock.sendall(pdata)

                echo_resp = sock.recv(4096)
                if echo_resp and echo_resp[0] == 0x04:
                    result.details["c_echo"] = "success"
                else:
                    result.details["c_echo"] = "failed"

            elif resp and resp[0] == 0x03:
                result.details["association"] = "rejected"
            else:
                result.details["association"] = "unknown"

            sock.close()

        except socket.timeout:
            result.error = "timeout"
        except ConnectionRefusedError:
            result.error = "connection_refused"
        except Exception as e:
            result.error = str(e)

        return result

    def compute_reward(self, response: Dict[str, Any], response_time_ms: float,
                       field_mutations: Dict[str, Any],
                       payload_injections: Dict[str, bytes]) -> float:
        """DICOM-specific reward computation."""
        reward = 0.0

        # Base reward from response
        is_interesting, multiplier = self.is_interesting_response(response)
        if is_interesting:
            reward += 15.0 * multiplier

        # Slow-response bonus: reward responses significantly slower than the
        # server's normal latency (~315ms for this Orthanc instance).
        # Flat +25 for anything >100ms was useless since ALL responses are >315ms.
        # Now reward only genuinely abnormal slowness.
        if response_time_ms > 3000:     # >3s: very suspicious, possible blocking
            reward += 20.0
        elif response_time_ms > 1500:   # >1.5s: noticeably slow
            reward += 10.0
        elif response_time_ms > 800:    # >800ms: slightly above baseline (315ms)
            reward += 4.0

        # Semantic mutation bonus
        critical_fields = {"message_id", "context_id", "command_field"}
        for field in critical_fields:
            if field in field_mutations:
                val = field_mutations[field]
                # Bonus for boundary values
                if field == "message_id" and val in (0, 65535, 32767):
                    reward += 5.0
                elif field == "context_id" and val in (0, 2, 254):  # Invalid even
                    reward += 5.0
                elif field == "command_field" and val in (0x8030, 0xFFFF, 0x0000):
                    reward += 5.0

        # Payload bonus
        if payload_injections:
            reward += 8.0 * len(payload_injections)

        return reward
