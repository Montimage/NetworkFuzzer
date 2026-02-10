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
    0x0001, 0x0010, 0x0020, 0x0021, 0x0030, 0x0FFF,  # Valid requests
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
        return ["assoc_rq", "pdata", "release_rq", "abort", "assoc_ac", "assoc_rj"]

    def build_message(self, message_type: str, fields: Dict[str, Any],
                      payloads: Dict[str, bytes]) -> bytes:
        if message_type == "assoc_rq":
            return self._build_assoc_rq(fields, payloads)
        elif message_type == "pdata":
            return self._build_pdata(fields)
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
                           "Multiple PDATA in sequence", is_valid=False),
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
        ]

    def get_payload_targets(self) -> List[PayloadTarget]:
        return [
            PayloadTarget("called_ae", "called_ae", max_size=16, encoding="string"),
            PayloadTarget("calling_ae", "calling_ae", max_size=16, encoding="string"),
            PayloadTarget("abstract_syntax", "abstract_syntax", max_size=64, encoding="bytes"),
            PayloadTarget("transfer_syntax", "transfer_syntax", max_size=64, encoding="bytes"),
            PayloadTarget("impl_uid", "impl_uid", max_size=64, encoding="bytes"),
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

        # Response rewards
        rewards = {
            "timeout": (True, 5.0),    # Hang
            "pdata": (True, 2.5),      # Server processed our request
            "abort": (True, 1.5),      # Server entered abort state
            "accept": (True, 1.0),     # Association accepted
            "release": (True, 1.0),
            "reject": (False, 0.5),
            "reset": (False, 0.3),
            "empty": (True, 2.0),      # Server closed connection
        }

        # Unknown responses are interesting
        if resp_type.startswith("type_"):
            return (True, 3.0)

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

        # Time bonus
        if response_time_ms > 100:
            reward += 25.0
        elif response_time_ms > 50:
            reward += 12.0

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
