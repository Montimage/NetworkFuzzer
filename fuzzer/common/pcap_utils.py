#!/usr/bin/env python3
"""
Shared PCAP/PDU utilities used by both GAN and RL components.

Extracted from synthetic_to_pcap.py — provides:
  - wrap_tcp_ip()        — Wrap DICOM PDUs in TCP/IP packets
  - build_associate_rq() — Build A-ASSOCIATE-RQ PDU
  - build_associate_ac() — Build A-ASSOCIATE-AC PDU
  - build_release_rq()   — Build A-RELEASE-RQ PDU
  - build_release_rp()   — Build A-RELEASE-RP PDU
"""

import struct

from scapy.all import IP, TCP, Raw, Ether, conf

# Suppress scapy warnings
conf.verb = 0

# Standard DICOM UIDs
VERIFICATION_SOP = "1.2.840.10008.1.1"
IMPLICIT_VR_LE = "1.2.840.10008.1.2"
DICOM_APP_CONTEXT = "1.2.840.10008.3.1.1.1"

# Default network parameters
DEFAULT_SRC_IP = "192.168.1.100"
DEFAULT_DST_IP = "192.168.1.200"
DEFAULT_SRC_PORT = 50000
DEFAULT_DST_PORT = 4006


def _pad_ae_title(ae_title, length=16):
    """Pad AE title to 16 bytes with spaces (DICOM PS3.8 requirement)."""
    if isinstance(ae_title, str):
        ae_bytes = ae_title.encode('latin-1', errors='replace')
    else:
        ae_bytes = ae_title
    ae_bytes = ae_bytes[:length]
    ae_bytes = ae_bytes + b' ' * (length - len(ae_bytes))
    return ae_bytes


def _encode_uid(uid_str):
    """Encode a UID string to bytes, with odd-length padding."""
    if isinstance(uid_str, str):
        uid_bytes = uid_str.encode('ascii', errors='replace')
    else:
        uid_bytes = uid_str
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
    """Build Presentation Context Item for A-ASSOCIATE-RQ (type 0x20)."""
    abs_uid = _encode_uid(abstract_syntax)
    abs_item = _build_sub_item(0x30, abs_uid)

    xfer_items = b''
    if isinstance(transfer_syntaxes, str):
        transfer_syntaxes = [transfer_syntaxes]
    for ts in transfer_syntaxes:
        ts_uid = _encode_uid(ts)
        xfer_items += _build_sub_item(0x40, ts_uid)

    pctx_data = struct.pack('!B3x', ctx_id) + abs_item + xfer_items
    return _build_item(0x20, pctx_data)


def build_presentation_context_ac(ctx_id, result, transfer_syntax):
    """Build Presentation Context Item for A-ASSOCIATE-AC (type 0x21)."""
    ts_uid = _encode_uid(transfer_syntax)
    ts_item = _build_sub_item(0x40, ts_uid)

    pctx_data = struct.pack('!BBBB', ctx_id, 0x00, result, 0x00) + ts_item
    return _build_item(0x21, pctx_data)


def build_user_info_item(max_pdu_len=16384, impl_uid=None, impl_version=None):
    """Build User Information Item (type 0x50) with sub-items."""
    sub_items = b''

    max_len_data = struct.pack('!I', max_pdu_len)
    sub_items += _build_sub_item(0x51, max_len_data)

    if impl_uid is None:
        impl_uid = "1.2.826.0.1.3680043.9.3811.2.1.0"
    uid_data = _encode_uid(impl_uid)
    sub_items += _build_sub_item(0x52, uid_data)

    if impl_version is None:
        impl_version = "NETWORKFUZZER"
    ver_data = impl_version.encode('ascii', errors='replace')
    sub_items += _build_sub_item(0x55, ver_data)

    return _build_item(0x50, sub_items)


def build_associate_rq(called_ae="ANY-SCP", calling_ae="PYNETDICOM",
                       abstract_syntaxes=None, transfer_syntaxes=None,
                       max_pdu_len=16384, app_context=None):
    """Build A-ASSOCIATE-RQ PDU (type 0x01) per DICOM PS3.8 Section 9.3.2."""
    if abstract_syntaxes is None:
        abstract_syntaxes = [VERIFICATION_SOP]
    if transfer_syntaxes is None:
        transfer_syntaxes = [IMPLICIT_VR_LE]

    variable_items = b''
    variable_items += build_application_context_item(app_context)

    for i, abs_syn in enumerate(abstract_syntaxes if isinstance(abstract_syntaxes, list) else [abstract_syntaxes]):
        ctx_id = 2 * i + 1
        variable_items += build_presentation_context_rq(ctx_id, abs_syn, transfer_syntaxes)

    variable_items += build_user_info_item(max_pdu_len)

    protocol_version = 0x0001
    called = _pad_ae_title(called_ae)
    calling = _pad_ae_title(calling_ae)
    reserved_32 = b'\x00' * 32

    pdu_data = struct.pack('!HH', protocol_version, 0x0000) + \
               called + calling + reserved_32 + variable_items

    pdu_header = struct.pack('!BBI', 0x01, 0x00, len(pdu_data))
    return pdu_header + pdu_data


def build_associate_ac(called_ae="ANY-SCP", calling_ae="PYNETDICOM",
                       abstract_syntaxes=None, transfer_syntaxes=None,
                       max_pdu_len=16384, app_context=None):
    """Build A-ASSOCIATE-AC PDU (type 0x02) per DICOM PS3.8 Section 9.3.3."""
    if abstract_syntaxes is None:
        abstract_syntaxes = [VERIFICATION_SOP]
    if transfer_syntaxes is None:
        transfer_syntaxes = [IMPLICIT_VR_LE]

    variable_items = b''
    variable_items += build_application_context_item(app_context)

    for i, _ in enumerate(abstract_syntaxes if isinstance(abstract_syntaxes, list) else [abstract_syntaxes]):
        ctx_id = 2 * i + 1
        ts = transfer_syntaxes[0] if isinstance(transfer_syntaxes, list) else transfer_syntaxes
        variable_items += build_presentation_context_ac(ctx_id, 0, ts)

    variable_items += build_user_info_item(max_pdu_len)

    protocol_version = 0x0001
    called = _pad_ae_title(called_ae)
    calling = _pad_ae_title(calling_ae)
    reserved_32 = b'\x00' * 32

    pdu_data = struct.pack('!HH', protocol_version, 0x0000) + \
               called + calling + reserved_32 + variable_items

    pdu_header = struct.pack('!BBI', 0x02, 0x00, len(pdu_data))
    return pdu_header + pdu_data


def build_release_rq():
    """Build A-RELEASE-RQ PDU (type 0x05). Fixed 10 bytes."""
    return struct.pack('!BBI', 0x05, 0x00, 4) + b'\x00' * 4


def build_release_rp():
    """Build A-RELEASE-RP PDU (type 0x06). Fixed 10 bytes."""
    return struct.pack('!BBI', 0x06, 0x00, 4) + b'\x00' * 4


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
    is_client = True
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
