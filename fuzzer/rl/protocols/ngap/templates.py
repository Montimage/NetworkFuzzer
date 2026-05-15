#!/usr/bin/env python3
"""
Hardcoded NGAP binary templates for messages that mmt-dpi cannot re-encode.

NGSetup (3GPP TS 38.413 procedure code 21) is the only such case: mmt-dpi's
ngap.c handles UE-centric procedures but does not implement the NGSetup IE
decoder. We keep a valid APER-encoded NGSetup Request and patch the PLMN
bytes at runtime.

Template provenance
-------------------
Generated via pycrate (pycrate_asn1dir.NGAP) with:
    procedureCode = 21 (id-NGSetup)
    globalGNB-ID: PLMN=999/70, gNB-ID=0x10000 (22-bit)
    SupportedTAList: TAC=1, PLMN=999/70, SST=1
    DefaultPagingDRX: v32

Verified: open5GS AMF responds with NGSetupResponse (0x20 0x15) when this
PDU is sent with the correct PLMN (999/70 for the default sample.yaml config).

To regenerate:
    from pycrate_asn1dir.NGAP import NGAP_PDU_Descriptions as D
    pdu = D.NGAP_PDU
    pdu.set_val(('initiatingMessage', {
        'procedureCode': 21, 'criticality': 'reject',
        'value': ('NGSetupRequest', {'protocolIEs': [
            {'id': 27, 'criticality': 'reject',
             'value': ('GlobalRANNodeID', ('globalGNB-ID', {
                 'pLMNIdentity': b'\x99\xf9\x07',
                 'gNB-ID': ('gNB-ID', (0x10000, 22))}))},
            {'id': 102, 'criticality': 'reject',
             'value': ('SupportedTAList', [{'tAC': b'\x00\x00\x01',
                 'broadcastPLMNList': [{'pLMNIdentity': b'\x99\xf9\x07',
                     'tAISliceSupportList': [{'s-NSSAI': {'sST': b'\x01'}}]}]}])},
            {'id': 21, 'criticality': 'ignore', 'value': ('PagingDRX', 'v32')}
        ]})
    }))
    print(pdu.to_aper().hex())
"""

# ---------------------------------------------------------------------------
# NG Setup Request template (41 bytes, APER-encoded, proc_code=21)
# Original PLMN: MCC=999 MNC=70 (99 f9 07) — replaced at runtime.
# Verified to elicit NGSetupResponse from open5GS AMF (sample.yaml config).
# ---------------------------------------------------------------------------
NG_SETUP_REQUEST_TEMPLATE = bytes.fromhex(
    '00150025000003'
    '001b00080099f907000400000066000d00000000010099f907000000080015400100'
)

# Original PLMN bytes in the template (MCC=999 MNC=70).
# All occurrences are replaced when build_ng_setup_request() is called.
_ORIGINAL_PLMN = bytes.fromhex('99f907')


def encode_plmn(mcc: str, mnc: str) -> bytes:
    """
    Encode MCC/MNC into the 3-byte PLMN Identity BCD format.

    Layout (3GPP TS 24.008 §10.5.1.13):
        octet 1: MCC digit 2 | MCC digit 1
        octet 2: MNC digit 3 | MCC digit 3   (MNC digit 3 = 0xF if 2-digit MNC)
        octet 3: MNC digit 2 | MNC digit 1

    Examples:
        MCC=999, MNC=70  → b'\\x99\\xf9\\x07'  (open5GS default sample.yaml)
        MCC=901, MNC=70  → b'\\x09\\xf1\\x07'
        MCC=001, MNC=01  → b'\\x00\\xf1\\x10'
    """
    mcc = mcc.zfill(3)
    mnc = mnc.zfill(2) if len(mnc) <= 2 else mnc.zfill(3)

    octet1 = (int(mcc[1]) << 4) | int(mcc[0])
    if len(mnc) == 2:
        octet2 = (0xF << 4) | int(mcc[2])
    else:
        octet2 = (int(mnc[2]) << 4) | int(mcc[2])
    octet3 = (int(mnc[1]) << 4) | int(mnc[0])

    return bytes([octet1, octet2, octet3])


def build_ng_setup_request(gnb_id: int = 1,
                           plmn_mcc: str = '999',
                           plmn_mnc: str = '70') -> bytes:
    """
    Return a valid NG Setup Request PDU patched for the given PLMN.

    When plmn_mcc='999' and plmn_mnc='70' (the defaults, matching the
    open5GS sample.yaml config), the template is returned unchanged and
    the AMF responds with NGSetupResponse.
    """
    plmn = encode_plmn(plmn_mcc, plmn_mnc)
    return NG_SETUP_REQUEST_TEMPLATE.replace(_ORIGINAL_PLMN, plmn)
