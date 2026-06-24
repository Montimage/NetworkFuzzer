#!/usr/bin/env python3
"""
Pre-flight reachability + provisioning checks for SBI fuzzing campaigns.

Catches the two depth-killing misconfigurations that otherwise burn a whole NF
job collecting ``bad_request`` noise instead of exercising handler logic:

  1. **Reachability** — the NF process is down or not answering HTTP/2 on its
     SBI port, or it is up but pointed at the wrong NRF and never registers
     (the "NRF wrong IP" class of bug that previously starved PCF of depth).
     We reuse :meth:`SbiAdapter.check_health`, the same probe the trainer uses.

  2. **Provisioning** — the target subscriber is absent from MongoDB, so every
     stateful UDR / UDM / PCF / SMF / AUSF request hits "Cannot find SUPI in DB"
     / "Data not found" → 404 and never reaches handler logic. We verify the
     subscriber exists and, when ``auto_provision`` is set, add it idempotently:
       - open5GS via ``open5gs-dbctl`` (subscribers collection)
       - free5GC via direct mongosh upserts into the ``free5gc`` DB (auth +
         provisioned + policy collections, keyed by ueId — mirrors free5GC's own
         test/mongodb.go fixture).  This unblocks the UDM UEAU auth-vector path.

Used by ``run_campaign.py`` before each NF job. Can also be run standalone:

    python -m fuzzer.rl.preflight --nf UDR --core open5gs
    python -m fuzzer.rl.preflight --nf UDM --provision-imsi 001010000000001
    python -m fuzzer.rl.preflight --nf UDM --core free5gc          # 208930000000001
    python -m fuzzer.rl.preflight --nf UDR --core free5gc --plmn-mcc 208 --plmn-mnc 93
"""

import argparse
import os
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# NF → SBI host maps (mirror of train_protocol._SBI_NF_HOSTS; kept local so the
# preflight has no import-time dependency on the trainer's arg parsing).
# ---------------------------------------------------------------------------

_SBI_NF_HOSTS = {
    'open5gs': {
        'NRF': '127.0.0.10', 'UDR': '127.0.0.20', 'UDM': '127.0.0.12',
        'AUSF': '127.0.0.11', 'BSF': '127.0.0.15', 'PCF': '127.0.0.13',
        'NSSF': '127.0.0.14', 'AMF': '127.0.0.5',  'SMF': '127.0.0.4',
    },
    'free5gc': {
        'NRF': '127.0.0.10', 'AMF': '127.0.0.18', 'SMF': '127.0.0.2',
        'UDR': '127.0.0.4',  'UDM': '127.0.0.3',  'AUSF': '127.0.0.9',
        'PCF': '127.0.0.7',  'BSF': '127.0.0.31', 'NSSF': '127.0.0.15',
        'CHF': '127.0.0.113',
    },
}

# NFs whose handler logic is only reachable once a subscriber is provisioned.
# NRF holds no subscriber state, so it is excluded.
_NEEDS_SUBSCRIBER = {'UDR', 'UDM', 'PCF', 'SMF', 'AUSF', 'AMF'}

# Standard open5GS test credentials (matches misc/db defaults & most tutorials).
_DEFAULT_KEY = '465B5CE8B199B49FAA5F0A2EE238A6BC'
_DEFAULT_OPC = 'E8ED289DEBA952E4283B54E88E6183CA'

# Session slice the SBI adapter assumes (sst=1, sd=010203, dnn=internet).
_DEFAULT_DNN = 'internet'
_DEFAULT_SST = '1'
_DEFAULT_SD  = '010203'

_DEFAULT_DB_URI = 'mongodb://localhost/open5gs'

# free5GC stores subscribers in a separate MongoDB database with a completely
# different layout (one collection per dotted name, keyed by ueId) and is *not*
# managed by open5gs-dbctl.  These are the free5GC defaults.
_FREE5GC_DB_URI = 'mongodb://localhost/free5gc'

# Per-core default SBI port (open5gs 7777, free5gc 8000) for the reachability probe.
_CORE_DEFAULT_PORT = {'open5gs': 7777, 'free5gc': 8000}

# free5GC default test subscriber crypto (matches the webconsole "New Subscriber"
# form defaults).  Exact values are irrelevant for fuzzing — what matters is that
# the auth-subscription doc exists so UDM's UEAU flow proceeds past the UDR lookup
# into Milenage auth-vector generation instead of returning "Data not found".
_F5GC_KEY = '8baf473f2f8fd09487cccbd7097c6862'   # permanent key K
_F5GC_OPC = '8e27b6af0e692e750f32667a3b14605d'   # OPc
_F5GC_SQN = '000000000023'
_F5GC_AMF = '8000'

# Candidate locations for open5gs-dbctl, in priority order.
_DBCTL_CANDIDATES = [
    os.environ.get('OPEN5GS_DBCTL', ''),
    '/home/strongcourage/open5gs/misc/db/open5gs-dbctl',
    '/home/strongcourage/open5gs/build_main/misc/db/open5gs-dbctl',
]


def serving_plmn_id(mcc: str, mnc: str) -> str:
    """free5GC servingPlmnId = mcc concatenated with mnc (e.g. 208/93 → '20893')."""
    return f'{mcc}{mnc}'


def nf_host(core: str, nf_type: str) -> str:
    """Return the SBI host IP for the given NF, or '127.0.0.1' if unknown."""
    return _SBI_NF_HOSTS.get(core, {}).get(nf_type.upper(), '127.0.0.1')


def find_dbctl(explicit: str = '') -> str:
    """Locate open5gs-dbctl: explicit arg → known paths → $PATH. '' if absent."""
    for cand in [explicit, *_DBCTL_CANDIDATES]:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    found = shutil.which('open5gs-dbctl')
    return found or ''


def _bare_imsi(imsi: str) -> str:
    """Strip the 'imsi-' prefix and any null-injection suffix → 15 bare digits."""
    s = imsi.split('\x00', 1)[0]
    if s.startswith('imsi-'):
        s = s[len('imsi-'):]
    return s


def plmn_matched_imsi(mcc: str, mnc: str) -> str:
    """Bare 15-digit IMSI whose home PLMN matches mcc/mnc (msin ends in …0001).

    Stateful NFs (SMF/AMF) require a subscriber whose home PLMN equals the
    serving network, else SMF treats the session as HR roaming.  Mirrors
    SbiAdapter.get_baseline_fields()'s SUPI derivation.
    """
    msin = '0' * (15 - 3 - len(mnc) - 1) + '1'
    return f'{mcc}{mnc}{msin}'


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------

def check_reachable(core: str, nf_type: str, port: int = 7777,
                    timeout: float = 5.0):
    """Probe the NF over HTTP/2. Returns (ok: bool, detail: str)."""
    host = nf_host(core, nf_type)
    try:
        from fuzzer.rl.protocols.sbi.adapter import SbiAdapter
    except Exception as exc:  # pragma: no cover - import guard
        return False, f'cannot import SbiAdapter: {exc}'

    try:
        adapter = SbiAdapter(nf_type=nf_type, core=core)
        res = adapter.check_health(host, port, timeout=timeout)
    except Exception as exc:
        return False, f'health check raised: {exc}'

    if res.is_healthy:
        status = res.details.get('status')
        return True, f'{host}:{port} healthy (status={status}, {res.latency_ms:.0f} ms)'

    mode = res.details.get('failure_mode', 'unreachable')
    return False, f'{host}:{port} {mode}: {res.error or "no HTTP/2 response"}'


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------

def subscriber_exists(imsi: str, db_uri: str = _DEFAULT_DB_URI) -> bool:
    """Return True if the bare-IMSI subscriber exists in MongoDB."""
    mongosh = shutil.which('mongosh') or shutil.which('mongo')
    if not mongosh:
        raise RuntimeError('mongosh/mongo not found — cannot check provisioning')
    bare = _bare_imsi(imsi)
    out = subprocess.run(
        [mongosh, '--quiet', db_uri, '--eval',
         f'db.subscribers.countDocuments({{imsi:"{bare}"}})'],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
    )
    return out.returncode == 0 and out.stdout.strip().splitlines()[-1].strip() not in ('0', '')


def provision_subscriber(imsi: str, dbctl: str,
                         key: str = _DEFAULT_KEY, opc: str = _DEFAULT_OPC,
                         dnn: str = _DEFAULT_DNN, sst: str = _DEFAULT_SST,
                         sd: str = _DEFAULT_SD, db_uri: str = _DEFAULT_DB_URI):
    """Add the subscriber via dbctl add_ue_with_slice. Returns (ok, detail)."""
    bare = _bare_imsi(imsi)
    # Pass the full URI *including* the db name — dbctl forwards it straight to
    # mongosh, and a host-only URI silently lands in the default 'test' db.
    cmd = [dbctl, f'--db_uri={db_uri}',
           'add_ue_with_slice', bare, key, opc, dnn, sst, sd]
    r = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return False, f'dbctl add failed (rc={r.returncode}): {r.stderr.strip()[:200]}'
    return True, f'provisioned imsi-{bare} (sst={sst} sd={sd} dnn={dnn})'


def ensure_provisioned(imsi: str, dbctl: str = '', auto_provision: bool = True,
                       db_uri: str = _DEFAULT_DB_URI):
    """Ensure the subscriber exists; add it if missing and auto_provision.

    Returns (ok: bool, detail: str). ``ok`` is True when the subscriber is
    present after the call (already there, or successfully provisioned).
    """
    try:
        if subscriber_exists(imsi, db_uri):
            return True, f'subscriber {_bare_imsi(imsi)} already provisioned'
    except Exception as exc:
        return False, str(exc)

    if not auto_provision:
        return False, (f'subscriber {_bare_imsi(imsi)} MISSING — provision with:\n'
                       f'    open5gs-dbctl add_ue_with_slice {_bare_imsi(imsi)} '
                       f'{_DEFAULT_KEY} {_DEFAULT_OPC} '
                       f'{_DEFAULT_DNN} {_DEFAULT_SST} {_DEFAULT_SD}')

    dbctl = find_dbctl(dbctl)
    if not dbctl:
        return False, ('subscriber missing and open5gs-dbctl not found '
                       '(set --dbctl or $OPEN5GS_DBCTL)')

    ok, detail = provision_subscriber(imsi, dbctl, db_uri=db_uri)
    if not ok:
        return False, detail
    # Re-verify the write landed.
    try:
        if subscriber_exists(imsi, db_uri):
            return True, detail
    except Exception:
        pass
    return False, f'{detail} — but subscriber still not visible in DB'


# ---------------------------------------------------------------------------
# free5GC provisioning  (direct MongoDB writes — no dbctl equivalent)
# ---------------------------------------------------------------------------

def _free5gc_subscriber_docs(ue_id: str, serving_plmn: str,
                             key: str = _F5GC_KEY, opc: str = _F5GC_OPC,
                             sqn: str = _F5GC_SQN, amf: str = _F5GC_AMF,
                             dnn: str = _DEFAULT_DNN, sst: str = _DEFAULT_SST,
                             sd: str = _DEFAULT_SD):
    """Build the (collection, filter, document) set for one free5GC subscriber.

    Mirrors free5GC's own test fixture (test/mongodb.go::InsertUeToMongoDB) and
    the openapi model field names (encPermanentKey / encOpcKey / sequenceNumber).
    Covers the docs that gate UDM/UDR/PCF handler depth:
      - authenticationSubscription → UDM UEAU auth-vector path (the QueryAuthSubsData
        "Data not found" that otherwise stalls every auth request)
      - provisionedData.{amData,smfSelectionSubscriptionData,smData} → UDM SDM GETs
      - policyData.ues.{amData,smData} → PCF / UDR policy reads
    """
    snssai = {'sst': int(sst), 'sd': sd}
    nssai_key = f'{int(sst):02x}{sd}'           # e.g. sst=1 sd=010203 → '01010203'
    ambr = {'uplink': '1000 Kbps', 'downlink': '1000 Kbps'}

    return [
        ('subscriptionData.authenticationData.authenticationSubscription',
         {'ueId': ue_id},
         {'ueId': ue_id,
          'authenticationMethod': '5G_AKA',
          'encPermanentKey': key,
          'encOpcKey': opc,
          'authenticationManagementField': amf,
          'sequenceNumber': {'sqn': sqn}}),

        ('subscriptionData.provisionedData.amData',
         {'ueId': ue_id, 'servingPlmnId': serving_plmn},
         {'ueId': ue_id, 'servingPlmnId': serving_plmn,
          'subscribedUeAmbr': ambr,
          'nssai': {'defaultSingleNssais': [snssai], 'singleNssais': [snssai]}}),

        ('subscriptionData.provisionedData.smfSelectionSubscriptionData',
         {'ueId': ue_id, 'servingPlmnId': serving_plmn},
         {'ueId': ue_id, 'servingPlmnId': serving_plmn,
          'subscribedSnssaiInfos': {nssai_key: {'dnnInfos': [{'dnn': dnn}]}}}),

        ('subscriptionData.provisionedData.smData',
         {'ueId': ue_id, 'servingPlmnId': serving_plmn},
         {'ueId': ue_id, 'servingPlmnId': serving_plmn,
          'singleNssai': snssai,
          'dnnConfigurations': {dnn: {
              'sscModes': {'defaultSscMode': 'SSC_MODE_1',
                           'allowedSscModes': ['SSC_MODE_1', 'SSC_MODE_2', 'SSC_MODE_3']},
              'pduSessionTypes': {'defaultSessionType': 'IPV4',
                                  'allowedSessionTypes': ['IPV4']},
              'sessionAmbr': ambr,
              '5gQosProfile': {'5qi': 9,
                               'arp': {'priorityLevel': 8,
                                       'preemptCap': 'NOT_PREEMPT',
                                       'preemptVuln': 'NOT_PREEMPTABLE'},
                               'priorityLevel': 8}}}}),

        ('policyData.ues.amData',
         {'ueId': ue_id},
         {'ueId': ue_id, 'subscCats': ['free5gc']}),

        ('policyData.ues.smData',
         {'ueId': ue_id},
         {'ueId': ue_id,
          'smPolicySnssaiData': {nssai_key: {
              'snssai': snssai,
              'smPolicyDnnData': {dnn: {'dnn': dnn}}}}}),
    ]


def subscriber_exists_free5gc(ue_id: str, db_uri: str = _FREE5GC_DB_URI) -> bool:
    """Return True if the free5GC auth-subscription doc exists for ueId."""
    mongosh = shutil.which('mongosh') or shutil.which('mongo')
    if not mongosh:
        raise RuntimeError('mongosh/mongo not found — cannot check provisioning')
    coll = 'subscriptionData.authenticationData.authenticationSubscription'
    # mongosh (Node-based) has a slow cold start (~10s here); allow generous margin.
    out = subprocess.run(
        [mongosh, '--quiet', db_uri, '--eval',
         f'db.getCollection("{coll}").countDocuments({{ueId:"{ue_id}"}})'],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
    )
    return (out.returncode == 0
            and out.stdout.strip().splitlines()[-1].strip() not in ('0', ''))


def provision_subscriber_free5gc(ue_id: str, serving_plmn: str,
                                 db_uri: str = _FREE5GC_DB_URI, **kw):
    """Upsert the full free5GC subscriber doc set via mongosh. Returns (ok, detail)."""
    import json
    mongosh = shutil.which('mongosh') or shutil.which('mongo')
    if not mongosh:
        return False, 'mongosh/mongo not found — cannot provision free5GC subscriber'

    docs = _free5gc_subscriber_docs(ue_id, serving_plmn, **kw)
    payload = [{'c': c, 'f': f, 'd': d} for (c, f, d) in docs]
    # Embed the docs as JSON (valid JS) and upsert each idempotently.
    js = ('const docs = ' + json.dumps(payload) + ';'
          'let n=0; docs.forEach(function(x){'
          'db.getCollection(x.c).replaceOne(x.f, x.d, {upsert:true}); n++;});'
          'print("upserted "+n+" docs");')
    r = subprocess.run([mongosh, '--quiet', db_uri, '--eval', js],
                       stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=60)
    if r.returncode != 0:
        return False, f'mongosh upsert failed (rc={r.returncode}): {r.stderr.strip()[:200]}'
    return True, (f'provisioned {ue_id} (plmn={serving_plmn}, {len(docs)} docs: '
                  'auth + am/smf/sm subscription + am/sm policy)')


def ensure_provisioned_free5gc(ue_id: str, serving_plmn: str,
                               auto_provision: bool = True,
                               db_uri: str = _FREE5GC_DB_URI, **kw):
    """Ensure the free5GC subscriber exists; upsert it if missing and auto_provision.

    Returns (ok: bool, detail: str).
    """
    try:
        if subscriber_exists_free5gc(ue_id, db_uri):
            return True, f'subscriber {ue_id} already provisioned'
    except Exception as exc:
        return False, str(exc)

    if not auto_provision:
        return False, (f'subscriber {ue_id} MISSING — provision via the free5GC '
                       'webconsole, or re-run without --no-provision')

    ok, detail = provision_subscriber_free5gc(ue_id, serving_plmn, db_uri=db_uri, **kw)
    if not ok:
        return False, detail
    try:
        if subscriber_exists_free5gc(ue_id, db_uri):
            return True, detail
    except Exception:
        pass
    return False, f'{detail} — but subscriber still not visible in DB'


def preflight_nf(nf_type: str, core: str = 'open5gs', port: int = None,
                 imsi: str = '001010000000001', dbctl: str = '',
                 auto_provision: bool = True, db_uri: str = None,
                 check_provisioning: bool = True, serving_plmn: str = None):
    """Run reachability + (conditional) provisioning checks for one NF.

    Returns a dict: {nf, reachable, reach_detail, provisioned, prov_detail}.
    provisioned is None when the NF does not require subscriber state.
    """
    nf = nf_type.upper()

    # Resolve core-dependent defaults so callers (run_campaign) that only pass
    # the open5gs defaults still probe the right port/DB for free5GC.
    if not port:
        port = _CORE_DEFAULT_PORT.get(core, 7777)
    if core == 'free5gc' and (not db_uri or 'free5gc' not in db_uri):
        db_uri = _FREE5GC_DB_URI
    elif not db_uri:
        db_uri = _DEFAULT_DB_URI

    reachable, reach_detail = check_reachable(core, nf, port)

    provisioned, prov_detail = None, 'n/a (no subscriber state)'
    if check_provisioning and nf in _NEEDS_SUBSCRIBER:
        if core == 'open5gs':
            provisioned, prov_detail = ensure_provisioned(
                imsi, dbctl=dbctl, auto_provision=auto_provision, db_uri=db_uri)
        elif core == 'free5gc':
            ue_id = f'imsi-{_bare_imsi(imsi)}'
            # serving PLMN: explicit arg, else derived from the IMSI's mcc(3)+mnc(2)
            # prefix (free5GC default 208/93 → '20893').
            plmn = serving_plmn or _bare_imsi(imsi)[:5]
            provisioned, prov_detail = ensure_provisioned_free5gc(
                ue_id, plmn, auto_provision=auto_provision, db_uri=db_uri)

    return {
        'nf': nf,
        'reachable': reachable,
        'reach_detail': reach_detail,
        'provisioned': provisioned,
        'prov_detail': prov_detail,
    }


def main() -> int:
    p = argparse.ArgumentParser(description='SBI pre-flight reachability + provisioning check')
    p.add_argument('--nf', required=True, help='NF type (UDR, UDM, ...)')
    p.add_argument('--core', default='open5gs', choices=['open5gs', 'free5gc'])
    p.add_argument('--port', type=int, default=None,
                   help='SBI port (default: 7777 open5gs / 8000 free5gc)')
    p.add_argument('--provision-imsi', default=None,
                   help='IMSI to provision (default: 001010000000001 open5gs / '
                        '208930000000001 free5gc)')
    p.add_argument('--plmn-mcc', default=None,
                   help='free5GC: serving-PLMN MCC for the subscriber (default 208)')
    p.add_argument('--plmn-mnc', default=None,
                   help='free5GC: serving-PLMN MNC for the subscriber (default 93)')
    p.add_argument('--dbctl', default='', help='Path to open5gs-dbctl (open5gs only)')
    p.add_argument('--db-uri', default=None,
                   help='Mongo URI (default: open5gs / free5gc DB per --core)')
    p.add_argument('--no-provision', action='store_true',
                   help='Warn on missing subscriber instead of auto-provisioning')
    args = p.parse_args()

    # Core-aware defaults so the standalone CLI "just works" for free5GC.
    imsi = args.provision_imsi or (
        '208930000000001' if args.core == 'free5gc' else '001010000000001')
    serving = None
    if args.core == 'free5gc':
        serving = serving_plmn_id(args.plmn_mcc or '208', args.plmn_mnc or '93')

    r = preflight_nf(args.nf, core=args.core, port=args.port,
                     imsi=imsi, dbctl=args.dbctl,
                     auto_provision=not args.no_provision, db_uri=args.db_uri,
                     serving_plmn=serving)

    print(f"[{r['nf']}] reachable : {'OK ' if r['reachable'] else 'FAIL'} — {r['reach_detail']}")
    if r['provisioned'] is None:
        print(f"[{r['nf']}] provision : {r['prov_detail']}")
    else:
        print(f"[{r['nf']}] provision : {'OK ' if r['provisioned'] else 'FAIL'} — {r['prov_detail']}")

    return 0 if r['reachable'] and (r['provisioned'] is not False) else 1


if __name__ == '__main__':
    sys.exit(main())
