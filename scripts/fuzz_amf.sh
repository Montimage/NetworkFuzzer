#!/usr/bin/env bash
#
# fuzz_amf.sh — run the RL fuzzer against a 5G core's AMF over NGAP (N2/SCTP).
#
# Twin of fuzz_udm.sh/fuzz_udr.sh but for the NGAP protocol: the fuzzer connects
# as a gNB to the AMF's N2 SCTP endpoint and fuzzes NGAP PDUs / IEs (and, with
# --protocol ngap_nas, the NAS payloads inside them).  Coverage-guided reward
# works the same as the SBI scripts when AMF is run from its -cover binary.
#
# Targets two cores via CORE (default: open5gs):
#   CORE=open5gs   open5GS AMF  (127.0.0.5:38412)
#   CORE=free5gc   free5GC AMF  (127.0.0.18:38412)
#
# Coverage-guided (free5GC) workflow — AMF instrumented, NRF up:
#   sudo scripts/free5gc.sh build-cover main amf
#   sudo COVER_NFS=amf scripts/free5gc.sh start main
#   GO_COVER_EVAL_EVERY=100 CORE=free5gc \
#     RESTART_CMD='sudo scripts/free5gc.sh start-cover main amf' ./scripts/fuzz_amf.sh
#   sudo scripts/free5gc.sh stop main
#   scripts/free5gc.sh coverage main amf --func
#
# PROTO=ngap_nas fuzzes NAS-in-NGAP (deeper; reaches SMF via PDU-session flows).
#
# Override via env vars: CORE, FREE5GC_VERSION, PROTO, TIMESTEPS, MAX_STEPS,
# ANNEAL_STEPS, RESTART_CMD, PLMN_MCC, PLMN_MNC, GNB_ID.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

CORE="${CORE:-open5gs}"
PROTO="${PROTO:-ngap}"          # ngap | ngap_nas
TIMESTEPS="${TIMESTEPS:-100000}"
MAX_STEPS="${MAX_STEPS:-20}"
ANNEAL_STEPS="${ANNEAL_STEPS:-8000}"
GNB_ID="${GNB_ID:-1}"

case "${CORE}" in
    open5gs)
        PLMN_MCC="${PLMN_MCC:-999}"
        PLMN_MNC="${PLMN_MNC:-70}"
        RESTART_CMD="${RESTART_CMD:-sudo scripts/open5gs.sh restart main}"
        ;;
    free5gc)
        FREE5GC_VERSION="${FREE5GC_VERSION:-main}"
        PLMN_MCC="${PLMN_MCC:-208}"
        PLMN_MNC="${PLMN_MNC:-93}"
        RESTART_CMD="${RESTART_CMD:-sudo scripts/free5gc.sh start-nf ${FREE5GC_VERSION} amf}"
        ;;
    *)
        echo "ERROR: unknown CORE '${CORE}' (expected 'open5gs' or 'free5gc')" >&2
        exit 1
        ;;
esac

PYTHON="${PYTHON:-python}"
if [[ -x "${REPO_ROOT}/venv/bin/python" && -z "${VIRTUAL_ENV:-}" ]]; then
    PYTHON="${REPO_ROOT}/venv/bin/python"
fi

echo "======================================================================"
echo "  AMF fuzzing run (NGAP)"
echo "    core          : ${CORE}   PLMN: ${PLMN_MCC}/${PLMN_MNC}   gNB: ${GNB_ID}"
echo "    protocol      : ${PROTO}"
echo "    python        : ${PYTHON}"
echo "    timesteps     : ${TIMESTEPS}   max-steps: ${MAX_STEPS}   anneal: ${ANNEAL_STEPS}"
echo "    restart-cmd   : ${RESTART_CMD}"
[[ $# -gt 0 ]] && echo "    extra args    : $*"
echo "======================================================================"

# Coverage-guided reward auto-activates when --core free5gc and a start-cover AMF
# is running (train_protocol auto-derives /tmp/free5gc-<ver>-cov/amf).
exec "${PYTHON}" -m fuzzer.rl.train_protocol \
    --protocol "${PROTO}" \
    --core "${CORE}" \
    --plmn-mcc "${PLMN_MCC}" \
    --plmn-mnc "${PLMN_MNC}" \
    --gnb-id "${GNB_ID}" \
    --timesteps "${TIMESTEPS}" \
    --max-steps "${MAX_STEPS}" \
    --anneal-steps "${ANNEAL_STEPS}" \
    --restart-cmd "${RESTART_CMD}" \
    "$@"
