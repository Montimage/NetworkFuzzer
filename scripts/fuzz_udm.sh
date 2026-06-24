#!/usr/bin/env bash
#
# fuzz_udm.sh — run the RL fuzzer against a 5G core's UDM with the tuned config.
#
# Wraps the train_protocol invocation as a single command so the flags can't be
# mangled by shell line-continuation when copy-pasted.  The three levers that
# matter for UDM depth are baked in:
#   --scenario        curated, productive UDM scenarios (shrinks the action space)
#   --max-spec-per-op caps spec mutations per op so remaining actions stay dense
#   --anneal-steps    reaches valid-create exploitation by ~13% of the run
#
# Targets two cores, selected with CORE (default: open5gs):
#   CORE=open5gs   open5GS UDM (127.0.0.12:7777), restart via scripts/open5gs.sh
#   CORE=free5gc   free5GC UDM (127.0.0.3:8000),  restart via scripts/free5gc.sh
#
# --core also auto-derives the target host/port; PLMN defaults switch too
# (open5gs 999/70, free5GC 208/93) because the baseline/provisioned SUPI is
# derived from the PLMN.
#
# Usage:
#   source venv/bin/activate
#   ./scripts/fuzz_udm.sh                      # open5gs defaults (60k steps)
#   CORE=free5gc ./scripts/fuzz_udm.sh         # free5GC
#   CORE=free5gc TIMESTEPS=120000 ./scripts/fuzz_udm.sh
#   ./scripts/fuzz_udm.sh --test               # extra args forwarded verbatim
#
# free5GC notes:
#   - FREE5GC_VERSION (default: main) must match the running instance; it
#     selects the /tmp/free5gc-<version>-logs dir and the start-nf restart-cmd.
#     Start the core first with:  sudo scripts/free5gc.sh start <version>
#   - free5GC auto-provisioning is NOT handled here (preflight is open5gs-only).
#     Provision the default subscriber (imsi-208930000000001, PLMN 208/93) via
#     the free5GC webconsole / MongoDB before depth scenarios reach handlers.
#
# Override via env vars: CORE, FREE5GC_VERSION, TIMESTEPS, MAX_STEPS,
# ANNEAL_STEPS, MAX_SPEC_PER_OP, SCENARIOS, RESTART_CMD, PLMN_MCC, PLMN_MNC.
#
set -euo pipefail

# ── Resolve repo root so the script works from any CWD ──────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# ── Tunables (env-overridable) ──────────────────────────────────────────────
CORE="${CORE:-open5gs}"
TIMESTEPS="${TIMESTEPS:-100000}"
MAX_STEPS="${MAX_STEPS:-20}"
ANNEAL_STEPS="${ANNEAL_STEPS:-8000}"
MAX_SPEC_PER_OP="${MAX_SPEC_PER_OP:-15}"

# ── Core-specific defaults (scenarios, restart-cmd, PLMN) ───────────────────
case "${CORE}" in
    open5gs)
        PLMN_MCC="${PLMN_MCC:-999}"
        PLMN_MNC="${PLMN_MNC:-70}"
        RESTART_CMD="${RESTART_CMD:-sudo scripts/open5gs.sh restart main}"
        # Curated, productive UDM scenarios (comma-separated, no spaces).
        SCENARIOS="${SCENARIOS:-udm_fuzz_auth_data_supi,udm_fuzz_smf_reg_psi_boundary,udm_fuzz_sdm_shared_data,udm_fuzz_uecm_incomplete_reg,udm_fuzz_psi_after_context,udm_null_byte_supi_path}"
        ;;
    free5gc)
        FREE5GC_VERSION="${FREE5GC_VERSION:-main}"
        PLMN_MCC="${PLMN_MCC:-208}"
        PLMN_MNC="${PLMN_MNC:-93}"
        RESTART_CMD="${RESTART_CMD:-sudo scripts/free5gc.sh start-nf ${FREE5GC_VERSION} udm}"
        # free5GC UDM scenarios: generic SUPI-depth fuzzers + the free5GC-specific
        # UECM probes (#761 incomplete registration, #780 null-byte SUPI path).
        SCENARIOS="${SCENARIOS:-udm_fuzz_auth_data_supi,udm_fuzz_sdm_shared_data,udm_fuzz_smf_reg_psi_boundary,udm_fuzz_psi_after_context,udm_fuzz_uecm_incomplete_reg,udm_null_byte_supi_path}"
        ;;
    *)
        echo "ERROR: unknown CORE '${CORE}' (expected 'open5gs' or 'free5gc')" >&2
        exit 1
        ;;
esac

# Prefer the project venv's python if present and not already active.
PYTHON="${PYTHON:-python}"
if [[ -x "${REPO_ROOT}/venv/bin/python" && -z "${VIRTUAL_ENV:-}" ]]; then
    PYTHON="${REPO_ROOT}/venv/bin/python"
fi

echo "======================================================================"
# SCENARIOS=all (or none) → omit --scenario so the FULL spec-driven action space
# is active (all 95 UDM ops / every API family), instead of the curated 6.  Use
# this for coverage-BREADTH campaigns; the named list is for focused depth.
SCEN_ARGS=()
if [[ "${SCENARIOS}" == "all" || "${SCENARIOS}" == "none" ]]; then
    SCEN_DESC="all (no --scenario filter; full spec-driven breadth)"
else
    SCEN_ARGS=(--scenario "${SCENARIOS}")
    SCEN_DESC="${SCENARIOS}"
fi

echo "  UDM fuzzing run"
echo "    core          : ${CORE}   PLMN: ${PLMN_MCC}/${PLMN_MNC}"
echo "    python        : ${PYTHON}"
echo "    timesteps     : ${TIMESTEPS}   max-steps: ${MAX_STEPS}   anneal: ${ANNEAL_STEPS}"
echo "    max-spec/op   : ${MAX_SPEC_PER_OP}"
echo "    scenarios     : ${SCEN_DESC}"
echo "    restart-cmd   : ${RESTART_CMD}"
[[ $# -gt 0 ]] && echo "    extra args    : $*"
echo "======================================================================"

# ── Preflight: provision the free5GC subscriber so the run reaches handler depth
# (UEAU auth-vectors, SDM data) instead of bouncing on "Data not found".  Skip
# with NO_PREFLIGHT=1.  Non-fatal: a provisioning hiccup must not block fuzzing.
if [[ "${CORE}" == "free5gc" && -z "${NO_PREFLIGHT:-}" ]]; then
    echo "  preflight: reachability + free5GC subscriber provisioning ..."
    "${PYTHON}" -m fuzzer.rl.preflight --nf UDM --core free5gc \
        --plmn-mcc "${PLMN_MCC}" --plmn-mnc "${PLMN_MNC}" \
        || echo "  preflight reported issues — continuing anyway"
fi

exec "${PYTHON}" -m fuzzer.rl.train_protocol \
    --protocol sbi \
    --core "${CORE}" \
    --nf-types UDM \
    --plmn-mcc "${PLMN_MCC}" \
    --plmn-mnc "${PLMN_MNC}" \
    --timesteps "${TIMESTEPS}" \
    --max-steps "${MAX_STEPS}" \
    "${SCEN_ARGS[@]}" \
    --max-spec-per-op "${MAX_SPEC_PER_OP}" \
    --anneal-steps "${ANNEAL_STEPS}" \
    --restart-cmd "${RESTART_CMD}" \
    "$@"
