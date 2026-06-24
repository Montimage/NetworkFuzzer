#!/usr/bin/env bash
# Download 3GPP 5G SBI OpenAPI YAML specs for spec-driven fuzzing.
# Output: fuzzer/rl/protocols/sbi/openapi_specs/
#
# Usage:
#   bash scripts/fetch_specs.sh            # fetch Release 17 (default)
#   bash scripts/fetch_specs.sh REL-18     # specific release tag
#   bash scripts/fetch_specs.sh main       # bleeding edge
#
# The cloned directory is added to .gitignore automatically.
# Requires: git

set -euo pipefail

RELEASE="${1:-REL-17}"
REPO_URL="https://forge.3gpp.org/rep/all/5G_APIs.git"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$REPO_ROOT/fuzzer/rl/protocols/sbi/openapi_specs"

# Only the YAML files needed for SBI fuzzing (not the full 300+ file repo)
NEEDED_FILES=(
    # Common data types referenced by all NF specs
    "TS29571_CommonData.yaml"
    "TS29122_CommonData.yaml"
    # NRF — TS 29.510
    "TS29510_Nnrf_NFManagement.yaml"
    "TS29510_Nnrf_NFDiscovery.yaml"
    # AMF — TS 29.518
    "TS29518_Namf_Communication.yaml"
    "TS29518_Namf_EventExposure.yaml"
    # SMF — TS 29.502
    "TS29502_Nsmf_PDUSession.yaml"
    "TS29502_Nsmf_EventExposure.yaml"
    # UDM — TS 29.503 (all service groups free5GC routes — see NFs/udm/internal/sbi/api_*.go)
    "TS29503_Nudm_SDM.yaml"
    "TS29503_Nudm_UECM.yaml"
    "TS29503_Nudm_UEAU.yaml"
    "TS29503_Nudm_EE.yaml"
    "TS29503_Nudm_PP.yaml"
    "TS29503_Nudm_MT.yaml"
    "TS29503_Nudm_NIDDAU.yaml"
    "TS29503_Nudm_RSDS.yaml"
    "TS29503_Nudm_SSAU.yaml"
    "TS29503_Nudm_UEID.yaml"
    # UDR — TS 29.504 (Nudr_DR aggregates path-items from the data specs below via $ref)
    "TS29504_Nudr_DR.yaml"
    "TS29505_Subscription_Data.yaml"
    "TS29519_Policy_Data.yaml"
    "TS29519_Application_Data.yaml"
    "TS29519_Exposure_Data.yaml"
    # AUSF — TS 29.509 (free5GC routes ueauthentication + sorprotection + upuprotection)
    "TS29509_Nausf_UEAuthentication.yaml"
    "TS29509_Nausf_SoRProtection.yaml"
    "TS29509_Nausf_UPUProtection.yaml"
    # PCF — TS 29.507 / 29.512 / 29.514
    "TS29507_Npcf_AMPolicyControl.yaml"
    "TS29512_Npcf_SMPolicyControl.yaml"
    "TS29514_Npcf_PolicyAuthorization.yaml"
    # NSSF — TS 29.531
    "TS29531_Nnssf_NSSelection.yaml"
    "TS29531_Nnssf_NSSAIAvailability.yaml"
    # BSF — TS 29.521
    "TS29521_Nbsf_Management.yaml"
    # CHF — TS 29.594
    "TS29594_Nchf_ConvergedCharging.yaml"
    # NEF — TS 29.522 (O-RAN / network exposure)
    "TS29522_Nef_EventExposure.yaml"
    # NRF OAuth2 — needed for cross-service token attack
    "TS29510_Nnrf_AccessToken.yaml"
)

echo "[fetch_specs] target release: $RELEASE"
echo "[fetch_specs] output dir:     $OUT_DIR"

mkdir -p "$OUT_DIR"

# ── Strategy: sparse checkout to avoid downloading 500 MB of history ──────────
CLONE_DIR="$OUT_DIR/.git_clone"

if [ -d "$CLONE_DIR/.git" ]; then
    echo "[fetch_specs] updating existing clone..."
    git -C "$CLONE_DIR" fetch --depth 1 origin "$RELEASE" 2>/dev/null \
        || git -C "$CLONE_DIR" fetch --depth 1 origin
    git -C "$CLONE_DIR" checkout FETCH_HEAD -- . 2>/dev/null \
        || git -C "$CLONE_DIR" reset --hard FETCH_HEAD
else
    echo "[fetch_specs] cloning (sparse, depth=1)..."
    git clone \
        --depth 1 \
        --filter=blob:none \
        --sparse \
        --branch "$RELEASE" \
        "$REPO_URL" \
        "$CLONE_DIR" 2>/dev/null \
    || git clone \
        --depth 1 \
        --filter=blob:none \
        --sparse \
        "$REPO_URL" \
        "$CLONE_DIR"
    git -C "$CLONE_DIR" sparse-checkout init --cone
    # Specs live at the repo root — no subdirectory needed
    git -C "$CLONE_DIR" sparse-checkout set /
fi

# ── Copy only the files we need ───────────────────────────────────────────────
COPIED=0
MISSING=0
for f in "${NEEDED_FILES[@]}"; do
    src="$CLONE_DIR/$f"
    dst="$OUT_DIR/$f"
    if [ -f "$src" ]; then
        cp -u "$src" "$dst"
        COPIED=$((COPIED + 1))
    else
        echo "[fetch_specs] WARNING: $f not found in repo"
        MISSING=$((MISSING + 1))
    fi
done

echo "[fetch_specs] done: $COPIED files copied, $MISSING missing"
echo "[fetch_specs] specs at: $OUT_DIR"
ls "$OUT_DIR"/*.yaml 2>/dev/null | wc -l | xargs -I{} echo "[fetch_specs] {} YAML files available"

# ── Add to .gitignore if not already there ────────────────────────────────────
GITIGNORE="$REPO_ROOT/.gitignore"
IGNORE_ENTRY="fuzzer/rl/protocols/sbi/openapi_specs/"
if [ -f "$GITIGNORE" ] && ! grep -qF "$IGNORE_ENTRY" "$GITIGNORE"; then
    echo "" >> "$GITIGNORE"
    echo "# 3GPP OpenAPI specs (fetched by scripts/fetch_specs.sh)" >> "$GITIGNORE"
    echo "$IGNORE_ENTRY" >> "$GITIGNORE"
    echo "[fetch_specs] added $IGNORE_ENTRY to .gitignore"
fi

# ── Remind about generate step ────────────────────────────────────────────────
echo ""
echo "Next step: generate spec mutations JSON"
echo "  python scripts/generate_spec_mutations.py"
