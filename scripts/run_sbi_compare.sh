#!/usr/bin/env bash
#
# run_sbi_compare.sh — RQ2 SBI/HTTP-2 experiment driver (NF vs FivGeeFuzz).
#
# Twin of run_ngap_compare.sh, but for the Service-Based Interface (HTTP/2) and a
# different baseline. Compares two tools on a single 5G-core NF under identical
# conditions, collecting coverage (open5gs gcov build) and defect data per run:
#
#   - fivgee        : train_protocol --random --api fivgee
#                     (RL-FREE, FivGeeFuzz-style schema fuzzer: uniform-random over
#                      the schema-mutation catalog — omit-optional / type-mismatch /
#                      cross-service-token. No learning.)
#   - networkfuzzer : train_protocol (RL, --mode hybrid)
#                     (our contribution: RL-guided action selection over the same
#                      spec-driven SBI action space.)
#
# Both are the SAME python fuzzer (fuzzer.rl.train_protocol) on the SAME engine,
# targeting the SAME NF over HTTP/2, seeded identically — so the delta isolates RL.
#
# ─────────────────────────────────────────────────────────────────────────────
# CRASH-COUNT HEALTH WARNING (learned from RQ1/NGAP):
#   The fuzzer restarts the NF on hang/refused; a process briefly absent mid-restart
#   can be miscounted as a "crash". DO NOT trust the raw crash count blindly. The
#   trustworthy signals this script captures per trial are:
#     (a) sanitizer/panic SIGNATURES  -> trial_<k>/sanitizer/   (ASAN/UBSan/Go panic)
#     (b) crash corpus                -> fuzzer/data/crashes/   (replay to confirm)
#   Always replay-confirm before reporting crashes:
#     sudo venv/bin/python3 -m fuzzer.rl.replay_crash fuzzer/data/crashes \
#          --protocol sbi --core <core> --repeat 3 \
#          --restart-cmd '<single-NF restart>'
#   A TRUE crash = the NF process actually dies and stays dead (see RQ1 notes).
#
# WHERE THE CRASHES ARE:
#   open5gs SBI is hardened (we observed only recoverable UBSan UB, 0 real crashes).
#   For real crashes target a core with known defects:
#     CORE=free5gc  (Go nil-pointer panics that crash the process)
#     CORE=ella     (ASAN build; the bugs already filed in bug_report_ella_*.md)
# ─────────────────────────────────────────────────────────────────────────────
#
# Output layout (one dir per run), mirroring run_ngap_compare.sh:
#   $OUTDIR/<tool>/trial_<k>/
#       run_meta.txt        tool, trial, start ts, budget, git sha, host, target
#       coverage_ts.csv     final line/func coverage (open5gs gcov only)
#       bugs.csv            t_sec,nf,event   (process-down events — see warning)
#       sanitizer/          ubsan.*/asan.* (open5gs/ella) or panic excerpts (free5gc)
#       tool.log            stdout/stderr of the fuzzer
#
# Usage:
#   sudo ./scripts/run_sbi_compare.sh                       # open5gs UDM, defaults
#   sudo CORE=free5gc NF=udm ./scripts/run_sbi_compare.sh   # crash-hunting on free5GC
#   sudo CORE=ella ./scripts/run_sbi_compare.sh             # ella-core (ASAN)
#   sudo TRIALS=5 BUDGET=1800 NF=udr ./scripts/run_sbi_compare.sh
#
set -uo pipefail

# ─── configuration (override via env) ───────────────────────────────────────
CORE="${CORE:-open5gs}"               # open5gs | free5gc | ella
NF="${NF:-udm}"                       # target NF (lowercase): udm|udr|nrf|smf|amf|...
TRIALS="${TRIALS:-5}"
BUDGET="${BUDGET:-1800}"              # wall-clock seconds per run (default 30 min)
INTERVAL="${INTERVAL:-15}"            # crash-detection / gcov-flush period (s)
COV_SAMPLE_EVERY="${COV_SAMPLE_EVERY:-2}"  # coverage time-series cadence, in INTERVAL ticks
HEARTBEAT="${HEARTBEAT:-300}"         # min seconds between heartbeat prints
TIMESTEPS="${TIMESTEPS:-100000000}"   # huge: the wall-clock watchdog is what stops a run
MAX_STEPS="${MAX_STEPS:-20}"
PLMN_MCC="${PLMN_MCC:-}"              # auto per core if empty
PLMN_MNC="${PLMN_MNC:-}"
# Baseline (FivGeeFuzz) and treatment (NF-RL) extra args. Override BASELINE_ARGS to
# "--random" if --api fivgee filters to an empty action set on your spec build.
BASELINE_ARGS="${BASELINE_ARGS:---random --api fivgee}"
NF_ARGS="${NF_ARGS:---mode hybrid --anneal-steps 8000 --exploration-rate 0.15}"
SCENARIOS="${SCENARIOS:-all}"         # 'all' = full spec breadth; or comma list for depth
OPEN5GS_VERSION="${OPEN5GS_VERSION:-v2.7.7}"
FREE5GC_VERSION="${FREE5GC_VERSION:-main}"
OUTDIR="${OUTDIR:-results/rq2_sbi}"
TOOLS="${TOOLS:-fivgee networkfuzzer}"
COVERAGE="${COVERAGE:-auto}"          # auto: on for open5gs gcov, off otherwise

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Resolve the invoking user's home even under sudo ($HOME is /root there), matching
# how open5gs.sh derives OPEN5GS_DIR. The gcov build lives in build_<version>, NOT
# a bare build/ dir — getting either wrong makes lcov capture nothing (0% coverage).
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
    REAL_HOME="$HOME"
fi
GCOV_DIR="${GCOV_DIR:-${REAL_HOME}/open5gs/build_${OPEN5GS_VERSION}}"
LCOV_TIMEOUT="${LCOV_TIMEOUT:-600}"

# Spawned python needs the in-repo venv (numpy/SB3) even under sudo.
VENV_DIR="${VENV_DIR:-$REPO_ROOT/venv}"
PYTHON="${VENV_DIR}/bin/python3"
[[ -x "$PYTHON" ]] || PYTHON="python3"

NF="${NF,,}"

# ─── per-core target maps (host, SBI port, process name, restart, log dir) ───
case "$CORE" in
  open5gs)
    declare -A IPMAP=( [nrf]=127.0.0.10 [udm]=127.0.0.12 [udr]=127.0.0.20
                       [ausf]=127.0.0.11 [pcf]=127.0.0.13 [smf]=127.0.0.4 [amf]=127.0.0.5 )
    TGT_HOST="${TGT_HOST:-${IPMAP[$NF]:-127.0.0.12}}"; TGT_PORT="${TGT_PORT:-7777}"
    PROC="open5gs-${NF}d"
    RESTART_CMD="${RESTART_CMD:-${REPO_ROOT}/scripts/open5gs.sh start-nf ${OPEN5GS_VERSION} ${NF} --gcov}"
    # Trial-START restart: full core so ALL NFs' gcov counters are fresh (clean
    # per-trial coverage baseline). In-trial crash RECOVERY uses the cheaper
    # single-NF RESTART_CMD above to minimize churn.
    INIT_RESTART_CMD="${INIT_RESTART_CMD:-${REPO_ROOT}/scripts/open5gs.sh restart ${OPEN5GS_VERSION} --gcov}"
    LOG_DIR="${LOG_DIR:-/tmp/open5gs-${OPEN5GS_VERSION}-logs}"
    GCOV_NFS="${GCOV_NFS:-${NF} nrf udr}"     # target + common SBI deps
    PLMN_MCC="${PLMN_MCC:-999}"; PLMN_MNC="${PLMN_MNC:-70}"
    ;;
  free5gc)
    declare -A IPMAP=( [nrf]=127.0.0.10 [udm]=127.0.0.3 [udr]=127.0.0.4
                       [ausf]=127.0.0.9 [pcf]=127.0.0.7 [smf]=127.0.0.2 [amf]=127.0.0.18 )
    declare -A PORTMAP=( [udm]=8000 [udr]=8000 [nrf]=8000 )
    TGT_HOST="${TGT_HOST:-${IPMAP[$NF]:-127.0.0.3}}"; TGT_PORT="${TGT_PORT:-${PORTMAP[$NF]:-8000}}"
    PROC="${NF}"                              # free5GC procs are e.g. 'udm', 'udr'
    RESTART_CMD="${RESTART_CMD:-${REPO_ROOT}/scripts/free5gc.sh start-nf ${FREE5GC_VERSION} ${NF}}"
    INIT_RESTART_CMD="${INIT_RESTART_CMD:-$RESTART_CMD}"
    LOG_DIR="${LOG_DIR:-/tmp/free5gc-${FREE5GC_VERSION}-logs}"
    GCOV_NFS="${GCOV_NFS:-${NF}}"
    PLMN_MCC="${PLMN_MCC:-208}"; PLMN_MNC="${PLMN_MNC:-93}"
    COVERAGE="off"                            # Go core: no lcov here
    ;;
  ella)
    TGT_HOST="${TGT_HOST:-127.0.0.1}"; TGT_PORT="${TGT_PORT:-5000}"
    PROC="ella-core-asan"
    RESTART_CMD="${RESTART_CMD:-${REPO_ROOT}/scripts/ella.sh restart}"
    INIT_RESTART_CMD="${INIT_RESTART_CMD:-$RESTART_CMD}"
    LOG_DIR="${LOG_DIR:-/tmp/ella-logs}"
    GCOV_NFS="${GCOV_NFS:-}"
    COVERAGE="off"
    ;;
  *) echo "ERROR: unknown CORE '$CORE'" >&2; exit 2 ;;
esac

[[ "$COVERAGE" == "auto" ]] && { [[ "$CORE" == "open5gs" ]] && COVERAGE="on" || COVERAGE="off"; }

[[ $EUID -eq 0 ]] || { echo "error: run as root (NF management + gcov)" >&2; exit 1; }
if [[ -x "$VENV_DIR/bin/python3" ]]; then
    export VIRTUAL_ENV="$VENV_DIR"; export PATH="$VENV_DIR/bin:$PATH"
fi
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# ─── helpers ─────────────────────────────────────────────────────────────────
target_alive() { pgrep -f "$PROC" >/dev/null 2>&1; }

wait_target_ready() {                         # wait for the SBI TCP port to listen
    local w=0
    while (( w < 60 )); do
        ss -ltn 2>/dev/null | grep -q "[:.]${TGT_PORT}\b" && return 0
        sleep 0.5; (( w++ ))
    done
    return 1
}

# lcov summary -> "lcov ltot lpct fcov ftot fpct" (open5gs gcov only)
lcov_snapshot() {
    local lcov_to="${1:-$LCOV_TIMEOUT}"
    local tmp; tmp="$(mktemp)"
    timeout "$lcov_to" lcov --capture --directory "$GCOV_DIR" --quiet \
         --rc lcov_branch_coverage=0 --ignore-errors source,gcov,empty \
         --output-file "$tmp" >/dev/null 2>&1
    local summ lline fline lpct lcv ltot fpct fcv ftot
    summ="$(lcov --summary "$tmp" 2>&1)"
    lline="$(grep -E 'lines\.+:' <<<"$summ")"; fline="$(grep -E 'functions\.+:' <<<"$summ")"
    lpct="$(sed -E 's/.*: *([0-9.]+)%.*/\1/' <<<"$lline")"
    lcv="$( sed -E 's/.*\(([0-9]+) of [0-9]+ lines.*/\1/' <<<"$lline")"
    ltot="$(sed -E 's/.*of ([0-9]+) lines.*/\1/' <<<"$lline")"
    fpct="$(sed -E 's/.*: *([0-9.]+)%.*/\1/' <<<"$fline")"
    fcv="$( sed -E 's/.*\(([0-9]+) of [0-9]+ functions.*/\1/' <<<"$fline")"
    ftot="$(sed -E 's/.*of ([0-9]+) functions.*/\1/' <<<"$fline")"
    rm -f "$tmp"
    echo "${lcv:-0} ${ltot:-0} ${lpct:-0} ${fcv:-0} ${ftot:-0} ${fpct:-0}"
}

# Background sampler: detect target-NF death (process-level), restart it (single NF),
# snapshot any NEW sanitizer/panic files into the trial dir, throttled heartbeat.
sampler_loop() {
    local run_dir="$1" t0="$2" last_print=0 last_ncrash=0 nsample=0
    while :; do
        sleep "$INTERVAL"
        local now t; now="$(date +%s)"; t=$(( now - t0 ))
        if ! target_alive; then
            echo "${t},${PROC},down" >> "${run_dir}/bugs.csv"
            timeout 120 bash -c "$RESTART_CMD" >>"${run_dir}/setup.log" 2>&1
            sleep 2
        fi
        # snapshot sanitizer/panic artifacts produced since t0 (best-effort)
        find "$LOG_DIR" -maxdepth 1 \( -name 'ubsan.*' -o -name 'asan.*' \) \
             -newermt "@$t0" 2>/dev/null | while read -r f; do
            cp -n "$f" "${run_dir}/sanitizer/" 2>/dev/null || true
        done
        # Periodic coverage sample → real growth curve for the paper's figures.
        # gcov counters are cumulative (no per-request reset), so reading whatever
        # .gcda the fuzzer last dumped gives a monotonic curve. Best-effort: a
        # failed/slow lcov never affects run control flow. Cadence = COV_SAMPLE_EVERY
        # watchdog ticks (default every 2 → ~30s when INTERVAL=15).
        if [[ "$COVERAGE" == "on" ]]; then
            nsample=$(( nsample + 1 ))
            if (( nsample % COV_SAMPLE_EVERY == 0 )); then
                local cov tot pct fcov ftot fpct nex
                read -r cov tot pct fcov ftot fpct < <(lcov_snapshot "${COV_SAMPLE_TIMEOUT:-90}")
                # latest cumulative execution count so coverage can be plotted
                # against executions (throughput-controlled) as well as time.
                nex="$(grep -oE 'total_timesteps[ |]+[0-9]+' "${run_dir}/tool.log" 2>/dev/null \
                       | grep -oE '[0-9]+' | tail -1)"; nex="${nex:-0}"
                if (( ${cov:-0} > 0 )); then
                    echo "${t},${cov},${tot},${pct},${fcov},${ftot},${fpct},${nex}" \
                        >> "${run_dir}/coverage_ts.csv"
                fi
            fi
        fi
        local ncrash; ncrash="$(( $(wc -l < "${run_dir}/bugs.csv") - 1 ))"; (( ncrash<0 )) && ncrash=0
        if (( t - last_print >= HEARTBEAT || ncrash > last_ncrash )); then
            echo "       [t=${t}s/${BUDGET}s] ${run_dir#${OUTDIR}/} ... downs=${ncrash}" >&2
            last_print=$t; last_ncrash=$ncrash
        fi
    done
}

# Launch a tool's fuzzer in the background; sets TOOL_PID.
launch_tool() {
    local tool="$1" run_dir="$2"
    local fresh_model="rm -f ${REPO_ROOT}/fuzzer/data/models/rl_fuzzer* 2>/dev/null"
    # Tool/arm → train_protocol args. The first two are the RQ1 head-to-head tools;
    # the rest are the RQ2 ablation arms (leave-one-out from 'full' + 'floor').
    #   full     = NF_ARGS (RL + spec mutations + stateful chains)        [reference]
    #   norl     = full but uniform-random selection (RL ablated)
    #   nospec   = full minus 3GPP-spec-derived actions
    #   nochains = full minus producer→consumer chaining
    #   floor    = all three off ≈ schema-only random (≈ FivGeeFuzz floor)
    local extra; case "$tool" in
        fivgee)            extra="$BASELINE_ARGS" ;;
        networkfuzzer|full) extra="$NF_ARGS"; eval "$fresh_model" ;;
        norl)              extra="$NF_ARGS --random" ;;
        nospec)            extra="$NF_ARGS --no-spec-mutations"; eval "$fresh_model" ;;
        nochains)          extra="$NF_ARGS --no-stateful-chains"; eval "$fresh_model" ;;
        floor)             extra="--mode hybrid --random --no-spec-mutations --no-stateful-chains" ;;
        *) echo "unknown tool: $tool" >&2; return 1 ;;
    esac
    local scen=(); [[ "$SCENARIOS" != "all" && "$SCENARIOS" != "none" ]] && scen=(--scenario "$SCENARIOS")
    # shellcheck disable=SC2086
    "$PYTHON" -m fuzzer.rl.train_protocol \
        --protocol sbi --core "$CORE" --nf-types "${NF^^}" \
        --target-host "$TGT_HOST" --target-port "$TGT_PORT" \
        --plmn-mcc "$PLMN_MCC" --plmn-mnc "$PLMN_MNC" \
        --timesteps "$TIMESTEPS" --max-steps "$MAX_STEPS" \
        "${scen[@]}" $extra \
        --restart-cmd "$RESTART_CMD" \
        >"${run_dir}/tool.log" 2>&1 &
    TOOL_PID=$!
}

# ─── one run ──────────────────────────────────────────────────────────────────
run_once() {
    local tool="$1" trial="$2"
    local run_dir="${OUTDIR}/${tool}/trial_${trial}"
    mkdir -p "${run_dir}/sanitizer"
    echo "===> ${tool} trial ${trial}/${TRIALS}  core=${CORE} nf=${NF} (${TGT_HOST}:${TGT_PORT}) budget ${BUDGET}s"

    echo "     trial-start restart (log: ${run_dir}/setup.log) ..."
    timeout 240 bash -c "$INIT_RESTART_CMD" > "${run_dir}/setup.log" 2>&1 \
        || echo "     WARNING: restart failed — see ${run_dir}/setup.log" >&2
    # Cold-start tolerance: after a full-core restart the target NF can lag (it waits
    # for NRF to be ready). Poll up to ~25s; if still down, retry the cheap single-NF
    # start once (NRF is up by now), then give up.
    local w=0; while ! target_alive && (( w < 25 )); do sleep 1; (( w++ )); done
    if ! target_alive; then
        echo "     ${NF} still down — retrying single-NF start ..." >&2
        timeout 120 bash -c "$RESTART_CMD" >>"${run_dir}/setup.log" 2>&1
        w=0; while ! target_alive && (( w < 15 )); do sleep 1; (( w++ )); done
    fi
    if ! target_alive; then echo "     ERROR: ${PROC} not running after restart" >&2; return 1; fi
    if ! wait_target_ready; then echo "     ERROR: SBI :${TGT_PORT} not listening" >&2; return 1; fi
    echo "     ${NF} up; SBI ready."

    if [[ "$COVERAGE" == "on" ]]; then
        find "$GCOV_DIR" -name '*.gcda' -delete 2>/dev/null   # fresh baseline this run
    fi

    local t0; t0="$(date +%s)"
    # Remember the NF-log length NOW so the end-of-trial defect grep captures only
    # THIS trial's lines (the log is shared/append-only across trials).
    local log_lines0=0
    [[ -f "${LOG_DIR}/${NF}.log" ]] && log_lines0="$(wc -l < "${LOG_DIR}/${NF}.log")"
    {
        echo "tool=$tool"; echo "trial=$trial"; echo "start_epoch=$t0"
        echo "budget_s=$BUDGET"; echo "interval_s=$INTERVAL"; echo "core=$CORE"
        echo "nf=$NF"; echo "target=${TGT_HOST}:${TGT_PORT}"; echo "scenarios=$SCENARIOS"
        echo "git_sha=$GIT_SHA"; echo "host=$(hostname)"
    } > "${run_dir}/run_meta.txt"
    echo "t_sec,nf,event" > "${run_dir}/bugs.csv"
    # Coverage time series: header now, rows appended live by sampler_loop (and a
    # final flushed row after the run). A multi-row file yields a growth curve;
    # analyze.py still takes the last row for the summary table.
    echo "t_sec,lines_covered,lines_total,line_pct,func_covered,func_total,func_pct,executions" \
        > "${run_dir}/coverage_ts.csv"

    sampler_loop "$run_dir" "$t0" & local sampler_pid=$!
    TOOL_PID=""; launch_tool "$tool" "$run_dir"; local tool_pid="$TOOL_PID"

    # Budget watchdog. Send SIGINT first (NOT SIGTERM): both fuzzer modes catch
    # KeyboardInterrupt to print their training summary, which emits the parseable
    # 'total_timesteps' line the execution-count grep below depends on. The RL path
    # only prints SB3's rollout table after a full rollout (2048 steps) — a crash-heavy
    # run never reaches that — so without the graceful summary it scores execs=0 even
    # though it executed plenty. Give it a grace window, then escalate to TERM/KILL.
    ( sleep "$BUDGET"
      kill -INT "$tool_pid" 2>/dev/null
      pkill -INT -f 'fuzzer.rl.train_protocol' 2>/dev/null
      sleep "${SHUTDOWN_GRACE:-20}"
      kill -TERM "$tool_pid" 2>/dev/null
      pkill -TERM -f 'fuzzer.rl.train_protocol' 2>/dev/null
    ) & local watchdog=$!
    wait "$tool_pid" 2>/dev/null

    kill "$sampler_pid" "$watchdog" 2>/dev/null; wait "$sampler_pid" 2>/dev/null
    pkill -TERM -f 'fuzzer.rl.train_protocol' 2>/dev/null; sleep 2
    pkill -KILL -f 'fuzzer.rl.train_protocol' 2>/dev/null

    # final sanitizer snapshot (catch artifacts written near the end)
    find "$LOG_DIR" -maxdepth 1 \( -name 'ubsan.*' -o -name 'asan.*' \) \
         -newermt "@$t0" 2>/dev/null -exec cp -n {} "${run_dir}/sanitizer/" \; 2>/dev/null
    # Capture THIS trial's NF-log defect signatures (only lines appended since t0;
    # the log is shared/append-only, so a whole-file grep would mis-attribute across
    # trials). Real signal on open5gs SBI is ogs_assert/abort; on Go cores, panics.
    if [[ -f "${LOG_DIR}/${NF}.log" ]]; then
        local pat; local outf
        if [[ "$CORE" == "open5gs" ]]; then
            pat="Assertion .* failed|ogs_assert|should not be reached|FATAL|ABORT"; outf="asserts.txt"
        else
            pat="panic:|runtime error|goroutine [0-9]+ \[running\]"; outf="panics.txt"
        fi
        tail -n "+$((log_lines0 + 1))" "${LOG_DIR}/${NF}.log" 2>/dev/null \
            | grep -nE "$pat" > "${run_dir}/sanitizer/${outf}" 2>/dev/null || true
    fi

    # Final coverage flush: stop NFs so gcov writes complete .gcda, then append
    # the authoritative end-of-run row (the live samples above can lag by a dump
    # interval; this row is exact). Header was already written before the run.
    if [[ "$COVERAGE" == "on" ]]; then
        echo "     stopping NFs to flush gcov, then lcov ..."
        timeout 90 "${REPO_ROOT}/scripts/open5gs.sh" stop "$OPEN5GS_VERSION" >>"${run_dir}/setup.log" 2>&1
        sleep 2
        read -r cov tot pct fcov ftot fpct < <(lcov_snapshot)
        local nex; nex="$(grep -oE 'total_timesteps[ |]+[0-9]+' "${run_dir}/tool.log" 2>/dev/null \
                          | grep -oE '[0-9]+' | sort -n | tail -1)"; nex="${nex:-0}"
        echo "$(( $(date +%s) - t0 )),${cov},${tot},${pct},${fcov},${ftot},${fpct},${nex}" >> "${run_dir}/coverage_ts.csv"
    fi

    # Max (not last) over all total_timesteps prints: SB3 rollout tables and the
    # end-of-run summary can interleave; the summary's env._total_steps is the truth.
    local execs; execs="$(grep -oE 'total_timesteps[ |]+[0-9]+' "${run_dir}/tool.log" \
                          | grep -oE '[0-9]+' | sort -n | tail -1)"; execs="${execs:-0}"
    local downs; downs="$(( $(wc -l < "${run_dir}/bugs.csv") - 1 ))"; (( downs<0 )) && downs=0
    local nsan; nsan="$(ls -1 "${run_dir}/sanitizer/" 2>/dev/null | grep -cE 'ubsan|asan' || true)"
    {
        echo "executions=$execs"
        echo "throughput_msg_per_s=$(awk "BEGIN{printf \"%.1f\", ${execs}/${BUDGET}}")"
        echo "proc_down_events=$downs"
        echo "sanitizer_files=$nsan"
    } >> "${run_dir}/run_meta.txt"
    echo "     final: execs=${execs}  proc-downs=${downs}  sanitizer-files=${nsan}"
    echo "            (replay-confirm crashes before reporting — see header)"
}

# ─── main ────────────────────────────────────────────────────────────────────
mkdir -p "$OUTDIR"
echo "RQ2 SBI comparison | core=$CORE nf=$NF target=${TGT_HOST}:${TGT_PORT} coverage=$COVERAGE"
echo "  tools=[$TOOLS] trials=$TRIALS budget=${BUDGET}s git=$GIT_SHA"
echo "  baseline(fivgee) args: $BASELINE_ARGS"
echo "  treatment(nf)    args: $NF_ARGS"
for tool in $TOOLS; do
    for k in $(seq 1 "$TRIALS"); do run_once "$tool" "$k"; done
done
[[ "$CORE" == "open5gs" ]] && "${REPO_ROOT}/scripts/open5gs.sh" stop "$OPEN5GS_VERSION" >/dev/null 2>&1
echo "done. results in $OUTDIR/"
echo
echo "NEXT: analyze (UBSan/sanitizer signatures = defect metric, NOT raw proc-downs):"
echo "  venv/bin/python3 -m fuzzer.eval.analyze --results $OUTDIR --ubsan <sanitizer-dir> --out /tmp/rq2_analysis"
echo "  and replay-confirm any crashes:"
echo "  sudo venv/bin/python3 -m fuzzer.rl.replay_crash fuzzer/data/crashes --protocol sbi --core $CORE --repeat 3 --restart-cmd '$RESTART_CMD'"
