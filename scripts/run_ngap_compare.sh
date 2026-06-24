#!/usr/bin/env bash
#
# run_ngap_compare.sh — RQ1 NGAP-track experiment driver.
#
# Compares two tools on the Open5GS AMF N2/SCTP interface under identical
# conditions, collecting coverage-over-time and crash data per run:
#
#   - 5greplay      : ./networkfuzzer replay  (rule-based, NGAP rules 6-10, no RL)
#   - networkfuzzer : ./networkfuzzer fuzz --mode rl --protocol ngap (RL-guided)
#
# Fairness controls (see RQ1 setup):
#   * same gcov-instrumented Open5GS build, restarted before every run
#   * gcov counters reset at run start, dumped every $INTERVAL s
#   * same seed pcap, same target AMF, same wall-clock budget $BUDGET s, $TRIALS trials
#   * coverage measured by an external lcov oracle, not by either tool
#
# Output layout (one dir per run):
#   $OUTDIR/<tool>/trial_<k>/
#       run_meta.txt        tool, trial, start ts, budget, git sha, host
#       coverage_ts.csv     t_sec,lines_covered,lines_total,line_pct
#       bugs.csv            t_sec,nf,event           (nf death = crash)
#       tool.log            stdout/stderr of the fuzzer
#
# Requires: root (Open5GS NFs + SCTP), lcov, the open5gs.sh helper built --gcov.
#
# Usage:
#   sudo ./scripts/run_ngap_compare.sh [--trials N] [--budget SEC] [--interval SEC]
#
set -uo pipefail

# ─── configuration (override via flags or env) ──────────────────────────────
TRIALS="${TRIALS:-10}"               # independent repetitions per tool
BUDGET="${BUDGET:-900}"              # wall-clock seconds per run (default 15 min)
INTERVAL="${INTERVAL:-15}"           # crash-detection / gcov-flush period (s)
HEARTBEAT="${HEARTBEAT:-300}"        # min seconds between heartbeat prints (crash-detect stays at INTERVAL)
OPEN5GS_VERSION="${OPEN5GS_VERSION:-v2.7.7}"
AMF_HOST="${AMF_HOST:-127.0.0.5}"
AMF_PORT="${AMF_PORT:-38412}"
SEED_PCAP="${SEED_PCAP:-fuzzer/data/5g-sa.pcap}"
NGAP_RULES="${NGAP_RULES:-6,7,8,9,10}"
# 1 = each replay pass uses a random non-empty subset of NGAP_RULES (singles +
#     combinations across the run); 0 = every pass uses all rules at once.
RANDOMIZE_RULES="${RANDOMIZE_RULES:-1}"
# FORWARD = replay the whole NGAP flow (legit handshake + fuzzed pkts) so the AMF
# stays in a valid state; DROP = only forward rule-matched (fuzzed) packets.
FORWARD_DEFAULT="${FORWARD_DEFAULT:-FORWARD}"
OUTDIR="${OUTDIR:-results/rq1_ngap}"
TOOLS="${TOOLS:-5greplay networkfuzzer}"

# NFs whose coverage we attribute to the NGAP campaign (AMF + registration deps)
GCOV_NFS="${GCOV_NFS:-amf nrf ausf udm udr pcf smf}"
# gcov object dir produced by open5gs.sh setup --gcov (adjust if different)
GCOV_DIR="${GCOV_DIR:-$HOME/open5gs/build}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NF_BIN="${REPO_ROOT}/networkfuzzer"
O5G="${REPO_ROOT}/scripts/open5gs.sh"

# The networkfuzzer binary spawns `python3 -m fuzzer.rl.train_protocol`; under sudo
# the interactive venv is lost, so numpy/stable_baselines3 fail to import. Put the
# in-repo venv on PATH so the spawned python3 resolves to it.
VENV_DIR="${VENV_DIR:-$REPO_ROOT/venv}"
if [[ -x "$VENV_DIR/bin/python3" ]]; then
    export VIRTUAL_ENV="$VENV_DIR"
    export PATH="$VENV_DIR/bin:$PATH"
fi

# ─── arg parsing ────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --trials)   TRIALS="$2";   shift 2 ;;
        --budget)   BUDGET="$2";   shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --outdir)   OUTDIR="$2";   shift 2 ;;
        --tools)    TOOLS="$2";    shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "error: run as root (SCTP + NF management)" >&2; exit 1; }
command -v lcov >/dev/null || { echo "error: lcov not found" >&2; exit 1; }
[[ -x "$NF_BIN" ]] || { echo "error: $NF_BIN not found/executable" >&2; exit 1; }
[[ -f "$SEED_PCAP" ]] || echo "warning: seed pcap $SEED_PCAP missing" >&2

GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# ─── helpers ────────────────────────────────────────────────────────────────

# PIDs of the instrumented NFs (used for gcov signals + crash detection).
nf_pids() { pgrep -d' ' -f "open5gs-(${GCOV_NFS// /|})d" 2>/dev/null; }

# NOTE: open5gs hijacks SIGUSR1/SIGUSR2 (talloc reports) via its signal thread, so
# the gcov_ctrl.so signal handlers never fire. gcc writes .gcda only on normal exit
# (atexit __gcov_dump), so coverage is flushed by gracefully STOPPING the NFs.

# Wait until the AMF's NGAP/SCTP port is actually listening (process up != ready).
wait_amf_ready() {
    local w=0
    while (( w < 60 )); do
        ss -lna 2>/dev/null | grep -q "[:.]${AMF_PORT}\b" && return 0
        sleep 0.5; (( w++ ))
    done
    return 1
}

# Capture an lcov summary and emit "covered total pct".
# lcov 1.14 is slow (~minutes on a large tree), so it is called ONCE per run (at the
# end), never in the per-interval sampler, and is bounded by LCOV_TIMEOUT.
LCOV_TIMEOUT="${LCOV_TIMEOUT:-600}"
lcov_snapshot() {
    local tmp; tmp="$(mktemp)"
    timeout "$LCOV_TIMEOUT" lcov --capture --directory "$GCOV_DIR" --quiet \
         --rc lcov_branch_coverage=0 --output-file "$tmp" >/dev/null 2>&1
    # lcov --summary prints e.g.:
    #   lines......: 12.3% (4567 of 37123 lines)
    #   functions..: 15.7% (665 of 4246 functions)
    local summ lline fline lcv ltot lpct fcv ftot fpct
    summ="$(lcov --summary "$tmp" 2>&1)"
    lline="$(grep -E 'lines\.+:' <<<"$summ")"
    fline="$(grep -E 'functions\.+:' <<<"$summ")"
    lpct="$(sed -E 's/.*: *([0-9.]+)%.*/\1/' <<<"$lline")"
    lcv="$( sed -E 's/.*\(([0-9]+) of [0-9]+ lines.*/\1/' <<<"$lline")"
    ltot="$(sed -E 's/.*of ([0-9]+) lines.*/\1/' <<<"$lline")"
    fpct="$(sed -E 's/.*: *([0-9.]+)%.*/\1/' <<<"$fline")"
    fcv="$( sed -E 's/.*\(([0-9]+) of [0-9]+ functions.*/\1/' <<<"$fline")"
    ftot="$(sed -E 's/.*of ([0-9]+) functions.*/\1/' <<<"$fline")"
    rm -f "$tmp"
    # emit: line_covered line_total line_pct  func_covered func_total func_pct
    echo "${lcv:-0} ${ltot:-0} ${lpct:-0} ${fcv:-0} ${ftot:-0} ${fpct:-0}"
}

# Background sampler: every INTERVAL do only FAST work — flush gcov counters to
# .gcda (so coverage survives crashes via gcov's merge-on-dump), detect NF deaths,
# and print a heartbeat. NO lcov here (too slow); coverage is captured once at end.
# args: run_dir start_epoch
sampler_loop() {
    local run_dir="$1" t0="$2"
    local expected_nfs; expected_nfs="$(echo $GCOV_NFS | wc -w)"
    local last_print=0 last_ncrash=0
    while :; do
        sleep "$INTERVAL"
        local now t; now="$(date +%s)"; t=$(( now - t0 ))
        # crash detection: any expected NF no longer running
        local alive; alive="$(nf_pids | wc -w)"
        if (( alive < expected_nfs )); then
            for nf in $GCOV_NFS; do
                if ! pgrep -f "open5gs-${nf}d" >/dev/null 2>&1; then
                    echo "${t},${nf},down" >> "${run_dir}/bugs.csv"
                fi
            done
            timeout 180 "$O5G" restart "$OPEN5GS_VERSION" --gcov \
                >>"${run_dir}/setup.log" 2>&1   # recover; .gcda merges across restarts
            sleep 3
        fi
        local ncrash; ncrash="$(( $(wc -l < "${run_dir}/bugs.csv") - 1 ))"; (( ncrash<0 )) && ncrash=0
        # Throttle the heartbeat: print only every HEARTBEAT seconds, or immediately
        # when a new crash is detected (so crashes are never silently delayed).
        if (( t - last_print >= HEARTBEAT || ncrash > last_ncrash )); then
            echo "       [t=${t}s/${BUDGET}s] running ${run_dir#${OUTDIR}/} ... crashes=${ncrash}" >&2
            last_print=$t; last_ncrash=$ncrash
        fi
    done
}

# Count NGAP packets in the seed pcap (one replay pass ≈ this many executions).
# Falls back to total packet count, then to 1, if tshark/capinfos are absent.
ngap_pkts_in_pcap() {
    local pcap="$1" n=""
    if command -v tshark >/dev/null 2>&1; then
        n="$(tshark -r "$pcap" -Y ngap 2>/dev/null | wc -l)"
        [ "${n:-0}" -gt 0 ] 2>/dev/null || n="$(tshark -r "$pcap" 2>/dev/null | wc -l)"
    elif command -v capinfos >/dev/null 2>&1; then
        n="$(capinfos -c -M "$pcap" 2>/dev/null | sed -nE 's/.*Number of packets *= *([0-9]+).*/\1/p')"
    fi
    [ "${n:-0}" -gt 0 ] 2>/dev/null && echo "$n" || echo 1
}

# Pick a random non-empty subset of a comma-separated rule list.
rand_subset() {
    local IFS=','; read -ra arr <<<"$1"; local out=()
    local r; for r in "${arr[@]}"; do (( RANDOM % 2 )) && out+=("$r"); done
    (( ${#out[@]} == 0 )) && out=("${arr[$(( RANDOM % ${#arr[@]} ))]}")
    local IFS=','; echo "${out[*]}"
}

# engine.rules-mask distributes rules to threads — it does NOT filter. To keep
# only a subset active we must exclude every other rule id (1..MAX_RULE_ID).
MAX_RULE_ID="${MAX_RULE_ID:-100}"
exclude_list() {                      # arg: comma-list of rule ids to KEEP
    local keep=",$1," out=() i
    for i in $(seq 1 "$MAX_RULE_ID"); do [[ "$keep" == *",$i,"* ]] || out+=("$i"); done
    local IFS=','; echo "${out[*]}"
}

# Launch a tool in the background; echo its PID.
# args: tool run_dir
launch_tool() {
    local tool="$1" run_dir="$2"
    case "$tool" in
      5greplay)
        # replay terminates on a finite pcap, so loop passes until the budget is spent;
        # each pass applies a random rule subset (or all rules) for mutation diversity.
        (
          # NOTE: no `trap 'kill 0'` here — job control is off in scripts, so the
          # subshell shares the main script's process group and `kill 0` would kill
          # the whole campaign. The watchdog kills the in-flight replay via pkill.
          local deadline=$(( $(date +%s) + BUDGET )) pass=0 mask
          while [ "$(date +%s)" -lt "$deadline" ]; do
            pass=$(( pass + 1 ))
            if [ "$RANDOMIZE_RULES" = "1" ]; then mask="$(rand_subset "$NGAP_RULES")";
            else mask="$NGAP_RULES"; fi
            local excl; excl="$(exclude_list "$mask")"
            echo "[pass $pass] keep-rules=$mask" >> "${run_dir}/tool.log"
            "$NF_BIN" replay \
                -t "$SEED_PCAP" \
                -X engine.exclude-rules="$excl" \
                -X forward.enable=true \
                -X forward.default="$FORWARD_DEFAULT" \
                -X forward.target-protocols=SCTP \
                -X forward.target-hosts="$AMF_HOST" \
                -X forward.target-ports="$AMF_PORT" \
                -X output.enable=false \
                >>"${run_dir}/tool.log" 2>&1
          done
        ) &
        ;;
      networkfuzzer)
        # Independent trials: remove any saved RL model so each trial trains a fresh
        # policy (otherwise train_protocol resumes the prior model -> trials correlate).
        rm -f "${REPO_ROOT}/fuzzer/data/models/rl_ngap_hybrid"* 2>/dev/null
        # huge timestep cap so the wall-clock watchdog is what actually stops it,
        # matching 5Greplay's budget. Actual executed steps are read from the log.
        "$NF_BIN" fuzz --mode rl \
            --protocol ngap \
            --target-host "$AMF_HOST" \
            --target-port "$AMF_PORT" \
            --fuzz-mode hybrid \
            --timesteps 100000000 \
            --exploration 0.15 \
            >"${run_dir}/tool.log" 2>&1 &
        ;;
      *) echo "unknown tool: $tool" >&2; return 1 ;;
    esac
    # Export the PID via a global, NOT via `echo $!` + command substitution: $(...)
    # runs in a subshell that exits immediately, orphaning a raw binary child which
    # then dies of SIGHUP. Calling launch_tool directly keeps the main script as the
    # tool's parent so it lives for the whole budget.
    TOOL_PID=$!
}

# ─── one run ────────────────────────────────────────────────────────────────
run_once() {
    local tool="$1" trial="$2"
    local run_dir="${OUTDIR}/${tool}/trial_${trial}"
    mkdir -p "${run_dir}/raw"
    echo "===> ${tool} trial ${trial}/${TRIALS} (budget ${BUDGET}s)"

    # Always restart the gcov-instrumented build for a clean, correctly-instrumented
    # core every trial. (A conditional skip risks running against a stale/non-gcov
    # build -> 0% coverage, or against a core whose AMF was crashed by the prior tool.)
    echo "     restarting gcov open5gs (log: ${run_dir}/setup.log) ..."
    timeout 200 "$O5G" restart "$OPEN5GS_VERSION" --gcov > "${run_dir}/setup.log" 2>&1 \
        || echo "     WARNING: restart timed out/failed — see ${run_dir}/setup.log" >&2
    sleep 3
    # require every target NF (incl. AMF) to be up, else abort this trial
    local missing=0; for nf in $GCOV_NFS; do
        pgrep -x "open5gs-${nf}d" >/dev/null 2>&1 || { echo "     missing: $nf" >&2; missing=1; }
    done
    if (( missing )); then
        echo "     ERROR: open5gs not fully up — see ${run_dir}/setup.log" >&2; return 1
    fi
    if ! wait_amf_ready; then
        echo "     ERROR: AMF NGAP/SCTP :${AMF_PORT} not listening after restart" >&2; return 1
    fi
    echo "     open5gs up ($(nf_pids | wc -w) NFs); AMF NGAP ready; clearing gcov baseline ..."
    # Fresh processes from the restart already have zeroed in-memory counters; just
    # remove stale on-disk .gcda so the final dump reflects only this run.
    find "$GCOV_DIR" -name '*.gcda' -delete 2>/dev/null

    local t0; t0="$(date +%s)"
    {
        echo "tool=$tool"; echo "trial=$trial"; echo "start_epoch=$t0"
        echo "budget_s=$BUDGET"; echo "interval_s=$INTERVAL"
        echo "open5gs=$OPEN5GS_VERSION"; echo "rules=$NGAP_RULES"
        echo "git_sha=$GIT_SHA"; echo "host=$(hostname)"; echo "seed=$SEED_PCAP"
    } > "${run_dir}/run_meta.txt"
    echo "t_sec,lines_covered,lines_total,line_pct,func_covered,func_total,func_pct" \
        > "${run_dir}/coverage_ts.csv"
    echo "t_sec,nf,event" > "${run_dir}/bugs.csv"

    sampler_loop "$run_dir" "$t0" &
    local sampler_pid=$!

    TOOL_PID=""; launch_tool "$tool" "$run_dir"; local tool_pid="$TOOL_PID"

    # Enforce the wall-clock budget. The networkfuzzer binary spawns a python RL
    # child that is NOT killed by killing the binary, so it would keep fuzzing past
    # the budget; kill the binary AND the python trainer.
    ( sleep "$BUDGET"
      kill -TERM "$tool_pid" 2>/dev/null
      pkill -TERM -f "$NF_BIN" 2>/dev/null               # stop in-flight replay/fuzz binary
      pkill -TERM -f 'fuzzer.rl.train_protocol' 2>/dev/null
    ) &
    local watchdog=$!
    wait "$tool_pid" 2>/dev/null

    kill "$sampler_pid" "$watchdog" 2>/dev/null
    wait "$sampler_pid" 2>/dev/null
    # reap any lingering children (replay binary + orphaned python RL trainer)
    pkill -TERM -f "$NF_BIN" 2>/dev/null
    pkill -TERM -f 'fuzzer.rl.train_protocol' 2>/dev/null
    sleep 2
    pkill -KILL -f 'fuzzer.rl.train_protocol' 2>/dev/null  # ensure it's gone before coverage

    # final coverage — stop NFs so gcc's atexit __gcov_dump flushes .gcda (the only
    # reliable flush, since open5gs swallows SIGUSR1/2), then capture with lcov.
    echo "     budget reached; stopping NFs to flush gcov, then lcov (1-3 min) ..."
    timeout 90 "$O5G" stop "$OPEN5GS_VERSION" >>"${run_dir}/setup.log" 2>&1
    sleep 2
    read -r cov tot pct fcov ftot fpct < <(lcov_snapshot)
    local elapsed=$(( $(date +%s) - t0 ))
    echo "${elapsed},${cov},${tot},${pct},${fcov},${ftot},${fpct}" >> "${run_dir}/coverage_ts.csv"

    # executions delivered to the AMF (the efficiency metric) — parsed from tool.log:
    #   5Greplay : sum of "Packets forwarded: N" across passes
    #   NetworkFuzzer : last SB3 "total_timesteps N" (run is killed mid-training, so the
    #                   banner's requested "Timesteps:" cap must NOT be used).
    local execs crashes
    if [ "$tool" = "5greplay" ]; then
        execs="$(grep -oE 'Packets forwarded: [0-9]+' "${run_dir}/tool.log" \
                 | grep -oE '[0-9]+' | awk '{s+=$1} END{print s+0}')"
    else
        execs="$(grep -oE 'total_timesteps[ |]+[0-9]+' "${run_dir}/tool.log" \
                 | grep -oE '[0-9]+' | tail -1)"; execs="${execs:-0}"
    fi
    crashes="$(( $(grep -c ',' "${run_dir}/bugs.csv") - 1 ))"; (( crashes < 0 )) && crashes=0
    # throughput over the FUZZING window (budget), not elapsed (which includes lcov)
    local tput="0"; (( BUDGET > 0 )) && tput="$(awk "BEGIN{printf \"%.1f\", ${execs}/${BUDGET}}")"
    {
        echo "elapsed_s=$elapsed"; echo "executions=$execs"
        echo "throughput_msg_per_s=$tput"
        echo "final_line_pct=$pct"; echo "final_func_pct=$fpct"
        echo "crashes=$crashes"
    } >> "${run_dir}/run_meta.txt"
    echo "     final: line=${pct}% func=${fpct}%  execs=${execs}  thr=${tput} msg/s  crashes=${crashes}"
}

# ─── main ───────────────────────────────────────────────────────────────────
mkdir -p "$OUTDIR"
echo "RQ1 NGAP comparison | tools=[$TOOLS] trials=$TRIALS budget=${BUDGET}s git=$GIT_SHA"
for tool in $TOOLS; do
    for k in $(seq 1 "$TRIALS"); do
        run_once "$tool" "$k"
    done
done
"$O5G" stop "$OPEN5GS_VERSION" >/dev/null 2>&1
echo "done. results in $OUTDIR/"
