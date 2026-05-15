#!/usr/bin/env python3
"""
Sequential multi-NF fuzzing campaign runner.

Runs a list of NF fuzzing jobs one after another, collecting crash counts and
timing per NF.  Supports built-in presets or a JSON campaign file.

Usage
-----
# open5GS preset (--core auto-inferred from preset name):
    python -m fuzzer.rl.run_campaign --preset open5gs \\
        --restart-cmd "sudo scripts/open5gs.sh restart v2.7.7"

# free5GC preset (--core auto-inferred):
    python -m fuzzer.rl.run_campaign --preset free5gc \\
        --restart-cmd "sudo scripts/free5gc.sh restart v4.2.2"

# Long overnight run:
    python -m fuzzer.rl.run_campaign --preset open5gs_long \\
        --restart-cmd "sudo scripts/open5gs.sh restart v2.7.7"

# 30-minute smoke test:
    python -m fuzzer.rl.run_campaign --preset free5gc_quick \\
        --restart-cmd "sudo scripts/free5gc.sh restart v4.2.2"

# Custom JSON campaign file:
    python -m fuzzer.rl.run_campaign --campaign my_campaign.json \\
        --core free5gc \\
        --restart-cmd "sudo scripts/free5gc.sh restart v4.2.2"

# List available presets:
    python -m fuzzer.rl.run_campaign --list-presets

Campaign JSON format
--------------------
[
  {
    "nf_type":   "SMF",
    "timesteps": 60000,
    "scenarios": ["smf_fuzz_ctx_create_fields", "smf_fuzz_ctx_double_create"],
    "mode":      "hybrid"          // optional, default: hybrid
  },
  ...
]
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Per-NF scenario lists  (union of open5GS + free5GC scenarios)
# ---------------------------------------------------------------------------

_NRF_SCENARIOS = [
    "nrf_fuzz_register_body",
    "nrf_fuzz_register_malformed",
    "nrf_fuzz_scp_array_count",           # open5GS #4383 stack overflow via scpDomainInfoList
    "nrf_fuzz_subscribe_flood",            # subscription table exhaustion
    "nrf_fuzz_discover_multi_registered",
    "nrf_fuzz_update_after_register",
    "nrf_fuzz_deregister_unregistered",
    "nrf_fuzz_status_notify_dnn",         # #4406/#4469/#4470 dnnInfos overflow in AMF
    "nrf_fuzz_disc_gpsi_short",           # free5GC #757: short gpsi → slice bounds panic
    "nrf_fuzz_disc_empty_snssai",         # free5GC #758: empty snssai → nil deref
    "nrf_fuzz_oauth2_unknown_type",       # free5GC #434: unknown targetNfType → panic
]

_AMF_SCENARIOS = [
    "amf_fuzz_ue_ctx_create_supi",
    "amf_fuzz_ue_ctx_bad_supi",
    "amf_fuzz_n1n2_after_ctx",
    "amf_fuzz_n1n2_no_ctx",
    "amf_fuzz_event_subscribe_after_ctx",
    "amf_fuzz_nssai_array_count",         # open5GS #4403 oversized nssai array
    "amf_fuzz_ue_ctx_transfer",           # #4397/#4399/#4402 nil-deref on transfer
    "amf_fuzz_comm_sub_seq",              # #876/#902 panic on DELETE after PUT
    "amf_fuzz_callback_sdm_notify",       # #4395 sdm-notify nil-deref
    "amf_fuzz_multipart_ue_ctx",          # free5GC #755: multipart → JSON decode panic
    "amf_fuzz_evts_sub_modify",           # free5GC #754: PATCH after DELETE → nil panic
    "amf_fuzz_restricted_rat_list",       # free5GC #756: restrictedRatList[0] unchecked
]

_SMF_SCENARIOS = [
    "smf_fuzz_ctx_create_fields",
    "smf_fuzz_ctx_create_wrong_plmn",
    "smf_fuzz_ctx_modify_after_create",
    "smf_fuzz_ctx_release_after_create",
    "smf_fuzz_ctx_double_create",
    "smf_fuzz_issue4408_wrong_n2type",    # open5GS #4408 wrong n2SmInfoType assert
    "smf_fuzz_policy_notify",             # #4442/#4453 policy-notify nil-deref
]

_UDM_SCENARIOS = [
    "udm_fuzz_smf_reg_psi_boundary",
    "poc_4255_udm_psi_zero",              # open5GS #4255 PSI=0 regression probe
    "poc_4420_udm_purgeflag",             # open5GS #4420: PUT then PATCH purgeFlag
    "udm_purgeflag_guami_mismatch",       # open5GS #4420: Guami-mismatch memcmp boundary
    "udm_purgeflag_after_auth",           # open5GS #4420: via auth-data + registration
    "udm_fuzz_psi_after_context",         # psi OOB with udm_ue already in memory
    "udm_smf_reg_delete_before_get",      # psi > OGS_MAX_NUM_OF_PDU_SESSIONS OOB
    "udm_fuzz_auth_data_supi",            # #4418/#1037 nil sequenceNumber
    "udm_fuzz_sdm_shared_data",           # free5GC #762: GET shared-data nil deref
    "udm_fuzz_uecm_incomplete_reg",       # free5GC #761: PUT missing mandatory fields
    "udm_null_byte_supi_path",            # free5GC #780: null byte in SUPI path
]

_UDR_SCENARIOS = [
    "udr_fuzz_policy_supi_variant",
    "udr_fuzz_sub_supi_variant",
    "udr_fuzz_sub_provisioned_supi",      # provisioned-data path crashes on prefix_only
    "poc_4412_udr_prefix_supi",           # open5GS #4412 bare "imsi" path assertion
    "udr_prefix_sub_provisioned",         # open5GS #4412 via subscription-data path
    "poc_4411_udr_malformed_pei",         # open5GS #4411 pei="foo" NULL deref
    "poc_4411_udr_bad_pei_type",          # open5GS #4411 variant: unknown type → assert
]

_AUSF_SCENARIOS = [
    "ausf_fuzz_auth_create",              # #4472/#4523 AUSF auth create crash
    "ausf_fuzz_eap_session",              # #1030/#982/#983 decodeEapAkaPrime OOB
]

# Full scenario list per NF (used for standard and long tiers)
_SCENARIOS: dict = {
    "NRF":  _NRF_SCENARIOS,
    "AMF":  _AMF_SCENARIOS,
    "SMF":  _SMF_SCENARIOS,
    "UDM":  _UDM_SCENARIOS,
    "UDR":  _UDR_SCENARIOS,
    "AUSF": _AUSF_SCENARIOS,
}

# 2 representative scenarios per NF for quick smoke tests
_QUICK_SCENARIOS: dict = {
    "NRF":  ["nrf_fuzz_subscribe_flood",   "nrf_fuzz_scp_array_count"],
    "AMF":  ["amf_fuzz_ue_ctx_transfer",   "amf_fuzz_n1n2_no_ctx"],
    "SMF":  ["smf_fuzz_ctx_create_fields", "smf_fuzz_ctx_double_create"],
    "AUSF": ["ausf_fuzz_auth_create",      "ausf_fuzz_eap_session"],
}

# Timestep budgets per NF: (standard, long, quick)
# quick=0 → NF excluded from quick presets (setup cost too high for a smoke test)
_STEPS: dict = {
    "NRF":  ( 50000, 150000, 10000),
    "AMF":  ( 50000, 200000, 10000),
    "SMF":  ( 50000, 150000, 10000),
    "AUSF": ( 50000, 150000, 10000),
    "UDM":  ( 50000, 150000,     0),
    "UDR":  ( 50000, 150000,     0),
}

# NF processing order per core
_OPEN5GS_NFS = ["NRF", "AMF", "SMF", "UDM", "UDR", "AUSF"]
_FREE5GC_NFS = ["NRF", "AMF", "SMF", "AUSF", "UDM", "UDR"]

_TIER_IDX = {"standard": 0, "long": 1, "quick": 2}


def _preset(nf_order: list, tier: str) -> list:
    """Build a campaign job list for the given NF order and timestep tier."""
    idx = _TIER_IDX[tier]
    jobs = []
    for nf in nf_order:
        steps = _STEPS[nf][idx]
        if steps == 0:
            continue
        scens = _QUICK_SCENARIOS[nf] if tier == "quick" else _SCENARIOS[nf]
        jobs.append({
            "nf_type":   nf,
            "timesteps": steps,
            "mode":      "hybrid",
            "scenarios": scens,
        })
    return jobs


# ---------------------------------------------------------------------------
# Built-in campaign presets
# ---------------------------------------------------------------------------
# --core is auto-inferred from the preset name (free5gc* → free5gc, else open5gs).
# Pass --restart-cmd matching the target core.
#
# open5gs / free5gc              balanced coverage,  ~6–7h
# open5gs_long / free5gc_long    deep overnight run, ~20h
# open5gs_quick / free5gc_quick  smoke test,         ~30min

PRESETS: dict = {
    "open5gs":       _preset(_OPEN5GS_NFS, "standard"),
    "open5gs_long":  _preset(_OPEN5GS_NFS, "long"),
    "open5gs_quick": _preset(_OPEN5GS_NFS, "quick"),
    "free5gc":       _preset(_FREE5GC_NFS, "standard"),
    "free5gc_long":  _preset(_FREE5GC_NFS, "long"),
    "free5gc_quick": _preset(_FREE5GC_NFS, "quick"),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_sudo(restart_cmd: str) -> bool:
    """Return True if restart_cmd can run without a password prompt.

    Extracts the first token that looks like an absolute path (the script),
    then probes it with 'sudo -n -l <path>'.  Warns but does not abort —
    the user may have entered credentials recently via sudo's timestamp cache.
    """
    if not restart_cmd:
        return True
    # Find the script path: first token starting with / or a relative scripts/
    parts = restart_cmd.split()
    script = next(
        (p for p in parts if p.startswith('/') or p.startswith('scripts/')),
        None,
    )
    if script is None:
        return True
    script = os.path.abspath(script)
    try:
        r = subprocess.run(
            ['sudo', '-n', '-l', script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _crash_count(crash_dir: str, since_ts: float) -> int:
    """Count crash files written to crash_dir after since_ts (epoch seconds)."""
    count = 0
    for path in glob.glob(os.path.join(crash_dir, "crash_*.json")):
        try:
            if os.path.getmtime(path) >= since_ts:
                count += 1
        except OSError:
            pass
    return count


def _build_cmd(job: dict, restart_cmd: str, crash_dir: str,
               model_dir: str, no_test: bool,
               core: str = 'open5gs',
               plmn_mcc: str = '', plmn_mnc: str = '') -> list:
    scenarios = ",".join(job["scenarios"])
    cmd = [
        sys.executable, "-m", "fuzzer.rl.train_protocol",
        "--protocol",    "sbi",
        "--core",        core,
        "--nf-type",     job["nf_type"],
        "--scenario",    scenarios,
        "--mode",        job.get("mode", "hybrid"),
        "--timesteps",   str(job["timesteps"]),
        "--output-dir",  crash_dir,
        "--model-out",   os.path.join(model_dir, f"rl_{job['nf_type'].lower()}"),
    ]
    if plmn_mcc:
        cmd += ["--plmn-mcc", plmn_mcc]
    if plmn_mnc:
        cmd += ["--plmn-mnc", plmn_mnc]
    if restart_cmd:
        cmd += ["--restart-cmd", restart_cmd]
    if not no_test:
        cmd += ["--test"]
    return cmd


def _hms(seconds: float) -> str:
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a sequential multi-NF fuzzing campaign.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--preset",       metavar="NAME",
                     help="Built-in campaign preset (see --list-presets)")
    src.add_argument("--campaign",     metavar="FILE",
                     help="Path to a JSON campaign file")
    src.add_argument("--list-presets", action="store_true",
                     help="Print available built-in presets and exit")

    parser.add_argument("--core", default=None,
                        choices=["open5gs", "free5gc"],
                        help="5G core to fuzz (auto-inferred from preset name if omitted)")
    parser.add_argument("--plmn-mcc", default="",
                        help="PLMN MCC override (default: 999 for open5gs, 208 for free5gc)")
    parser.add_argument("--plmn-mnc", default="",
                        help="PLMN MNC override (default: 70 for open5gs, 93 for free5gc)")
    parser.add_argument("--restart-cmd", metavar="CMD", default="",
                        help="Shell command to restart all NFs after a crash "
                             "(passed to every train_protocol invocation)")
    parser.add_argument("--crash-dir",  default="fuzzer/data/crashes",
                        metavar="DIR",  help="Directory for crash corpus files")
    parser.add_argument("--model-dir",  default="fuzzer/data/models",
                        metavar="DIR",  help="Directory for saved models")
    parser.add_argument("--no-test",    action="store_true",
                        help="Skip post-training test episodes")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Print the commands that would be run, then exit")

    args = parser.parse_args()

    if args.list_presets:
        print("Available presets:")
        for name, jobs in PRESETS.items():
            core_hint = "free5gc" if name.startswith("free5gc") else "open5gs"
            total_steps = sum(j["timesteps"] for j in jobs)
            nfs = ", ".join(f"{j['nf_type']}({j['timesteps']//1000}k)" for j in jobs)
            print(f"  {name:<18} [{core_hint}]  {total_steps//1000}k steps — {nfs}")
        return 0

    # Load campaign
    if args.preset:
        if args.preset not in PRESETS:
            print(f"ERROR: unknown preset {args.preset!r}. "
                  f"Use --list-presets to see options.", file=sys.stderr)
            return 1
        jobs = PRESETS[args.preset]
        # Auto-infer core from preset name when not explicitly set
        if args.core is None:
            args.core = "free5gc" if args.preset.startswith("free5gc") else "open5gs"
    else:
        with open(args.campaign) as f:
            jobs = json.load(f)
        if args.core is None:
            args.core = "open5gs"

    os.makedirs(args.crash_dir, exist_ok=True)
    os.makedirs(args.model_dir, exist_ok=True)

    # Auto-derive PLMN defaults per core when not explicitly overridden
    _PLMN_DEFAULTS = {
        'open5gs': ('999', '70'),
        'free5gc':  ('208', '93'),
    }
    plmn_mcc = args.plmn_mcc or _PLMN_DEFAULTS[args.core][0]
    plmn_mnc = args.plmn_mnc or _PLMN_DEFAULTS[args.core][1]

    total_steps = sum(j["timesteps"] for j in jobs)
    bar = "=" * 72

    print(bar)
    print(f"  FUZZING CAMPAIGN — {len(jobs)} NFs — {total_steps//1000}k total timesteps")
    print(f"  Core:        {args.core}  PLMN: {plmn_mcc}/{plmn_mnc}")
    print(f"  Restart cmd: {args.restart_cmd or '(none)'}")
    print(bar)

    # Pre-flight: verify restart command won't block on a sudo password prompt.
    if args.restart_cmd and not args.dry_run:
        if not _check_sudo(args.restart_cmd):
            print(
                "WARNING: restart command may require a password:\n"
                f"  {args.restart_cmd}\n"
                "  The campaign will hang if sudo prompts during a restart.\n"
                "  Fix: add a NOPASSWD rule — see README or run:\n"
                "    sudo visudo -f /etc/sudoers.d/networkfuzzer\n"
                "  and add:\n"
                f"    {os.environ.get('USER','<user>')} ALL=(root) NOPASSWD: "
                f"{os.path.abspath(args.restart_cmd.split()[1] if len(args.restart_cmd.split()) > 1 else args.restart_cmd.split()[0])}\n"
                "  Press Ctrl-C within 10s to abort, or wait to continue anyway ...",
                file=sys.stderr,
            )
            try:
                time.sleep(10)
            except KeyboardInterrupt:
                print("Aborted.", file=sys.stderr)
                return 1
        else:
            print(f"  sudo check: OK (passwordless restart confirmed)")

    campaign_start = time.monotonic()
    results = []

    for idx, job in enumerate(jobs, 1):
        nf      = job["nf_type"]
        steps   = job["timesteps"]
        mode    = job.get("mode", "hybrid")
        scens   = job["scenarios"]

        print(f"\n[{idx}/{len(jobs)}] {nf}  —  {steps//1000}k steps  mode={mode}")
        print(f"  scenarios: {', '.join(scens)}")

        if steps == 0:
            print(f"  timesteps=0 — skipping")
            results.append({"nf": nf, "steps": 0, "crashes": 0,
                            "elapsed": 0, "rc": 0, "skipped": True})
            continue

        cmd = _build_cmd(job, args.restart_cmd, args.crash_dir,
                         args.model_dir, args.no_test,
                         core=args.core, plmn_mcc=plmn_mcc, plmn_mnc=plmn_mnc)

        if args.dry_run:
            print("  CMD:", " ".join(cmd))
            results.append({"nf": nf, "steps": steps, "crashes": 0,
                            "elapsed": 0, "rc": 0})
            continue

        t0 = time.monotonic()
        since_ts = time.time()

        try:
            # stdin=DEVNULL ensures any unexpected sudo password prompt fails
            # immediately rather than blocking the campaign indefinitely.
            rc = subprocess.run(cmd, stdin=subprocess.DEVNULL).returncode
        except KeyboardInterrupt:
            print(f"\n  Interrupted during {nf} — stopping campaign.")
            break

        elapsed  = time.monotonic() - t0
        crashes  = _crash_count(args.crash_dir, since_ts)
        results.append({"nf": nf, "steps": steps, "crashes": crashes,
                        "elapsed": elapsed, "rc": rc})

        status = "OK" if rc == 0 else f"exit={rc}"
        print(f"  {nf} done in {_hms(elapsed)} — {crashes} new crash file(s) — {status}")

    # Final summary
    total_elapsed = time.monotonic() - campaign_start
    total_crashes = sum(r["crashes"] for r in results)

    print(f"\n{bar}")
    print(f"  CAMPAIGN SUMMARY")
    print(f"{bar}")
    print(f"  {'NF':<8} {'Steps':>8}  {'Crashes':>8}  {'Time':>10}  Status")
    print(f"  {'-'*56}")
    for r in results:
        if r.get("skipped"):
            status = "SKIP"
        elif r["rc"] == 0:
            status = "OK"
        else:
            status = f"exit={r['rc']}"
        print(f"  {r['nf']:<8} {r['steps']:>8}  {r['crashes']:>8}  "
              f"{_hms(r['elapsed']):>10}  {status}")
    print(f"  {'-'*56}")
    ran = [r for r in results if not r.get("skipped")]
    print(f"  {'TOTAL':<8} {sum(r['steps'] for r in ran):>8}  "
          f"{total_crashes:>8}  {_hms(total_elapsed):>10}")
    print(bar)

    return 0


if __name__ == "__main__":
    sys.exit(main())
