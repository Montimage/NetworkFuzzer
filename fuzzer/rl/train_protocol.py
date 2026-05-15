#!/usr/bin/env python3
"""
Protocol-Agnostic RL Fuzzer Training.

This script uses the new refactored architecture with protocol adapters.
It can fuzz any protocol that has a registered adapter.

Usage:
    # DICOM fuzzing (default)
    python -m fuzzer.rl.train_protocol --protocol dicom \
        --target-host 192.168.1.100 --target-port 4242 \
        --mode hybrid --timesteps 20000 --test

    # List available protocols
    python -m fuzzer.rl.train_protocol --list-protocols

    # DICOM with specific options
    python -m fuzzer.rl.train_protocol --protocol dicom \
        --target-host localhost --target-port 4242 \
        --called-ae ORTHANC --mode semantic --timesteps 10000
"""

import os
import sys
import time
import argparse
import logging

import numpy as np

# Ensure imports work
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("rl_fuzzer_training.log"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Protocol-Agnostic RL Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # DICOM fuzzing against Orthanc
  %(prog)s --protocol dicom --target-host localhost --target-port 4242 \\
      --called-ae ORTHANC --mode hybrid --timesteps 20000 --test

  # DICOM semantic fuzzing
  %(prog)s --protocol dicom --target-host localhost --target-port 4242 \\
      --mode semantic --timesteps 10000

  # List available protocols
  %(prog)s --list-protocols
"""
    )

    # Protocol selection
    parser.add_argument("--protocol", type=str, default="dicom",
                        help="Protocol to fuzz (default: dicom)")
    parser.add_argument("--list-protocols", action="store_true",
                        help="List available protocol adapters")

    # Target configuration
    parser.add_argument("--target-host", type=str, default=None,
                        help="Target server hostname/IP")
    parser.add_argument("--target-port", type=int, default=None,
                        help="Target server port (default: protocol-specific)")

    # Protocol-specific options — DICOM
    parser.add_argument("--called-ae", type=str, default="ORTHANC",
                        help="DICOM: Called AE title")
    parser.add_argument("--calling-ae", type=str, default="FUZZER",
                        help="DICOM: Calling AE title")

    # Protocol-specific options — NGAP / open5GS
    parser.add_argument("--gnb-id", type=int, default=1,
                        help="NGAP: gNB identifier (default: 1)")
    parser.add_argument("--plmn-mcc", type=str, default="999",
                        help="NGAP/SBI: PLMN Mobile Country Code (default: 999)")
    parser.add_argument("--plmn-mnc", type=str, default="70",
                        help="NGAP/SBI: PLMN Mobile Network Code (default: 70)")
    parser.add_argument("--amf-log", type=str, default="",
                        help="NGAP: path to AMF log file for crash detection "
                             "(auto-derived from --core when not set)")

    # Protocol-specific options — SBI (HTTP/2 5G Service-Based Interface)
    parser.add_argument("--nf-type", type=str, default="NRF",
                        choices=["NRF", "AMF", "SMF", "UDM", "UDR", "PCF", "AUSF"],
                        help="SBI: target NF type (default: NRF)")
    parser.add_argument("--nf-log", type=str, default="",
                        help="SBI: override NF log file path for crash/anomaly detection")
    parser.add_argument("--extra-nfs", type=str, default="",
                        help="SBI: comma-separated extra NF types to monitor for crashes "
                             "(e.g. 'AMF,SMF' when fuzzing NRF to detect cascade crashes)")

    # Fuzzing mode
    parser.add_argument("--mode", type=str, default="hybrid",
                        choices=["semantic", "aggressive", "state", "hybrid"],
                        help="Fuzzing mode (default: hybrid)")

    # Training parameters
    parser.add_argument("--algorithm", type=str, default="PPO",
                        choices=["DQN", "PPO"],
                        help="RL algorithm (default: PPO)")
    parser.add_argument("--timesteps", type=int, default=50000,
                        help="Training timesteps (default: 50000)")
    parser.add_argument("--max-steps", type=int, default=30,
                        help="Max steps per episode (default: 30)")

    # Output
    parser.add_argument("--model-out", type=str, default="fuzzer/data/models/rl_fuzzer",
                        help="Model output path")
    parser.add_argument("--output-dir", type=str, default="fuzzer/data/pcap_output/rl_generated",
                        help="Output directory for generated traffic")

    # Testing
    parser.add_argument("--test", action="store_true",
                        help="Run test episodes after training")
    parser.add_argument("--n-test", type=int, default=10,
                        help="Number of test episodes (default: 10)")

    # Timeouts
    parser.add_argument("--recv-timeout", type=float, default=0.5,
                        help="Per-message recv timeout in seconds (default: 0.5)")
    parser.add_argument("--connect-timeout", type=float, default=3.0,
                        help="Socket connect timeout in seconds (default: 3.0)")
    parser.add_argument("--inter-step-delay", type=float, default=0.0,
                        help="Sleep between actions in seconds (default: 0.0). "
                             "Use 0.1-0.5 to avoid SCTP backlog flooding.")
    parser.add_argument("--persistent-conn", action="store_true",
                        help="Reuse one SCTP/TCP association per episode instead of "
                             "opening a new connection per action. More realistic "
                             "(real gNBs maintain a single SCTP association) and "
                             "avoids N2 listener overload.")
    parser.add_argument("--restart-cmd", type=str, default=None,
                        dest="amf_restart_cmd",
                        help="Shell command to restart all NFs after a crash/hang. "
                             "Example: 'sudo scripts/open5gs.sh restart v2.7.7'. "
                             "Auto-derived from --open5gs-dir when not set.")
    parser.add_argument("--open5gs-dir", type=str, default=None,
                        help="Path to open5GS source tree for auto-deriving restart "
                             "command (default: ../open5gs relative to CWD)")

    # Core selection
    parser.add_argument("--core", type=str, default="open5gs",
                        choices=["open5gs", "free5gc"],
                        help="5G core implementation to target (default: open5gs)")
    parser.add_argument("--free5gc-dir", type=str, default=None,
                        help="Path to free5GC repo root for binary/log path "
                             "auto-derivation (default: ~/free5gc)")
    parser.add_argument("--gcov-gcda-dir", type=str, default=None,
                        dest="gcov_gcda_dir",
                        help="Path to open5GS BUILD_DIR/src where .gcda files are written "
                             "(enables gcov source-level coverage reward). "
                             "Example: ~/open5gs/build_v2.7.7/src")
    parser.add_argument("--gcov-src-dir", type=str, default=None,
                        dest="gcov_src_dir",
                        help="Path to open5GS source root, used as gcovr --root. "
                             "Example: ~/open5gs  (default: parent of --gcov-gcda-dir)")

    # Exploration
    parser.add_argument("--exploration-rate", type=float, default=0.15,
                        help="Novel combo exploration rate 0.0-1.0 (default: 0.15)")

    # Action space filtering
    parser.add_argument("--api", type=str, default=None,
                        help="Restrict fuzzing to a message/scenario name prefix "
                             "(e.g. 'nrf_nf_register', 'nrf_', 'amf_', 'smf_'). "
                             "Only scenarios and state transitions whose messages "
                             "all start with this prefix are included.")
    parser.add_argument("--scenario", type=str, default=None,
                        help="Comma-separated list of exact scenario names to fuzz "
                             "(e.g. 'nrf_fuzz_register_body,nrf_fuzz_subscribe_flood'). "
                             "Lists available scenarios when used with --list-scenarios.")
    parser.add_argument("--list-scenarios", action="store_true",
                        help="Print all available scenario names for the chosen protocol and exit.")

    args = parser.parse_args()

    # Import protocol adapter system
    from fuzzer.rl.base.protocol_adapter import get_protocol_adapter, list_protocols

    # Register all protocols by importing the protocols module
    import fuzzer.rl.protocols

    # List protocols if requested (no adapter needed)
    if args.list_protocols:
        print("\nAvailable Protocol Adapters:")
        print("-" * 40)
        for proto in list_protocols():
            _a = get_protocol_adapter(proto)
            print(f"  {proto:<12} (default port: {_a.default_port})")
        print()
        return 0

    # Parse filters
    scenario_filter = [s.strip() for s in args.scenario.split(',') if s.strip()] \
                      if args.scenario else None
    api_filter = args.api or None

    # NF host tables (indexed by core)
    _SBI_NF_HOSTS = {
        'open5gs': {
            'NRF': '127.0.0.10', 'UDR': '127.0.0.20', 'UDM': '127.0.0.12',
            'AUSF': '127.0.0.11', 'BSF': '127.0.0.15', 'PCF': '127.0.0.13',
            'NSSF': '127.0.0.14', 'AMF': '127.0.0.5',  'SMF': '127.0.0.4',
        },
        'free5gc': {
            'NRF': '127.0.0.10', 'AMF': '127.0.0.18', 'SMF': '127.0.0.2',
            'UDR': '127.0.0.3',  'UDM': '127.0.0.4',  'AUSF': '127.0.0.9',
            'PCF': '127.0.0.7',  'BSF': '127.0.0.31', 'NSSF': '127.0.0.15',
            'CHF': '127.0.0.113',
        },
    }
    _NGAP_AMF_HOST = {'open5gs': '127.0.0.5', 'free5gc': '127.0.0.18'}

    # Auto-derive log paths before building adapters
    import glob as _glob

    def _find_open5gs_log(nf_name: str) -> str:
        """Return the most-recently-written open5gs NF log from runtime tmp dirs."""
        dirs = sorted(_glob.glob('/tmp/open5gs-*-logs'), reverse=True)
        for d in dirs:
            p = f'{d}/{nf_name}.log'
            if os.path.exists(p):
                return p
        # Fall back to install path
        return f'/home/strongcourage/open5gs/install/var/log/open5gs/{nf_name}.log'

    if args.protocol.lower() == 'ngap' and not args.amf_log:
        if args.core == 'free5gc':
            _ld = sorted(_glob.glob('/tmp/free5gc-*-logs'), reverse=True)
            args.amf_log = f'{_ld[0]}/amf.log' if _ld else '/tmp/free5gc-logs/amf.log'
        else:
            args.amf_log = _find_open5gs_log('amf')

    if args.protocol.lower() == 'sbi' and not args.nf_log:
        if args.core == 'open5gs':
            args.nf_log = _find_open5gs_log(args.nf_type.lower())

    # free5GC bin dir for process detection
    _free5gc_dir = args.free5gc_dir or os.path.expanduser('~/free5gc')
    _bin_dir = os.path.join(_free5gc_dir, 'bin') if args.core == 'free5gc' else None

    # Get protocol adapter
    try:
        adapter_kwargs = {}
        if args.protocol.lower() == "dicom":
            adapter_kwargs = {
                "called_ae": args.called_ae,
                "calling_ae": args.calling_ae,
            }
        elif args.protocol.lower() == "ngap":
            adapter_kwargs = {
                "gnb_id":   args.gnb_id,
                "plmn_mcc": args.plmn_mcc,
                "plmn_mnc": args.plmn_mnc,
                "amf_log":  args.amf_log,
                "core":     args.core,
                "bin_dir":  _bin_dir,
            }
        elif args.protocol.lower() == "sbi":
            extra = [n.strip().upper() for n in args.extra_nfs.split(',')
                     if n.strip()] if args.extra_nfs else []
            # Auto-derive gcov_src_dir as parent of gcov_gcda_dir when not set
            _gcov_src = getattr(args, 'gcov_src_dir', None)
            _gcov_gcda = getattr(args, 'gcov_gcda_dir', None)
            if _gcov_gcda and not _gcov_src:
                import os as _os
                _gcov_src = _os.path.dirname(_gcov_gcda.rstrip('/'))
            adapter_kwargs = {
                "nf_type":       args.nf_type,
                "plmn_mcc":      args.plmn_mcc,
                "plmn_mnc":      args.plmn_mnc,
                "nf_log":        args.nf_log,
                "extra_nfs":     extra,
                "core":          args.core,
                "bin_dir":       _bin_dir,
                "gcov_gcda_dir": _gcov_gcda,
                "gcov_src_dir":  _gcov_src,
            }
        adapter = get_protocol_adapter(args.protocol, **adapter_kwargs)
    except ValueError as e:
        logger.error(str(e))
        return 1

    # Derive --target-host from --nf-type / --core when not specified
    if not args.target_host:
        if args.protocol.lower() == 'sbi':
            args.target_host = _SBI_NF_HOSTS[args.core].get(
                args.nf_type.upper(), '127.0.0.1')
        elif args.protocol.lower() == 'ngap':
            args.target_host = _NGAP_AMF_HOST[args.core]

    # Derive --nf-log from --nf-type / --core when not specified
    if args.protocol.lower() == 'sbi' and not args.nf_log:
        if args.core == 'free5gc':
            import glob as _glob
            _ld = sorted(_glob.glob('/tmp/free5gc-*-logs'), reverse=True)
            args.nf_log = (f'{_ld[0]}/{args.nf_type.lower()}.log'
                           if _ld else f'/tmp/free5gc-logs/{args.nf_type.lower()}.log')
        else:
            args.nf_log = f'/tmp/open5gs-v277-logs/{args.nf_type.lower()}.log'
        # propagate into the already-built adapter
        adapter._monitor._log_path = args.nf_log

    # Derive --restart-cmd from the core build tree when not specified
    if not args.amf_restart_cmd:
        nf = args.nf_type.lower() if args.protocol.lower() == 'sbi' else 'amf'
        if args.core == 'free5gc':
            nf_bin = os.path.join(_free5gc_dir, 'bin', nf)
            nf_cfg = os.path.join(_free5gc_dir, 'config', f'{nf}cfg.yaml')
            nf_log = args.nf_log or f'/tmp/free5gc-logs/{nf}.log'
            if os.path.isfile(nf_bin):
                args.amf_restart_cmd = (
                    f'{nf_bin} --config {nf_cfg} -l {nf_log} >> {nf_log} 2>&1 &'
                )
        else:
            open5gs_dir = args.open5gs_dir or os.path.abspath(
                os.path.join(os.getcwd(), '../open5gs'))
            nf_bin = os.path.join(open5gs_dir, 'build', 'src', nf, f'open5gs-{nf}d')
            nf_cfg = os.path.join(open5gs_dir, 'build', 'configs', 'open5gs', f'{nf}.yaml')
            nf_log = args.nf_log or f'/tmp/open5gs-v277-logs/{nf}.log'
            if os.path.isfile(nf_bin):
                args.amf_restart_cmd = (
                    f'{nf_bin} -c {nf_cfg} -l {nf_log} >> {nf_log} 2>&1 &'
                )

    # Determine port
    target_port = args.target_port or adapter.default_port

    # List scenarios if requested (adapter now available)
    if args.list_scenarios:
        print(f"\nAvailable scenarios for '{args.protocol}':")
        print(f"{'Name':<45} {'Fuzz target':<30} Setup messages")
        print("-" * 100)
        for s in adapter.get_scenarios():
            selected = ""
            if scenario_filter and s.name in scenario_filter:
                selected = " ✓"
            elif api_filter and s.name.startswith(api_filter):
                selected = " ✓"
            setup = ', '.join(s.setup_messages) if s.setup_messages else "(none)"
            print(f"  {s.name + selected:<45} {s.fuzz_message:<30} {setup}")
        print()
        return 0

    # Print configuration
    print("\n" + "=" * 70)
    print(f"PROTOCOL-AGNOSTIC RL FUZZER")
    print("=" * 70)
    print(f"Protocol:    {adapter.protocol_name}")
    print(f"Core:        {args.core}")
    print(f"Mode:        {args.mode}")
    print(f"Algorithm:   {args.algorithm}")
    print(f"Timesteps:   {args.timesteps}")
    print(f"Max steps:   {args.max_steps}")
    if args.target_host:
        print(f"Target:      {args.target_host}:{target_port}")
        if args.protocol.lower() == "dicom":
            print(f"DICOM AE:    Called={args.called_ae}, Calling={args.calling_ae}")
        elif args.protocol.lower() == "ngap":
            print(f"NGAP:        gNB-ID={args.gnb_id}  PLMN={args.plmn_mcc}/{args.plmn_mnc}")
            print(f"AMF log:     {args.amf_log}")
        elif args.protocol.lower() == "sbi":
            print(f"SBI NF:      {args.nf_type}  PLMN={args.plmn_mcc}/{args.plmn_mnc}")
            if args.extra_nfs:
                print(f"Monitor NFs: {args.extra_nfs}")
    else:
        print(f"Target:      offline (no live testing)")
    print("=" * 70 + "\n")

    # Show protocol capabilities
    semantic_fields = adapter.get_semantic_fields()
    state_transitions = adapter.get_state_transitions()
    payload_targets = adapter.get_payload_targets()

    print(f"Protocol capabilities:")
    print(f"  Semantic fields:    {len(semantic_fields)}")
    for f in semantic_fields[:5]:
        print(f"    - {f.name}: {f.description}")
    print(f"  State transitions:  {len(state_transitions)}")
    print(f"  Payload targets:    {len(payload_targets)}")
    print()

    # Initial health check
    if args.target_host:
        print("--- Initial Health Check ---")
        health = adapter.check_health(args.target_host, target_port)
        print(f"  Healthy:  {health.is_healthy}")
        print(f"  Latency:  {health.latency_ms:.1f} ms")
        if health.details:
            for k, v in health.details.items():
                print(f"  {k}:  {v}")
        if health.error:
            print(f"  Error:    {health.error}")
        print()

    # Create environment
    from fuzzer.rl.base.generic_env import GenericFuzzEnv

    if api_filter or scenario_filter:
        label = f"api='{api_filter}'" if api_filter else ""
        if scenario_filter:
            label += (" " if label else "") + f"scenarios={scenario_filter}"
        print(f"Action filter: {label}")

    env = GenericFuzzEnv(
        adapter=adapter,
        target_host=args.target_host,
        target_port=target_port,
        max_steps=args.max_steps,
        mode=args.mode,
        recv_timeout=args.recv_timeout,
        connect_timeout=args.connect_timeout,
        inter_step_delay=args.inter_step_delay,
        persistent_conn=args.persistent_conn,
        scenario_filter=scenario_filter,
        api_filter=api_filter,
    )

    if args.amf_restart_cmd:
        env.set_restart_cmd(args.amf_restart_cmd)
        print(f"Auto-restart: {args.amf_restart_cmd}")

    print(f"Environment created with {env.n_actions} actions")
    print()

    # Create and train agent
    from fuzzer.rl.agent import create_agent, train_agent, run_agent

    model = create_agent(env, algorithm=args.algorithm)
    start_time = time.monotonic()

    try:
        model = train_agent(model, total_timesteps=args.timesteps, model_path=args.model_out)

        # Test
        if args.test:
            # Ensure the server is alive before running test episodes.
            # Training may have ended with the NF crashed; restart it now so
            # the test episodes produce meaningful rewards rather than all 0.0.
            if args.target_host:
                health = adapter.check_health(args.target_host, target_port)
                if not health.is_healthy and args.amf_restart_cmd:
                    print("Server down before test — restarting...")
                    env._restart_server()
                    health = adapter.check_health(args.target_host, target_port)
                if not health.is_healthy:
                    print("WARNING: server still unhealthy — test rewards will be 0.0 "
                          "(connection refused). Pass --restart-cmd to auto-recover.")

            print(f"\n{'=' * 90}")
            print(f"TEST RUN ({args.n_test} episodes)")
            print(f"{'=' * 90}")

            results = run_agent(model, env, n_episodes=args.n_test)

            os.makedirs(args.output_dir, exist_ok=True)

            print(f"\n{'Ep':>3} {'Reward':>7} {'Action Type':<12} {'Details':<30} "
                  f"{'Response':<12} {'Crash':>6} {'Hang':>6}")
            print("-" * 100)

            total_crashes = 0
            total_hangs = 0
            action_results = {}

            for i, (pdu_bytes, ep_reward, info) in enumerate(results):
                action_type = info.get('action_type', 'unknown')
                details = info.get('mutation', info.get('payload', info.get('sequence', '-')))
                resp = info.get('response', 'none')
                crash = "CRASH!" if info.get('crash', False) else ""
                hang = "HANG!" if info.get('hang', False) else ""

                if info.get('crash'):
                    total_crashes += 1
                if info.get('hang'):
                    total_hangs += 1

                # Track action effectiveness
                action_key = f"{action_type}"
                if action_key not in action_results:
                    action_results[action_key] = {"count": 0, "reward": 0, "crashes": 0, "hangs": 0}
                action_results[action_key]["count"] += 1
                action_results[action_key]["reward"] += ep_reward
                if info.get('crash'):
                    action_results[action_key]["crashes"] += 1
                if info.get('hang'):
                    action_results[action_key]["hangs"] += 1

                print(f"{i+1:>3} {ep_reward:>7.1f} {action_type:<12} {str(details)[:30]:<30} "
                      f"{resp:<12} {crash:>6} {hang:>6}")

                # Show response sequence
                for r in info.get('responses', []):
                    print(f"      -> {r['message']}: {r['response']} ({r.get('time_ms', 0):.0f}ms)")

            print("-" * 100)

            rewards = [r[1] for r in results]
            print(f"\nSummary:")
            print(f"  Avg reward:     {sum(rewards)/len(rewards):.1f}")
            print(f"  Total crashes:  {total_crashes}")
            print(f"  Total hangs:    {total_hangs}")

            print(f"\n  Action type effectiveness:")
            for action, data in sorted(action_results.items(), key=lambda x: -x[1]["reward"]):
                avg = data['reward'] / max(data['count'], 1)
                print(f"    {action:<15} avg={avg:.1f} "
                      f"crashes={data['crashes']} hangs={data['hangs']} n={data['count']}")

            # Show top actions from environment stats
            print(f"\n  Top actions (from training):")
            for action, stats in env.get_action_stats(10):
                avg = stats['reward'] / max(stats['count'], 1)
                print(f"    {action:<40} avg={avg:.1f} n={stats['count']}")

            # Final health check
            if args.target_host:
                print(f"\n--- Post-Training Health Check ---")
                health = adapter.check_health(args.target_host, target_port)
                print(f"  Healthy:  {health.is_healthy}")
                print(f"  Latency:  {health.latency_ms:.1f} ms")
                if health.error:
                    print(f"  Error:    {health.error}")

    except KeyboardInterrupt:
        import signal as _signal
        _signal.signal(_signal.SIGINT, _signal.SIG_IGN)   # block further Ctrl+C during cleanup
        _print_interrupt_summary(env, model, start_time, adapter,
                                args.target_host, target_port)

    finally:
        env.close()
        print("\nDone.")

    return 0


def _print_interrupt_summary(env, model, start_time, adapter, target_host, target_port):
    """Print training summary after Ctrl+C interruption.

    SIGINT is already masked by the caller before this function is entered,
    so further Ctrl+C presses are ignored for the duration of cleanup.
    """
    elapsed = time.monotonic() - start_time

    print(f"\n{'=' * 70}")
    print(f"TRAINING INTERRUPTED (Ctrl+C)")
    print(f"{'=' * 70}")

    # Duration
    mins, secs = divmod(elapsed, 60)
    hrs, mins = divmod(mins, 60)
    if hrs > 0:
        print(f"  Duration:       {int(hrs)}h {int(mins)}m {int(secs)}s")
    elif mins > 0:
        print(f"  Duration:       {int(mins)}m {int(secs)}s")
    else:
        print(f"  Duration:       {secs:.1f}s")

    # Timesteps from model
    if model and hasattr(model, 'num_timesteps'):
        print(f"  Timesteps:      {model.num_timesteps}")

    # Environment counters
    print(f"  Hangs:          {env.counters['hangs']}")
    print(f"  Crashes:        {env.counters['crashes']}")
    print(f"  Successes:      {env.counters['successes']}")
    print(f"  Errors:         {env.counters['errors']}")

    # Top actions
    top_actions = env.get_action_stats(10)
    if top_actions:
        print(f"\n  Top actions (by avg reward):")
        for action, stats in top_actions:
            avg = stats['reward'] / max(stats['count'], 1)
            print(f"    {action:<40} avg={avg:.1f} n={stats['count']} "
                  f"crashes={stats['crashes']} hangs={stats['hangs']}")

    # Health check
    if target_host:
        print(f"\n--- Post-Interrupt Health Check ---")
        try:
            health = adapter.check_health(target_host, target_port, timeout=3.0)
            print(f"  Healthy:  {health.is_healthy}")
            print(f"  Latency:  {health.latency_ms:.1f} ms")
            if health.error:
                print(f"  Error:    {health.error}")
        except Exception as e:
            print(f"  Health check failed: {e}")

    print(f"{'=' * 70}")


if __name__ == "__main__":
    sys.exit(main())
