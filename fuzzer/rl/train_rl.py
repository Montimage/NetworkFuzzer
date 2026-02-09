#!/usr/bin/env python3
"""
Train an RL agent to fuzz DICOM targets.

Usage:
    # Fuzz ASSOC_RQ against live Orthanc
    python -m fuzzer.rl.train_rl --target-host 152.228.175.65 --target-port 4242 \\
        --seed-dir fuzzer/data/training_data/pdus/assoc_rq --timesteps 10000 --algorithm PPO --test

    # Fuzz PDATA in multi-PDU sessions (sends valid ASSOC_RQ first, then fuzzed PDATA)
    python -m fuzzer.rl.train_rl --target-host 152.228.175.65 --target-port 4242 \\
        --seed-dir fuzzer/data/training_data/pdus/pdata --mode session --timesteps 10000 --test

    # Use ML-generated PDUs as seeds (combine Transformer/VAE outputs with RL)
    python -m fuzzer.rl.train_rl --target-host 152.228.175.65 --target-port 4242 \\
        --seed-dir fuzzer/data/pcap_output/vae_deg_05 --timesteps 10000 --test

    # Offline only (mmt-security only, no live target)
    python -m fuzzer.rl.train_rl --seed-dir fuzzer/data/training_data/pdus/assoc_rq --timesteps 5000
"""

import os
import sys
import argparse
import logging
import glob

import numpy as np

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


def load_seed_pdus(seed_dir, max_pdus=200, pdu_type_filter=None):
    """Load seed PDUs from a directory.

    Supports:
      - numpy format (bytes.npy + offsets.npy)
      - raw .bin files
      - Mix of ML-generated outputs
    """
    pdus = []

    bytes_path = os.path.join(seed_dir, "bytes.npy")
    offsets_path = os.path.join(seed_dir, "offsets.npy")

    if os.path.exists(bytes_path) and os.path.exists(offsets_path):
        all_bytes = np.load(bytes_path)
        offsets = np.load(offsets_path)
        for i in range(min(len(offsets) - 1, max_pdus)):
            start, end = offsets[i], offsets[i + 1]
            pdu = bytes(all_bytes[start:end])
            if pdu_type_filter is None or (len(pdu) > 0 and pdu[0] == pdu_type_filter):
                pdus.append(pdu)
    else:
        for f in sorted(glob.glob(os.path.join(seed_dir, "*.bin")))[:max_pdus]:
            with open(f, 'rb') as fh:
                pdu = fh.read()
                if pdu_type_filter is None or (len(pdu) > 0 and pdu[0] == pdu_type_filter):
                    pdus.append(pdu)

    # Also check subdirectories (for ML-generated outputs)
    for subdir in sorted(os.listdir(seed_dir)):
        subpath = os.path.join(seed_dir, subdir)
        if os.path.isdir(subpath) and subdir != "pcap":
            for f in sorted(glob.glob(os.path.join(subpath, "*.bin")))[:max_pdus]:
                with open(f, 'rb') as fh:
                    pdu = fh.read()
                    # Strip trailing zeros (padding from RL environment)
                    pdu = pdu.rstrip(b'\x00')
                    if len(pdu) > 6 and (pdu_type_filter is None or pdu[0] == pdu_type_filter):
                        pdus.append(pdu)

    return pdus[:max_pdus]


def main():
    parser = argparse.ArgumentParser(description="Train RL agent for DICOM fuzzing")
    parser.add_argument("--seed-dir", type=str, default="fuzzer/data/training_data/pdus/assoc_rq",
                        help="Directory with seed PDUs (numpy, .bin, or ML-generated)")
    parser.add_argument("--extra-seeds", type=str, nargs="*", default=[],
                        help="Additional seed directories (e.g., ML-generated outputs)")
    parser.add_argument("--mode", type=str, default="single",
                        choices=["single", "session", "state_machine", "aggressive", "semantic", "hybrid"],
                        help="single: fuzz one PDU; session: valid ASSOC_RQ then fuzzed PDATA; "
                             "state_machine: test protocol state machine; "
                             "aggressive: combined exploit injection + state confusion; "
                             "semantic: DICOM-aware mutations with valid/boundary values; "
                             "hybrid: combines semantic + aggressive + state attacks")
    parser.add_argument("--target-host", type=str, default=None)
    parser.add_argument("--target-port", type=int, default=4242)
    parser.add_argument("--called-ae", type=str, default="ORTHANC")
    parser.add_argument("--algorithm", type=str, default="DQN",
                        choices=["DQN", "PPO"])
    parser.add_argument("--timesteps", type=int, default=5000)
    parser.add_argument("--max-steps", type=int, default=30)
    parser.add_argument("--model-out", type=str, default="fuzzer/data/models/rl_fuzzer")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--n-test", type=int, default=5, help="Number of test episodes")
    parser.add_argument("--output-dir", type=str, default="fuzzer/data/pcap_output/rl_generated")

    # Log monitoring options (for depth-based rewards)
    parser.add_argument("--log-path", type=str, default=None,
                        help="Path to LOCAL server log file (e.g., /var/log/orthanc.log)")
    parser.add_argument("--ssh-host", type=str, default=None,
                        help="SSH host for REMOTE log monitoring (e.g., user@192.168.1.100)")
    parser.add_argument("--ssh-log-path", type=str, default=None,
                        help="Path to log file on SSH host (e.g., /tmp/storescp.log)")
    parser.add_argument("--docker-container", type=str, default=None,
                        help="Docker container name for log monitoring (e.g., orthanc)")
    parser.add_argument("--server-type", type=str, default="orthanc",
                        choices=["orthanc", "dcmtk", "generic"],
                        help="Server type for log parsing (default: orthanc)")

    # Exploration options (for discovering novel attack combinations)
    parser.add_argument("--exploration-rate", type=float, default=0.15,
                        help="Probability of trying novel random combinations (0.0-1.0, default: 0.15)")
    parser.add_argument("--diversity-bonus", type=float, default=1.0,
                        help="Scale factor for diversity enforcement (0=disabled, 1.0=default, 2.0=aggressive)")
    parser.add_argument("--ssh-process", type=str, default=None,
                        help="Process name to monitor via SSH (e.g., 'storescp'). Requires --ssh-host.")
    parser.add_argument("--ssh-asan-log-pattern", type=str, default=None,
                        help="ASAN log file glob on remote host (e.g., '/tmp/asan_storescp.*'). "
                             "Requires --ssh-host and DCMTK compiled with -fsanitize=address.")
    parser.add_argument("--ssh-coverage-dir", type=str, default=None,
                        help="Build directory with .gcda coverage files on remote host "
                             "(e.g., '/opt/dcmtk/build'). Requires --ssh-host and DCMTK compiled with --coverage.")
    parser.add_argument("--fast", action="store_true",
                        help="Disable slow attacks (slowloris, fragment, concurrent, rapid_reconnect, "
                             "memory_exhaust) for faster training throughput")

    args = parser.parse_args()

    # Modes that don't need seed PDUs (they generate their own)
    SEEDLESS_MODES = ["state_machine", "aggressive", "semantic", "hybrid"]

    # Load seeds only for modes that need them
    seed_pdus = []
    if args.mode not in SEEDLESS_MODES:
        # Determine PDU type filter based on mode
        pdu_type_filter = None
        if args.mode == "session":
            pdu_type_filter = 0x04  # Only load PDATA PDUs

        # Load seeds from primary directory
        seed_pdus = load_seed_pdus(args.seed_dir, pdu_type_filter=pdu_type_filter)

        # Load extra seeds (from ML-generated outputs)
        for extra_dir in args.extra_seeds:
            if os.path.isdir(extra_dir):
                extra = load_seed_pdus(extra_dir, max_pdus=50, pdu_type_filter=pdu_type_filter)
                seed_pdus.extend(extra)
                logger.info(f"Loaded {len(extra)} extra seeds from {extra_dir}")

        if not seed_pdus:
            logger.error(f"No seed PDUs found in {args.seed_dir}")
            sys.exit(1)
        logger.info(f"Total seeds: {len(seed_pdus)} PDUs")

    print("\n" + "=" * 70)
    print("RL FUZZER TRAINING (with server health monitoring)")
    print("=" * 70)
    print(f"Mode:        {args.mode}")
    print(f"Algorithm:   {args.algorithm}")
    print(f"Timesteps:   {args.timesteps}")
    print(f"Max steps:   {args.max_steps}")
    if seed_pdus:
        print(f"Seeds:       {len(seed_pdus)} PDUs from {args.seed_dir}")
        if args.extra_seeds:
            print(f"Extra seeds: {args.extra_seeds}")
    elif args.mode == "hybrid":
        base_seed = os.path.dirname(args.seed_dir)
        has_assoc = os.path.isdir(os.path.join(base_seed, "assoc_rq"))
        has_pdata = os.path.isdir(os.path.join(base_seed, "pdata"))
        if has_assoc or has_pdata:
            print(f"Seeds:       seed corpus from {base_seed} (loaded at env init)")
        else:
            print(f"Seeds:       N/A (no seed corpus; use --seed-dir to point to pdus/ parent)")
    else:
        print(f"Seeds:       N/A (mode generates its own PDUs)")
    if args.target_host:
        print(f"Target:      {args.target_host}:{args.target_port} (AE: {args.called_ae})")
        print(f"Metrics:     response, mmt-security, C-ECHO health, "
              f"connection pool, latency delta")
    else:
        print(f"Target:      offline (mmt-security only)")
    if args.log_path or args.docker_container:
        log_src = args.log_path or f"docker:{args.docker_container}"
        print(f"Log monitor: {log_src} (type: {args.server_type})")
    print("=" * 70 + "\n")

    # Take initial baseline if we have a live target
    if args.target_host:
        from fuzzer.rl.server_monitor import ServerMonitor
        baseline_monitor = ServerMonitor(
            target_host=args.target_host,
            target_port=args.target_port,
            called_ae=args.called_ae,
        )
        try:
            baseline = baseline_monitor.check_health(full=True)
            print("--- Initial Server Health ---")
            print(f"  Echo latency:      {baseline.echo_latency_ms:.1f} ms")
            print(f"  Connect latency:   {baseline.connect_latency_ms:.1f} ms")
            print(f"  Association:       {'accepted' if baseline.assoc_accepted else 'FAILED'}")
            print(f"  C-ECHO:            {'OK' if baseline.echo_success else 'FAILED'}")
            print(f"  Concurrent conns:  {baseline.concurrent_connections}/{baseline.max_concurrent_tested}")
            print(f"  Health score:      {baseline.health_score():.0f}/100")
            if baseline.error:
                print(f"  Error:             {baseline.error}")
            print()
        except Exception as e:
            print(f"  Baseline check failed: {e}\n")

    # Create environment
    if args.mode == "session":
        from fuzzer.rl.session_env import DicomSessionEnv
        env = DicomSessionEnv(
            seed_pdus=seed_pdus,
            target_host=args.target_host,
            target_port=args.target_port,
            called_ae=args.called_ae,
            max_steps=args.max_steps,
        )
    elif args.mode == "state_machine":
        from fuzzer.rl.state_machine_env import DicomStateMachineEnv
        env = DicomStateMachineEnv(
            target_host=args.target_host,
            target_port=args.target_port,
            called_ae=args.called_ae,
            max_steps=args.max_steps,
        )
        print(f"State machine mode: testing {env.n_sequences} attack sequences")
    elif args.mode == "aggressive":
        from fuzzer.rl.aggressive_env import AggressiveFuzzEnv
        env = AggressiveFuzzEnv(
            target_host=args.target_host,
            target_port=args.target_port,
            called_ae=args.called_ae,
            max_steps=args.max_steps,
        )
        print(f"Aggressive mode: {env.n_strategies} attack strategies × {env.n_intensities} intensities")
        print("  Attacks: format_string, path_traversal, buffer_overflow, length_corruption,")
        print("           state_confusion, concurrent_flood, fragment_confusion, etc.")
    elif args.mode == "semantic":
        from fuzzer.rl.semantic_env import DicomSemanticEnv
        env = DicomSemanticEnv(
            target_host=args.target_host,
            target_port=args.target_port,
            called_ae=args.called_ae,
            max_steps=args.max_steps,
        )
        print(f"Semantic mode: {env.n_actions} DICOM-aware mutations")
        print("  Fields: message_id, command_field, data_set_type, context_id, msg_control")
        print("  Uses valid/boundary values to pass initial validation and reach deeper code")
    elif args.mode == "hybrid":
        from fuzzer.rl.hybrid_env import SimplifiedHybridEnv
        # Resolve seed directory for hybrid mode (uses parent pdus/ dir)
        hybrid_seed_dir = None
        base_seed = os.path.dirname(args.seed_dir)  # e.g., fuzzer/data/training_data/pdus
        if os.path.isdir(base_seed) and any(
            os.path.isdir(os.path.join(base_seed, d)) for d in ["assoc_rq", "pdata"]
        ):
            hybrid_seed_dir = base_seed
        env = SimplifiedHybridEnv(
            target_host=args.target_host,
            target_port=args.target_port,
            called_ae=args.called_ae,
            max_steps=args.max_steps,
            log_path=args.log_path,
            ssh_host=args.ssh_host,
            ssh_log_path=args.ssh_log_path,
            docker_container=args.docker_container,
            server_type=args.server_type,
            exploration_rate=args.exploration_rate,
            diversity_bonus=args.diversity_bonus,
            ssh_process=args.ssh_process,
            ssh_asan_log_pattern=args.ssh_asan_log_pattern,
            ssh_coverage_dir=args.ssh_coverage_dir,
            seed_dir=hybrid_seed_dir,
            disable_slow_attacks=args.fast,
        )
        print(f"Hybrid mode: {env.n_actions} pre-defined attack combinations")
        print("  Combines: semantic mutations + payload injection + protocol state attacks")
        print("  Categories: semantic-only, payload-only, state-only, combined attacks")
        if args.fast:
            print("  Fast mode: slowloris/fragment/concurrent/rapid_reconnect/memory_exhaust disabled")
        if env.seed_assoc_rq or env.seed_pdata:
            print(f"  Seeds:     {len(env.seed_assoc_rq)} ASSOC_RQ + {len(env.seed_pdata)} PDATA from corpus")
        else:
            print("  Seeds:     none (add --seed-dir pointing to pdus/ for seed-based attacks)")
        if args.exploration_rate > 0:
            print(f"  Exploration: {args.exploration_rate*100:.0f}% chance of novel combinations")
        if args.log_path or args.docker_container or args.ssh_host:
            if args.ssh_host:
                log_src = f"ssh://{args.ssh_host}:{args.ssh_log_path}"
            elif args.docker_container:
                log_src = f"docker:{args.docker_container}"
            else:
                log_src = args.log_path
            print(f"  Log monitoring: {log_src} (type: {args.server_type})")
            print("  Rewards: +15*severity for new errors, +20 for new code locations")
        if args.ssh_process and args.ssh_host:
            print(f"  Process monitor: {args.ssh_process} via {args.ssh_host}")
        if args.ssh_asan_log_pattern and args.ssh_host:
            print(f"  ASAN monitor:   {args.ssh_asan_log_pattern} via {args.ssh_host}")
        if args.ssh_coverage_dir and args.ssh_host:
            print(f"  Coverage monitor: {args.ssh_coverage_dir} via {args.ssh_host}")
    else:
        from fuzzer.rl.environment import DicomFuzzEnv
        env = DicomFuzzEnv(
            seed_pdus=seed_pdus,
            target_host=args.target_host,
            target_port=args.target_port,
            called_ae=args.called_ae,
            max_steps=args.max_steps,
        )

    # Take process monitor baseline if enabled
    if hasattr(env, 'process_monitor') and env.process_monitor:
        print("--- Taking process baseline ---")
        if env.process_monitor.take_baseline():
            print(f"  Process: {args.ssh_process} (PID {env.process_monitor._pid})")
            print(f"  RSS: {env.process_monitor.baseline_rss_kb}KB")
            print(f"  FDs: {env.process_monitor.baseline_fd_count}")
            print(f"  CPU: {env.process_monitor.baseline_cpu}%")
            print(f"  Threads: {env.process_monitor.baseline_threads}")
        else:
            print(f"  WARNING: Could not find process '{args.ssh_process}'")
        print()

    # Take ASAN monitor baseline if enabled
    if hasattr(env, 'asan_monitor') and env.asan_monitor:
        print("--- Taking ASAN baseline ---")
        if env.asan_monitor.take_baseline():
            print(f"  Pattern: {args.ssh_asan_log_pattern}")
            print(f"  Existing log files: {len(env.asan_monitor._seen_files)} (marked as seen)")
        else:
            print(f"  WARNING: ASAN baseline failed (SSH to {args.ssh_host})")
        print()

    # Coverage monitor (optional — requires DCMTK compiled with --coverage + coverage_handler.o)
    if hasattr(env, 'coverage_monitor') and env.coverage_monitor:
        print("--- Taking coverage baseline ---")
        if env.coverage_monitor.take_baseline():
            cov = env.coverage_monitor.get_current_coverage()
            print(f"  Lines:     {cov.get('lines', 0)} ({env.coverage_monitor.baseline_line_pct:.1f}%)")
            print(f"  Functions: {cov.get('functions', 0)} ({env.coverage_monitor.baseline_func_pct:.1f}%)")
            print(f"  Sampling:  every {env.coverage_monitor.sample_interval} steps (~3s per read)")
        else:
            print(f"  WARNING: coverage baseline failed (check lcov + .gcda files on {args.ssh_host})")
        print()

    # Create and train agent
    from fuzzer.rl.agent import create_agent, train_agent, run_agent

    model = create_agent(env, algorithm=args.algorithm)
    model = train_agent(model, total_timesteps=args.timesteps, model_path=args.model_out)

    # Test
    if args.test:
        print(f"\n{'=' * 90}")
        print(f"TEST RUN ({args.n_test} episodes)")
        print(f"{'=' * 90}")
        results = run_agent(model, env, n_episodes=args.n_test)

        os.makedirs(args.output_dir, exist_ok=True)

        if args.mode == "state_machine":
            # State machine mode: different output format
            print(f"\n{'Ep':>3} {'Reward':>7} {'Sequence':<20} {'Response':<12} "
                  f"{'Time':>6} {'Crash':>6}")
            print("-" * 70)

            for i, (pdu_bytes, ep_reward, info) in enumerate(results):
                seq = info.get('sequence', 'unknown')
                resp = info.get('final_response', 'none')
                rtime = info.get('response_time_ms', 0)
                crash = "YES!" if info.get('crash', False) else ""

                print(f"{i+1:>3} {ep_reward:>7.1f} {seq:<20} {resp:<12} "
                      f"{rtime:>5.0f}ms {crash:>6}")

                # Show individual PDU responses
                for r in info.get('responses', []):
                    print(f"      -> {r['pdu']}: {r['response']} ({r['time_ms']:.0f}ms)")

            print("-" * 70)

            rewards = [r[1] for r in results]
            crashes = sum(1 for r in results if r[2].get('crash', False))
            responses = {}
            for _, _, info in results:
                r = info.get('final_response', 'none')
                responses[r] = responses.get(r, 0) + 1

            print(f"\nSummary:")
            print(f"  Avg reward:     {sum(rewards)/len(rewards):.1f}")
            print(f"  Crashes:        {crashes}")
            print(f"  Responses:      {responses}")

        elif args.mode == "aggressive":
            # Aggressive mode: show attack results
            print(f"\n{'Ep':>3} {'Reward':>7} {'Strategy':<25} {'Intensity':>4} "
                  f"{'Response':<15} {'Time':>6} {'Crash':>6} {'Hang':>6}")
            print("-" * 95)

            total_crashes = 0
            total_hangs = 0
            strategy_results = {}

            for i, (pdu_bytes, ep_reward, info) in enumerate(results):
                strategy = info.get('strategy', 'unknown')
                intensity = info.get('intensity', 0)
                resp = info.get('response', 'none')
                rtime = info.get('response_time_ms', 0)
                crash = "CRASH!" if info.get('crash', False) else ""
                hang = "HANG!" if info.get('hang', False) else ""

                if info.get('crash'):
                    total_crashes += 1
                if info.get('hang'):
                    total_hangs += 1

                if strategy not in strategy_results:
                    strategy_results[strategy] = {"count": 0, "crashes": 0, "hangs": 0, "reward": 0}
                strategy_results[strategy]["count"] += 1
                strategy_results[strategy]["reward"] += ep_reward
                if info.get('crash'):
                    strategy_results[strategy]["crashes"] += 1
                if info.get('hang'):
                    strategy_results[strategy]["hangs"] += 1

                print(f"{i+1:>3} {ep_reward:>7.1f} {strategy:<25} {intensity:>4} "
                      f"{resp:<15} {rtime:>5.0f}ms {crash:>6} {hang:>6}")

                if info.get('error'):
                    print(f"      Error: {info['error']}")

            print("-" * 95)

            rewards = [r[1] for r in results]
            print(f"\nSummary:")
            print(f"  Avg reward:     {sum(rewards)/len(rewards):.1f}")
            print(f"  Total crashes:  {total_crashes}")
            print(f"  Total hangs:    {total_hangs}")
            print(f"\n  Strategy effectiveness:")
            for strat, data in sorted(strategy_results.items(), key=lambda x: -x[1]["reward"]):
                print(f"    {strat:<25} reward={data['reward']:.1f} "
                      f"crashes={data['crashes']} hangs={data['hangs']}")

        elif args.mode == "hybrid":
            # Hybrid mode: show combined attack results
            print(f"\n{'Ep':>3} {'Reward':>7} {'Combo':<30} {'Semantic':<20} "
                  f"{'Payload':<20} {'Response':<12} {'Crash':>6} {'Hang':>6} "
                  f"{'ASAN':>6} {'Proc':>16}")
            print("-" * 150)

            total_crashes = 0
            total_hangs = 0
            combo_results = {}

            for i, (pdu_bytes, ep_reward, info) in enumerate(results):
                combo = info.get('combo_name', 'unknown')
                semantic = info.get('semantic', '-')
                payload = info.get('payload', '-')
                resp = info.get('response', 'none')
                crash = "CRASH!" if info.get('crash', False) else ""
                hang = "HANG!" if info.get('hang', False) else ""

                if info.get('crash'):
                    total_crashes += 1
                if info.get('hang'):
                    total_hangs += 1

                asan_bugs = info.get('asan_bugs', 0)
                rss_g = info.get('proc_rss_growth_mb', 0)
                fd_g = info.get('proc_fd_growth', 0)
                cpu_v = info.get('proc_cpu', 0)
                anom_v = info.get('proc_anomaly_score', 0)
                asan_str = str(asan_bugs) if asan_bugs > 0 else ""
                proc_parts = []
                if rss_g > 0.1:
                    proc_parts.append(f"+{rss_g:.1f}MB")
                if fd_g > 0:
                    proc_parts.append(f"+{fd_g}fd")
                if anom_v > 0.5:
                    proc_parts.append(f"a{anom_v:.1f}")
                proc_str = " ".join(proc_parts) if proc_parts else ""

                if combo not in combo_results:
                    combo_results[combo] = {"count": 0, "crashes": 0, "hangs": 0, "reward": 0,
                                            "asan_bugs": 0,
                                            "max_rss_growth_mb": 0.0, "max_fd_growth": 0,
                                            "max_cpu": 0.0, "max_anomaly_score": 0.0}
                combo_results[combo]["count"] += 1
                combo_results[combo]["reward"] += ep_reward
                if info.get('crash'):
                    combo_results[combo]["crashes"] += 1
                if info.get('hang'):
                    combo_results[combo]["hangs"] += 1
                combo_results[combo]["asan_bugs"] += asan_bugs
                if rss_g > combo_results[combo]["max_rss_growth_mb"]:
                    combo_results[combo]["max_rss_growth_mb"] = rss_g
                if fd_g > combo_results[combo]["max_fd_growth"]:
                    combo_results[combo]["max_fd_growth"] = fd_g
                if cpu_v > combo_results[combo]["max_cpu"]:
                    combo_results[combo]["max_cpu"] = cpu_v
                if anom_v > combo_results[combo]["max_anomaly_score"]:
                    combo_results[combo]["max_anomaly_score"] = anom_v

                print(f"{i+1:>3} {ep_reward:>7.1f} {combo:<30} {str(semantic):<20} "
                      f"{str(payload):<20} {resp:<12} {crash:>6} {hang:>6} "
                      f"{asan_str:>6} {proc_str:>16}")

                # Show individual responses in sequence
                for r in info.get('responses', []):
                    print(f"      -> {r['pdu']}: {r['response']}")

            print("-" * 150)

            rewards = [r[1] for r in results]
            total_asan = sum(d["asan_bugs"] for d in combo_results.values())
            max_rss = max((d["max_rss_growth_mb"] for d in combo_results.values()), default=0)
            max_fd = max((d["max_fd_growth"] for d in combo_results.values()), default=0)
            print(f"\nSummary:")
            print(f"  Avg reward:     {sum(rewards)/len(rewards):.1f}")
            print(f"  Total crashes:  {total_crashes}")
            print(f"  Total hangs:    {total_hangs}")
            print(f"  Total ASAN bugs:{total_asan}")
            print(f"  Max RSS growth: {max_rss:+.1f}MB")
            print(f"  Max FD growth:  {max_fd:+d}")
            print(f"\n  Attack combo effectiveness:")
            for combo, data in sorted(combo_results.items(), key=lambda x: -x[1]["reward"]):
                avg = data['reward'] / max(data['count'], 1)
                extras = ""
                if data['asan_bugs'] > 0:
                    extras += f" asan={data['asan_bugs']}"
                if data['max_rss_growth_mb'] > 0.1:
                    extras += f" rss=+{data['max_rss_growth_mb']:.1f}MB"
                if data['max_fd_growth'] > 0:
                    extras += f" fd=+{data['max_fd_growth']}"
                if data['max_cpu'] > 50:
                    extras += f" cpu={data['max_cpu']:.0f}%"
                if data['max_anomaly_score'] > 0.5:
                    extras += f" anom={data['max_anomaly_score']:.2f}"
                print(f"    {combo:<30} avg={avg:.1f} "
                      f"crashes={data['crashes']} hangs={data['hangs']} count={data['count']}{extras}")

            # Show overall stats from environment
            if hasattr(env, 'get_combo_stats'):
                print(f"\n  Training combo stats (all episodes):")
                for combo, stats in env.get_combo_stats()[:15]:
                    if stats["count"] > 0:
                        avg = stats["reward"] / stats["count"]
                        extras = ""
                        if stats.get('asan_bugs', 0) > 0:
                            extras += f" asan={stats['asan_bugs']}"
                        if stats.get('max_rss_growth_mb', 0) > 0.1:
                            extras += f" rss=+{stats['max_rss_growth_mb']:.1f}MB"
                        if stats.get('max_fd_growth', 0) > 0:
                            extras += f" fd=+{stats['max_fd_growth']}"
                        if stats.get('max_cpu', 0) > 50:
                            extras += f" cpu={stats['max_cpu']:.0f}%"
                        if stats.get('max_anomaly_score', 0) > 0.5:
                            extras += f" anom={stats['max_anomaly_score']:.2f}"
                        print(f"    {combo:<30} avg={avg:.1f} "
                              f"crashes={stats['crashes']} hangs={stats['hangs']} n={stats['count']}{extras}")

            # Show log monitoring stats if enabled
            if hasattr(env, 'log_monitor') and env.log_monitor:
                from fuzzer.rl.log_monitor import LogParser
                log_stats = env.log_monitor.get_stats()
                print(f"\n  Log monitoring stats:")
                print(f"    Total log entries:    {log_stats['total_entries']}")
                print(f"    Errors:               {log_stats['errors']}")
                print(f"    Warnings:             {log_stats['warnings']}")
                print(f"    Unique messages:      {log_stats['unique_messages']}")
                print(f"    Unique code locations:{log_stats['unique_locations']}")
                print(f"    Unique error codes:   {log_stats.get('unique_error_codes', 0)}")
                print(f"    New messages (session):{log_stats['new_messages_session']}")
                print(f"    New locations (session):{log_stats['new_locations_session']}")
                print(f"    New error codes (session):{log_stats.get('new_error_codes_session', 0)}")
                if log_stats.get('error_codes'):
                    print(f"\n  Error codes discovered:")
                    for code in log_stats['error_codes']:
                        meaning = LogParser.DCMTK_ERROR_MEANINGS.get(code, "unknown")
                        print(f"    {code}: {meaning}")
                if log_stats.get('top_locations'):
                    print(f"\n  Top error locations (code paths reached):")
                    for loc, count in log_stats['top_locations'][:10]:
                        print(f"    {loc}: {count}")
                if log_stats.get('top_messages'):
                    print(f"\n  Top error messages:")
                    for msg, count in log_stats['top_messages'][:5]:
                        print(f"    {msg[:70]}: {count}")

            # Show exploration/novel combo stats
            if hasattr(env, 'get_exploration_summary'):
                exploration = env.get_exploration_summary()
                print(f"\n  Exploration stats:")
                print(f"    Predefined actions:   {exploration['predefined_actions']}")
                print(f"    Novel actions:        {exploration['novel_actions']}")
                print(f"    Unique novel combos:  {exploration['unique_novel_combos']}")
                if exploration['best_novel_combos']:
                    print(f"\n  Best novel combinations discovered:")
                    for nc in exploration['best_novel_combos'][:10]:
                        extras = ""
                        if nc.get('asan_bugs', 0) > 0:
                            extras += f" asan={nc['asan_bugs']}"
                        if nc.get('max_rss_growth_mb', 0) > 0.1:
                            extras += f" rss=+{nc['max_rss_growth_mb']:.1f}MB"
                        if nc.get('max_fd_growth', 0) > 0:
                            extras += f" fd=+{nc['max_fd_growth']}"
                        if nc.get('max_cpu', 0) > 50:
                            extras += f" cpu={nc['max_cpu']:.0f}%"
                        if nc.get('max_anomaly_score', 0) > 0.5:
                            extras += f" anom={nc['max_anomaly_score']:.2f}"
                        print(f"    {nc['name'][:40]:<40} avg={nc['avg_reward']:.1f} "
                              f"crashes={nc['crashes']} hangs={nc['hangs']} "
                              f"new_locs={nc['new_locations']} n={nc['count']}{extras}")

            # Show process monitoring summary
            if hasattr(env, 'process_monitor') and env.process_monitor:
                # Force a final sample to get latest metrics
                env.process_monitor.sample(force=True)
                proc_summary = env.process_monitor.get_summary()
                if proc_summary:
                    print(f"\n  Process monitoring summary ({args.ssh_process}):")
                    print(f"    Samples collected:  {proc_summary['samples']}")
                    print(f"    RSS: {proc_summary['baseline_rss_kb']}KB -> "
                          f"{proc_summary['current_rss_kb']}KB "
                          f"(growth: {proc_summary['rss_growth_mb']:+.1f}MB, "
                          f"max: {proc_summary['max_rss_kb']}KB)")
                    print(f"    FDs: {proc_summary['baseline_fd_count']} -> "
                          f"{proc_summary['current_fd_count']} "
                          f"(growth: {proc_summary['fd_growth']:+d}, "
                          f"max: {proc_summary['max_fd_count']})")
                    print(f"    CPU: avg={proc_summary['avg_cpu']:.1f}% "
                          f"max={proc_summary['max_cpu']:.1f}%")
                    print(f"    Anomaly score: {proc_summary['final_anomaly_score']:.0f}/100 "
                          f"(max: {proc_summary['max_anomaly_score']:.0f}/100)")
                    if proc_summary['rss_growth_mb'] > 10:
                        print(f"    !! POTENTIAL MEMORY LEAK: +{proc_summary['rss_growth_mb']:.1f}MB")
                    if proc_summary['fd_growth'] > 20:
                        print(f"    !! POTENTIAL FD LEAK: +{proc_summary['fd_growth']} file descriptors")
                else:
                    print(f"\n  Process monitoring: no samples collected "
                          f"(SSH to {args.ssh_host} may have failed)")

            # Show ASAN monitoring summary
            if hasattr(env, 'asan_monitor') and env.asan_monitor:
                env.asan_monitor.sample(force=True)
                asan_summary = env.asan_monitor.get_summary()
                if asan_summary:
                    print(f"\n  ASAN bug detection summary:")
                    print(f"    Total unique bugs:  {asan_summary['total_unique_bugs']}")
                    print(f"    Log files scanned:  {asan_summary['total_files_seen']}")
                    sev = asan_summary['severity_counts']
                    print(f"    Severity: critical={sev['critical']} "
                          f"high={sev['high']} medium={sev['medium']}")
                    if asan_summary['error_types']:
                        print(f"    Error types:")
                        for etype, count in sorted(asan_summary['error_types'].items(),
                                                   key=lambda x: -x[1]):
                            print(f"      {etype}: {count}")
                    if asan_summary['top_stack_frames']:
                        print(f"    Top stack frames:")
                        for frame, count in asan_summary['top_stack_frames'][:5]:
                            print(f"      {frame}: {count}")
                    if sev['critical'] > 0:
                        print(f"    !! {sev['critical']} CRITICAL MEMORY SAFETY BUGS FOUND!")
                else:
                    print(f"\n  ASAN monitoring: no bugs detected (clean run)")

            # Show coverage monitoring summary
            if hasattr(env, 'coverage_monitor') and env.coverage_monitor:
                env.coverage_monitor.sample(force=True)
                cov_summary = env.coverage_monitor.get_summary()
                if cov_summary:
                    print(f"\n  Code coverage summary:")
                    print(f"    Baseline:  {cov_summary['baseline_lines']} lines "
                          f"({cov_summary['baseline_line_pct']:.1f}%), "
                          f"{cov_summary['baseline_functions']} functions "
                          f"({cov_summary['baseline_func_pct']:.1f}%)")
                    print(f"    Peak:      {cov_summary['peak_lines']} lines, "
                          f"{cov_summary['peak_functions']} functions")
                    line_growth = cov_summary['peak_lines'] - cov_summary['baseline_lines']
                    func_growth = cov_summary['peak_functions'] - cov_summary['baseline_functions']
                    print(f"    Growth:    +{line_growth} lines, +{func_growth} functions")

        else:
            # Header for PDU fuzzing modes
            print(f"\n{'Ep':>3} {'Reward':>7} {'Response':<16} {'Div':>5} "
                  f"{'Time':>6} {'Depth':>5} {'MMT':>4} "
                  f"{'Health':>7} {'Impact':>7} {'Echo+':>7} {'ConnLost':>8}")
            print("-" * 90)

            for i, (pdu_bytes, ep_reward, info) in enumerate(results):
                out_path = os.path.join(args.output_dir, f"rl_fuzzed_{i:04d}.bin")
                with open(out_path, 'wb') as f:
                    f.write(pdu_bytes)

                div = info.get('divergence', 0)
                resp = info.get('live_response', 'n/a')
                mmt = info.get('mmt_alerts', 0)
                rj_src = info.get('reject_source', '')
                rj_rsn = info.get('reject_reason', '')
                depth = info.get('parser_depth', 0)
                rtime = info.get('response_time_ms', 0)
                novelty = info.get('response_novelty', False)
                h_delta = info.get('health_delta', 0)
                impact = info.get('impact_score', 0)
                echo_d = info.get('echo_latency_delta_ms', 0)
                conn_lost = info.get('connections_lost', 0)
                h_bonus = info.get('health_bonus', 0)
                field_bonus = info.get('field_bonus', 0)
                field_hits = info.get('field_hits', {})

                flags = ""
                if novelty:
                    flags += "N"
                if info.get('echo_lost', False):
                    flags += "E!"
                if info.get('assoc_lost', False):
                    flags += "A!"
                if info.get('crash', False):
                    flags += "CRASH!"
                if info.get('rare_response', False):
                    flags += "R"
                if field_hits:
                    flags += f" F:{','.join(field_hits.keys())}"

                print(f"{i+1:>3} {ep_reward:>7.1f} {resp:<16} {div:>4.0%} "
                      f"{rtime:>5.0f}ms {depth:>5.1f} {mmt:>4} "
                      f"{h_delta:>+6.0f} {impact:>6.0f} {echo_d:>+6.0f}ms {conn_lost:>5} "
                      f" {flags}")
                if rj_src:
                    print(f"    reject: source={rj_src} reason={rj_rsn}")

            print("-" * 90)

            # Summary
            rewards = [r[1] for r in results]
            impacts = [r[2].get('impact_score', 0) for r in results]
            mmt_total = sum(r[2].get('mmt_alerts', 0) for r in results)
            responses = {}
            for _, _, info in results:
                r = info.get('live_response', 'none')
                responses[r] = responses.get(r, 0) + 1

            print(f"\nSummary:")
            print(f"  Avg reward:     {sum(rewards)/len(rewards):.1f}")
            print(f"  Max impact:     {max(impacts):.0f}")
            print(f"  Total MMT:      {mmt_total}")
            print(f"  Responses:      {responses}")
            print(f"  Saved {len(results)} fuzzed PDUs to {args.output_dir}")

        # Final server health check
        if args.target_host and hasattr(env, 'server_monitor') and env.server_monitor:
            try:
                final_health = env.server_monitor.check_health(full=True)
                print(f"\n--- Post-Training Server Health ---")
                print(f"  Echo latency:      {final_health.echo_latency_ms:.1f} ms")
                print(f"  Connect latency:   {final_health.connect_latency_ms:.1f} ms")
                print(f"  Association:       {'accepted' if final_health.assoc_accepted else 'FAILED'}")
                print(f"  C-ECHO:            {'OK' if final_health.echo_success else 'FAILED'}")
                print(f"  Concurrent conns:  {final_health.concurrent_connections}/{final_health.max_concurrent_tested}")
                print(f"  Health score:      {final_health.health_score():.0f}/100")
            except Exception as e:
                print(f"  Post-training health check failed: {e}")

    env.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
