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

    # Protocol-specific options
    parser.add_argument("--called-ae", type=str, default="ORTHANC",
                        help="DICOM: Called AE title")
    parser.add_argument("--calling-ae", type=str, default="FUZZER",
                        help="DICOM: Calling AE title")

    # Fuzzing mode
    parser.add_argument("--mode", type=str, default="hybrid",
                        choices=["semantic", "aggressive", "state", "hybrid"],
                        help="Fuzzing mode (default: hybrid)")

    # Training parameters
    parser.add_argument("--algorithm", type=str, default="DQN",
                        choices=["DQN", "PPO"],
                        help="RL algorithm (default: DQN)")
    parser.add_argument("--timesteps", type=int, default=10000,
                        help="Training timesteps (default: 10000)")
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

    # Exploration
    parser.add_argument("--exploration-rate", type=float, default=0.15,
                        help="Novel combo exploration rate 0.0-1.0 (default: 0.15)")

    args = parser.parse_args()

    # Import protocol adapter system
    from fuzzer.rl.base.protocol_adapter import get_protocol_adapter, list_protocols

    # Register all protocols by importing the protocols module
    import fuzzer.rl.protocols

    # List protocols if requested
    if args.list_protocols:
        print("\nAvailable Protocol Adapters:")
        print("-" * 40)
        for proto in list_protocols():
            adapter = get_protocol_adapter(proto)
            print(f"  {proto:<12} (default port: {adapter.default_port})")
        print()
        return 0

    # Get protocol adapter
    try:
        adapter_kwargs = {}
        if args.protocol.lower() == "dicom":
            adapter_kwargs = {
                "called_ae": args.called_ae,
                "calling_ae": args.calling_ae,
            }
        adapter = get_protocol_adapter(args.protocol, **adapter_kwargs)
    except ValueError as e:
        logger.error(str(e))
        return 1

    # Determine port
    target_port = args.target_port or adapter.default_port

    # Print configuration
    print("\n" + "=" * 70)
    print(f"PROTOCOL-AGNOSTIC RL FUZZER")
    print("=" * 70)
    print(f"Protocol:    {adapter.protocol_name}")
    print(f"Mode:        {args.mode}")
    print(f"Algorithm:   {args.algorithm}")
    print(f"Timesteps:   {args.timesteps}")
    print(f"Max steps:   {args.max_steps}")
    if args.target_host:
        print(f"Target:      {args.target_host}:{target_port}")
        if args.protocol.lower() == "dicom":
            print(f"DICOM AE:    Called={args.called_ae}, Calling={args.calling_ae}")
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

    env = GenericFuzzEnv(
        adapter=adapter,
        target_host=args.target_host,
        target_port=target_port,
        max_steps=args.max_steps,
        mode=args.mode,
    )

    print(f"Environment created with {env.n_actions} actions")
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

    env.close()
    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
