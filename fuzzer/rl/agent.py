#!/usr/bin/env python3
"""
DQN/PPO agent wrapper using stable-baselines3 for DICOM RL fuzzing.

Provides a simple interface to train and run RL agents against the
DicomFuzzEnv environment.
"""

import os
import time
import logging

logger = logging.getLogger(__name__)


def create_agent(env, algorithm="DQN", policy_kwargs=None, **kwargs):
    """
    Create a stable-baselines3 agent.

    Args:
        env: DicomFuzzEnv instance
        algorithm: "DQN" or "PPO"
        policy_kwargs: override network architecture
        **kwargs: passed to the algorithm constructor

    Returns:
        stable-baselines3 model instance
    """
    if policy_kwargs is None:
        policy_kwargs = dict(net_arch=[256, 128])

    defaults = {
        "verbose": 0,   # suppress SB3 per-episode output
        "policy_kwargs": policy_kwargs,
    }
    defaults.update(kwargs)

    if algorithm.upper() == "DQN":
        from stable_baselines3 import DQN
        agent_defaults = {
            "learning_rate": 1e-4,
            "buffer_size": 50000,
            "learning_starts": 200,
            "batch_size": 64,
            "exploration_fraction": 0.5,
            "exploration_final_eps": 0.1,
            "gamma": 0.99,
            "target_update_interval": 500,
        }
        agent_defaults.update(defaults)
        model = DQN("MlpPolicy", env, **agent_defaults)

    elif algorithm.upper() == "PPO":
        from stable_baselines3 import PPO
        agent_defaults = {
            "learning_rate": 3e-4,
            "n_steps": 256,
            "batch_size": 64,
            "n_epochs": 10,
            "ent_coef": 0.05,     # Entropy bonus to encourage exploration
            "clip_range": 0.2,
            "gamma": 0.99,
        }
        agent_defaults.update(defaults)
        model = PPO("MlpPolicy", env, **agent_defaults)

    else:
        raise ValueError(f"Unknown algorithm: {algorithm}. Use 'DQN' or 'PPO'.")

    return model


class ProgressCallback:
    """Time-based progress callback (prints every 60s regardless of step count)."""

    def __init__(self, log_interval=500, total_timesteps=10000, print_every_sec=60,
                 fuzz_env=None):
        self.log_interval = log_interval        # kept for compat, not used for printing
        self.total_timesteps = total_timesteps
        self.print_every_sec = print_every_sec
        self.hangs = 0
        self.crashes = 0
        self.saved = 0
        self.skipped = 0
        self.num_timesteps = 0
        self.start_time = time.monotonic()
        self.last_print_time = time.monotonic()
        # Direct reference to the underlying GenericFuzzEnv — avoids fragile
        # SB3 locals_ introspection which fails silently across SB3 versions.
        self._fuzz_env = fuzz_env

    def __call__(self, locals_, globals_):
        """Called after each step."""
        if 'infos' in locals_:
            for info in locals_['infos']:
                if isinstance(info, dict):
                    if info.get('hang'):
                        self.hangs += 1
                    if info.get('crash'):
                        self.crashes += 1

        # SB3 exposes num_timesteps via the model object in locals_['self'],
        # not as a top-level key — fall back through several access patterns.
        ts = locals_.get('num_timesteps')
        if ts is None:
            sb3_self = locals_.get('self')
            if sb3_self is not None:
                ts = getattr(sb3_self, 'num_timesteps',
                             getattr(getattr(sb3_self, 'model', None), 'num_timesteps', None))
        self.num_timesteps = ts or self.num_timesteps  # don't regress to 0 on bad reads

        # Read saved/skipped directly from the GenericFuzzEnv reference.
        if self._fuzz_env is not None:
            self.saved = self._fuzz_env._corpus_idx
            self.skipped = self._fuzz_env._skipped_duplicates

        # Print every print_every_sec wall-clock seconds
        now = time.monotonic()
        if now - self.last_print_time >= self.print_every_sec:
            elapsed = now - self.start_time
            progress = self.num_timesteps / self.total_timesteps * 100
            rate = self.num_timesteps / elapsed if elapsed > 0 else 0
            eta_s = (self.total_timesteps - self.num_timesteps) / rate if rate > 0 else 0
            eta_str = f"{eta_s/3600:.1f}h" if eta_s > 3600 else f"{eta_s/60:.0f}m"
            elapsed_str = f"{elapsed/3600:.1f}h" if elapsed > 3600 else f"{elapsed/60:.0f}m"
            sps = rate  # steps per second
            print(
                f"[{elapsed_str} / {progress:5.1f}%] step={self.num_timesteps}/{self.total_timesteps}"
                f"  hangs={self.hangs} saved={self.saved} skip={self.skipped}"
                f"  {sps:.2f}stp/s  ETA={eta_str}",
                flush=True,
            )
            self.last_print_time = now

        return True

    @property
    def elapsed_seconds(self):
        return time.monotonic() - self.start_time


def train_agent(model, total_timesteps=10000, model_path="fuzzer/data/models/rl_fuzzer.zip",
                log_interval=10):
    """
    Train the agent and save the model.

    Args:
        model: stable-baselines3 model
        total_timesteps: total training steps
        model_path: where to save the trained model
        log_interval: log every N episodes

    Returns:
        model: the trained (or partially trained) model

    Raises:
        KeyboardInterrupt: re-raised after saving the model so callers
            can print summary stats.
    """
    os.makedirs(os.path.dirname(model_path) or '.', exist_ok=True)

    logger.info(f"Training for {total_timesteps} timesteps...")

    # Unwrap the SB3 VecEnv/Monitor layers to reach the raw GenericFuzzEnv,
    # then hand a direct reference to the callback so it can read _corpus_idx.
    fuzz_env = None
    try:
        vec_env = model.env
        inner = vec_env.envs[0] if hasattr(vec_env, 'envs') else vec_env
        while hasattr(inner, 'env') and not hasattr(inner, '_corpus_idx'):
            inner = inner.env
        if hasattr(inner, '_corpus_idx'):
            fuzz_env = inner
    except Exception:
        pass

    callback = ProgressCallback(
        log_interval=max(200, total_timesteps // 40),
        total_timesteps=total_timesteps,
        fuzz_env=fuzz_env,
    )

    interrupted = False
    try:
        model.learn(total_timesteps=total_timesteps, log_interval=log_interval, callback=callback)
    except KeyboardInterrupt:
        interrupted = True
        logger.info(f"\nTraining interrupted after {callback.num_timesteps}/{total_timesteps} timesteps "
                    f"({callback.elapsed_seconds:.1f}s)")

    # Always save model
    logger.info(f"Hangs: {callback.hangs}, Crashes: {callback.crashes}")
    model.save(model_path)
    logger.info(f"Model saved to {model_path}")

    if interrupted:
        raise KeyboardInterrupt()

    return model


def load_agent(model_path, env, algorithm="DQN"):
    """Load a trained agent from file."""
    if algorithm.upper() == "DQN":
        from stable_baselines3 import DQN
        return DQN.load(model_path, env=env)
    elif algorithm.upper() == "PPO":
        from stable_baselines3 import PPO
        return PPO.load(model_path, env=env)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def run_agent(model, env, n_episodes=10):
    """
    Run a trained agent and collect generated PDUs.

    Returns list of (pdu_bytes, episode_reward, info) tuples.
    For state_machine mode, pdu_bytes will be empty.
    """
    results = []

    for ep in range(n_episodes):
        obs, _ = env.reset()
        episode_reward = 0
        done = False
        last_info = {}

        while not done:
            action, _ = model.predict(obs, deterministic=False)
            obs, reward, terminated, truncated, info = env.step(action)
            episode_reward += reward
            last_info = info
            done = terminated or truncated

        # Handle different environment types
        if hasattr(env, 'current_pdu'):
            pdu_bytes = bytes(env.current_pdu)
        else:
            pdu_bytes = b''  # State machine mode doesn't have PDU bytes

        results.append((pdu_bytes, episode_reward, last_info))

        # Log based on environment type
        if hasattr(env, 'current_pdu'):
            div = last_info.get('divergence', 0)
            resp = last_info.get('live_response', 'n/a')
            mmt = last_info.get('mmt_alerts', 0)
            impact = last_info.get('impact_score', 0)
            h_delta = last_info.get('health_delta', 0)
            echo_d = last_info.get('echo_latency_delta_ms', 0)
            conn_lost = last_info.get('connections_lost', 0)
            logger.info(f"Episode {ep+1}: reward={episode_reward:.1f} "
                         f"response={resp} div={div:.1%} mmt={mmt} "
                         f"impact={impact:.0f} health={h_delta:+.0f} "
                         f"echo_delta={echo_d:+.0f}ms conn_lost={conn_lost}")
        elif hasattr(env, 'n_strategies'):
            # Aggressive mode
            strategy = last_info.get('strategy', 'unknown')
            resp = last_info.get('response', 'none')
            crash = last_info.get('crash', False)
            hang = last_info.get('hang', False)
            logger.info(f"Episode {ep+1}: reward={episode_reward:.1f} "
                         f"strategy={strategy} response={resp} crash={crash} hang={hang}")
        else:
            # State machine mode
            seq = last_info.get('sequence', 'unknown')
            resp = last_info.get('final_response', 'none')
            crash = last_info.get('crash', False)
            logger.info(f"Episode {ep+1}: reward={episode_reward:.1f} "
                         f"sequence={seq} response={resp} crash={crash}")

    return results
