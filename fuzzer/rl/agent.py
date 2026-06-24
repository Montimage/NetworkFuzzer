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
        "verbose": 1,
        "policy_kwargs": policy_kwargs,
    }
    defaults.update(kwargs)

    if algorithm.upper() == "DQN":
        from stable_baselines3 import DQN
        agent_defaults = {
            "learning_rate": 1e-4,
            "buffer_size": 50000,
            "learning_starts": 500,
            "batch_size": 64,
            "exploration_fraction": 0.7,   # Explore for 70% of training timesteps
            "exploration_final_eps": 0.05, # Then keep 5% random exploration
            "gamma": 0.95,                 # Slightly less future-discounting for fuzzing
            "target_update_interval": 500,
        }
        agent_defaults.update(defaults)
        model = DQN("MlpPolicy", env, **agent_defaults)

    elif algorithm.upper() == "PPO":
        from stable_baselines3 import PPO
        agent_defaults = {
            "learning_rate": 3e-4,
            "n_steps": 512,       # 128→512: ~17 episodes/rollout; richer advantage estimates → fixes EV≈0
            "batch_size": 128,    # scale batch with n_steps
            "n_epochs": 10,
            "ent_coef": 0.05,     # 0.01→0.05: prevent policy collapse to single action (seq_payload exploit)
            "clip_range": 0.2,
            "gamma": 0.99,
            "target_kl": 0.15,   # 0.05 was too tight — cut updates after 5 steps; 0.15 uses all 10 epochs
        }
        agent_defaults.update(defaults)
        model = PPO("MlpPolicy", env, **agent_defaults)

    else:
        raise ValueError(f"Unknown algorithm: {algorithm}. Use 'DQN' or 'PPO'.")

    return model


class ProgressCallback:
    """Callback to show training progress with hangs/crashes."""

    def __init__(self, log_interval=500, total_timesteps=10000):
        self.log_interval = log_interval
        self.total_timesteps = total_timesteps
        self.hangs = 0
        self.crashes = 0
        self.last_log = 0
        self.num_timesteps = 0
        self.start_time = time.monotonic()

    def __call__(self, locals_, globals_):
        """Called after each step."""
        # Count hangs and crashes from info
        if 'infos' in locals_:
            for info in locals_['infos']:
                if isinstance(info, dict):
                    if info.get('hang'):
                        self.hangs += 1
                    if info.get('crash'):
                        self.crashes += 1

        # SB3 PPO: num_timesteps is a model instance attribute, not a local var.
        # Read it via self.model if available (BaseCallback sets self.model).
        model_obj = locals_.get('self', None)
        if model_obj is not None and hasattr(model_obj, 'num_timesteps'):
            self.num_timesteps = model_obj.num_timesteps
        else:
            self.num_timesteps = locals_.get('num_timesteps', self.num_timesteps)
        if self.num_timesteps - self.last_log >= self.log_interval:
            progress = self.num_timesteps / self.total_timesteps * 100
            logger.info(f"Progress: {self.num_timesteps}/{self.total_timesteps} ({progress:.1f}%) | "
                       f"Hangs: {self.hangs} | Crashes: {self.crashes}")
            self.last_log = self.num_timesteps

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

    # Create progress callback
    callback = ProgressCallback(
        log_interval=max(500, total_timesteps // 20),  # Log ~20 times during training
        total_timesteps=total_timesteps
    )

    interrupted = False
    try:
        model.learn(total_timesteps=total_timesteps, log_interval=log_interval,
                    callback=callback, reset_num_timesteps=not getattr(model, '_loaded', False))
    except KeyboardInterrupt:
        import signal as _signal
        _signal.signal(_signal.SIGINT, _signal.SIG_IGN)   # block further Ctrl+C during cleanup
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
    """Load a trained agent from file and mark it so train_agent continues timesteps."""
    if algorithm.upper() == "DQN":
        from stable_baselines3 import DQN
        model = DQN.load(model_path, env=env)
    elif algorithm.upper() == "PPO":
        from stable_baselines3 import PPO
        model = PPO.load(model_path, env=env)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    model._loaded = True  # tells train_agent to keep the timestep counter
    return model


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
            # GenericFuzzEnv / state machine mode
            seq = last_info.get('sequence', last_info.get('action_type', 'unknown'))
            resp = last_info.get('response', last_info.get('final_response', 'none'))
            crash = last_info.get('crash', False)
            hang = last_info.get('hang', False)
            logger.info(f"Episode {ep+1}: reward={episode_reward:.1f} "
                         f"sequence={seq} response={resp} crash={crash} hang={hang}")

    return results
