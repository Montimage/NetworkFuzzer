#!/usr/bin/env python3
"""
Session Plan Generator for Smart GAN Pipeline.

Generates structured attack session plans (~8 fields) instead of raw CSV features.
Plans are then built into valid DICOM PDUs by the semantic_pcap_builder.

Three backends:
  - Thompson Sampling: works with zero training data, improves with feedback
  - CTGAN: trained on scored session plans after 200+ accumulate
  - Random: uniform random baseline

A SessionPlan describes a single fuzzing session:
  - Which attack category to use
  - Which DICOM field to mutate and how
  - What aggressive payload to inject and where
  - What PDU sequence to send
  - Intensity level and max PDU length
"""

import os
import random
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Optional

import numpy as np

from fuzzer.rl.hybrid_env import (
    SEMANTIC_FIELDS,
    PAYLOAD_TYPES,
    INJECTION_TARGETS,
    STATE_SEQUENCES,
)

logger = logging.getLogger(__name__)

# ============================================================================
# Attack categories for Thompson Sampling
# ============================================================================

ATTACK_CATEGORIES = [
    "semantic",       # DICOM-aware field mutations only
    "aggressive",     # Payload injection only
    "state",          # Protocol state machine attacks only
    "semantic+aggressive",  # Field mutation + payload injection
    "semantic+state",       # Field mutation + state attacks
    "aggressive+state",     # Payload + state attacks
    "full_hybrid",          # All three combined
    "cve_inspired",         # CVE-specific payload combinations
]

# Maps each category to which plan fields should be active
CATEGORY_ACTIVE_FIELDS = {
    "semantic":             {"semantic": True,  "payload": False, "state": False},
    "aggressive":           {"semantic": False, "payload": True,  "state": False},
    "state":                {"semantic": False, "payload": False, "state": True},
    "semantic+aggressive":  {"semantic": True,  "payload": True,  "state": False},
    "semantic+state":       {"semantic": True,  "payload": False, "state": True},
    "aggressive+state":     {"semantic": False, "payload": True,  "state": True},
    "full_hybrid":          {"semantic": True,  "payload": True,  "state": True},
    "cve_inspired":         {"semantic": True,  "payload": True,  "state": True},
}

# State sequences grouped by type for category-aware sampling
NORMAL_SEQUENCES = [i for i, (name, _) in enumerate(STATE_SEQUENCES)
                    if name in ("normal", "no_release")]
STATE_ATTACK_SEQUENCES = [i for i, (name, _) in enumerate(STATE_SEQUENCES)
                          if name not in ("normal", "no_release")]

# CVE-inspired payload indices (integer_overflow, path_uid, large_alloc, rle_attack, etc.)
CVE_PAYLOAD_INDICES = [i for i, (name, _) in enumerate(PAYLOAD_TYPES)
                       if name in ("integer_overflow", "path_uid", "large_alloc",
                                   "rle_attack", "nested_seq", "type_confusion")]


# ============================================================================
# Session Plan
# ============================================================================

@dataclass
class SessionPlan:
    """Structured descriptor for a single fuzzing session."""
    attack_category: str          # One of ATTACK_CATEGORIES
    semantic_field: int           # Index into SEMANTIC_FIELDS (0 = none)
    semantic_value_idx: int       # Index into that field's mutation values
    payload_type: int             # Index into PAYLOAD_TYPES (0 = none)
    injection_target: int         # Index into INJECTION_TARGETS (0 = none)
    pdu_sequence: int             # Index into STATE_SEQUENCES
    intensity: int                # 0=low, 1=medium, 2=high
    max_pdu_length: int           # Max PDU length for ASSOC_RQ

    # Feedback fields (filled after scoring)
    score: float = 0.0
    depth: float = 0.0
    response_type: str = ""

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d):
        return SessionPlan(**{k: v for k, v in d.items()
                              if k in SessionPlan.__dataclass_fields__})


# ============================================================================
# Session Plan Generator
# ============================================================================

class SessionPlanGenerator:
    """
    Generates session plans using Thompson Sampling, CTGAN, or random.

    Thompson Sampling (primary): maintains Beta distribution priors per
    attack category, updated with depth scores from server feedback.
    """

    def __init__(self, seed=None):
        self.rng = random.Random(seed)
        self.np_rng = np.random.RandomState(seed)

        # Thompson Sampling priors: (alpha, beta) per category
        # Start with uniform priors (alpha=1, beta=1)
        self.ts_priors = {cat: [1.0, 1.0] for cat in ATTACK_CATEGORIES}

        # History of scored plans for CTGAN retraining
        self.scored_plans: List[SessionPlan] = []

        # CTGAN model (lazy init)
        self._ctgan_model = None

    # ------------------------------------------------------------------
    # Plan field samplers
    # ------------------------------------------------------------------

    def _sample_semantic_field(self):
        """Sample a semantic field index and value index."""
        field_idx = self.rng.randint(0, len(SEMANTIC_FIELDS) - 1)
        _, values = SEMANTIC_FIELDS[field_idx]
        value_idx = self.rng.randint(0, len(values) - 1)
        # +1 because 0 means "no semantic mutation"
        return field_idx + 1, value_idx

    def _sample_payload(self):
        """Sample a payload type and injection target."""
        payload_idx = self.rng.randint(0, len(PAYLOAD_TYPES) - 1)
        target_idx = self.rng.randint(0, len(INJECTION_TARGETS) - 1)
        return payload_idx + 1, target_idx + 1

    def _sample_cve_payload(self):
        """Sample a CVE-inspired payload and injection target."""
        if CVE_PAYLOAD_INDICES:
            payload_idx = self.rng.choice(CVE_PAYLOAD_INDICES)
        else:
            payload_idx = self.rng.randint(0, len(PAYLOAD_TYPES) - 1)
        target_idx = self.rng.randint(0, len(INJECTION_TARGETS) - 1)
        return payload_idx + 1, target_idx + 1

    def _sample_state_sequence(self):
        """Sample a state-attack sequence."""
        if STATE_ATTACK_SEQUENCES:
            return self.rng.choice(STATE_ATTACK_SEQUENCES)
        return self.rng.randint(0, len(STATE_SEQUENCES) - 1)

    def _sample_normal_sequence(self):
        """Sample a normal/baseline sequence."""
        if NORMAL_SEQUENCES:
            return self.rng.choice(NORMAL_SEQUENCES)
        return 0

    def _sample_intensity(self):
        return self.rng.randint(0, 2)

    def _sample_max_pdu_length(self):
        return self.rng.choice([16384, 32768, 65536, 0, 1, 100,
                                0x7FFFFFFF, 0xFFFFFFFF])

    # ------------------------------------------------------------------
    # Plan generation per category
    # ------------------------------------------------------------------

    def _generate_plan_for_category(self, category):
        """Generate a single SessionPlan for the given attack category."""
        active = CATEGORY_ACTIVE_FIELDS[category]

        # Semantic fields
        if active["semantic"]:
            sem_field, sem_value = self._sample_semantic_field()
        else:
            sem_field, sem_value = 0, 0

        # Payload injection
        if active["payload"]:
            if category == "cve_inspired":
                pay_type, inj_target = self._sample_cve_payload()
            else:
                pay_type, inj_target = self._sample_payload()
        else:
            pay_type, inj_target = 0, 0

        # State sequence
        if active["state"]:
            pdu_seq = self._sample_state_sequence()
        else:
            pdu_seq = self._sample_normal_sequence()

        return SessionPlan(
            attack_category=category,
            semantic_field=sem_field,
            semantic_value_idx=sem_value,
            payload_type=pay_type,
            injection_target=inj_target,
            pdu_sequence=pdu_seq,
            intensity=self._sample_intensity(),
            max_pdu_length=self._sample_max_pdu_length(),
        )

    # ------------------------------------------------------------------
    # Thompson Sampling backend
    # ------------------------------------------------------------------

    def generate_thompson(self, n):
        """
        Generate n session plans using Thompson Sampling over attack categories.

        Each category's weight is sampled from Beta(alpha, beta).
        Categories with higher historical depth scores get more samples.
        """
        plans = []
        for _ in range(n):
            # Sample from Beta distribution for each category
            scores = {}
            for cat, (alpha, beta) in self.ts_priors.items():
                scores[cat] = self.np_rng.beta(alpha, beta)

            # Select category with highest sampled score
            category = max(scores, key=scores.get)
            plan = self._generate_plan_for_category(category)
            plans.append(plan)

        return plans

    # ------------------------------------------------------------------
    # CTGAN backend
    # ------------------------------------------------------------------

    def generate_ctgan(self, n):
        """
        Generate n session plans using CTGAN trained on scored plans.

        Requires 200+ scored plans to have accumulated.
        Falls back to Thompson Sampling if not enough data.
        """
        if len(self.scored_plans) < 200:
            logger.warning(
                f"Only {len(self.scored_plans)} scored plans, need 200+ for CTGAN. "
                f"Falling back to Thompson Sampling.")
            return self.generate_thompson(n)

        if self._ctgan_model is None:
            self._train_ctgan()

        try:
            import pandas as pd
            synthetic = self._ctgan_model.sample(n)

            plans = []
            for _, row in synthetic.iterrows():
                cat = str(row.get("attack_category", "full_hybrid"))
                if cat not in ATTACK_CATEGORIES:
                    cat = self.rng.choice(ATTACK_CATEGORIES)

                plan = SessionPlan(
                    attack_category=cat,
                    semantic_field=int(np.clip(row.get("semantic_field", 0),
                                               0, len(SEMANTIC_FIELDS))),
                    semantic_value_idx=int(max(0, row.get("semantic_value_idx", 0))),
                    payload_type=int(np.clip(row.get("payload_type", 0),
                                             0, len(PAYLOAD_TYPES))),
                    injection_target=int(np.clip(row.get("injection_target", 0),
                                                  0, len(INJECTION_TARGETS))),
                    pdu_sequence=int(np.clip(row.get("pdu_sequence", 0),
                                             0, len(STATE_SEQUENCES) - 1)),
                    intensity=int(np.clip(row.get("intensity", 1), 0, 2)),
                    max_pdu_length=int(max(0, row.get("max_pdu_length", 16384))),
                )
                plans.append(plan)

            return plans

        except Exception as e:
            logger.warning(f"CTGAN generation failed: {e}, falling back to Thompson")
            return self.generate_thompson(n)

    def _train_ctgan(self):
        """Train CTGAN on accumulated scored plans."""
        import logging
        import pandas as pd
        from ctgan import CTGAN
        # Suppress sdv/ctgan library noise ("Guidance: There are no missing values...")
        for _noisy in ("ctgan", "sdv", "rdt", "copulas"):
            logging.getLogger(_noisy).setLevel(logging.WARNING)

        # Use only the most recent 500 plans to keep training time bounded.
        # Older plans are already encoded in the model's previous weights;
        # recent plans carry fresher signal about what the server responds to.
        recent = self.scored_plans[-500:]

        # Weight by score but cap copies at 3 to avoid dataset explosion
        weighted = []
        for plan in recent:
            copies = max(1, min(3, int(plan.score / 10.0)))
            weighted.extend([plan.to_dict()] * copies)

        df = pd.DataFrame(weighted)
        # Select plan fields only (not feedback fields)
        plan_cols = ["attack_category", "semantic_field", "semantic_value_idx",
                     "payload_type", "injection_target", "pdu_sequence",
                     "intensity", "max_pdu_length"]
        df = df[plan_cols]

        categorical = ["attack_category"]

        model = CTGAN(epochs=50, batch_size=min(100, len(df)))
        model.fit(df, categorical)
        self._ctgan_model = model
        logger.info(f"CTGAN trained on {len(df)} weighted plans")

    # ------------------------------------------------------------------
    # Random baseline
    # ------------------------------------------------------------------

    def generate_random(self, n):
        """Generate n uniformly random session plans."""
        plans = []
        for _ in range(n):
            category = self.rng.choice(ATTACK_CATEGORIES)
            plan = self._generate_plan_for_category(category)
            plans.append(plan)
        return plans

    # ------------------------------------------------------------------
    # Feedback integration
    # ------------------------------------------------------------------

    def update_with_scores(self, scored_plans, retrain_ctgan: bool = False):
        """
        Update Thompson Sampling priors and store plans for CTGAN.

        For each scored plan, updates the Beta(alpha, beta) prior:
          - depth > 2.0 → treat as success (alpha += scaled_depth)
          - depth <= 2.0 → treat as failure (beta += 1)

        Args:
            retrain_ctgan: if True, invalidate the cached CTGAN model so it
                           gets retrained on the next generate_ctgan() call.
                           Pass True every ~100 steps; False every step to keep
                           TS priors current without paying the retrain cost.
        """
        for plan in scored_plans:
            self.scored_plans.append(plan)

            cat = plan.attack_category
            if cat not in self.ts_priors:
                continue

            if plan.depth > 2.0:
                self.ts_priors[cat][0] += min(plan.depth, 10.0) / 2.0
            else:
                self.ts_priors[cat][1] += 1.0

        if retrain_ctgan:
            self._ctgan_model = None

        logger.debug(
            f"Updated priors with {len(scored_plans)} plans. "
            f"Total scored: {len(self.scored_plans)}")

    def get_category_weights(self):
        """Get current Thompson Sampling category weights (mean of Beta)."""
        weights = {}
        for cat, (alpha, beta) in self.ts_priors.items():
            weights[cat] = alpha / (alpha + beta)
        return weights

    def save_plans_csv(self, plans, output_path):
        """Save session plans to CSV."""
        import csv as csv_mod
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        if not plans:
            return output_path
        fieldnames = list(plans[0].to_dict().keys())
        with open(output_path, 'w', newline='') as f:
            writer = csv_mod.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for p in plans:
                writer.writerow(p.to_dict())
        logger.info(f"Saved {len(plans)} plans to {output_path}")
        return output_path

    def load_scored_plans(self, csv_path):
        """Load previously scored plans from CSV."""
        import csv as csv_mod
        plans = []
        with open(csv_path, 'r') as f:
            reader = csv_mod.DictReader(f)
            for row in reader:
                # Convert numeric fields
                for key in ("semantic_field", "semantic_value_idx", "payload_type",
                            "injection_target", "pdu_sequence", "intensity",
                            "max_pdu_length"):
                    if key in row:
                        row[key] = int(float(row[key]))
                for key in ("score", "depth"):
                    if key in row:
                        row[key] = float(row[key])
                plan = SessionPlan.from_dict(row)
                plans.append(plan)
        self.scored_plans.extend(plans)
        logger.info(f"Loaded {len(plans)} scored plans from {csv_path}")
        return plans
