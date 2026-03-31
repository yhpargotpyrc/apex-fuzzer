"""
APEX Adaptive Scheduler
Implements energy-based seed scheduling with optional ML guidance.

Energy = how many mutations to apply to a given seed.
High-energy seeds = seeds that historically find new coverage.

Strategies:
  - AFL-style: favor shorter, faster, earlier seeds
  - AFLFast: power schedules (FAST, EXPLORE, EXPLOIT, etc.)
  - ML-guided: train a lightweight model on (seed_features -> coverage_gain)
"""

import logging
import math
import random
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("apex.scheduler")


@dataclass
class SeedStats:
    """Per-seed statistics used for energy calculation."""
    seed_id: int = 0
    exec_count: int = 0
    coverage_gain: int = 0
    crash_count: int = 0
    discovery_time: float = field(default_factory=time.time)
    last_exec_time: float = field(default_factory=time.time)
    input_length: int = 0
    energy: int = 8  # initial energy


class AdaptiveScheduler:
    """
    Seed energy scheduler.
    Decides how many mutations to apply to each seed per fuzzing round.
    """

    SCHEDULES = ["fast", "explore", "exploit", "linear", "quad"]

    def __init__(self, ml_enabled: bool = False, schedule: str = "explore"):
        self.ml_enabled = ml_enabled
        self.schedule = schedule
        self._seed_stats: dict = {}
        self._global_execs: int = 0
        self._ml_model = None

        if ml_enabled:
            self._init_ml_model()

    def _init_ml_model(self):
        """Initialize a lightweight ML model for energy prediction."""
        try:
            from sklearn.ensemble import GradientBoostingRegressor
            import numpy as np
            self._ml_model = GradientBoostingRegressor(n_estimators=50, max_depth=3)
            self._ml_X = []
            self._ml_y = []
            log.info("ML scheduler initialized (GradientBoosting)")
        except ImportError:
            log.warning("scikit-learn not installed — ML scheduler disabled")
            self.ml_enabled = False

    def get_energy(self, seed) -> int:
        """Calculate energy for a seed (number of mutations to try)."""
        seed_id = id(seed)
        if seed_id not in self._seed_stats:
            stats = SeedStats(
                seed_id=seed_id,
                input_length=len(seed.data),
                discovery_time=time.time()
            )
            self._seed_stats[seed_id] = stats
        else:
            stats = self._seed_stats[seed_id]

        if self.ml_enabled and self._ml_model and len(self._ml_X) > 20:
            return self._ml_energy(stats)
        else:
            return self._heuristic_energy(stats)

    def _heuristic_energy(self, stats: SeedStats) -> int:
        """
        AFLFast-style power schedule.
        Favors:
          - Seeds that found coverage recently
          - Seeds with fewer executions (under-explored)
          - Shorter seeds (faster to mutate)
        """
        if self.schedule == "fast":
            p = min(0.5 * math.pow(2, stats.coverage_gain / (stats.exec_count + 1)), 512)
        elif self.schedule == "explore":
            p = min(0.5 * math.pow(2, 1.0 / (stats.exec_count + 1)), 512)
        elif self.schedule == "exploit":
            p = min(stats.coverage_gain * 8.0, 512)
        elif self.schedule == "linear":
            p = min(stats.exec_count / 10 + 1, 512)
        elif self.schedule == "quad":
            p = min((stats.exec_count / 10 + 1) ** 2, 512)
        else:
            p = 8

        # Bonus for seeds that have found crashes (related paths likely useful)
        if stats.crash_count > 0:
            p *= 1.5

        # Penalty for very large inputs (slow to execute)
        if stats.input_length > 10000:
            p *= 0.5

        return max(1, int(p))

    def _ml_energy(self, stats: SeedStats) -> int:
        """Predict energy using the ML model."""
        import numpy as np
        features = self._extract_features(stats)
        try:
            prediction = self._ml_model.predict([features])[0]
            return max(1, min(512, int(prediction)))
        except Exception:
            return self._heuristic_energy(stats)

    def _extract_features(self, stats: SeedStats) -> list:
        """Feature vector for ML model."""
        age = time.time() - stats.discovery_time
        return [
            stats.exec_count,
            stats.coverage_gain,
            stats.crash_count,
            stats.input_length,
            age,
            stats.coverage_gain / (stats.exec_count + 1),  # coverage rate
            math.log1p(stats.exec_count),
        ]

    def update_energy(self, seed, execs_done: int, coverage_gain: int = 0, crashed: bool = False):
        """Update seed statistics after a fuzzing round."""
        self._global_execs += execs_done
        seed_id = id(seed)
        if seed_id in self._seed_stats:
            stats = self._seed_stats[seed_id]
            stats.exec_count += execs_done
            stats.coverage_gain += coverage_gain
            if crashed:
                stats.crash_count += 1
            stats.last_exec_time = time.time()

            # Feed ML training data
            if self.ml_enabled and self._ml_model is not None:
                features = self._extract_features(stats)
                self._ml_X.append(features)
                self._ml_y.append(float(coverage_gain))

                # Retrain periodically
                if len(self._ml_X) % 100 == 0 and len(self._ml_X) > 20:
                    self._retrain_ml()

    def _retrain_ml(self):
        """Retrain the ML model on accumulated data."""
        import numpy as np
        try:
            X = np.array(self._ml_X[-1000:])  # use last 1000 samples
            y = np.array(self._ml_y[-1000:])
            self._ml_model.fit(X, y)
            log.debug(f"ML model retrained on {len(X)} samples")
        except Exception as e:
            log.debug(f"ML retrain failed: {e}")

    def get_stats(self) -> dict:
        return {
            "total_seeds_tracked": len(self._seed_stats),
            "global_execs": self._global_execs,
            "schedule": self.schedule,
            "ml_enabled": self.ml_enabled,
            "ml_samples": len(self._ml_X) if self.ml_enabled else 0,
        }


class ResourceManager:
    """
    Controls system resource usage across all workers.
    Ensures we don't OOM or thrash the system.
    """

    def __init__(self, max_workers: int, memory_limit_mb: int):
        self.max_workers = max_workers
        self.memory_limit_mb = memory_limit_mb
        self._worker_semaphore = None

    async def initialize(self):
        import asyncio
        self._worker_semaphore = asyncio.Semaphore(self.max_workers)
        log.info(f"Resource manager ready: {self.max_workers} workers, "
                 f"{self.memory_limit_mb}MB/worker")

    async def acquire(self):
        await self._worker_semaphore.acquire()

    def release(self):
        self._worker_semaphore.release()

    def get_memory_limit_bytes(self) -> int:
        return self.memory_limit_mb * 1024 * 1024
