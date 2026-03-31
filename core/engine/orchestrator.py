"""
APEX Core Orchestrator
Manages the full fuzzing campaign: worker pool, corpus, coverage tracking,
crash deduplication, and adaptive scheduling.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import ApexConfig
from ..mutators.mutator_chain import MutatorChain
from ..coverage.coverage_map import CoverageMap
from ..scheduler.adaptive_scheduler import AdaptiveScheduler
from ...modules.network.network_fuzzer import NetworkFuzzer
from ...modules.fileparser.file_fuzzer import FileFuzzer
from ...modules.kernel.kernel_fuzzer import KernelFuzzer
from ...modules.firmware.firmware_fuzzer import FirmwareFuzzer

log = logging.getLogger("apex.orchestrator")


@dataclass
class CampaignStats:
    start_time: float = field(default_factory=time.time)
    total_executions: int = 0
    unique_crashes: int = 0
    total_paths: int = 0
    execs_per_sec_samples: list = field(default_factory=list)

    @property
    def avg_execs_per_sec(self):
        if not self.execs_per_sec_samples:
            return 0.0
        return sum(self.execs_per_sec_samples) / len(self.execs_per_sec_samples)

    @property
    def runtime_human(self):
        elapsed = int(time.time() - self.start_time)
        h, remainder = divmod(elapsed, 3600)
        m, s = divmod(remainder, 60)
        return f"{h:02d}h {m:02d}m {s:02d}s"


class FuzzOrchestrator:
    """
    Central orchestrator. Manages:
    - Worker pool lifecycle
    - Seed corpus queue
    - Global coverage bitmap
    - Crash deduplication
    - Adaptive energy scheduling
    - Dashboard telemetry
    """

    MODULE_MAP = {
        "network": NetworkFuzzer,
        "fileparser": FileFuzzer,
        "kernel": KernelFuzzer,
        "firmware": FirmwareFuzzer,
    }

    def __init__(self, config: ApexConfig, resource_mgr, crash_analyzer, dashboard=None):
        self.config = config
        self.resource_mgr = resource_mgr
        self.crash_analyzer = crash_analyzer
        self.dashboard = dashboard

        self.stats = CampaignStats()
        self.coverage = CoverageMap()
        self.scheduler = AdaptiveScheduler(ml_enabled=config.ml_mutator)
        self.mutator_chain = MutatorChain(config)

        # Corpus queue — shared across workers
        self.corpus_queue: asyncio.Queue = asyncio.Queue()
        self._shutdown = asyncio.Event()

        self.workers = []

    async def run(self) -> CampaignStats:
        """Main campaign entry point."""
        log.info("Initializing campaign...")

        # Load seed corpus
        await self._load_corpus()

        # Instantiate the mode-specific fuzzer module
        FuzzerClass = self.MODULE_MAP[self.config.mode]
        fuzzer_module = FuzzerClass(self.config)
        await fuzzer_module.initialize()

        # Spawn workers
        log.info(f"Spawning {self.config.workers} fuzzer workers...")
        self.workers = [
            asyncio.create_task(
                self._worker_loop(worker_id=i, fuzzer_module=fuzzer_module)
            )
            for i in range(self.config.workers)
        ]

        # Stat reporting loop
        stat_task = asyncio.create_task(self._stat_reporter())

        # Wait for shutdown
        await self._shutdown.wait()

        # Clean up
        for w in self.workers:
            w.cancel()
        stat_task.cancel()
        await asyncio.gather(*self.workers, stat_task, return_exceptions=True)
        await fuzzer_module.teardown()

        return self.stats

    async def _worker_loop(self, worker_id: int, fuzzer_module):
        """
        Core worker loop:
          1. Pull seed from corpus queue
          2. Apply mutator chain
          3. Execute target
          4. Check for coverage gain
          5. Check for crash
          6. Update scheduler energy
        """
        log = logging.getLogger(f"apex.worker.{worker_id}")
        log.info(f"Worker {worker_id} started")

        exec_count = 0
        last_time = time.time()

        while not self._shutdown.is_set():
            try:
                # Get seed (with timeout so we can check shutdown)
                seed = await asyncio.wait_for(self.corpus_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            # Get energy (how many mutations to apply to this seed)
            energy = self.scheduler.get_energy(seed)

            for _ in range(energy):
                if self._shutdown.is_set():
                    break

                # Mutate
                mutated = self.mutator_chain.mutate(seed.data)

                # Execute target
                result = await fuzzer_module.execute(mutated)
                exec_count += 1
                self.stats.total_executions += 1

                # Coverage-guided seed addition
                new_paths = self.coverage.update(result.coverage_bitmap)
                if new_paths > 0:
                    self.stats.total_paths += new_paths
                    new_seed = seed.derive(mutated, coverage_gain=new_paths)
                    await self.corpus_queue.put(new_seed)
                    log.debug(f"New coverage: +{new_paths} paths")

                # Crash handling
                if result.crashed:
                    crash_id = await self.crash_analyzer.handle(
                        input_data=mutated,
                        result=result,
                        seed=seed
                    )
                    if crash_id:  # unique crash
                        self.stats.unique_crashes += 1
                        log.warning(f"UNIQUE CRASH #{self.stats.unique_crashes} "
                                    f"— id={crash_id}, signal={result.signal}")
                        if self.dashboard:
                            await self.dashboard.push_crash(crash_id, result)

                # Update exec/sec every 1000 execs
                if exec_count % 1000 == 0:
                    now = time.time()
                    eps = 1000 / (now - last_time)
                    self.stats.execs_per_sec_samples.append(eps)
                    last_time = now

            # Update scheduler feedback
            self.scheduler.update_energy(seed, exec_count)

            # Re-queue seed (circular corpus)
            await self.corpus_queue.put(seed)

    async def _load_corpus(self):
        """Load initial seeds from corpus directory into queue."""
        corpus_dir = Path(self.config.corpus_dir)
        if not corpus_dir.exists():
            corpus_dir.mkdir(parents=True)
            log.warning(f"Corpus dir {corpus_dir} was empty — using minimal seed")
            await self.corpus_queue.put(Seed(data=b"\x00", source="minimal"))
            return

        seeds_loaded = 0
        for seed_file in sorted(corpus_dir.rglob("*")):
            if seed_file.is_file():
                data = seed_file.read_bytes()
                seed = Seed(data=data, source=str(seed_file))
                await self.corpus_queue.put(seed)
                seeds_loaded += 1

        log.info(f"Loaded {seeds_loaded} seeds from {corpus_dir}")

        if seeds_loaded == 0:
            await self.corpus_queue.put(Seed(data=b"\x00", source="minimal"))

    async def _stat_reporter(self):
        """Print live stats every 30 seconds."""
        while not self._shutdown.is_set():
            await asyncio.sleep(30)
            log.info(
                f"[STATS] execs={self.stats.total_executions:,} | "
                f"eps={self.stats.avg_execs_per_sec:,.0f} | "
                f"paths={self.stats.total_paths:,} | "
                f"crashes={self.stats.unique_crashes} | "
                f"corpus={self.corpus_queue.qsize()} | "
                f"runtime={self.stats.runtime_human}"
            )
            if self.dashboard:
                await self.dashboard.push_stats(self.stats)

    async def graceful_shutdown(self):
        """Signal all workers to stop."""
        log.info("Initiating graceful shutdown...")
        self._shutdown.set()


@dataclass
class Seed:
    """Represents a single fuzzing seed in the corpus."""
    data: bytes
    source: str
    coverage_gain: int = 0
    exec_count: int = 0
    crash_count: int = 0
    generation: int = 0

    def derive(self, new_data: bytes, coverage_gain: int = 0) -> "Seed":
        return Seed(
            data=new_data,
            source=self.source,
            coverage_gain=coverage_gain,
            generation=self.generation + 1
        )
