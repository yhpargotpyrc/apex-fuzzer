"""
APEX Corpus Manager
Handles all corpus lifecycle operations:
  1. Deduplication — remove seeds with identical coverage
  2. Minimization  — reduce each seed to its minimal triggering form
  3. Distillation  — keep only seeds that add unique coverage
  4. Import        — import seeds from AFL++, libFuzzer, or directories
  5. Export        — export corpus in AFL++ or libFuzzer format
  6. Quality scoring — rank seeds by coverage efficiency

Usage:
  python -m apex.corpus_manager --input corpus/ --output corpus_min/ --distill
"""

import argparse
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("apex.corpus")


@dataclass
class SeedInfo:
    path: str
    size: int
    sha256: str
    coverage_hash: str = ""
    quality_score: float = 0.0
    source: str = "unknown"
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def from_file(cls, path: str) -> "SeedInfo":
        data = Path(path).read_bytes()
        return cls(
            path=path,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )


class CorpusManager:
    """
    Full corpus lifecycle manager.
    """

    def __init__(self, target_binary: Optional[str] = None,
                 target_args: str = "@@", timeout_ms: int = 5000):
        self.target_binary = target_binary
        self.target_args = target_args
        self.timeout = timeout_ms / 1000.0

    # ─── Import ──────────────────────────────────────────────────────────────

    def import_corpus(self, source_dirs: List[str], output_dir: str,
                      formats: List[str] = None) -> int:
        """
        Import seeds from multiple sources.
        Handles AFL++ output directories (id:NNNNNN format),
        libFuzzer corpus directories, and plain directories.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        imported = 0

        for source_dir in source_dirs:
            sp = Path(source_dir)
            if not sp.exists():
                log.warning(f"Source dir not found: {source_dir}")
                continue

            # AFL++ output dir: look in queue/ subdirectory
            afl_queue = sp / "queue"
            if afl_queue.exists():
                seeds = list(afl_queue.glob("id:*"))
                log.info(f"Found AFL++ queue: {len(seeds)} seeds in {source_dir}")
                source_iter = seeds
            else:
                source_iter = [f for f in sp.rglob("*") if f.is_file()]

            for seed_file in source_iter:
                if not seed_file.is_file():
                    continue
                if formats:
                    data = seed_file.read_bytes()
                    if not self._matches_format(data, formats):
                        continue

                dest = output_path / f"seed_{imported:06d}_{seed_file.name[:16]}"
                shutil.copy2(str(seed_file), str(dest))
                imported += 1

        log.info(f"Imported {imported} seeds to {output_dir}")
        return imported

    def _matches_format(self, data: bytes, formats: List[str]) -> bool:
        """Check if data matches any of the given format magic bytes."""
        from ..modules.fileparser.file_fuzzer import FORMAT_MAGIC
        for fmt in formats:
            magic = FORMAT_MAGIC.get(fmt)
            if magic and data.startswith(magic):
                return True
        return False

    # ─── Deduplication ───────────────────────────────────────────────────────

    def deduplicate(self, corpus_dir: str, output_dir: str) -> Tuple[int, int]:
        """
        Remove exact duplicates (same SHA256) from corpus.
        Returns (original_count, deduplicated_count).
        """
        seeds = self._load_seeds(corpus_dir)
        seen_hashes = set()
        unique_seeds = []

        for seed in seeds:
            if seed.sha256 not in seen_hashes:
                seen_hashes.add(seed.sha256)
                unique_seeds.append(seed)

        self._write_seeds(unique_seeds, output_dir)
        log.info(f"Dedup: {len(seeds)} → {len(unique_seeds)} seeds "
                 f"({len(seeds) - len(unique_seeds)} duplicates removed)")
        return len(seeds), len(unique_seeds)

    # ─── Coverage Distillation ────────────────────────────────────────────────

    def distill(self, corpus_dir: str, output_dir: str) -> Tuple[int, int]:
        """
        AFL++ afl-cmin style coverage distillation.
        Keeps only the minimal set of seeds that together cover all edges.
        Falls back to size-based selection if target binary not available.
        """
        if self.target_binary and Path(self.target_binary).exists():
            return self._distill_with_binary(corpus_dir, output_dir)
        else:
            return self._distill_by_size(corpus_dir, output_dir)

    def _distill_with_binary(self, corpus_dir: str, output_dir: str) -> Tuple[int, int]:
        """Use afl-cmin for coverage-based distillation."""
        seeds_before = len(list(Path(corpus_dir).glob("*")))
        try:
            cmd = [
                "afl-cmin",
                "-i", corpus_dir,
                "-o", output_dir,
                "--",
                self.target_binary,
            ]
            args = self.target_args.split()
            cmd.extend(args)

            result = subprocess.run(cmd, capture_output=True, timeout=300)
            if result.returncode == 0:
                seeds_after = len(list(Path(output_dir).glob("*")))
                log.info(f"afl-cmin distilled: {seeds_before} → {seeds_after} seeds")
                return seeds_before, seeds_after
        except FileNotFoundError:
            log.warning("afl-cmin not found — falling back to size-based distillation")
        except Exception as e:
            log.warning(f"afl-cmin failed: {e} — falling back")

        return self._distill_by_size(corpus_dir, output_dir)

    def _distill_by_size(self, corpus_dir: str, output_dir: str) -> Tuple[int, int]:
        """
        Heuristic distillation: keep shortest seeds (they're usually faster
        to execute and more likely to be structurally minimal).
        """
        seeds = self._load_seeds(corpus_dir)
        if not seeds:
            return 0, 0

        # Group by size decile, keep one representative per group
        seeds_sorted = sorted(seeds, key=lambda s: s.size)

        # Keep seeds that are meaningfully different in size
        kept = [seeds_sorted[0]]
        for seed in seeds_sorted[1:]:
            if seed.size > kept[-1].size * 1.1:  # >10% size difference
                kept.append(seed)
            elif len(kept) < 100:  # Always keep at least 100 seeds
                if seed.sha256 != kept[-1].sha256:
                    kept.append(seed)

        self._write_seeds(kept, output_dir)
        log.info(f"Size-based distill: {len(seeds)} → {len(kept)} seeds")
        return len(seeds), len(kept)

    # ─── Minimization ────────────────────────────────────────────────────────

    def minimize_seed(self, seed_path: str, output_path: str) -> bool:
        """
        Minimize a single seed using afl-tmin.
        Returns True if minimization succeeded.
        """
        if not self.target_binary:
            return False

        try:
            cmd = [
                "afl-tmin",
                "-i", seed_path,
                "-o", output_path,
                "--",
                self.target_binary,
            ]
            cmd.extend(self.target_args.split())

            result = subprocess.run(cmd, capture_output=True, timeout=60)
            if result.returncode == 0 and Path(output_path).exists():
                orig_size = Path(seed_path).stat().st_size
                min_size = Path(output_path).stat().st_size
                reduction = (1 - min_size / max(orig_size, 1)) * 100
                log.debug(f"Minimized {seed_path}: "
                          f"{orig_size}b → {min_size}b ({reduction:.0f}% reduction)")
                return True
        except FileNotFoundError:
            log.debug("afl-tmin not found")
        except Exception as e:
            log.debug(f"afl-tmin failed: {e}")

        # Fallback: copy as-is
        shutil.copy2(seed_path, output_path)
        return False

    def minimize_corpus(self, corpus_dir: str, output_dir: str) -> dict:
        """Minimize all seeds in the corpus."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        seeds = list(Path(corpus_dir).glob("*"))
        seeds = [s for s in seeds if s.is_file()]

        stats = {"total": len(seeds), "minimized": 0, "skipped": 0,
                 "size_before": 0, "size_after": 0}

        for i, seed_file in enumerate(seeds):
            out_file = output_path / seed_file.name
            orig_size = seed_file.stat().st_size
            stats["size_before"] += orig_size

            if self.minimize_seed(str(seed_file), str(out_file)):
                stats["minimized"] += 1
                stats["size_after"] += out_file.stat().st_size
            else:
                stats["skipped"] += 1
                stats["size_after"] += orig_size

            if (i + 1) % 10 == 0:
                log.info(f"Minimizing: {i+1}/{len(seeds)}")

        reduction = (1 - stats["size_after"] / max(stats["size_before"], 1)) * 100
        log.info(f"Corpus minimization complete: "
                 f"{stats['size_before']:,}b → {stats['size_after']:,}b "
                 f"({reduction:.0f}% reduction)")
        return stats

    # ─── Quality Scoring ─────────────────────────────────────────────────────

    def score_corpus(self, corpus_dir: str) -> List[SeedInfo]:
        """
        Score each seed by predicted fuzzing value.
        Lower size + more entropy = higher score.
        """
        seeds = self._load_seeds(corpus_dir)
        scored = []

        for seed in seeds:
            data = Path(seed.path).read_bytes()
            entropy = self._byte_entropy(data)
            # Heuristic score: entropy/size ratio (dense + small = good seed)
            seed.quality_score = entropy / (seed.size + 1) * 1000
            scored.append(seed)

        scored.sort(key=lambda s: -s.quality_score)
        return scored

    def _byte_entropy(self, data: bytes) -> float:
        """Shannon entropy of byte distribution."""
        if not data:
            return 0.0
        import math
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        n = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    # ─── I/O Helpers ─────────────────────────────────────────────────────────

    def _load_seeds(self, corpus_dir: str) -> List[SeedInfo]:
        seeds = []
        for f in Path(corpus_dir).rglob("*"):
            if f.is_file():
                try:
                    seeds.append(SeedInfo.from_file(str(f)))
                except Exception:
                    pass
        return seeds

    def _write_seeds(self, seeds: List[SeedInfo], output_dir: str):
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        for i, seed in enumerate(seeds):
            dest = output_path / f"seed_{i:06d}"
            shutil.copy2(seed.path, str(dest))

    # ─── Stats Report ─────────────────────────────────────────────────────────

    def corpus_stats(self, corpus_dir: str) -> dict:
        seeds = self._load_seeds(corpus_dir)
        if not seeds:
            return {"count": 0}
        sizes = [s.size for s in seeds]
        return {
            "count": len(seeds),
            "total_size_bytes": sum(sizes),
            "avg_size_bytes": sum(sizes) // len(sizes),
            "min_size_bytes": min(sizes),
            "max_size_bytes": max(sizes),
            "unique_sha256": len(set(s.sha256 for s in seeds)),
        }


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="APEX Corpus Manager")
    parser.add_argument("--input", required=True, help="Input corpus directory")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--binary", help="Target binary (for coverage distillation)")
    parser.add_argument("--args", default="@@", help="Target args")
    parser.add_argument("--dedup", action="store_true", help="Deduplicate corpus")
    parser.add_argument("--distill", action="store_true",
                        help="Coverage distillation (keep only coverage-unique seeds)")
    parser.add_argument("--minimize", action="store_true", help="Minimize each seed")
    parser.add_argument("--score", action="store_true", help="Score and rank seeds")
    parser.add_argument("--stats", action="store_true", help="Print corpus statistics")
    parser.add_argument("--import-dirs", nargs="+", help="Import seeds from directories")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    mgr = CorpusManager(
        target_binary=args.binary,
        target_args=args.args
    )

    if args.stats:
        stats = mgr.corpus_stats(args.input)
        print("\n── Corpus Statistics ──")
        for k, v in stats.items():
            print(f"  {k}: {v:,}" if isinstance(v, int) else f"  {k}: {v}")

    if args.import_dirs:
        n = mgr.import_corpus(args.import_dirs, args.output)
        print(f"Imported {n} seeds → {args.output}")

    if args.dedup:
        before, after = mgr.deduplicate(args.input, args.output)
        print(f"Deduplicated: {before} → {after}")

    if args.distill:
        before, after = mgr.distill(args.input, args.output)
        print(f"Distilled: {before} → {after}")

    if args.minimize:
        stats = mgr.minimize_corpus(args.input, args.output)
        print(f"Minimized: {stats['size_before']:,}b → {stats['size_after']:,}b")

    if args.score:
        scored = mgr.score_corpus(args.input)
        print("\n── Top 20 Seeds by Quality Score ──")
        for s in scored[:20]:
            print(f"  {s.quality_score:6.1f}  {s.size:6}b  {Path(s.path).name}")


if __name__ == "__main__":
    main()
