"""
APEX Crash Analyzer
State-of-the-art crash triage:
  1. Deduplication via stack hash + coverage path hash
  2. Exploitability classification (signal, PC, access type)
  3. Minimization (reduce crashing input to smallest form)
  4. Severity scoring
  5. Report generation
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import signal as signal_mod
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

log = logging.getLogger("apex.crash_analyzer")


# Exploitability levels (inspired by !exploitable / GDB plugin)
class Exploitability:
    EXPLOITABLE = "EXPLOITABLE"
    PROBABLY_EXPLOITABLE = "PROBABLY_EXPLOITABLE"
    UNKNOWN = "UNKNOWN"
    PROBABLY_NOT_EXPLOITABLE = "PROBABLY_NOT_EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"


# Signal -> exploitability heuristic
SIGNAL_EXPLOITABILITY = {
    signal_mod.SIGSEGV: Exploitability.PROBABLY_EXPLOITABLE,
    signal_mod.SIGBUS:  Exploitability.PROBABLY_EXPLOITABLE,
    signal_mod.SIGFPE:  Exploitability.PROBABLY_NOT_EXPLOITABLE,
    signal_mod.SIGILL:  Exploitability.EXPLOITABLE,
    signal_mod.SIGABRT: Exploitability.PROBABLY_NOT_EXPLOITABLE,
    signal_mod.SIGTRAP: Exploitability.UNKNOWN,
    signal_mod.SIGKILL: Exploitability.NOT_EXPLOITABLE,  # likely OOM/timeout
}


@dataclass
class ExecutionResult:
    """Result from running the target once."""
    crashed: bool = False
    signal: Optional[int] = None
    exit_code: int = 0
    coverage_bitmap: Optional[bytes] = None
    stdout: bytes = b""
    stderr: bytes = b""
    exec_time_ms: float = 0.0
    timed_out: bool = False
    oom: bool = False


@dataclass
class CrashReport:
    crash_id: str = ""
    timestamp: float = field(default_factory=time.time)
    signal: Optional[int] = None
    signal_name: str = ""
    exploitability: str = Exploitability.UNKNOWN
    severity_score: int = 0  # 0-100
    input_file: str = ""
    minimized_input_file: str = ""
    stack_hash: str = ""
    coverage_hash: str = ""
    input_size_original: int = 0
    input_size_minimized: int = 0
    asan_output: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CrashAnalyzer:
    """
    Central crash triage engine.
    """

    def __init__(self, output_dir: str, dedup_method: str = "stack_hash",
                 exploitability_check: bool = True, minimize: bool = True):
        self.output_dir = Path(output_dir)
        self.dedup_method = dedup_method
        self.exploitability_check = exploitability_check
        self.minimize = minimize

        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "crashes").mkdir(exist_ok=True)
        (self.output_dir / "minimized").mkdir(exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)

        # Seen crash hashes for deduplication
        self._seen_hashes: set = set()
        self._crash_count: int = 0

        # Load previously seen hashes if resuming
        self._load_seen_hashes()

    def _load_seen_hashes(self):
        hash_file = self.output_dir / "seen_hashes.json"
        if hash_file.exists():
            try:
                self._seen_hashes = set(json.loads(hash_file.read_text()))
                log.info(f"Loaded {len(self._seen_hashes)} known crash hashes")
            except Exception as e:
                log.warning(f"Could not load seen hashes: {e}")

    def _save_seen_hashes(self):
        hash_file = self.output_dir / "seen_hashes.json"
        hash_file.write_text(json.dumps(list(self._seen_hashes)))

    async def handle(self, input_data: bytes, result: ExecutionResult,
                     seed=None) -> Optional[str]:
        """
        Process a crash. Returns crash_id if unique, None if duplicate.
        """
        # Compute crash hash
        crash_hash = self._compute_crash_hash(result, input_data)

        # Deduplication check
        if crash_hash in self._seen_hashes:
            log.debug(f"Duplicate crash (hash={crash_hash[:8]})")
            return None

        self._seen_hashes.add(crash_hash)
        self._crash_count += 1
        crash_id = f"crash_{self._crash_count:06d}_{crash_hash[:8]}"

        # Save raw crashing input
        input_file = self.output_dir / "crashes" / f"{crash_id}.bin"
        input_file.write_bytes(input_data)

        # Build crash report
        report = CrashReport(
            crash_id=crash_id,
            signal=result.signal,
            signal_name=self._signal_name(result.signal),
            exploitability=self._classify_exploitability(result),
            severity_score=self._score_severity(result),
            input_file=str(input_file),
            stack_hash=crash_hash,
            input_size_original=len(input_data),
            asan_output=result.stderr.decode("utf-8", errors="replace")[:4096],
        )

        # Minimization (async, non-blocking)
        if self.minimize:
            asyncio.create_task(self._minimize_crash(crash_id, input_data, report))

        # Save report
        report_file = self.output_dir / "reports" / f"{crash_id}.json"
        report_file.write_text(json.dumps(report.to_dict(), indent=2))

        self._save_seen_hashes()

        log.warning(
            f"NEW CRASH: {crash_id} | "
            f"signal={report.signal_name} | "
            f"exploitability={report.exploitability} | "
            f"severity={report.severity_score}/100 | "
            f"size={len(input_data)}b"
        )

        return crash_id

    def _compute_crash_hash(self, result: ExecutionResult, input_data: bytes) -> str:
        """
        Multi-factor crash hash for accurate deduplication.
        Combines: signal + ASAN stack trace + coverage path hash.
        """
        h = hashlib.sha256()

        # Signal
        h.update(str(result.signal).encode())

        # ASAN/sanitizer stack trace (most reliable dedup signal)
        if result.stderr:
            stack = self._extract_stack_trace(result.stderr)
            if stack:
                h.update(stack.encode())
            else:
                # Fall back to coverage bitmap hash
                if result.coverage_bitmap:
                    h.update(result.coverage_bitmap[:256])  # first 256 bytes

        # If no sanitizer output, use input hash as last resort
        else:
            h.update(hashlib.md5(input_data).digest())

        return h.hexdigest()

    def _extract_stack_trace(self, stderr: bytes) -> str:
        """
        Extract and normalize a stack trace from ASAN/sanitizer output.
        Normalizes addresses to just function names for stable hashing.
        """
        text = stderr.decode("utf-8", errors="replace")
        lines = []
        in_trace = False
        for line in text.splitlines():
            if "SUMMARY:" in line or "#0 " in line:
                in_trace = True
            if in_trace:
                # Extract function name (strip addresses)
                match = re.search(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)", line)
                if match:
                    lines.append(match.group(1))
                if len(lines) > 8:  # top 8 frames is enough for dedup
                    break
        return "\n".join(lines)

    def _classify_exploitability(self, result: ExecutionResult) -> str:
        """Heuristic exploitability classification."""
        if not result.signal:
            return Exploitability.NOT_EXPLOITABLE

        base = SIGNAL_EXPLOITABILITY.get(result.signal, Exploitability.UNKNOWN)

        # Upgrade based on ASAN findings
        stderr = result.stderr.decode("utf-8", errors="replace")
        if "heap-buffer-overflow" in stderr:
            return Exploitability.EXPLOITABLE
        if "stack-buffer-overflow" in stderr:
            return Exploitability.EXPLOITABLE
        if "use-after-free" in stderr:
            return Exploitability.EXPLOITABLE
        if "heap-use-after-free" in stderr:
            return Exploitability.EXPLOITABLE
        if "WRITE of size" in stderr:
            return Exploitability.EXPLOITABLE
        if "READ of size" in stderr:
            return Exploitability.PROBABLY_EXPLOITABLE
        if "attempting free on address which was not malloc" in stderr:
            return Exploitability.PROBABLY_NOT_EXPLOITABLE

        return base

    def _score_severity(self, result: ExecutionResult) -> int:
        """Score 0-100 for crash severity."""
        score = 50  # baseline

        stderr = result.stderr.decode("utf-8", errors="replace")

        # High severity indicators
        if "heap-buffer-overflow" in stderr: score += 30
        elif "use-after-free" in stderr: score += 30
        elif "stack-buffer-overflow" in stderr: score += 25
        elif result.signal == signal_mod.SIGILL: score += 20  # likely RIP control
        elif result.signal == signal_mod.SIGSEGV: score += 10

        # WRITE > READ
        if "WRITE of size" in stderr: score += 10
        if "READ of size" in stderr: score += 5

        # Large overflows are worse
        size_match = re.search(r"of size (\d+)", stderr)
        if size_match:
            size = int(size_match.group(1))
            if size > 1024: score += 10
            elif size > 64: score += 5

        return min(100, max(0, score))

    def _signal_name(self, sig: Optional[int]) -> str:
        if sig is None:
            return "NONE"
        try:
            return signal_mod.Signals(sig).name
        except (ValueError, AttributeError):
            return f"SIG{sig}"

    async def _minimize_crash(self, crash_id: str, input_data: bytes, report: CrashReport):
        """
        Minimize the crashing input using binary search (afl-tmin style).
        Goal: smallest input that still triggers the same crash hash.
        """
        min_file = self.output_dir / "minimized" / f"{crash_id}_min.bin"
        current = bytearray(input_data)
        original_size = len(current)

        if original_size <= 4:
            min_file.write_bytes(bytes(current))
            return

        log.debug(f"Minimizing {crash_id} ({original_size}b)...")

        # Block-based minimization: try removing halves recursively
        current = await self._block_minimize(bytes(current))

        # Byte-level minimization: zero out individual bytes
        current = await self._byte_minimize(current)

        min_file.write_bytes(current)
        report.minimized_input_file = str(min_file)
        report.input_size_minimized = len(current)

        reduction = (1 - len(current) / original_size) * 100
        log.info(f"Minimized {crash_id}: {original_size}b -> {len(current)}b "
                 f"({reduction:.0f}% reduction)")

        # Update report
        report_file = self.output_dir / "reports" / f"{crash_id}.json"
        report_file.write_text(json.dumps(report.to_dict(), indent=2))

    async def _block_minimize(self, data: bytes) -> bytes:
        """Remove blocks of bytes that aren't needed to trigger the crash."""
        # Placeholder: in a real implementation, re-executes the target
        # For now, returns data unchanged (requires target reference)
        return data

    async def _byte_minimize(self, data: bytes) -> bytes:
        """Zero out bytes that aren't needed."""
        # Placeholder: in a real implementation, re-executes the target
        return data

    def get_stats(self) -> dict:
        return {
            "unique_crashes": self._crash_count,
            "seen_hashes": len(self._seen_hashes),
            "output_dir": str(self.output_dir),
        }
