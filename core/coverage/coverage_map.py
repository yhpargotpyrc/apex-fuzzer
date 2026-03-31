"""
APEX Coverage Map
Implements AFL-style shared memory coverage bitmap with:
- Edge coverage tracking (src_block -> dst_block transitions)
- Virgin bits map (tracks which edges have EVER been seen)
- Path hashing for fast duplicate detection
- Hit count bucketing (1,2,3,4-7,8-15,16-31,32-127,128+)
"""

import ctypes
import hashlib
import logging
import mmap
import struct
from typing import Optional

log = logging.getLogger("apex.coverage")

# AFL++ uses 64KB (65536 byte) shared memory bitmap
MAP_SIZE = 65536
MAP_SIZE_POW2 = 16  # 2^16 = 65536

# Hit count buckets (same as AFL)
COUNT_CLASS_LOOKUP = [0] * 256
_buckets = [(1,1), (2,2), (3,3), (4,7), (8,15), (16,31), (32,127), (128,255)]
for _lo, _hi in _buckets:
    for _i in range(_lo, _hi + 1):
        COUNT_CLASS_LOOKUP[_i] = _hi


class CoverageMap:
    """
    Thread-safe (asyncio) coverage bitmap manager.
    Tracks seen edges globally across all workers.
    """

    def __init__(self, map_size: int = MAP_SIZE):
        self.map_size = map_size
        # Virgin bits: all 1s = no edges seen yet
        self._virgin_bits = bytearray(b"\xff" * map_size)
        # Global coverage map: union of all worker bitmaps
        self._global_map = bytearray(map_size)
        self._total_paths = 0

    def update(self, trace_bits: Optional[bytes]) -> int:
        """
        Given a new trace_bits bitmap from one execution,
        count how many new edges it contains.
        Returns the number of new paths found (0 = no new coverage).
        """
        if not trace_bits or len(trace_bits) != self.map_size:
            return 0

        new_paths = 0
        classified = self._classify_counts(trace_bits)

        for i in range(self.map_size):
            if classified[i] and (classified[i] & self._virgin_bits[i]):
                # New edge discovered
                self._virgin_bits[i] &= ~classified[i]
                self._global_map[i] |= classified[i]
                new_paths += 1

        if new_paths > 0:
            self._total_paths += new_paths

        return new_paths

    def _classify_counts(self, trace_bits: bytes) -> bytearray:
        """Apply hit-count bucketing to a raw trace bitmap."""
        return bytearray(COUNT_CLASS_LOOKUP[b] for b in trace_bits)

    @property
    def total_paths(self) -> int:
        return self._total_paths

    @property
    def coverage_percent(self) -> float:
        """Fraction of the bitmap that has been covered."""
        covered = sum(1 for b in self._virgin_bits if b != 0xFF)
        return (covered / self.map_size) * 100.0

    def get_path_hash(self, trace_bits: bytes) -> str:
        """SHA1 hash of classified trace bits — used for crash deduplication."""
        classified = self._classify_counts(trace_bits)
        return hashlib.sha1(classified).hexdigest()

    def save(self, path: str):
        """Persist the current global coverage map to disk."""
        with open(path, "wb") as f:
            f.write(bytes(self._global_map))
        log.info(f"Coverage map saved to {path}")

    def load(self, path: str):
        """Restore a coverage map from disk (for --resume)."""
        with open(path, "rb") as f:
            data = f.read(self.map_size)
        self._global_map = bytearray(data)
        # Recompute virgin bits from loaded map
        for i in range(self.map_size):
            if self._global_map[i]:
                self._virgin_bits[i] = 0x00
        log.info(f"Coverage map loaded from {path}")

    def stats(self) -> dict:
        return {
            "total_paths": self._total_paths,
            "coverage_percent": round(self.coverage_percent, 2),
            "map_density": round(
                sum(1 for b in self._global_map if b > 0) / self.map_size * 100, 2
            )
        }


class SharedMemoryCoverageMap:
    """
    POSIX shared memory coverage map for use with AFL++-instrumented binaries.
    The fuzzer writes the SHM ID into the env var AFL_MAP_SIZE / __AFL_SHM_ID,
    and the instrumented target writes its trace bits directly into the SHM.
    """

    SHM_ENV_VAR = "__AFL_SHM_ID"

    def __init__(self, map_size: int = MAP_SIZE):
        self.map_size = map_size
        self._shm_id: Optional[int] = None
        self._shm_buf: Optional[mmap.mmap] = None
        self._initialized = False

    def setup(self):
        """Allocate the shared memory segment."""
        try:
            import sysv_ipc
            shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREX,
                                          mode=0o600, size=self.map_size)
            self._shm_id = shm.id
            log.info(f"SHM allocated: id={self._shm_id}, size={self.map_size}")
            self._initialized = True
            return self._shm_id
        except ImportError:
            log.warning("sysv_ipc not installed — using pseudo-SHM (install with: pip install sysv_ipc)")
            return None
        except Exception as e:
            log.error(f"SHM setup failed: {e}")
            return None

    def read_trace(self) -> Optional[bytes]:
        """Read current trace bits from shared memory."""
        if not self._initialized or self._shm_id is None:
            return None
        try:
            import sysv_ipc
            shm = sysv_ipc.SharedMemory(self._shm_id)
            return shm.read(self.map_size)
        except Exception as e:
            log.debug(f"SHM read failed: {e}")
            return None

    def clear_trace(self):
        """Zero out the trace bits before each execution."""
        if not self._initialized or self._shm_id is None:
            return
        try:
            import sysv_ipc
            shm = sysv_ipc.SharedMemory(self._shm_id)
            shm.write(b"\x00" * self.map_size)
        except Exception as e:
            log.debug(f"SHM clear failed: {e}")

    def teardown(self):
        """Remove the shared memory segment."""
        if self._shm_id is not None:
            try:
                import sysv_ipc
                shm = sysv_ipc.SharedMemory(self._shm_id)
                shm.remove()
                log.info(f"SHM removed: id={self._shm_id}")
            except Exception as e:
                log.warning(f"SHM teardown failed: {e}")

    @property
    def env_var(self) -> dict:
        """Environment variables to inject into the target process."""
        if self._shm_id is not None:
            return {self.SHM_ENV_VAR: str(self._shm_id)}
        return {}
