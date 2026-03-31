"""
APEX CmpLog Tracer
Implements AFL++-style comparison logging to capture:
  - Magic byte sequences the target checks against
  - Integer comparison values (CRC32s, checksums, protocol constants)
  - String literals compared at runtime

How it works:
  - In source mode: compile with -fsanitize-coverage=trace-cmp
    which instruments every cmp/switch instruction
  - In binary mode: use Frida to hook libc strcmp/memcmp/etc.
  - The captured values are fed to CmpLogMutator to generate
    inputs that pass those checks

This is one of the most powerful AFL++ techniques for:
  - Bypassing format magic checks
  - Passing CRC validation
  - Discovering protocol state machine transitions
"""

import ctypes
import logging
import struct
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("apex.cmplog")


# ─── Source-Mode CmpLog (via AFL++ instrumentation) ──────────────────────────

class SHMCmpLog:
    """
    Reads CmpLog data from AFL++'s shared memory CmpLog map.
    When a binary is compiled with afl-clang-fast --cmplog, AFL++ writes
    comparison operands to a second shared memory region.

    CmpLog SHM layout (from AFL++ source):
      struct cmp_map {
        struct cmp_header {
          u32 hits;
          u8 id;
          u8 shape:4;   // operand size: 0=8bit, 1=16bit, 2=32bit, 3=64bit
          u8 type:2;    // 0=cmp, 1=switch, 2=fn (strcmp etc.)
          u8 attribute:4;
        } headers[CMP_MAP_W];
        union cmp_operands {
          struct { u64 v0, v1; } operands[CMP_MAP_H];
          // ...
        } log[CMP_MAP_W];
      };
    """

    CMP_MAP_W = 65536
    CMP_MAP_H = 32
    SHM_ENV_VAR = "__AFL_CMPLOG_SHM_ID"

    def __init__(self):
        self._shm_id: Optional[int] = None
        self._available = False

    def setup(self) -> Optional[int]:
        try:
            import sysv_ipc
            # CmpLog map is larger: W * H * 16 bytes for operands + W * 8 bytes for headers
            map_size = self.CMP_MAP_W * (8 + self.CMP_MAP_H * 16)
            shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREX,
                                          mode=0o600, size=map_size)
            self._shm_id = shm.id
            self._available = True
            log.info(f"CmpLog SHM: id={self._shm_id}")
            return self._shm_id
        except ImportError:
            log.debug("sysv_ipc not available — CmpLog SHM disabled")
            return None
        except Exception as e:
            log.debug(f"CmpLog SHM setup failed: {e}")
            return None

    def read_comparisons(self) -> Dict[int, List]:
        """
        Read all captured comparisons from the SHM.
        Returns {offset -> [target_values]} mapping.
        """
        if not self._available or self._shm_id is None:
            return {}

        cmp_table = defaultdict(list)
        try:
            import sysv_ipc
            shm = sysv_ipc.SharedMemory(self._shm_id)
            data = shm.read()

            # Parse CmpLog header section
            for i in range(min(1000, self.CMP_MAP_W)):
                offset = i * 8
                if offset + 8 > len(data):
                    break

                hits = struct.unpack_from("<I", data, offset)[0]
                if hits == 0:
                    continue

                id_byte = data[offset + 4]
                shape_type = data[offset + 5]
                shape = shape_type & 0x0F  # 0=8bit, 1=16bit, 2=32bit, 3=64bit
                cmp_type = (shape_type >> 4) & 0x03

                # Read operand log
                log_base = self.CMP_MAP_W * 8 + i * self.CMP_MAP_H * 16
                for j in range(min(hits, self.CMP_MAP_H)):
                    op_offset = log_base + j * 16
                    if op_offset + 16 > len(data):
                        break
                    v0, v1 = struct.unpack_from("<QQ", data, op_offset)

                    # v1 is the comparison target (what the program checks against)
                    size_bytes = 1 << shape  # 1, 2, 4, or 8
                    mask = (1 << (size_bytes * 8)) - 1
                    cmp_table[i].append(v1 & mask)

        except Exception as e:
            log.debug(f"CmpLog read failed: {e}")

        return dict(cmp_table)

    def clear(self):
        if not self._available or self._shm_id is None:
            return
        try:
            import sysv_ipc
            shm = sysv_ipc.SharedMemory(self._shm_id)
            map_size = self.CMP_MAP_W * (8 + self.CMP_MAP_H * 16)
            shm.write(b"\x00" * map_size)
        except Exception:
            pass

    def teardown(self):
        if self._shm_id is not None:
            try:
                import sysv_ipc
                sysv_ipc.SharedMemory(self._shm_id).remove()
            except Exception:
                pass

    @property
    def env_var(self) -> dict:
        if self._shm_id is not None:
            return {self.SHM_ENV_VAR: str(self._shm_id)}
        return {}


# ─── Binary-Mode CmpLog (via Frida hooks) ────────────────────────────────────

class FridaCmpLog:
    """
    Hook libc comparison functions with Frida to capture magic values.
    Works on any binary without instrumentation.
    Hooks: strcmp, strncmp, memcmp, strcasecmp, memmem, strstr
    """

    HOOK_SCRIPT = """
    var cmpLog = {};

    function logCmp(func_name, arg1, arg2, len) {
        var key = func_name;
        if (!cmpLog[key]) cmpLog[key] = [];

        try {
            var s1 = '', s2 = '';
            if (len && len > 0) {
                s1 = Memory.readByteArray(ptr(arg1), Math.min(len, 64));
                s2 = Memory.readByteArray(ptr(arg2), Math.min(len, 64));
            } else {
                s1 = Memory.readCString(ptr(arg1));
                s2 = Memory.readCString(ptr(arg2));
            }
            cmpLog[key].push([s1, s2]);
        } catch(e) {}
    }

    ['strcmp', 'strncmp', 'strcasecmp', 'strncasecmp'].forEach(function(fn) {
        try {
            var addr = Module.findExportByName('libc.so.6', fn) ||
                       Module.findExportByName(null, fn);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        logCmp(fn, args[0], args[1],
                               (fn.includes('n') ? args[2].toInt32() : 0));
                    }
                });
            }
        } catch(e) {}
    });

    try {
        var memcmp_addr = Module.findExportByName('libc.so.6', 'memcmp') ||
                         Module.findExportByName(null, 'memcmp');
        if (memcmp_addr) {
            Interceptor.attach(memcmp_addr, {
                onEnter: function(args) {
                    logCmp('memcmp', args[0], args[1], args[2].toInt32());
                }
            });
        }
    } catch(e) {}

    rpc.exports = {
        getCmpLog: function() {
            var result = JSON.stringify(cmpLog);
            cmpLog = {};
            return result;
        }
    };
    """

    def __init__(self):
        self._available = self._check_frida()
        self._script = None
        self._session = None

    def _check_frida(self) -> bool:
        try:
            import frida
            return True
        except ImportError:
            return False

    def attach(self, pid: int) -> bool:
        if not self._available:
            return False
        try:
            import frida
            device = frida.get_local_device()
            self._session = device.attach(pid)
            self._script = self._session.create_script(self.HOOK_SCRIPT)
            self._script.load()
            log.info(f"Frida CmpLog hooks installed on PID {pid}")
            return True
        except Exception as e:
            log.debug(f"Frida CmpLog attach failed: {e}")
            return False

    def get_comparisons(self) -> Dict[str, List[Tuple]]:
        """Get captured comparisons and reset the log."""
        if not self._script:
            return {}
        try:
            import json
            raw = self._script.exports.get_cmp_log()
            return json.loads(raw)
        except Exception as e:
            log.debug(f"Frida CmpLog read failed: {e}")
            return {}

    def extract_magic_bytes(self) -> List[bytes]:
        """Extract unique byte sequences used in comparisons."""
        comparisons = self.get_comparisons()
        magic_bytes = set()

        for func_name, pairs in comparisons.items():
            for pair in pairs:
                for operand in pair:
                    if isinstance(operand, list) and operand:
                        # Convert byte array to bytes
                        try:
                            b = bytes(operand)
                            if len(b) >= 2 and len(b) <= 64:
                                magic_bytes.add(b)
                        except Exception:
                            pass
                    elif isinstance(operand, str) and len(operand) >= 2:
                        magic_bytes.add(operand.encode("latin-1", errors="replace"))

        return list(magic_bytes)

    def detach(self):
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass


# ─── CmpLog Integration ───────────────────────────────────────────────────────

class CmpLogIntegration:
    """
    Unified CmpLog interface that works in both source and binary mode.
    Feeds comparison data to the CmpLogMutator.
    """

    def __init__(self, source_mode: bool):
        self.source_mode = source_mode
        self._shm_cmplog = SHMCmpLog() if source_mode else None
        self._frida_cmplog = FridaCmpLog() if not source_mode else None
        self._captured_magic: List[bytes] = []
        self._comparison_table: Dict = {}
        self._lock = threading.Lock()

    def setup(self) -> dict:
        """Returns env vars to set before running the target."""
        if self.source_mode and self._shm_cmplog:
            shm_id = self._shm_cmplog.setup()
            return self._shm_cmplog.env_var
        return {}

    def collect(self, pid: Optional[int] = None):
        """Collect comparison data after an execution."""
        if self.source_mode and self._shm_cmplog:
            new_table = self._shm_cmplog.read_comparisons()
            self._shm_cmplog.clear()
            with self._lock:
                self._comparison_table.update(new_table)

        elif not self.source_mode and self._frida_cmplog:
            if pid and not self._frida_cmplog._session:
                self._frida_cmplog.attach(pid)
            magic = self._frida_cmplog.extract_magic_bytes()
            with self._lock:
                self._captured_magic.extend(magic)
                # Deduplicate
                self._captured_magic = list(set(self._captured_magic))[:500]

    def get_comparison_table(self) -> Dict:
        with self._lock:
            return dict(self._comparison_table)

    def get_magic_bytes(self) -> List[bytes]:
        with self._lock:
            return list(self._captured_magic)

    def update_mutator(self, cmplog_mutator):
        """Push collected data to the CmpLog mutator."""
        table = self.get_comparison_table()
        if table:
            cmplog_mutator.update_cmp_table(table)

        magic = self.get_magic_bytes()
        if magic:
            log.debug(f"CmpLog: {len(magic)} magic byte sequences captured")
            # Add magic bytes to the mutator's target list
            for i, mb in enumerate(magic[:50]):
                cmplog_mutator.update_cmp_table({i: [mb]})

    def teardown(self):
        if self._shm_cmplog:
            self._shm_cmplog.teardown()
        if self._frida_cmplog:
            self._frida_cmplog.detach()

    def get_stats(self) -> dict:
        return {
            "mode": "source" if self.source_mode else "binary",
            "comparison_sites": len(self._comparison_table),
            "magic_bytes_captured": len(self._captured_magic),
        }
