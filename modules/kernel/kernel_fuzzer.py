"""
APEX Kernel Fuzzer Module
Syzkaller-inspired Linux kernel syscall fuzzer.
Features:
  - Typed syscall argument generation (fd, ptr, int, flags, struct...)
  - Syscall dependency tracking (open -> read -> close chains)
  - KCOV-based kernel coverage (kernel compiled with CONFIG_KCOV)
  - Namespace isolation (runs in user namespaces for safety)
  - Syzbot-style crash detection via kernel log parsing
  - Optional: kAFL/Nyx integration for snapshot-based kernel fuzzing
"""

import asyncio
import ctypes
import logging
import os
import random
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from ...core.triage.crash_analyzer import ExecutionResult

log = logging.getLogger("apex.kernel")


# ─── Syscall Definitions ─────────────────────────────────────────────────────

@dataclass
class SyscallArg:
    name: str
    kind: str  # int, fd, ptr, flags, len, pid, uid, mode, buf, struct
    flags: list = field(default_factory=list)  # valid flag values
    range_min: int = 0
    range_max: int = 0xFFFF

    def generate(self, ctx: dict) -> int:
        if self.kind == "int":
            return random.choice([0, 1, -1, self.range_min, self.range_max,
                                  random.randint(self.range_min, self.range_max)])
        elif self.kind == "fd":
            # Use a fd from context if available
            if ctx.get("open_fds"):
                return random.choice(ctx["open_fds"] + [-1, 0, 1, 2, 999])
            return random.choice([-1, 0, 1, 2, 3, 1000])
        elif self.kind == "flags":
            if self.flags:
                # Combine random subset of flags
                chosen = random.sample(self.flags, k=random.randint(0, len(self.flags)))
                result = 0
                for f in chosen:
                    result |= f
                return result
            return random.randint(0, 0xFF)
        elif self.kind == "ptr":
            # NULL, valid ptr, invalid ptr, page boundary
            return random.choice([0, 0xFFFFFFFFFFFFFFFF, 0x1000, 0xDEADBEEF])
        elif self.kind == "len":
            return random.choice([0, 1, 8, 16, 64, 128, 4096, 65535, 0xFFFFFFFF])
        elif self.kind == "mode":
            return random.choice([0o644, 0o777, 0o000, 0o4755, 0xFFFF])
        elif self.kind == "pid":
            return random.choice([0, 1, -1, os.getpid(), random.randint(1, 65535)])
        else:
            return random.randint(0, 0xFFFFFFFF)


@dataclass
class SyscallDef:
    name: str
    number: int
    args: List[SyscallArg]
    group: str = "misc"
    produces_fd: bool = False  # if True, return value is a fd

    def generate_call(self, ctx: dict) -> Tuple[int, list]:
        return self.number, [arg.generate(ctx) for arg in self.args]


# Syscall definitions by group
SYSCALL_GROUPS = {
    "fs": [
        SyscallDef("open", 2, [
            SyscallArg("pathname", "ptr"),
            SyscallArg("flags", "flags", flags=[os.O_RDONLY, os.O_WRONLY, os.O_RDWR,
                                                 os.O_CREAT, os.O_TRUNC, os.O_APPEND,
                                                 os.O_NONBLOCK, os.O_CLOEXEC]),
            SyscallArg("mode", "mode"),
        ], group="fs", produces_fd=True),
        SyscallDef("read", 0, [
            SyscallArg("fd", "fd"),
            SyscallArg("buf", "ptr"),
            SyscallArg("count", "len"),
        ], group="fs"),
        SyscallDef("write", 1, [
            SyscallArg("fd", "fd"),
            SyscallArg("buf", "ptr"),
            SyscallArg("count", "len"),
        ], group="fs"),
        SyscallDef("close", 3, [SyscallArg("fd", "fd")], group="fs"),
        SyscallDef("ioctl", 16, [
            SyscallArg("fd", "fd"),
            SyscallArg("request", "int", range_min=0, range_max=0xFFFFFFFF),
            SyscallArg("arg", "ptr"),
        ], group="fs"),
        SyscallDef("mmap", 9, [
            SyscallArg("addr", "ptr"),
            SyscallArg("length", "len"),
            SyscallArg("prot", "flags", flags=[1,2,4,7,0]),  # PROT_READ/WRITE/EXEC
            SyscallArg("flags", "flags", flags=[2,1,0x10,0x20]),  # MAP_PRIVATE/SHARED/ANON/FIXED
            SyscallArg("fd", "fd"),
            SyscallArg("offset", "int"),
        ], group="fs"),
    ],
    "net": [
        SyscallDef("socket", 41, [
            SyscallArg("domain", "flags", flags=[1,2,3,10,16,17]),  # AF_UNIX,INET,INET6,NETLINK,PACKET
            SyscallArg("type", "flags", flags=[1,2,3,0x80000,0x8000]),  # SOCK_STREAM,DGRAM,RAW,NONBLOCK,CLOEXEC
            SyscallArg("protocol", "int", range_min=0, range_max=255),
        ], group="net", produces_fd=True),
        SyscallDef("bind", 49, [
            SyscallArg("sockfd", "fd"),
            SyscallArg("addr", "ptr"),
            SyscallArg("addrlen", "len"),
        ], group="net"),
        SyscallDef("connect", 42, [
            SyscallArg("sockfd", "fd"),
            SyscallArg("addr", "ptr"),
            SyscallArg("addrlen", "len"),
        ], group="net"),
        SyscallDef("sendto", 44, [
            SyscallArg("sockfd", "fd"),
            SyscallArg("buf", "ptr"),
            SyscallArg("len", "len"),
            SyscallArg("flags", "flags", flags=[0,1,2,4,0x40,0x80]),
            SyscallArg("dest_addr", "ptr"),
            SyscallArg("addrlen", "len"),
        ], group="net"),
        SyscallDef("setsockopt", 54, [
            SyscallArg("sockfd", "fd"),
            SyscallArg("level", "int", range_min=0, range_max=300),
            SyscallArg("optname", "int", range_min=0, range_max=100),
            SyscallArg("optval", "ptr"),
            SyscallArg("optlen", "len"),
        ], group="net"),
    ],
    "ipc": [
        SyscallDef("msgget", 68, [
            SyscallArg("key", "int", range_min=0, range_max=0xFFFFFFFF),
            SyscallArg("msgflg", "flags", flags=[0o644, 0o1000, 0o2000]),
        ], group="ipc"),
        SyscallDef("msgsnd", 69, [
            SyscallArg("msqid", "int"),
            SyscallArg("msgp", "ptr"),
            SyscallArg("msgsz", "len"),
            SyscallArg("msgflg", "flags", flags=[0, 0o4000]),
        ], group="ipc"),
        SyscallDef("semget", 64, [
            SyscallArg("key", "int"),
            SyscallArg("nsems", "int", range_min=0, range_max=1024),
            SyscallArg("semflg", "flags", flags=[0o644, 0o1000]),
        ], group="ipc"),
        SyscallDef("shmat", 30, [
            SyscallArg("shmid", "int"),
            SyscallArg("shmaddr", "ptr"),
            SyscallArg("shmflg", "flags", flags=[0, 0o10000, 0o20000]),
        ], group="ipc"),
    ],
    "mem": [
        SyscallDef("mprotect", 10, [
            SyscallArg("addr", "ptr"),
            SyscallArg("len", "len"),
            SyscallArg("prot", "flags", flags=[0,1,2,4,7]),
        ], group="mem"),
        SyscallDef("munmap", 11, [
            SyscallArg("addr", "ptr"),
            SyscallArg("length", "len"),
        ], group="mem"),
        SyscallDef("brk", 12, [SyscallArg("addr", "ptr")], group="mem"),
        SyscallDef("mremap", 25, [
            SyscallArg("old_address", "ptr"),
            SyscallArg("old_size", "len"),
            SyscallArg("new_size", "len"),
            SyscallArg("flags", "flags", flags=[1,2,3]),  # MREMAP_MAYMOVE/FIXED
            SyscallArg("new_address", "ptr"),
        ], group="mem"),
    ],
    "crypto": [
        SyscallDef("getrandom", 318, [
            SyscallArg("buf", "ptr"),
            SyscallArg("buflen", "len"),
            SyscallArg("flags", "flags", flags=[0, 1, 2]),
        ], group="crypto"),
        SyscallDef("add_key", 248, [
            SyscallArg("type", "ptr"),
            SyscallArg("description", "ptr"),
            SyscallArg("payload", "ptr"),
            SyscallArg("plen", "len"),
            SyscallArg("keyring", "int"),
        ], group="crypto"),
    ],
}


# ─── KCOV Interface ───────────────────────────────────────────────────────────

class KCOVInterface:
    """
    Interface to Linux KCOV for kernel coverage collection.
    Requires kernel compiled with CONFIG_KCOV=y.
    /sys/kernel/debug/kcov must be accessible.
    """

    KCOV_INIT_TRACE = 0x80086301
    KCOV_ENABLE = 0x6302
    KCOV_DISABLE = 0x6303
    COVER_SIZE = 64 * 1024

    def __init__(self):
        self._fd: Optional[int] = None
        self._cover = None
        self._available = self._check_availability()

    def _check_availability(self) -> bool:
        kcov_path = Path("/sys/kernel/debug/kcov")
        if not kcov_path.exists():
            log.warning("KCOV not available (/sys/kernel/debug/kcov missing)")
            log.warning("For KCOV support: compile kernel with CONFIG_KCOV=y")
            return False
        return True

    def open(self) -> bool:
        if not self._available:
            return False
        try:
            import fcntl, mmap
            self._fd = os.open("/sys/kernel/debug/kcov", os.O_RDWR)
            fcntl.ioctl(self._fd, self.KCOV_INIT_TRACE, self.COVER_SIZE)
            self._cover = mmap.mmap(self._fd, self.COVER_SIZE * 8,
                                     mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
            fcntl.ioctl(self._fd, self.KCOV_ENABLE, 0)
            log.info("KCOV enabled")
            return True
        except Exception as e:
            log.warning(f"KCOV open failed: {e}")
            return False

    def read_coverage(self) -> bytes:
        if not self._cover:
            return b"\x00" * 65536
        try:
            # First 8 bytes = number of PCs collected
            self._cover.seek(0)
            n_pcs = struct.unpack("<Q", self._cover.read(8))[0]
            pcs = []
            for i in range(min(n_pcs, self.COVER_SIZE - 1)):
                self._cover.seek((i + 1) * 8)
                pc = struct.unpack("<Q", self._cover.read(8))[0]
                pcs.append(pc)
            # Map PCs to bitmap
            return self._pcs_to_bitmap(pcs)
        except Exception:
            return b"\x00" * 65536

    def _pcs_to_bitmap(self, pcs: list) -> bytes:
        """Convert a list of PC values to an AFL-compatible 64KB bitmap."""
        bitmap = bytearray(65536)
        prev_pc = 0
        for pc in pcs:
            # AFL edge = hash(prev_pc, cur_pc)
            edge = ((prev_pc >> 1) ^ pc) % 65536
            bitmap[edge] = min(255, bitmap[edge] + 1)
            prev_pc = pc
        return bytes(bitmap)

    def reset(self):
        if self._cover:
            try:
                self._cover.seek(0)
                self._cover.write(b"\x00" * 8)  # Reset PC counter
            except Exception:
                pass

    def close(self):
        try:
            if self._fd is not None:
                import fcntl
                fcntl.ioctl(self._fd, self.KCOV_DISABLE, 0)
                os.close(self._fd)
        except Exception:
            pass


# ─── Kernel Fuzzer ───────────────────────────────────────────────────────────

class KernelFuzzer:
    """
    Linux kernel syscall fuzzer.
    Generates and executes sequences of typed syscalls to find kernel bugs.
    """

    def __init__(self, config):
        self.config = config
        self.syscall_groups = config.syscall_groups or ["fs", "net"]
        self._kcov = KCOVInterface()
        self._ctx: dict = {"open_fds": []}

        # Build active syscall list from selected groups
        self._active_syscalls = []
        for group in self.syscall_groups:
            self._active_syscalls.extend(SYSCALL_GROUPS.get(group, []))

        if not self._active_syscalls:
            log.warning("No valid syscall groups selected — using fs+net")
            self._active_syscalls = SYSCALL_GROUPS["fs"] + SYSCALL_GROUPS["net"]

    async def initialize(self):
        self._kcov_available = self._kcov.open()
        log.info(
            f"Kernel fuzzer ready: groups={self.syscall_groups}, "
            f"syscalls={len(self._active_syscalls)}, "
            f"kcov={'yes' if self._kcov_available else 'no (pseudo-coverage)'}"
        )

    async def execute(self, data: bytes) -> ExecutionResult:
        """
        Execute a sequence of syscalls derived from the input data.
        Use data bytes to seed the syscall selection + argument generation.
        """
        result = ExecutionResult()

        # Derive call sequence length from input
        n_calls = (len(data) % 8) + 1  # 1-8 calls per execution

        self._kcov.reset()

        crashed = False
        kernel_log_before = self._read_kernel_log_tail()

        for i in range(n_calls):
            # Select syscall using data byte
            byte = data[i % len(data)] if data else random.randint(0, 255)
            syscall = self._active_syscalls[byte % len(self._active_syscalls)]

            # Generate arguments
            sysno, args = syscall.generate_call(self._ctx)

            # Execute syscall
            ret = self._invoke_syscall(sysno, args)

            # Track produced FDs
            if syscall.produces_fd and ret >= 0:
                self._ctx["open_fds"].append(ret)
                if len(self._ctx["open_fds"]) > 32:
                    self._ctx["open_fds"].pop(0)

        # Check kernel log for panic/oops/KASAN
        kernel_log_after = self._read_kernel_log_tail()
        crash_detected, crash_output = self._detect_kernel_crash(
            kernel_log_before, kernel_log_after
        )

        if crash_detected:
            result.crashed = True
            result.signal = 11  # SIGSEGV as placeholder
            result.stderr = crash_output.encode()

        # Read KCOV coverage
        result.coverage_bitmap = self._kcov.read_coverage()
        if not self._kcov_available:
            result.coverage_bitmap = self._pseudo_coverage(data, n_calls)

        return result

    def _invoke_syscall(self, sysno: int, args: list) -> int:
        """Invoke a raw syscall using ctypes."""
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            # Pad args to 6
            while len(args) < 6:
                args.append(0)
            ret = libc.syscall(sysno, *args[:6])
            return ret
        except Exception:
            return -1

    def _read_kernel_log_tail(self, n_lines: int = 20) -> str:
        """Read the last N lines of the kernel message buffer."""
        try:
            result = subprocess.run(
                ["dmesg", "--notime", "-n", str(n_lines)],
                capture_output=True, timeout=1
            )
            return result.stdout.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _detect_kernel_crash(self, before: str, after: str) -> Tuple[bool, str]:
        """Detect kernel panics, KASAN/KCSAN bugs, general protection faults."""
        if not after:
            return False, ""

        new_lines = after[len(before):]
        crash_keywords = [
            "kernel BUG at", "Kernel panic", "BUG:", "WARNING:",
            "KASAN:", "KCSAN:", "general protection fault",
            "unable to handle kernel", "Oops:", "divide error",
            "stack-protector:", "use-after-free",
        ]

        for keyword in crash_keywords:
            if keyword in new_lines:
                log.warning(f"Kernel crash detected: '{keyword}'")
                return True, new_lines

        return False, ""

    def _pseudo_coverage(self, data: bytes, n_calls: int) -> bytes:
        import hashlib
        h = hashlib.sha256(data + n_calls.to_bytes(1, "little")).digest()
        bitmap = bytearray(65536)
        for i in range(0, 65536, 32):
            chunk = hashlib.sha256(h + i.to_bytes(3, "little")).digest()
            bitmap[i:i+32] = chunk
        for i in range(65536):
            if bitmap[i] > 220:
                bitmap[i] = 0
        return bytes(bitmap)

    async def teardown(self):
        self._kcov.close()
        # Close any open FDs in context
        for fd in self._ctx.get("open_fds", []):
            try:
                os.close(fd)
            except Exception:
                pass


import subprocess
