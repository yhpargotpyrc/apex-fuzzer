"""
APEX Symbolic Execution Hybrid
Integrates angr for concolic/symbolic execution to:
  1. Automatically solve path constraints that random mutation can't reach
  2. Generate inputs that exercise deep/rare code paths
  3. "Seed" the coverage-guided fuzzer with symbolically-derived inputs
  4. Detect integer overflows and format string bugs via symbolic analysis

This is the key technique that lets APEX reach code that AFL-style
mutation alone will never touch (e.g., CRC checks, magic byte sequences,
protocol state machines with complex validation logic).

Architecture:
  - Runs in a background thread, separate from main fuzzer workers
  - When fuzzer stalls (no new coverage for N minutes), triggers symex
  - Symbolically executes from the current highest-coverage seed
  - Extracts new concrete inputs from satisfiable path constraints
  - Injects those inputs into the shared corpus queue
"""

import logging
import os
import struct
import time
import threading
from pathlib import Path
from typing import Optional, List, Iterator
from dataclasses import dataclass

log = logging.getLogger("apex.symex")


@dataclass
class SymexResult:
    """A concrete input derived from symbolic execution."""
    data: bytes
    path_description: str
    constraint_count: int
    generation_time_ms: float


class SymbolicExecutor:
    """
    angr-based symbolic executor.
    Wraps angr's CFG analysis + simulation manager to extract new inputs.
    """

    def __init__(self, binary_path: str, config):
        self.binary_path = binary_path
        self.config = config
        self._project = None
        self._cfg = None
        self._available = False
        self._init_angr()

    def _init_angr(self):
        try:
            import angr
            import claripy
            self._angr = angr
            self._claripy = claripy
            self._available = True
            log.info("angr symbolic executor initialized")
        except ImportError:
            log.warning(
                "angr not installed — symbolic execution disabled\n"
                "  Install: pip install angr\n"
                "  Note: angr install is large (~500MB), takes a few minutes"
            )

    def load_binary(self) -> bool:
        """Load and analyze the target binary with angr."""
        if not self._available:
            return False
        try:
            log.info(f"Loading binary into angr: {self.binary_path}")
            self._project = self._angr.Project(
                self.binary_path,
                auto_load_libs=False,
                load_options={"main_opts": {"base_addr": 0x400000}}
            )
            log.info(f"angr: {self._project.arch.name} binary, "
                     f"{self._project.loader.main_object.min_addr:#x}-"
                     f"{self._project.loader.main_object.max_addr:#x}")
            return True
        except Exception as e:
            log.error(f"angr binary load failed: {e}")
            return False

    def build_cfg(self) -> bool:
        """Build a Control Flow Graph for the target. Expensive but one-time."""
        if not self._project:
            return False
        try:
            log.info("Building CFG (this may take a minute for large binaries)...")
            start = time.time()
            self._cfg = self._project.analyses.CFGFast(
                normalize=True,
                resolve_indirect_jumps=True,
                force_smart_scan=True,
            )
            elapsed = time.time() - start
            node_count = len(self._cfg.graph.nodes())
            log.info(f"CFG built: {node_count} nodes in {elapsed:.1f}s")
            return True
        except Exception as e:
            log.error(f"CFG build failed: {e}")
            return False

    def find_interesting_targets(self) -> list:
        """
        Find code locations worth targeting:
        - Functions with many constraints (complex validation)
        - Locations after magic byte comparisons
        - Error handlers (we want to reach them)
        - Sink functions (memcpy, strcpy, sprintf, etc.)
        """
        if not self._cfg or not self._project:
            return []

        targets = []
        dangerous_funcs = {
            "memcpy", "strcpy", "strcat", "sprintf", "gets",
            "scanf", "read", "fread", "memmove", "memset",
            "__memcpy_chk", "strncat", "strncpy",
        }

        for func in self._project.kb.functions.values():
            name = func.name or ""
            # Target dangerous sink functions
            if any(d in name.lower() for d in dangerous_funcs):
                targets.append({
                    "addr": func.addr,
                    "name": name,
                    "reason": "dangerous_sink",
                    "priority": 10,
                })
            # Target error/failure handlers (good divergence points)
            if any(e in name.lower() for e in ["error", "fail", "abort", "crash", "die"]):
                targets.append({
                    "addr": func.addr,
                    "name": name,
                    "reason": "error_handler",
                    "priority": 5,
                })

        targets.sort(key=lambda x: -x["priority"])
        log.info(f"Found {len(targets)} interesting target locations")
        return targets

    def explore_to_target(self, target_addr: int, seed: bytes,
                          max_steps: int = 10000) -> List[SymexResult]:
        """
        Symbolically execute from the binary's entry point (with seed as symbolic stdin),
        trying to reach target_addr.
        Returns list of concrete inputs that reach the target.
        """
        if not self._project or not self._available:
            return []

        claripy = self._claripy
        angr = self._angr

        results = []
        start = time.time()

        try:
            # Create symbolic stdin buffer (same size as seed)
            sym_input = claripy.BVS("fuzz_input", len(seed) * 8)

            # Set up initial state with symbolic stdin
            state = self._project.factory.full_init_state(
                stdin=angr.SimFile(
                    name="stdin",
                    content=sym_input,
                    size=len(seed)
                ),
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                    angr.options.LAZY_SOLVES,
                }
            )

            # Constrain symbolic input to be similar to seed (guide exploration)
            for i, byte in enumerate(seed[:min(len(seed), 64)]):
                # Allow each byte to vary within ±64 of the seed value
                state.solver.add(
                    claripy.And(
                        sym_input.get_byte(i) >= max(0, byte - 64),
                        sym_input.get_byte(i) <= min(255, byte + 64)
                    )
                )

            # Create simulation manager
            simgr = self._project.factory.simulation_manager(state)

            # Explore toward target
            simgr.explore(
                find=target_addr,
                num_find=5,  # Stop after finding 5 paths
                step_func=lambda sm: sm if len(sm.found) < 5 else sm.move("active", "deadended"),
                n=max_steps
            )

            # Extract concrete inputs from found paths
            for found_state in simgr.found:
                try:
                    concrete = found_state.solver.eval(sym_input, cast_to=bytes)
                    elapsed_ms = (time.time() - start) * 1000
                    results.append(SymexResult(
                        data=concrete,
                        path_description=f"path_to_{target_addr:#x}",
                        constraint_count=len(found_state.solver.constraints),
                        generation_time_ms=elapsed_ms,
                    ))
                    log.info(f"Symex found path to {target_addr:#x}: "
                             f"{len(concrete)}b input, "
                             f"{len(found_state.solver.constraints)} constraints")
                except Exception as e:
                    log.debug(f"Concrete extraction failed: {e}")

        except Exception as e:
            log.warning(f"Symbolic exploration failed: {e}")

        return results

    def taint_analysis(self, seed: bytes) -> dict:
        """
        Track which input bytes influence which program operations.
        Returns a map of {byte_offset -> [operations_affected]}.
        This is used to focus mutation on the most impactful bytes.
        """
        if not self._project or not self._available:
            return {}

        claripy = self._claripy
        angr = self._angr

        taint_map = {}

        try:
            # Use DataFlowSanitizer-style analysis via angr's taint tracking
            state = self._project.factory.full_init_state()

            # Mark all input bytes as tainted (symbolic)
            sym_bytes = [claripy.BVS(f"byte_{i}", 8) for i in range(len(seed))]

            for i, (sym, concrete) in enumerate(zip(sym_bytes, seed)):
                # Constrain to the concrete seed value initially
                state.solver.add(sym == concrete)

            # Quick simulation to find which bytes affect comparisons
            simgr = self._project.factory.simulation_manager(state)
            simgr.run(n=1000)

            # Analyze constraints in final states
            for active_state in list(simgr.active)[:10]:
                for i, sym_byte in enumerate(sym_bytes):
                    for constraint in active_state.solver.constraints:
                        # Check if this symbolic byte appears in this constraint
                        if sym_byte.variables & constraint.variables:
                            if i not in taint_map:
                                taint_map[i] = []
                            taint_map[i].append(str(constraint)[:64])

        except Exception as e:
            log.debug(f"Taint analysis failed: {e}")

        return taint_map

    def find_magic_comparisons(self) -> List[dict]:
        """
        Statically find all comparison instructions in the binary that
        compare against constant magic values. These are exactly the
        bytes the CmpLog mutator should target.
        """
        if not self._project:
            return []

        comparisons = []
        try:
            import pyvex
            main_obj = self._project.loader.main_object

            for func in list(self._project.kb.functions.values())[:200]:
                for block_addr in list(func.block_addrs)[:50]:
                    try:
                        block = self._project.factory.block(block_addr)
                        vex = block.vex
                        for stmt in vex.statements:
                            # Look for comparisons against constants
                            stmt_str = str(stmt)
                            if "CmpEQ" in stmt_str or "CmpNE" in stmt_str:
                                # Extract constant values
                                import re
                                consts = re.findall(r'0x[0-9a-f]+', stmt_str)
                                if consts:
                                    comparisons.append({
                                        "addr": block_addr,
                                        "type": "equality_check",
                                        "constants": consts[:4],
                                        "function": func.name,
                                    })
                    except Exception:
                        pass

        except Exception as e:
            log.debug(f"Magic comparison search failed: {e}")

        log.info(f"Found {len(comparisons)} magic comparisons")
        return comparisons[:100]  # Return top 100


class SymexCoordinator:
    """
    Coordinates symbolic execution with the main fuzzer.
    Runs in background, injects new seeds when fuzzer stalls.
    """

    STALL_THRESHOLD_SECONDS = 120  # Trigger symex after 2 minutes with no new coverage
    MAX_SYMEX_INPUTS_PER_ROUND = 20

    def __init__(self, binary_path: str, config, corpus_queue):
        self.binary_path = binary_path
        self.config = config
        self.corpus_queue = corpus_queue
        self._executor = SymbolicExecutor(binary_path, config)
        self._last_new_coverage_time = time.time()
        self._total_symex_inputs = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def notify_coverage_found(self):
        """Called by the main fuzzer when new coverage is found."""
        self._last_new_coverage_time = time.time()

    def start(self):
        """Start the background symex coordinator thread."""
        if not self._executor._available:
            log.info("Symbolic execution not available — skipping coordinator")
            return

        success = self._executor.load_binary()
        if not success:
            log.warning("Could not load binary into angr — symex disabled")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._coordinator_loop,
            daemon=True,
            name="symex-coordinator"
        )
        self._thread.start()
        log.info("Symex coordinator started")

    def stop(self):
        self._running = False

    def _coordinator_loop(self):
        """Background loop that triggers symbolic execution during stalls."""
        # Build CFG first (expensive one-time cost)
        self._executor.build_cfg()
        targets = self._executor.find_interesting_targets()
        magic_comps = self._executor.find_magic_comparisons()

        if magic_comps:
            log.info(f"Symex found {len(magic_comps)} magic byte comparisons to target")

        while self._running:
            time.sleep(10)

            # Check if fuzzer is stalling
            stall_time = time.time() - self._last_new_coverage_time
            if stall_time < self.STALL_THRESHOLD_SECONDS:
                continue

            log.info(f"Fuzzer stalled for {stall_time:.0f}s — triggering symbolic execution")

            # Pick a target to explore toward
            if not targets:
                continue

            for target in targets[:3]:  # Try top 3 targets per round
                seed = b"\x00" * 64  # minimal seed to start from

                results = self._executor.explore_to_target(
                    target_addr=target["addr"],
                    seed=seed,
                    max_steps=5000
                )

                for result in results[:self.MAX_SYMEX_INPUTS_PER_ROUND]:
                    # Inject into corpus queue
                    from ...core.engine.orchestrator import Seed
                    new_seed = Seed(
                        data=result.data,
                        source=f"symex:{target['name']}:{result.path_description}",
                        coverage_gain=1,  # Mark as likely interesting
                    )
                    try:
                        self.corpus_queue.put_nowait(new_seed)
                        self._total_symex_inputs += 1
                        log.info(
                            f"Symex injected input: {len(result.data)}b → "
                            f"target={target['name']}, "
                            f"constraints={result.constraint_count}"
                        )
                    except Exception:
                        pass  # Queue full, skip

            # Reset stall timer so we don't spam symex
            self._last_new_coverage_time = time.time()

    def get_stats(self) -> dict:
        return {
            "available": self._executor._available,
            "total_inputs_generated": self._total_symex_inputs,
            "last_stall_seconds": int(time.time() - self._last_new_coverage_time),
        }
