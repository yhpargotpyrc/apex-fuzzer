"""
APEX Mutator Chain
Combines multiple mutation strategies in a pipeline.
Strategies (in priority order):
  1. Havoc      — classic AFL-style random mutations (fast baseline)
  2. Splice     — combine two corpus seeds
  3. CmpLog     — target comparison values found during tracing
  4. Grammar    — structure-aware mutations (when grammar available)
  5. Taint      — mutate only taint-tracked bytes (DFSan)
  6. ML         — neural network guided byte selection (optional)
  7. Radamsa    — external chaos-based fuzzer for edge cases
"""

import os
import random
import struct
import logging
from typing import Optional

log = logging.getLogger("apex.mutator")

# "Interesting" integer values that commonly trigger bugs
INTERESTING_8  = [-128, -1, 0, 1, 16, 32, 64, 100, 127, 255]
INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 65535]
INTERESTING_32 = [-2147483648, -100663046, -32769, 32768, 65535, 65536,
                   100663045, 2147483647, 4294967295]


class MutatorChain:
    """
    Orchestrates all mutation strategies.
    The strategy is selected based on adaptive weights tracked per seed.
    """

    def __init__(self, config):
        self.config = config
        self.use_cmplog = config.cmplog
        self.use_ml = config.ml_mutator
        self.grammar_file = config.grammar_file

        self.havoc = HavocMutator()
        self.splice = SpliceMutator()
        self.cmplog_mut = CmpLogMutator() if self.use_cmplog else None
        self.grammar_mut = GrammarMutator(config.grammar_file) if config.grammar_file else None
        self.radamsa_mut = RadamsaMutator()

        # Strategy weights (adapted at runtime by scheduler)
        self.weights = {
            "havoc": 0.40,
            "splice": 0.20,
            "cmplog": 0.15 if self.use_cmplog else 0.0,
            "grammar": 0.15 if config.grammar_file else 0.0,
            "radamsa": 0.10,
        }
        self._normalize_weights()

    def _normalize_weights(self):
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}

    def mutate(self, data: bytes) -> bytes:
        """Apply one mutation strategy, chosen by weighted random selection."""
        strategy = self._pick_strategy()
        try:
            if strategy == "havoc":
                return self.havoc.mutate(data)
            elif strategy == "splice":
                return self.splice.mutate(data)
            elif strategy == "cmplog" and self.cmplog_mut:
                return self.cmplog_mut.mutate(data)
            elif strategy == "grammar" and self.grammar_mut:
                return self.grammar_mut.mutate(data)
            elif strategy == "radamsa":
                return self.radamsa_mut.mutate(data)
        except Exception as e:
            log.debug(f"Mutator '{strategy}' failed: {e}, falling back to havoc")
        return self.havoc.mutate(data)

    def _pick_strategy(self) -> str:
        r = random.random()
        cumulative = 0.0
        for strategy, weight in self.weights.items():
            cumulative += weight
            if r <= cumulative:
                return strategy
        return "havoc"

    def update_weights(self, strategy: str, coverage_gain: int):
        """Adaptive weight update — reward strategies that find new coverage."""
        if strategy in self.weights and coverage_gain > 0:
            self.weights[strategy] = min(0.8, self.weights[strategy] * 1.1)
            self._normalize_weights()


# ─────────────────────────────────────────────────────────────────────────────
# Individual Mutators
# ─────────────────────────────────────────────────────────────────────────────

class HavocMutator:
    """
    AFL-style havoc mutator. Applies random mutations:
    bit flips, byte substitutions, interesting values, block operations.
    """

    HAVOC_OPERATIONS = [
        "bit_flip", "byte_flip", "interesting_byte", "interesting_word",
        "interesting_dword", "random_byte", "delete_bytes", "insert_bytes",
        "duplicate_bytes", "overwrite_bytes", "byte_arith", "word_arith"
    ]

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return b"\x00"
        buf = bytearray(data)
        # Apply 1-16 random operations
        n_ops = random.randint(1, 16)
        for _ in range(n_ops):
            op = random.choice(self.HAVOC_OPERATIONS)
            buf = self._apply(buf, op)
        return bytes(buf)

    def _apply(self, buf: bytearray, op: str) -> bytearray:
        if not buf:
            return buf
        n = len(buf)

        if op == "bit_flip":
            pos = random.randint(0, n - 1)
            buf[pos] ^= 1 << random.randint(0, 7)

        elif op == "byte_flip":
            pos = random.randint(0, n - 1)
            buf[pos] ^= 0xFF

        elif op == "interesting_byte":
            pos = random.randint(0, n - 1)
            buf[pos] = random.choice(INTERESTING_8) & 0xFF

        elif op == "interesting_word" and n >= 2:
            pos = random.randint(0, n - 2)
            val = random.choice(INTERESTING_16) & 0xFFFF
            endian = random.choice(["<", ">"])
            buf[pos:pos+2] = struct.pack(f"{endian}H", val)

        elif op == "interesting_dword" and n >= 4:
            pos = random.randint(0, n - 4)
            val = random.choice(INTERESTING_32) & 0xFFFFFFFF
            endian = random.choice(["<", ">"])
            buf[pos:pos+4] = struct.pack(f"{endian}I", val)

        elif op == "random_byte":
            pos = random.randint(0, n - 1)
            buf[pos] = random.randint(0, 255)

        elif op == "delete_bytes" and n > 4:
            start = random.randint(0, n - 1)
            length = random.randint(1, min(32, n - start))
            del buf[start:start+length]

        elif op == "insert_bytes":
            pos = random.randint(0, n)
            length = random.randint(1, 32)
            insert = bytes([random.randint(0, 255) for _ in range(length)])
            buf[pos:pos] = insert

        elif op == "duplicate_bytes":
            start = random.randint(0, n - 1)
            length = random.randint(1, min(32, n - start))
            chunk = buf[start:start+length]
            insert_pos = random.randint(0, n)
            buf[insert_pos:insert_pos] = chunk

        elif op == "byte_arith":
            pos = random.randint(0, n - 1)
            delta = random.randint(1, 35)
            if random.random() < 0.5:
                buf[pos] = (buf[pos] + delta) % 256
            else:
                buf[pos] = (buf[pos] - delta) % 256

        elif op == "word_arith" and n >= 2:
            pos = random.randint(0, n - 2)
            val = struct.unpack("<H", buf[pos:pos+2])[0]
            delta = random.randint(1, 35)
            val = (val + (delta if random.random() < 0.5 else -delta)) % 65536
            buf[pos:pos+2] = struct.pack("<H", val)

        return buf


class SpliceMutator:
    """
    Splice two seeds together at a random split point.
    Requires a second seed from the corpus (uses a local cache).
    """

    def __init__(self):
        self._seed_cache: list = []

    def add_to_cache(self, data: bytes):
        self._seed_cache.append(data)
        if len(self._seed_cache) > 512:
            self._seed_cache.pop(0)

    def mutate(self, data: bytes) -> bytes:
        if len(self._seed_cache) < 1 or len(data) < 2:
            return HavocMutator().mutate(data)

        other = random.choice(self._seed_cache)
        if len(other) < 2:
            return HavocMutator().mutate(data)

        split1 = random.randint(1, len(data) - 1)
        split2 = random.randint(1, len(other) - 1)
        return data[:split1] + other[split2:]


class CmpLogMutator:
    """
    CmpLog-guided mutator.
    After CmpLog tracing, we know which input bytes were compared against
    what magic values. We directly substitute those bytes.
    """

    def __init__(self):
        self._cmp_table: dict = {}  # offset -> [target_values]

    def update_cmp_table(self, table: dict):
        """Called by the executor after a CmpLog-instrumented run."""
        self._cmp_table.update(table)

    def mutate(self, data: bytes) -> bytes:
        if not self._cmp_table or not data:
            return HavocMutator().mutate(data)

        buf = bytearray(data)
        # Pick a random comparison site
        offset, targets = random.choice(list(self._cmp_table.items()))

        if not targets:
            return HavocMutator().mutate(data)

        target_val = random.choice(targets)
        target_bytes = None

        # Encode target value as bytes matching size
        if isinstance(target_val, int):
            for size in [1, 2, 4, 8]:
                try:
                    target_bytes = target_val.to_bytes(size, byteorder="little", signed=False)
                    break
                except OverflowError:
                    continue
        elif isinstance(target_val, bytes):
            target_bytes = target_val
        elif isinstance(target_val, str):
            target_bytes = target_val.encode()

        if target_bytes and offset < len(buf):
            end = min(offset + len(target_bytes), len(buf))
            buf[offset:end] = target_bytes[:end - offset]

        return bytes(buf)


class GrammarMutator:
    """
    Grammar-aware mutator.
    Parses a grammar definition (JSON or ANTLR4 .g4) and generates
    valid-but-adversarial inputs that conform to the protocol/format structure.
    """

    def __init__(self, grammar_file: Optional[str]):
        self.grammar_file = grammar_file
        self.grammar = self._load_grammar(grammar_file) if grammar_file else None

    def _load_grammar(self, path: str) -> Optional[dict]:
        import json
        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            log.warning(f"Could not load grammar {path}: {e}")
            return None

    def mutate(self, data: bytes) -> bytes:
        if not self.grammar:
            return HavocMutator().mutate(data)
        # Simplified: generate from grammar rules
        try:
            return self._generate_from_grammar()
        except Exception:
            return HavocMutator().mutate(data)

    def _generate_from_grammar(self) -> bytes:
        """Walk grammar rules and generate a random valid input."""
        if not self.grammar or "rules" not in self.grammar:
            return b""
        start_rule = self.grammar.get("start", list(self.grammar["rules"].keys())[0])
        return self._expand_rule(start_rule, depth=0).encode("latin-1", errors="replace")

    def _expand_rule(self, rule_name: str, depth: int) -> str:
        if depth > 20:
            return ""
        rules = self.grammar.get("rules", {})
        if rule_name not in rules:
            return rule_name  # terminal
        alternatives = rules[rule_name]
        chosen = random.choice(alternatives)
        if isinstance(chosen, str):
            return chosen
        return "".join(self._expand_rule(token, depth + 1) for token in chosen)


class RadamsaMutator:
    """
    Radamsa integration — a chaos-oriented external fuzzer.
    Excellent for finding edge cases that AFL-style mutation misses.
    Falls back gracefully if radamsa is not installed.
    """

    def __init__(self):
        self._available = self._check_radamsa()

    def _check_radamsa(self) -> bool:
        import shutil
        available = shutil.which("radamsa") is not None
        if not available:
            log.debug("radamsa not found — RadamsaMutator disabled (install with: apt install radamsa)")
        return available

    def mutate(self, data: bytes) -> bytes:
        if not self._available:
            return HavocMutator().mutate(data)
        import subprocess
        try:
            result = subprocess.run(
                ["radamsa"],
                input=data,
                capture_output=True,
                timeout=2
            )
            return result.stdout if result.stdout else data
        except Exception as e:
            log.debug(f"Radamsa failed: {e}")
            return HavocMutator().mutate(data)
