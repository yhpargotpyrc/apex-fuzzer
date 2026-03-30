# Changelog

All notable changes to APEX will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — Initial Release

### Added

**Core engine**
- Async worker pool orchestrator with configurable worker count
- AFL++-compatible 64KB edge coverage bitmap with hit-count bucketing
- Shared memory (SHM) interface for AFL++-instrumented binaries
- Coverage path hashing for fast crash deduplication

**Mutation engine (5 strategies)**
- Havoc mutator — AFL-style bit flips, interesting values, block operations
- Splice mutator — cross-seed recombination
- CmpLog mutator — comparison-value guided byte substitution
- Grammar mutator — structure-aware generation from JSON grammars
- Radamsa mutator — external chaos-based mutation (optional)

**Scheduling**
- AFLFast power schedules: `fast`, `explore`, `exploit`, `linear`, `quad`
- Optional ML energy model (GradientBoosting via scikit-learn)
- Adaptive weight updates: rewards strategies that find new coverage

**Target modules**
- Network: HTTP/1.1, DNS, MQTT, Modbus/TCP grammar generators; stateful session fuzzing
- File parser: PNG, ZIP, ELF structure-aware mutators; LLVM SHM coverage
- Kernel: Typed syscall generation for fs/net/ipc/mem/crypto; KCOV interface
- Firmware: Multi-arch QEMU emulation (ARM/MIPS/x86/PPC); Frida coverage; binwalk unpack

**Crash triage**
- Stack-hash deduplication with ASAN output parsing
- Exploitability classification (EXPLOITABLE → NOT_EXPLOITABLE)
- Severity scoring 0–100
- Async crash minimization pipeline
- JSON triage reports

**Symbolic execution hybrid**
- angr-based CFG construction and dangerous sink identification
- Automatic exploration on coverage stall
- Concrete input injection from satisfiable path constraints
- Taint analysis for byte importance ranking

**Tooling**
- Auto harness generator — produces libFuzzer + AFL++ harnesses from `.so` + headers
- Corpus manager — dedup, coverage distillation, minimization, quality scoring
- CmpLog tracer — source (SHM) and binary (Frida hooks) modes
- Live web dashboard — WebSocket real-time stats

**Infrastructure**
- Full CLI with 40+ flags
- JSON config file support with `--config`
- `--resume` support (persists seen crash hashes)
- `--dry-run` for config validation
- `bash install.sh` one-command setup
- GitHub Actions CI (syntax check, dry run, import check)
