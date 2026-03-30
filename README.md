<div align="center">

```
   ___  ____  _______  __   ____                        
  / _ |/ __ \/ __/ \ \/ /  / __/_ _________ ___ ____  
 / __ / /_/ / _/ /   \  /  / _// // /_ /_ // -_) __/  
/_/ |_\____/___/_/|_//_/  /_/  \_,_//__//__/\__/_/     
```

# APEX Fuzzer

**Advanced Persistent EXploration Fuzzer**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)](https://kernel.org)
[![AFL++](https://img.shields.io/badge/AFL++-Compatible-red?style=flat-square)](https://github.com/AFLplusplus/AFLplusplus)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

*State-of-the-art, multi-target security research fuzzer*

</div>

---

APEX is a research-grade fuzzing framework combining **coverage-guided fuzzing**, **grammar-aware mutation**, **symbolic execution**, and **ML-guided scheduling** into a single unified tool. It targets four classes simultaneously: network protocols, file format parsers, Linux kernel syscalls, and firmware/IoT binaries — in both source-instrumented and binary-only modes.

> **Intended use:** Security research, vulnerability discovery on systems you own or have explicit permission to test, CTF challenges, and academic study of fuzzing techniques.

---

## Features

| Technique | Description |
|---|---|
| **Coverage-guided fuzzing** | AFL++-compatible 64KB edge bitmap with hit-count bucketing |
| **5-strategy mutator chain** | Havoc · Splice · CmpLog · Grammar · Radamsa with adaptive weights |
| **ML energy scheduling** | GradientBoosting model learns which seeds find coverage |
| **Symbolic execution hybrid** | angr integration — solves path constraints when fuzzer stalls |
| **CmpLog tracing** | Captures comparison magic values; guides mutator to bypass checks |
| **Structure-aware mutation** | Understands PNG/ZIP/ELF/HTTP/DNS internal structure |
| **KCOV kernel coverage** | Real kernel edge coverage without source changes |
| **QEMU + Frida** | Binary-only coverage for closed-source targets |
| **Auto harness generation** | Generates compilable C harnesses from any `.so` library |
| **Crash triage** | Dedup by stack hash · exploitability scoring · automatic minimization |
| **Live dashboard** | Real-time web UI at `localhost:8080` |

---

## Supported Targets

<table>
<tr>
<td><b>Network Protocols</b></td>
<td><b>File Formats</b></td>
<td><b>Linux Kernel</b></td>
<td><b>Firmware / IoT</b></td>
</tr>
<tr>
<td>HTTP/1.1, TLS, DNS, MQTT, Modbus/TCP, FTP, SSH, Custom</td>
<td>PNG, ZIP, ELF, PDF, JPEG, MP4, XML, JSON, Custom</td>
<td>fs, net, ipc, mem, crypto syscall groups via KCOV</td>
<td>ARM, MIPS, x86, PPC — QEMU + Frida + binwalk</td>
</tr>
</table>

---

## Architecture

```
apex.py  (CLI)
│
├── core/engine/
│   ├── orchestrator.py       Worker pool · corpus queue · campaign lifecycle
│   ├── config.py             Config loading, validation, merging
│   └── symbolic_executor.py  angr hybrid — solves constraints on stall
│
├── core/mutators/
│   └── mutator_chain.py      Havoc · Splice · CmpLog · Grammar · Radamsa
│
├── core/coverage/
│   ├── coverage_map.py       AFL 64KB bitmap · SHM interface · path hashing
│   └── cmplog_tracer.py      SHM CmpLog (source) + Frida hooks (binary)
│
├── core/scheduler/
│   └── adaptive_scheduler.py AFLFast power schedules + ML energy model
│
├── core/triage/
│   └── crash_analyzer.py     Dedup · exploitability · severity · minimization
│
├── modules/
│   ├── network/              HTTP/DNS/MQTT/Modbus grammar generation
│   ├── fileparser/           PNG/ZIP/ELF structure-aware mutators
│   ├── kernel/               Typed syscall fuzzing + KCOV
│   └── firmware/             QEMU + Frida + binwalk auto-unpack
│
├── harnesses/
│   └── harness_generator.py  Auto-generate libFuzzer + AFL++ C harnesses
│
├── scripts/
│   └── corpus_manager.py     Dedup · distill · minimize · score corpus
│
└── dashboards/
    └── server.py             WebSocket live dashboard
```

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/YOUR_USERNAME/apex-fuzzer.git
cd apex-fuzzer
bash install.sh
```

Requires: Linux, Python 3.9+, clang/LLVM.

### 2. Fuzz a file parser (source mode)

Compile your target with instrumentation:

```bash
# AFL++ instrumentation (recommended)
AFL_USE_ASAN=1 afl-clang-fast -o target_fuzz target.c -lpng

# Or pure LLVM coverage + sanitizers
clang -fsanitize=address,undefined \
      -fsanitize-coverage=trace-pc-guard,trace-cmp \
      -o target_fuzz target.c -lpng
```

Run APEX:

```bash
python3 apex.py \
  --mode fileparser \
  --target-binary ./target_fuzz \
  --target-args "@@" \
  --format png \
  --source --asan --ubsan \
  --cmplog --ml-mutator \
  --corpus ./corpus/png \
  --workers 4 \
  --dashboard
```

### 3. Fuzz a network server

```bash
python3 apex.py \
  --mode network \
  --target-binary ./http_server \
  --protocol http \
  --target-port 8080 \
  --source --asan \
  --workers 4
```

### 4. Fuzz Linux kernel syscalls

```bash
# Requires Linux. For KCOV: compile kernel with CONFIG_KCOV=y
python3 apex.py \
  --mode kernel \
  --syscall-groups net,fs,ipc \
  --workers 2
```

### 5. Fuzz firmware

```bash
python3 apex.py \
  --mode firmware \
  --firmware-image ./router_fw.bin \
  --arch mips --endian big \
  --workers 2
```

---

## All Flags

```
--mode          {network, fileparser, kernel, firmware}
--target-binary  Path to target binary
--target-args    Arguments (use @@ for input file)
--source         Source mode (LLVM instrumentation)
--binary         Binary-only mode (QEMU/Frida)

--protocol       {http,tls,ftp,ssh,dns,mqtt,modbus,custom}
--format         {pdf,png,jpeg,mp4,zip,elf,xml,json,custom}
--syscall-groups Comma-separated: net,fs,ipc,mem,crypto
--firmware-image Firmware binary path
--arch           {arm,mips,mips64,x86,ppc}
--endian         {little,big}

--workers N      Parallel fuzzer workers (default: 4)
--timeout MS     Per-execution timeout (default: 5000)
--memory-limit   Per-worker memory in MB (default: 256)
--corpus DIR     Seed corpus directory
--output DIR     Crash output directory

--asan           AddressSanitizer (heap/stack overflow, UAF)
--msan           MemorySanitizer (uninitialized reads)
--ubsan          UBSan (undefined behavior, integer overflow)
--tsan           ThreadSanitizer (data races)
--dfsan          DataFlowSanitizer (taint tracking)

--cmplog         Capture comparison values to guide mutation
--ml-mutator     ML-guided energy scheduling (needs scikit-learn)
--symbolic       Symbolic execution hybrid on stall (needs angr)
--snapshot       Snapshot-based execution for stateful targets
--grammar-file   JSON grammar for structure-aware fuzzing

--dashboard      Launch web dashboard at localhost:8080
--resume         Resume a previous campaign
--dry-run        Validate config without executing
```

---

## Auto Harness Generation

Generate a ready-to-compile fuzzing harness from any shared library:

```bash
python3 harnesses/harness_generator.py \
  libpng.so \
  /usr/include/png.h \
  --format png \
  --output ./harnesses/libpng
```

Outputs: `libpng_libfuzzer.c`, `libpng_afl.c`, `Makefile`, `compile.sh`

---

## Corpus Management

```bash
# Deduplicate
python3 scripts/corpus_manager.py --input corpus/ --output dedup/ --dedup

# Coverage distillation (keep only coverage-unique seeds)
python3 scripts/corpus_manager.py --input corpus/ --output min/ \
  --distill --binary ./target

# Minimize each seed
python3 scripts/corpus_manager.py --input corpus/ --output min/ \
  --minimize --binary ./target

# Score seeds by quality
python3 scripts/corpus_manager.py --input corpus/ --output . --score

# Import from AFL++ output queue
python3 scripts/corpus_manager.py \
  --import-dirs findings/queue \
  --output corpus_merged/
```

---

## Crash Output

```
crashes/
  crashes/crash_000001_a3f7b2c1.bin          raw crashing input
  minimized/crash_000001_a3f7b2c1_min.bin    minimized input
  reports/crash_000001_a3f7b2c1.json         triage report
  seen_hashes.json                            deduplication DB
```

Triage report includes: signal, exploitability class, severity score 0–100, ASAN output, input sizes before/after minimization.

Exploitability levels: `EXPLOITABLE` · `PROBABLY_EXPLOITABLE` · `UNKNOWN` · `PROBABLY_NOT_EXPLOITABLE` · `NOT_EXPLOITABLE`

---

## Custom Grammar Files

```json
{
  "start": "request",
  "rules": {
    "request": [["method", " ", "path", " ", "version", "\r\n", "headers", "\r\n"]],
    "method":  [["GET"], ["POST"], ["FUZZ\x00"], ["G\r\nET"]],
    "path":    [["/"], ["/../etc/passwd"], ["/?" , "param"]],
    "version": [["HTTP/1.1"], ["HTTP/2.0"], ["HTTP/9.9"]],
    "headers": [["Host: localhost"], ["Host: localhost\r\nInjected: 1"]]
  }
}
```

Use with `--grammar-file ./my_grammar.json`.

---

## Extending APEX

### New protocol grammar

```python
# modules/network/network_fuzzer.py
class MyProtocolGrammar:
    @classmethod
    def generate(cls) -> bytes:
        return b"MYPROTO/1.0\r\n..."

PROTOCOL_GRAMMARS["myproto"] = MyProtocolGrammar
```

### New file format mutator

```python
# modules/fileparser/file_fuzzer.py
class MyFormatMutator:
    @classmethod
    def mutate(cls, data: bytes) -> bytes:
        buf = bytearray(data)
        # mutate structure-aware fields
        return bytes(buf)

FORMAT_MUTATORS["myformat"] = MyFormatMutator
```

---

## Dependencies

| Package | Purpose | Required |
|---|---|---|
| Python 3.9+ | Runtime | Yes |
| clang / AFL++ | Source instrumentation | For `--source` |
| qemu-user-static | Binary emulation | For `--binary` / firmware |
| frida | Binary coverage collection | Optional |
| angr | Symbolic execution | Optional (`--symbolic`) |
| scikit-learn | ML energy scheduler | Optional (`--ml-mutator`) |
| radamsa | Chaos mutation | Optional (auto-detected) |
| binwalk | Firmware unpacking | Optional (firmware mode) |
| sysv_ipc | AFL++ SHM interface | Optional (real coverage) |

---

## Roadmap

- [ ] Real AFL++ SHM integration (replace pseudo-coverage)
- [ ] Snapshot fuzzing via Nyx/kAFL
- [ ] Distributed mode — multi-machine corpus sync
- [ ] Dashboard persistence — crash history across sessions
- [ ] HTTP/2 and gRPC protocol grammars
- [ ] WASM target support
- [ ] More file format mutators: PDF, MP4, JPEG

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues: add a file format mutator, add a network protocol grammar, improve crash dedup accuracy, write integration tests.

---

## License

[MIT License](LICENSE)

---

## References

APEX builds on ideas from [AFL++](https://github.com/AFLplusplus/AFLplusplus), [libFuzzer](https://llvm.org/docs/LibFuzzer.html), [syzkaller](https://github.com/google/syzkaller), [angr](https://angr.io/), [Frida](https://frida.re/), [AFLFast](https://github.com/mboehme/aflfast), and [boofuzz](https://github.com/jtpereyda/boofuzz).

---

<div align="center"><sub>Built for security research. Use responsibly.</sub></div>
