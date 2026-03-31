"""
APEX Auto Harness Generator
Automatically generates libFuzzer/AFL++-compatible fuzzing harnesses.

Given:
  - A shared library (.so) or static library (.a)
  - A binary to analyze
  - Optional: header files for API discovery

Produces:
  - A compilable C harness that calls the library's parsing functions
  - A compile command with all sanitizer flags
  - A corpus minimization script
  - Optionally: a Dockerfile for isolated fuzzing

This eliminates the single hardest part of fuzzing: writing the harness.
"""

import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

log = logging.getLogger("apex.harness")


# ─── API Discovery ────────────────────────────────────────────────────────────

@dataclass
class FunctionSignature:
    name: str
    return_type: str
    params: List[str]
    is_parser: bool = False  # likely a parsing/processing function
    is_init: bool = False    # likely initialization function
    is_cleanup: bool = False # likely cleanup/free function
    header_file: str = ""


class APIDiscovery:
    """
    Discovers fuzzable API functions from:
    1. nm/objdump symbol tables (binary analysis)
    2. C header files (source analysis)
    3. Heuristic classification (parse/load/decode = good fuzz targets)
    """

    # Heuristic patterns for function classification
    PARSER_PATTERNS = [
        r"parse", r"load", r"read", r"decode", r"deserializ",
        r"from_bytes", r"from_buffer", r"import", r"inflate",
        r"uncompress", r"unpack", r"process", r"handle",
        r"extract", r"open", r"init_from",
    ]
    INIT_PATTERNS = [r"init", r"create", r"new", r"alloc", r"open"]
    CLEANUP_PATTERNS = [r"free", r"destroy", r"close", r"cleanup", r"delete"]

    def discover_from_binary(self, binary_path: str) -> List[FunctionSignature]:
        """Extract exported symbols from a binary/library using nm."""
        functions = []
        try:
            result = subprocess.run(
                ["nm", "-D", "--defined-only", binary_path],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] in ("T", "W"):
                    name = parts[2]
                    if name.startswith("_") and not name.startswith("__"):
                        continue  # skip internal symbols
                    sig = FunctionSignature(
                        name=name,
                        return_type="int",   # assume int, header will correct
                        params=["const uint8_t *data", "size_t size"],
                        is_parser=self._is_parser(name),
                        is_init=self._is_init(name),
                        is_cleanup=self._is_cleanup(name),
                    )
                    functions.append(sig)
        except Exception as e:
            log.warning(f"nm failed: {e}")
        return functions

    def discover_from_headers(self, header_paths: List[str]) -> List[FunctionSignature]:
        """Parse C headers to find function signatures."""
        functions = []
        # Simple regex-based header parser (full clang-ast would be ideal)
        func_re = re.compile(
            r'(\w[\w\s\*]+?)\s+(\w+)\s*\(([^)]*)\)\s*;'
        )
        for header_path in header_paths:
            try:
                content = Path(header_path).read_text()
                for m in func_re.finditer(content):
                    ret_type = m.group(1).strip()
                    name = m.group(2).strip()
                    params_raw = m.group(3).strip()
                    params = [p.strip() for p in params_raw.split(",") if p.strip()]
                    sig = FunctionSignature(
                        name=name,
                        return_type=ret_type,
                        params=params,
                        is_parser=self._is_parser(name),
                        is_init=self._is_init(name),
                        is_cleanup=self._is_cleanup(name),
                        header_file=header_path,
                    )
                    functions.append(sig)
            except Exception as e:
                log.warning(f"Header parse failed {header_path}: {e}")
        return functions

    def _is_parser(self, name: str) -> bool:
        nl = name.lower()
        return any(re.search(p, nl) for p in self.PARSER_PATTERNS)

    def _is_init(self, name: str) -> bool:
        nl = name.lower()
        return any(re.search(p, nl) for p in self.INIT_PATTERNS)

    def _is_cleanup(self, name: str) -> bool:
        nl = name.lower()
        return any(re.search(p, nl) for p in self.CLEANUP_PATTERNS)

    def rank_functions(self, functions: List[FunctionSignature]) -> List[FunctionSignature]:
        """Rank functions by fuzzing value."""
        def score(f: FunctionSignature) -> int:
            s = 0
            if f.is_parser: s += 10
            if f.is_init: s += 3
            # Functions taking a buffer+size pair are ideal fuzz targets
            params_str = " ".join(f.params).lower()
            if "uint8" in params_str or "char *" in params_str: s += 5
            if "size" in params_str or "len" in params_str: s += 5
            if "FILE" in params_str: s += 3
            return s
        return sorted(functions, key=score, reverse=True)


# ─── Harness Generator ────────────────────────────────────────────────────────

@dataclass
class HarnessConfig:
    target_library: str
    functions: List[FunctionSignature]
    header_files: List[str] = field(default_factory=list)
    output_dir: str = "./harnesses"
    harness_name: str = "fuzz_harness"
    target_format: Optional[str] = None  # hint for magic byte injection
    use_asan: bool = True
    use_ubsan: bool = True
    use_msan: bool = False
    persistent_mode: bool = True  # AFL++ persistent mode (much faster)


# Magic bytes per format — inject these at input start to pass early validation
FORMAT_MAGIC = {
    "png":  r'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a',
    "jpeg": r'\xff\xd8\xff',
    "zip":  r'\x50\x4b\x03\x04',
    "elf":  r'\x7f\x45\x4c\x46',
    "pdf":  r'\x25\x50\x44\x46\x2d',
    "gif":  r'\x47\x49\x46\x38',
    "bmp":  r'\x42\x4d',
}


class HarnessGenerator:
    """
    Generates compilable C/C++ fuzzing harnesses.
    Supports:
      - libFuzzer (LLVMFuzzerTestOneInput)
      - AFL++ persistent mode (__AFL_LOOP)
      - AFL++ standard (stdin/file)
    """

    def __init__(self, config: HarnessConfig):
        self.config = config
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)

    def generate_all(self) -> dict:
        """Generate all harness variants and support files."""
        outputs = {}

        # 1. libFuzzer harness
        libfuzzer_path = self._generate_libfuzzer_harness()
        outputs["libfuzzer"] = libfuzzer_path

        # 2. AFL++ persistent mode harness
        afl_path = self._generate_afl_harness()
        outputs["afl"] = afl_path

        # 3. Compile commands
        compile_path = self._generate_compile_commands()
        outputs["compile"] = compile_path

        # 4. Makefile
        makefile_path = self._generate_makefile()
        outputs["makefile"] = makefile_path

        # 5. Corpus minimization script
        corpus_script = self._generate_corpus_minimizer()
        outputs["corpus_minimizer"] = corpus_script

        log.info(f"Generated harnesses in {self.config.output_dir}")
        return outputs

    def _generate_libfuzzer_harness(self) -> str:
        """Generate a libFuzzer-compatible harness."""
        funcs = self.config.functions[:5]  # Top 5 ranked functions
        includes = self._build_includes()
        magic = FORMAT_MAGIC.get(self.config.target_format or "", "")

        # Build the function call body
        call_body = self._build_call_body(funcs, "data", "size")

        harness = f"""/*
 * APEX Auto-Generated libFuzzer Harness
 * Target: {self.config.target_library}
 * Functions: {', '.join(f.name for f in funcs)}
 * Generated by: APEX Harness Generator
 *
 * Compile:
 *   clang -g -O1 -fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard
 *         -o {self.config.harness_name}_lf {self.config.harness_name}_libfuzzer.c
 *         -L. -l{Path(self.config.target_library).stem.lstrip('lib')}
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
{includes}

/* Minimum input size to even bother executing */
#define MIN_INPUT_SIZE 4

{"/* Require magic bytes at start of input */" if magic else ""}
{"static const uint8_t MAGIC[] = {" + magic + "};" if magic else ""}
{"static const size_t MAGIC_LEN = sizeof(MAGIC);" if magic else ""}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < MIN_INPUT_SIZE) return 0;
{self._build_magic_check(magic)}

{call_body}
    return 0;
}}
"""
        path = os.path.join(self.config.output_dir,
                            f"{self.config.harness_name}_libfuzzer.c")
        Path(path).write_text(harness)
        log.info(f"libFuzzer harness: {path}")
        return path

    def _generate_afl_harness(self) -> str:
        """Generate an AFL++ persistent mode harness."""
        funcs = self.config.functions[:5]
        includes = self._build_includes()
        call_body = self._build_call_body(funcs, "buf", "len")

        harness = f"""/*
 * APEX Auto-Generated AFL++ Persistent Mode Harness
 * Target: {self.config.target_library}
 * Functions: {', '.join(f.name for f in funcs)}
 *
 * Compile (source mode):
 *   AFL_USE_ASAN=1 afl-clang-fast -o {self.config.harness_name}_afl
 *       {self.config.harness_name}_afl.c
 *       -L. -l{Path(self.config.target_library).stem.lstrip('lib')}
 *
 * Run:
 *   afl-fuzz -i corpus/ -o findings/ -- ./{self.config.harness_name}_afl @@
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
{includes}

#define MAX_INPUT_SIZE (1 << 20)  /* 1MB */

static uint8_t buf[MAX_INPUT_SIZE];

int main(int argc, char **argv) {{
    /* AFL++ persistent mode: re-execute in a tight loop, ~1000x speedup */
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(10000)) {{
        ssize_t len;

        if (argc > 1) {{
            /* File mode: read from argument */
            FILE *f = fopen(argv[1], "rb");
            if (!f) continue;
            len = fread(buf, 1, MAX_INPUT_SIZE, f);
            fclose(f);
        }} else {{
            /* Stdin mode */
            len = read(STDIN_FILENO, buf, MAX_INPUT_SIZE);
        }}

        if (len < 4) continue;

{call_body}
    }}

    return 0;
}}
"""
        path = os.path.join(self.config.output_dir,
                            f"{self.config.harness_name}_afl.c")
        Path(path).write_text(harness)
        log.info(f"AFL++ harness: {path}")
        return path

    def _generate_compile_commands(self) -> str:
        """Generate a shell script with all compile commands."""
        lib_stem = Path(self.config.target_library).stem.lstrip("lib")
        lib_dir = str(Path(self.config.target_library).parent)
        harness = self.config.harness_name

        san_flags = []
        if self.config.use_asan:
            san_flags.append("address")
        if self.config.use_ubsan:
            san_flags.append("undefined")
        if self.config.use_msan:
            san_flags = ["memory"]  # MSan is mutually exclusive with ASan
        san_str = ",".join(san_flags) if san_flags else ""
        san_flag = f"-fsanitize={san_str}" if san_str else ""

        script = f"""#!/bin/bash
# APEX Auto-Generated Compile Commands
# ─────────────────────────────────────────────────────────

set -e
LIB="{self.config.target_library}"
LIB_DIR="{lib_dir}"
LIB_STEM="{lib_stem}"

echo "[+] Compiling libFuzzer harness..."
clang -g -O1 \\
    {san_flag} \\
    -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div \\
    -fno-omit-frame-pointer \\
    {harness}_libfuzzer.c \\
    -L${{LIB_DIR}} -l${{LIB_STEM}} \\
    -Wl,-rpath,${{LIB_DIR}} \\
    -o {harness}_libfuzzer
echo "[+] libFuzzer binary: {harness}_libfuzzer"

echo "[+] Compiling AFL++ harness..."
AFL_USE_ASAN=1 afl-clang-fast -g -O1 \\
    {harness}_afl.c \\
    -L${{LIB_DIR}} -l${{LIB_STEM}} \\
    -Wl,-rpath,${{LIB_DIR}} \\
    -o {harness}_afl 2>/dev/null || \\
  clang -g -O1 {san_flag} \\
    -fsanitize-coverage=trace-pc-guard \\
    {harness}_afl.c \\
    -L${{LIB_DIR}} -l${{LIB_STEM}} \\
    -o {harness}_afl_san
echo "[+] AFL++ binary: {harness}_afl (or {harness}_afl_san)"

echo ""
echo "Run AFL++:"
echo "  afl-fuzz -i corpus/ -o findings/ -m 256 -- ./{harness}_afl @@"
echo ""
echo "Run libFuzzer:"
echo "  ./{harness}_libfuzzer -max_len=65536 -timeout=5 corpus/"
echo ""
"""
        path = os.path.join(self.config.output_dir, "compile.sh")
        Path(path).write_text(script)
        os.chmod(path, 0o755)
        return path

    def _generate_makefile(self) -> str:
        lib_stem = Path(self.config.target_library).stem.lstrip("lib")
        lib_dir = str(Path(self.config.target_library).parent)
        harness = self.config.harness_name

        makefile = f"""# APEX Auto-Generated Makefile
CC      = clang
CFLAGS  = -g -O1 -fno-omit-frame-pointer
SANFLAGS = -fsanitize=address,undefined
COVFLAGS = -fsanitize-coverage=trace-pc-guard,trace-cmp
LDFLAGS = -L{lib_dir} -l{lib_stem} -Wl,-rpath,{lib_dir}

all: libfuzzer afl

libfuzzer: {harness}_libfuzzer.c
\t$(CC) $(CFLAGS) $(SANFLAGS) $(COVFLAGS) $< $(LDFLAGS) -o $@

afl: {harness}_afl.c
\tAFL_USE_ASAN=1 afl-clang-fast $(CFLAGS) $< $(LDFLAGS) -o $@ || \\
\t$(CC) $(CFLAGS) $(SANFLAGS) $(COVFLAGS) $< $(LDFLAGS) -o $@

clean:
\trm -f libfuzzer afl

run-afl: afl
\tafl-fuzz -i corpus/ -o findings/ -m 256 -- ./afl @@

run-libfuzzer: libfuzzer
\t./libfuzzer -max_len=65536 -timeout=5 corpus/

.PHONY: all clean run-afl run-libfuzzer
"""
        path = os.path.join(self.config.output_dir, "Makefile")
        Path(path).write_text(makefile)
        return path

    def _generate_corpus_minimizer(self) -> str:
        """Generate a corpus minimization script using afl-cmin + afl-tmin."""
        harness = self.config.harness_name
        script = f"""#!/bin/bash
# APEX Corpus Minimization Script
# Removes redundant seeds while keeping all coverage

set -e
INPUT_CORPUS="${{1:-corpus}}"
OUTPUT_CORPUS="${{2:-corpus_min}}"
BINARY="./{harness}_afl"

if [ ! -f "$BINARY" ]; then
    echo "Error: $BINARY not found. Run 'make afl' first."
    exit 1
fi

echo "[+] Step 1: afl-cmin (remove redundant seeds)"
afl-cmin -i "$INPUT_CORPUS" -o "${{OUTPUT_CORPUS}}_tmp" -- "$BINARY" @@ 2>/dev/null || {{
    echo "[!] afl-cmin not available, skipping deduplication"
    cp -r "$INPUT_CORPUS" "${{OUTPUT_CORPUS}}_tmp"
}}

echo "[+] Step 2: afl-tmin (minimize each remaining seed)"
mkdir -p "$OUTPUT_CORPUS"
count=0
for seed in "${{OUTPUT_CORPUS}}_tmp"/*; do
    if [ -f "$seed" ]; then
        fname=$(basename "$seed")
        afl-tmin -i "$seed" -o "$OUTPUT_CORPUS/$fname" -- "$BINARY" @@ 2>/dev/null || \\
            cp "$seed" "$OUTPUT_CORPUS/$fname"
        count=$((count + 1))
        echo "  Minimized $count: $fname ($(wc -c < "$OUTPUT_CORPUS/$fname")b)"
    fi
done

rm -rf "${{OUTPUT_CORPUS}}_tmp"

ORIG=$(ls "$INPUT_CORPUS" | wc -l)
MIN=$(ls "$OUTPUT_CORPUS" | wc -l)
echo ""
echo "[+] Corpus minimized: $ORIG seeds → $MIN seeds"
echo "[+] Output: $OUTPUT_CORPUS/"
"""
        path = os.path.join(self.config.output_dir, "minimize_corpus.sh")
        Path(path).write_text(script)
        os.chmod(path, 0o755)
        return path

    def _build_includes(self) -> str:
        includes = ""
        for h in self.config.header_files:
            includes += f'#include "{h}"\n'
        return includes

    def _build_magic_check(self, magic: str) -> str:
        if not magic:
            return ""
        return f"""    /* Require correct magic bytes to pass initial format validation */
    if (size < MAGIC_LEN || memcmp(data, MAGIC, MAGIC_LEN) != 0) return 0;
"""

    def _build_call_body(self, funcs: List[FunctionSignature],
                          buf_var: str, size_var: str) -> str:
        """Build the C code that calls each discovered function."""
        lines = ["    /* Call target parsing functions */"]

        # Find init + cleanup functions
        init_funcs = [f for f in funcs if f.is_init][:1]
        parser_funcs = [f for f in funcs if f.is_parser][:3]
        cleanup_funcs = [f for f in funcs if f.is_cleanup][:1]

        if init_funcs:
            f = init_funcs[0]
            lines.append(f"    /* Initialize */")
            lines.append(f"    void *ctx = (void*){f.name}();")
            lines.append(f"    if (!ctx) return 0;")
            lines.append("")

        if parser_funcs:
            lines.append("    /* Fuzz parsing functions */")
            for f in parser_funcs:
                params = ", ".join(self._adapt_param(p, buf_var, size_var)
                                   for p in f.params)
                lines.append(f"    {f.name}({params});")
        else:
            # Generic fallback — just call whatever we found
            for f in funcs[:3]:
                params = ", ".join(self._adapt_param(p, buf_var, size_var)
                                   for p in f.params)
                lines.append(f"    {f.name}({params});")

        if cleanup_funcs and init_funcs:
            f = cleanup_funcs[0]
            lines.append(f"    {f.name}(ctx);")

        return "\n".join(f"    {l}" if not l.startswith("    ") else l
                         for l in lines)

    def _adapt_param(self, param: str, buf_var: str, size_var: str) -> str:
        """Map a parameter declaration to a concrete argument."""
        p = param.lower()
        if "uint8" in p or "unsigned char" in p or "char *" in p or "void *" in p:
            return buf_var
        if "size" in p or "len" in p or "count" in p or "num" in p:
            return f"(size_t){size_var}"
        if "int" in p:
            return "0"
        if "file" in p:
            return "NULL"
        return "0"


# ─── CLI Interface ────────────────────────────────────────────────────────────

def run_harness_generator(
    target_library: str,
    header_files: List[str] = None,
    output_dir: str = "./harnesses",
    target_format: str = None,
    use_asan: bool = True,
) -> dict:
    """
    Main entry point for auto harness generation.
    Returns paths to generated files.
    """
    log.info(f"Auto-generating harness for: {target_library}")

    discovery = APIDiscovery()

    # Discover from binary
    functions = discovery.discover_from_binary(target_library)
    log.info(f"Discovered {len(functions)} symbols from binary")

    # Discover from headers if provided
    if header_files:
        header_funcs = discovery.discover_from_headers(header_files)
        # Merge: prefer header sigs (more type info) over binary sigs
        func_names = {f.name for f in functions}
        for hf in header_funcs:
            if hf.name not in func_names:
                functions.append(hf)
        log.info(f"Discovered {len(header_funcs)} symbols from headers")

    # Rank and filter
    functions = discovery.rank_functions(functions)
    parser_funcs = [f for f in functions if f.is_parser or f.is_init]
    if not parser_funcs:
        parser_funcs = functions  # fallback: use all

    log.info(f"Top targets: {[f.name for f in parser_funcs[:5]]}")

    config = HarnessConfig(
        target_library=target_library,
        functions=parser_funcs[:10],
        header_files=header_files or [],
        output_dir=output_dir,
        harness_name=Path(target_library).stem.lstrip("lib"),
        target_format=target_format,
        use_asan=use_asan,
    )

    generator = HarnessGenerator(config)
    return generator.generate_all()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python harness_generator.py <library.so> [headers...] "
              "[--format png] [--output ./harnesses]")
        sys.exit(1)

    lib = sys.argv[1]
    headers = [a for a in sys.argv[2:] if a.endswith(".h")]
    fmt = None
    for i, a in enumerate(sys.argv):
        if a == "--format" and i + 1 < len(sys.argv):
            fmt = sys.argv[i + 1]

    logging.basicConfig(level=logging.INFO)
    outputs = run_harness_generator(lib, headers, target_format=fmt)
    print("\nGenerated files:")
    for k, v in outputs.items():
        print(f"  {k}: {v}")
