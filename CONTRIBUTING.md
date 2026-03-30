# Contributing to APEX Fuzzer

Thank you for your interest in contributing. APEX is a security research tool — contributions that improve coverage quality, add new targets, or strengthen crash analysis are especially welcome.

---

## Ways to Contribute

### Good first issues

These are well-scoped and don't require deep knowledge of the whole codebase:

- **Add a file format mutator** — pick any format (PDF, JPEG, MP4, BMP, FLAC) and implement a `FORMAT_MUTATORS` entry in `modules/fileparser/file_fuzzer.py` following the pattern of `PNGMutator` or `ZIPMutator`
- **Add a network protocol grammar** — implement a `generate() -> bytes` class and register it in `PROTOCOL_GRAMMARS` in `modules/network/network_fuzzer.py`
- **Write integration tests** — any test in `tests/` that spawns a simple target binary and verifies APEX detects a crash is valuable
- **Improve crash deduplication** — better stack trace normalization, better ASAN output parsing
- **Documentation** — usage examples, a tutorial, architecture diagrams

### Larger contributions

- Additional target modules (browser DOM fuzzing, gRPC, WASM)
- Real AFL++ SHM integration (replace pseudo-coverage with actual bitmap reads)
- Snapshot fuzzing via Nyx integration
- Distributed mode (corpus sync across machines)

---

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/apex-fuzzer.git
cd apex-fuzzer

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Verify everything parses
python3 -c "import ast, os; [ast.parse(open(os.path.join(r,f)).read()) for r,d,fs in os.walk('.') for f in fs if f.endswith('.py')]"
echo "All files valid"
```

---

## Code Style

- **Python 3.9+** — no walrus operator (`3.8` compat), no `match` statements (`3.10`)
- **Type hints** on all public functions and class methods
- **Docstrings** on every module, class, and public function
- **Logging** via `logging.getLogger("apex.<module>")` — never `print()` in library code
- **No external runtime dependencies** beyond what's in `requirements.txt`
- Line length: 100 characters

```python
# Good
async def execute(self, data: bytes) -> ExecutionResult:
    """Execute the target binary with fuzz input and return result."""
    log = logging.getLogger("apex.fileparser")
    ...

# Bad
def execute(self, data):
    print("running target")
    ...
```

---

## Pull Request Process

1. **Fork** the repo and create a branch: `git checkout -b feat/my-new-mutator`
2. **Write your code** following the style guide above
3. **Test it** — at minimum run `python3 apex.py --dry-run --mode fileparser --target-binary /bin/ls`
4. **Update docs** — add your format/protocol to the README table if applicable
5. **Open a PR** with a clear description of what you changed and why

PR title format:
- `feat: add PDF structure-aware mutator`
- `fix: correct CmpLog SHM read on big-endian systems`
- `docs: add tutorial for kernel fuzzing setup`

---

## Reporting Bugs

Use the [bug report issue template](.github/ISSUE_TEMPLATE/bug_report.md). Include:

- OS and kernel version
- Python version (`python3 --version`)
- Exact command you ran
- Full error output or traceback
- What you expected vs what happened

---

## Security Issues

If you find a security vulnerability in APEX itself (not in a target you're fuzzing), please **do not open a public issue**. Email the maintainers directly. We'll coordinate a fix and credit you in the release notes.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
