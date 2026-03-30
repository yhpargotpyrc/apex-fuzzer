#!/bin/bash
# ============================================================
# APEX Fuzzer - Full Installation Script
# Installs all dependencies for state-of-the-art fuzzing
# Run as: bash install.sh
# ============================================================

set -e
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }
section() { echo -e "\n${GREEN}══ $1 ══${NC}"; }

# ─── System Check ──────────────────────────────────────────
section "System Check"
if [[ "$EUID" -eq 0 ]]; then
    warn "Running as root — some features may behave differently"
fi
OS=$(uname -s)
info "OS: $OS $(uname -r)"
info "CPU cores: $(nproc)"
info "RAM: $(free -h | awk '/^Mem:/{print $2}')"

# ─── Core System Packages ──────────────────────────────────
section "System Packages"
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y \
        build-essential clang llvm lld \
        gcc-multilib g++-multilib \
        python3 python3-pip python3-dev \
        git wget curl \
        qemu-user qemu-user-static \
        qemu-system-arm qemu-system-mips qemu-system-x86 \
        gdb gdb-multiarch \
        binwalk \
        radamsa \
        valgrind \
        libc6-dev \
        linux-headers-$(uname -r) 2>/dev/null || warn "linux-headers not available"
    info "System packages installed"
else
    warn "apt-get not found — install dependencies manually"
fi

# ─── AFL++ ─────────────────────────────────────────────────
section "AFL++"
if ! command -v afl-fuzz &>/dev/null; then
    info "Building AFL++ from source..."
    git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus.git /tmp/aflplusplus 2>/dev/null || true
    cd /tmp/aflplusplus
    make distrib -j$(nproc)
    sudo make install
    cd -
    info "AFL++ installed"
else
    info "AFL++ already installed: $(afl-fuzz --version 2>&1 | head -1)"
fi

# ─── LLVM/Clang Sanitizer Toolchain ────────────────────────
section "LLVM Sanitizer Toolchain"
if ! command -v clang-15 &>/dev/null && ! command -v clang &>/dev/null; then
    warn "clang not found — install LLVM 15+ for sanitizer support"
    warn "Ubuntu: sudo apt install clang-15 llvm-15"
else
    CLANG=$(command -v clang-15 || command -v clang)
    info "Clang: $CLANG ($($CLANG --version | head -1))"
fi

# ─── Python Dependencies ───────────────────────────────────
section "Python Dependencies"
pip3 install --break-system-packages --quiet \
    frida frida-tools \
    scikit-learn numpy \
    sysv_ipc \
    angr \
    websockets \
    psutil \
    2>/dev/null && info "Python packages installed" || warn "Some Python packages failed — check individually"

# Core required packages
pip3 install --break-system-packages --quiet \
    scikit-learn numpy psutil || warn "Core ML packages failed"

# ─── Syzkaller (optional, for kernel fuzzing) ──────────────
section "Syzkaller (Kernel Fuzzing)"
if ! command -v go &>/dev/null; then
    warn "Go not installed — syzkaller unavailable"
    warn "Install Go: https://go.dev/dl/ then run: go install github.com/google/syzkaller/..."
else
    info "Go available: $(go version)"
    info "To install syzkaller: git clone https://github.com/google/syzkaller && make"
fi

# ─── Frida ─────────────────────────────────────────────────
section "Frida"
if python3 -c "import frida" 2>/dev/null; then
    info "Frida available: $(python3 -c 'import frida; print(frida.__version__)')"
else
    warn "Frida not available — binary coverage collection disabled"
    warn "Install: pip3 install frida frida-tools"
fi

# ─── angr (Symbolic Execution) ─────────────────────────────
section "angr (Symbolic Execution)"
if python3 -c "import angr" 2>/dev/null; then
    info "angr available"
else
    warn "angr not available — symbolic execution disabled"
    warn "Install: pip3 install angr (may take a while)"
fi

# ─── Create Corpus Directories ─────────────────────────────
section "Corpus Setup"
mkdir -p corpus/http corpus/dns corpus/mqtt corpus/modbus
mkdir -p corpus/png corpus/zip corpus/elf corpus/pdf
mkdir -p crashes minimized reports

# Minimal seed files
printf 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n' > corpus/http/seed_01.bin
printf '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01' > corpus/dns/seed_01.bin
printf '\x10\x00\x00\x04MQTT\x04\xc2\x00\x3c\x00\x00' > corpus/mqtt/seed_01.bin
printf '\x89PNG\r\n\x1a\n' > corpus/png/seed_01.bin
printf 'PK\x03\x04' > corpus/zip/seed_01.bin
printf '\x7fELF' > corpus/elf/seed_01.bin
info "Corpus seeds created"

# ─── Kernel Fuzzing Prerequisites ──────────────────────────
section "Kernel Fuzzing"
if [ -f /sys/kernel/debug/kcov ]; then
    info "KCOV available — kernel coverage collection enabled"
else
    warn "KCOV not available (/sys/kernel/debug/kcov not found)"
    warn "For kernel fuzzing with coverage, recompile kernel with:"
    warn "  CONFIG_KCOV=y"
    warn "  CONFIG_KASAN=y"
    warn "  CONFIG_KASAN_INLINE=y"
    warn "  CONFIG_DEBUG_FS=y"
fi

# ─── Summary ───────────────────────────────────────────────
section "Installation Summary"
echo ""
echo "  Core fuzzer:       READY"
echo -n "  AFL++:             "; command -v afl-fuzz &>/dev/null && echo "✓ installed" || echo "✗ not found"
echo -n "  QEMU user-mode:    "; command -v qemu-arm &>/dev/null && echo "✓ installed" || echo "✗ not found"
echo -n "  radamsa:           "; command -v radamsa &>/dev/null && echo "✓ installed" || echo "✗ not found"
echo -n "  Frida:             "; python3 -c "import frida" 2>/dev/null && echo "✓ installed" || echo "✗ not installed"
echo -n "  angr (symex):      "; python3 -c "import angr" 2>/dev/null && echo "✓ installed" || echo "✗ not installed"
echo -n "  scikit-learn (ML): "; python3 -c "import sklearn" 2>/dev/null && echo "✓ installed" || echo "✗ not installed"
echo -n "  KCOV:              "; [ -f /sys/kernel/debug/kcov ] && echo "✓ available" || echo "✗ not available"
echo ""
echo "  Usage:"
echo "    python3 apex.py --mode fileparser --target-binary ./target --format png --source --asan"
echo "    python3 apex.py --mode network --target-binary ./server --protocol http --source"
echo "    python3 apex.py --mode kernel --syscall-groups net,fs"
echo "    python3 apex.py --mode firmware --firmware-image ./fw.bin --arch mips"
echo ""
echo "  Full campaign with dashboard:"
echo "    python3 apex.py --mode fileparser --target-binary ./target --format png \\"
echo "      --source --asan --cmplog --ml-mutator --workers 8 --dashboard"
echo ""
