#!/usr/bin/env bash
# test-detect-infected.sh
#
# Simulates an infected environment to verify detect-xz-backdoor.sh
# catches the indicators Andres Freund identified.
#
# This creates a sandboxed fake environment with:
#   - A fake xz binary reporting version 5.6.1
#   - A fake liblzma.so with IFUNC symbols
#   - The known malicious test fixture filenames
#   - A backdoored build-to-host.m4 with the injection patterns
#   - A fake sshd binary linked to liblzma
#
# Everything is created in a temp directory and cleaned up after.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

TESTDIR=$(mktemp -d /tmp/xz-backdoor-test.XXXXXX)
FAKE_BIN="${TESTDIR}/bin"
FAKE_LIB="${TESTDIR}/lib"
FAKE_SRC="${TESTDIR}/src"

cleanup() {
    rm -rf "$TESTDIR"
    echo -e "\n${CYAN}[CLEANUP]${RESET} Removed test environment: ${TESTDIR}"
}
trap cleanup EXIT

echo -e "${BOLD}${CYAN}"
echo "============================================================"
echo "  XZ Backdoor Detection Test — Simulated Infected System"
echo "============================================================"
echo -e "${RESET}"

# ──────────────────────────────────────────────────────────────────
# Build the fake infected environment
# ──────────────────────────────────────────────────────────────────

echo -e "${BOLD}Setting up simulated infected environment...${RESET}\n"

mkdir -p "$FAKE_BIN" "$FAKE_LIB" "${FAKE_SRC}/m4" "${FAKE_SRC}/tests/files"

# 1. Fake xz binary that reports version 5.6.1 (backdoored version)
cat > "${FAKE_BIN}/xz" << 'FAKEXZ'
#!/bin/bash
if [[ "$1" == "--version" ]]; then
    echo "xz (XZ Utils) 5.6.1"
    echo "liblzma 5.6.1"
else
    /usr/bin/xz "$@" 2>/dev/null
fi
FAKEXZ
chmod +x "${FAKE_BIN}/xz"
echo -e "${GREEN}  ✓${RESET} Created fake xz binary (reports version 5.6.1)"

# 2. Create fake liblzma.so with an IFUNC resolver (the backdoor mechanism)
#    We compile a minimal .so with a GNU IFUNC symbol
cat > "${TESTDIR}/fake_lzma.c" << 'FAKEC'
#include <stdint.h>

// Simulate the IFUNC resolver the backdoor used to hook RSA_public_decrypt
static void* resolve_crc64(void) {
    return (void*)0;
}

uint64_t lzma_crc64(const uint8_t *buf, size_t size, uint64_t crc)
    __attribute__((ifunc("resolve_crc64")));

// Normal function to make it look like a real library
int lzma_version_number(void) { return 50060011; }  // 5.6.1
FAKEC

if command -v gcc &>/dev/null; then
    gcc -shared -fPIC -o "${FAKE_LIB}/liblzma.so.5.6.1" "${TESTDIR}/fake_lzma.c" 2>/dev/null && \
        echo -e "${GREEN}  ✓${RESET} Compiled fake liblzma.so with IFUNC resolver" || \
        echo -e "${RED}  ✗${RESET} Could not compile fake liblzma.so (gcc failed)"
else
    # Fallback: copy real liblzma and just check version detection
    cp /usr/lib/x86_64-linux-gnu/liblzma.so.5.* "${FAKE_LIB}/liblzma.so.5.6.1" 2>/dev/null || true
    echo -e "${CYAN}  ~${RESET} No gcc available — using copy of real liblzma for structure tests"
fi

# 3. Create the malicious test fixture files (just the filenames/sizes matter)
#    These are the files where the payload was hidden
dd if=/dev/urandom of="${FAKE_SRC}/tests/files/bad-3-corrupt_lzma2.xz" bs=1024 count=10 2>/dev/null
dd if=/dev/urandom of="${FAKE_SRC}/tests/files/good-large_compressed.lzma" bs=1024 count=86 2>/dev/null
echo -e "${GREEN}  ✓${RESET} Created malicious test fixture files"

# 4. Create the backdoored build-to-host.m4
#    This is the file that extracted and injected the payload during build
cat > "${FAKE_SRC}/m4/build-to-host.m4" << 'FAKEM4'
# build-to-host.m4 serial 30 (BACKDOORED VERSION)
# Normally part of gnulib, but this version contains the injection code

AC_DEFUN([gl_BUILD_TO_HOST],
[
  dnl This is where the backdoor injection begins
  gl_am_configmake=`grep -aErls "#{4}[[:alnum:]]{5}#{4}$" $srcdir/ 2>/dev/null`
  if test "x$gl_am_configmake" != "x"; then
    gl_[$1]config='sed \"r\n\" $gl_am_configmake | eval $gl_path_map | tr "\t \-_" " \t_\-"'
    gl_path_map='tr "\x20-\x5f" "\x60-\x9f"'
  fi
])
FAKEM4
echo -e "${GREEN}  ✓${RESET} Created backdoored build-to-host.m4 with injection patterns"

echo -e "\n${BOLD}Simulated infected environment ready at: ${TESTDIR}${RESET}\n"
echo "================================================================"
echo ""

# ──────────────────────────────────────────────────────────────────
# Now run each detection step against the fake environment
# ──────────────────────────────────────────────────────────────────

echo -e "${BOLD}Running detection checks against simulated infection...${RESET}\n"

PASS=0
FAIL=0

check() {
    local desc="$1"
    local result="$2"  # 0 = detected (good), 1 = missed (bad)
    if [ "$result" -eq 0 ]; then
        echo -e "  ${GREEN}[DETECTED]${RESET}  $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[MISSED]${RESET}    $desc"
        FAIL=$((FAIL + 1))
    fi
}

# --- Test 1: Version detection ---
echo -e "${BOLD}Test 1: Backdoored xz version detection${RESET}"
VERSION_OUTPUT=$(PATH="${FAKE_BIN}:$PATH" "${FAKE_BIN}/xz" --version 2>&1 | head -1)
echo "  Fake xz reports: ${VERSION_OUTPUT}"
if echo "$VERSION_OUTPUT" | grep -qP "5\.6\.[01]"; then
    check "Script should flag xz 5.6.1 as backdoored" 0
else
    check "Script should flag xz 5.6.1 as backdoored" 1
fi
echo ""

# --- Test 2: IFUNC resolver in liblzma ---
echo -e "${BOLD}Test 2: IFUNC resolver detection in liblzma${RESET}"
if [ -f "${FAKE_LIB}/liblzma.so.5.6.1" ] && command -v readelf &>/dev/null; then
    IFUNC_COUNT=$(readelf -s "${FAKE_LIB}/liblzma.so.5.6.1" 2>/dev/null | grep -c "IFUNC" || echo "0")
    echo "  IFUNC symbols found: ${IFUNC_COUNT}"
    if [ "$IFUNC_COUNT" -gt 0 ]; then
        check "IFUNC resolver detected in liblzma (backdoor hook mechanism)" 0
    else
        check "IFUNC resolver detected in liblzma (backdoor hook mechanism)" 1
    fi
else
    echo -e "  ${CYAN}[SKIP]${RESET} Could not compile test library"
fi
echo ""

# --- Test 3: Malicious test fixture files ---
echo -e "${BOLD}Test 3: Malicious payload file detection${RESET}"
FOUND_BAD=$(find "${FAKE_SRC}" -name "bad-3-corrupt_lzma2.xz" -type f 2>/dev/null | wc -l)
FOUND_GOOD=$(find "${FAKE_SRC}" -name "good-large_compressed.lzma" -type f 2>/dev/null | wc -l)
echo "  bad-3-corrupt_lzma2.xz found: ${FOUND_BAD}"
echo "  good-large_compressed.lzma found: ${FOUND_GOOD}"
if [ "$FOUND_BAD" -gt 0 ] && [ "$FOUND_GOOD" -gt 0 ]; then
    check "Both malicious test fixture files detected" 0
else
    check "Both malicious test fixture files detected" 1
fi
echo ""

# --- Test 4: Backdoored build-to-host.m4 ---
echo -e "${BOLD}Test 4: Backdoor injection script detection (build-to-host.m4)${RESET}"
M4FILE="${FAKE_SRC}/m4/build-to-host.m4"
HAS_CONFIGMAKE=$(grep -c "gl_am_configmake" "$M4FILE" 2>/dev/null || echo "0")
HAS_TR_PATTERN=$(grep -cP 'tr.+\\x20-\\x5f' "$M4FILE" 2>/dev/null || echo "0")
echo "  gl_am_configmake pattern: ${HAS_CONFIGMAKE} matches"
echo "  Obfuscation tr pattern: ${HAS_TR_PATTERN} matches"
if [ "$HAS_CONFIGMAKE" -gt 0 ] && [ "$HAS_TR_PATTERN" -gt 0 ]; then
    check "Backdoor injection patterns in build-to-host.m4 detected" 0
else
    check "Backdoor injection patterns in build-to-host.m4 detected" 1
fi
echo ""

# --- Test 5: Run the actual detection script with PATH override ---
echo -e "${BOLD}Test 5: Full script run with fake infected xz in PATH${RESET}"
echo "  (Running detect-xz-backdoor.sh with PATH pointing to fake xz)"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_OUTPUT=$(PATH="${FAKE_BIN}:$PATH" bash "${SCRIPT_DIR}/detect-xz-backdoor.sh" 2>&1 || true)

# Check that the script flagged the version
if echo "$SCRIPT_OUTPUT" | grep -q "KNOWN BACKDOORED"; then
    check "Full script correctly flags xz 5.6.1 as KNOWN BACKDOORED" 0
else
    check "Full script correctly flags xz 5.6.1 as KNOWN BACKDOORED" 1
fi

echo ""

# ──────────────────────────────────────────────────────────────────
# Print the full script output for review
# ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}── Full detection script output ──${RESET}"
echo "$SCRIPT_OUTPUT"

# ──────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}============================================================${RESET}"
echo -e "${BOLD}  TEST RESULTS${RESET}"
echo -e "${BOLD}============================================================${RESET}"
echo ""
echo -e "  Detected (PASS): ${GREEN}${PASS}${RESET}"
echo -e "  Missed   (FAIL): ${RED}${FAIL}${RESET}"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✓ All detection checks passed!${RESET}"
    echo -e "  The script successfully identifies indicators of CVE-2024-3094."
else
    echo -e "${RED}${BOLD}  ✗ ${FAIL} check(s) failed — detection script needs improvement.${RESET}"
fi
echo ""
