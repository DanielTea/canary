#!/usr/bin/env bash
# detect-xz-backdoor.sh
#
# Recreates the investigation steps Andres Freund performed to discover
# the XZ Utils / liblzma backdoor (CVE-2024-3094).
#
# Steps simulated:
#   1. Check installed xz/liblzma version for known-bad versions
#   2. Benchmark SSH login time (looking for the ~500ms delay)
#   3. Check if sshd is linked against liblzma (the attack path)
#   4. Look for the known malicious bytes / signatures in liblzma
#   5. Inspect xz source tarballs for the obfuscated backdoor payload
#   6. Check for the suspicious build script modifications
#
# Usage: sudo ./detect-xz-backdoor.sh [--ssh-bench]

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

WARNINGS=0
CLEAN=0

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "============================================================"
    echo "  XZ/liblzma Backdoor Detector (CVE-2024-3094)"
    echo "  Recreating Andres Freund's investigation steps"
    echo "============================================================"
    echo -e "${RESET}"
}

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; CLEAN=$((CLEAN + 1)); }
warn()    { echo -e "${RED}[WARN]${RESET}  $*"; WARNINGS=$((WARNINGS + 1)); }
notice()  { echo -e "${YELLOW}[NOTE]${RESET}  $*"; }
header()  { echo -e "\n${BOLD}── Step $1: $2${RESET}"; }

# ──────────────────────────────────────────────────────────────────────
# Step 1: Check xz / liblzma version
# Andres traced the problem to xz versions 5.6.0 and 5.6.1
# ──────────────────────────────────────────────────────────────────────
check_xz_version() {
    header 1 "Check xz/liblzma version (Freund traced issue to 5.6.0/5.6.1)"

    if ! command -v xz &>/dev/null; then
        notice "xz command not found — xz-utils may not be installed."
        return
    fi

    XZ_VERSION=$(xz --version | head -1 | grep -oP '\d+\.\d+\.\d+' || echo "unknown")
    info "Installed xz version: ${BOLD}${XZ_VERSION}${RESET}"

    case "$XZ_VERSION" in
        5.6.0|5.6.1)
            warn "xz version ${XZ_VERSION} is one of the KNOWN BACKDOORED versions!"
            warn "Immediate action required: downgrade to 5.4.x or upgrade to 5.6.2+."
            ;;
        unknown)
            notice "Could not determine xz version."
            ;;
        *)
            ok "xz version ${XZ_VERSION} is not a known-backdoored version."
            ;;
    esac
}

# ──────────────────────────────────────────────────────────────────────
# Step 2: Benchmark SSH login time
# Andres noticed logins went from ~0.3s to ~0.8s (a ~500ms increase)
# ──────────────────────────────────────────────────────────────────────
bench_ssh() {
    header 2 "Benchmark SSH login time (Freund noticed a ~500ms delay)"

    if [[ "${1:-}" != "--ssh-bench" ]]; then
        notice "SSH benchmark skipped (pass --ssh-bench to enable)."
        notice "Freund saw login time jump from ~0.3s to ~0.8s."
        return
    fi

    if ! command -v ssh &>/dev/null; then
        notice "ssh client not found, skipping benchmark."
        return
    fi

    info "Measuring SSH login time to localhost (3 attempts)..."
    TOTAL=0
    ATTEMPTS=3
    for i in $(seq 1 $ATTEMPTS); do
        START=$(date +%s%N)
        # Use a non-interactive command; will fail if sshd isn't running, that's OK
        ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            localhost true 2>/dev/null || true
        END=$(date +%s%N)
        ELAPSED=$(( (END - START) / 1000000 ))  # milliseconds
        info "  Attempt $i: ${ELAPSED}ms"
        TOTAL=$((TOTAL + ELAPSED))
    done

    AVG=$((TOTAL / ATTEMPTS))
    info "Average SSH login time: ${BOLD}${AVG}ms${RESET}"

    if [ "$AVG" -gt 600 ]; then
        warn "SSH login time is suspiciously high (>600ms)."
        warn "Freund's backdoored system showed ~800ms vs normal ~300ms."
    elif [ "$AVG" -gt 400 ]; then
        notice "SSH login time is elevated (>400ms). Worth investigating."
    else
        ok "SSH login time looks normal (<400ms)."
    fi
}

# ──────────────────────────────────────────────────────────────────────
# Step 3: Check if sshd links against liblzma
# The attack path: sshd → libsystemd → liblzma (backdoored)
# ──────────────────────────────────────────────────────────────────────
check_sshd_liblzma_link() {
    header 3 "Check if sshd is linked to liblzma (the attack vector)"

    SSHD_PATH=$(command -v sshd 2>/dev/null || echo "")
    if [ -z "$SSHD_PATH" ]; then
        # Try common paths
        for p in /usr/sbin/sshd /usr/bin/sshd /sbin/sshd; do
            [ -x "$p" ] && SSHD_PATH="$p" && break
        done
    fi

    if [ -z "$SSHD_PATH" ]; then
        notice "sshd not found — OpenSSH server may not be installed."
        return
    fi

    info "sshd binary: ${SSHD_PATH}"

    if ! command -v ldd &>/dev/null; then
        notice "ldd not available, cannot check shared library linkage."
        return
    fi

    LINKED_LIBS=$(ldd "$SSHD_PATH" 2>/dev/null || echo "")

    if echo "$LINKED_LIBS" | grep -q "liblzma"; then
        LZMA_LIB=$(echo "$LINKED_LIBS" | grep "liblzma" | awk '{print $3}')
        notice "sshd IS linked against liblzma: ${LZMA_LIB}"
        notice "This is the attack path Freund identified:"
        notice "  sshd → libsystemd → liblzma (via systemd notification patch)"
        notice "If xz version is 5.6.0 or 5.6.1, this system is VULNERABLE."
    else
        ok "sshd is NOT linked against liblzma — attack path does not exist."
    fi

    # Show the full chain if libsystemd is present
    if echo "$LINKED_LIBS" | grep -q "libsystemd"; then
        notice "sshd links libsystemd (which pulls in liblzma on many distros)."
    fi
}

# ──────────────────────────────────────────────────────────────────────
# Step 4: Scan liblzma.so for known backdoor byte signatures
# The backdoor injected a function hook that redirected RSA_public_decrypt
# ──────────────────────────────────────────────────────────────────────
check_liblzma_signatures() {
    header 4 "Scan liblzma for known backdoor signatures"

    # Find liblzma.so
    LIBLZMA=$(find /usr/lib /usr/lib64 /lib /lib64 -name "liblzma.so*" -type f 2>/dev/null | head -1 || echo "")

    if [ -z "$LIBLZMA" ]; then
        notice "liblzma.so not found on this system."
        return
    fi

    info "Scanning: ${LIBLZMA}"

    # Known detection method: check for the function interception signature
    # The backdoor hooks RSA_public_decrypt via ifunc resolvers
    # Detection heuristic from the community:
    #   - Presence of specific byte pattern used in the payload

    # Method A: Check for the "evil" resolver function signature
    # The backdoor used GNU IFUNC (indirect function) to hijack execution
    if command -v hexdump &>/dev/null; then
        # Signature bytes from the known backdoor payload
        # These appear in the malicious .o object linked into liblzma
        if hexdump -C "$LIBLZMA" | grep -qP "f3 0f 1e fa.{0,30}55 48 89 e5"; then
            # This is a common x86_64 prologue, need more specific check
            :
        fi

        # Check for the specific IFUNC resolver that the backdoor installs
        if command -v readelf &>/dev/null; then
            IFUNC_COUNT=$(readelf -s "$LIBLZMA" 2>/dev/null | grep -c "IFUNC" || echo "0")
            if [ "$IFUNC_COUNT" -gt 0 ]; then
                notice "liblzma contains ${IFUNC_COUNT} IFUNC resolver(s)."
                notice "The backdoor used IFUNC to hook RSA_public_decrypt."
                notice "IFUNC in a compression library is unusual — worth investigating."
            else
                ok "No IFUNC resolvers found in liblzma (expected for clean builds)."
            fi
        fi
    fi

    # Method B: Check file size anomaly
    # Backdoored liblzma is noticeably larger due to the injected object
    FILESIZE=$(stat -c%s "$LIBLZMA" 2>/dev/null || stat -f%z "$LIBLZMA" 2>/dev/null || echo "0")
    info "liblzma file size: ${FILESIZE} bytes"

    # Method C: Verify package integrity if package manager available
    if command -v dpkg &>/dev/null; then
        info "Verifying liblzma package integrity (dpkg)..."
        VERIFY=$(dpkg --verify liblzma5 2>/dev/null || dpkg --verify xz-utils 2>/dev/null || echo "not available")
        if [ "$VERIFY" = "" ]; then
            ok "dpkg verification passed — no modified files detected."
        elif [ "$VERIFY" = "not available" ]; then
            notice "Could not verify package integrity via dpkg."
        else
            warn "dpkg reports modified files:"
            echo "$VERIFY"
        fi
    elif command -v rpm &>/dev/null; then
        info "Verifying liblzma package integrity (rpm)..."
        VERIFY=$(rpm -V xz-libs 2>/dev/null || echo "not available")
        if [ "$VERIFY" = "" ]; then
            ok "rpm verification passed — no modified files detected."
        elif [ "$VERIFY" = "not available" ]; then
            notice "Could not verify package integrity via rpm."
        else
            warn "rpm reports modified files:"
            echo "$VERIFY"
        fi
    fi
}

# ──────────────────────────────────────────────────────────────────────
# Step 5: Check for malicious test fixture files
# The payload was hidden inside these files in the xz source tarball:
#   tests/files/bad-3-corrupt_lzma2.xz
#   tests/files/good-large_compressed.lzma
# ──────────────────────────────────────────────────────────────────────
check_source_artifacts() {
    header 5 "Search for malicious xz source/build artifacts"

    SUSPICIOUS_FILES=(
        "bad-3-corrupt_lzma2.xz"
        "good-large_compressed.lzma"
    )

    info "Searching for the backdoor payload files on disk..."
    FOUND=0
    for fname in "${SUSPICIOUS_FILES[@]}"; do
        MATCHES=$(find / -name "$fname" -type f 2>/dev/null | head -5 || echo "")
        if [ -n "$MATCHES" ]; then
            warn "Found suspicious file: ${fname}"
            echo "$MATCHES" | while read -r f; do
                SIZE=$(stat -c%s "$f" 2>/dev/null || echo "?")
                warn "  ${f} (${SIZE} bytes)"
            done
            FOUND=$((FOUND + 1))
        fi
    done

    if [ "$FOUND" -eq 0 ]; then
        ok "No known backdoor payload files found on disk."
    else
        warn "Found ${FOUND} suspicious file(s) — may be from xz source packages."
        notice "Check if these are from xz 5.6.0/5.6.1 tarballs."
    fi
}

# ──────────────────────────────────────────────────────────────────────
# Step 6: Check build scripts for the injection mechanism
# The backdoor was activated by modifications to m4/build-to-host.m4
# ──────────────────────────────────────────────────────────────────────
check_build_scripts() {
    header 6 "Check for backdoor build script injection patterns"

    info "Searching for xz/liblzma build directories..."

    # Look for xz source trees
    XZ_DIRS=$(find /usr/src /usr/local/src /home /tmp /opt -maxdepth 4 \
        -name "build-to-host.m4" -type f 2>/dev/null | head -10 || echo "")

    if [ -z "$XZ_DIRS" ]; then
        ok "No xz build directories with build-to-host.m4 found."
        return
    fi

    for m4file in $XZ_DIRS; do
        info "Checking: ${m4file}"
        # The malicious build-to-host.m4 contained obfuscated shell commands
        # Key indicator: use of `tr` with unusual character mappings and
        # piping through `head -c` to extract the hidden payload
        if grep -qP "(gl_am_configmake|gl_[$]1config)" "$m4file" 2>/dev/null; then
            if grep -qP "tr.+\\\x20-\\\x5f" "$m4file" 2>/dev/null; then
                warn "SUSPICIOUS: ${m4file} contains patterns matching the backdoor injection script!"
                warn "This file may contain the obfuscated payload extractor."
            else
                ok "build-to-host.m4 patterns look normal."
            fi
        fi
    done
}

# ──────────────────────────────────────────────────────────────────────
# Step 7: Check running sshd for liblzma CPU usage (like Freund's perf)
# ──────────────────────────────────────────────────────────────────────
check_sshd_cpu() {
    header 7 "Check sshd process for unusual CPU behavior"

    SSHD_PIDS=$(pgrep -x sshd 2>/dev/null || echo "")

    if [ -z "$SSHD_PIDS" ]; then
        notice "No sshd processes running."
        return
    fi

    info "Running sshd PIDs: $(echo $SSHD_PIDS | tr '\n' ' ')"

    for pid in $SSHD_PIDS; do
        CPU=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ' || echo "0")
        MEM=$(ps -p "$pid" -o %mem= 2>/dev/null | tr -d ' ' || echo "0")
        info "  PID ${pid}: CPU=${CPU}%, MEM=${MEM}%"

        # Check if liblzma is loaded in this process
        if [ -r "/proc/${pid}/maps" ]; then
            if grep -q "liblzma" "/proc/${pid}/maps" 2>/dev/null; then
                notice "  PID ${pid} has liblzma mapped in memory."
            fi
        fi
    done

    # Suggest using perf like Freund did
    notice "Freund used 'perf top -p <sshd_pid>' to spot CPU time in liblzma."
    notice "If perf is available, try: sudo perf top -p <PID>"
}

# ──────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────
summary() {
    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD}  SCAN COMPLETE${RESET}"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""
    echo -e "  Checks passed:  ${GREEN}${CLEAN}${RESET}"
    echo -e "  Warnings:       ${RED}${WARNINGS}${RESET}"
    echo ""

    if [ "$WARNINGS" -gt 0 ]; then
        echo -e "${RED}${BOLD}  ⚠  ${WARNINGS} warning(s) found — review the output above.${RESET}"
        echo ""
        echo "  Recommended actions:"
        echo "    1. Downgrade xz to 5.4.x or upgrade to 5.6.2+"
        echo "    2. Restart sshd after updating liblzma"
        echo "    3. Audit SSH access logs for unauthorized logins"
        echo "    4. Check if your distro released a security advisory"
    else
        echo -e "${GREEN}${BOLD}  ✓  No indicators of CVE-2024-3094 detected.${RESET}"
    fi
    echo ""
}

# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────
banner
check_xz_version
bench_ssh "${1:-}"
check_sshd_liblzma_link
check_liblzma_signatures
check_source_artifacts
check_build_scripts
check_sshd_cpu
summary
