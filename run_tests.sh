#!/usr/bin/env bash
#
# run_tests.sh -- iterate every test executable produced by
# itb_tests.gpr and report pass / fail counts in Go-test style.
#
# Each test binary is a standalone main procedure; exit code 0 = pass,
# non-zero = fail. The build system stitches one .gpr Main entry per
# tests/test_*.adb source file, so the executables live as
# obj-tests/test_*. This harness filters that glob to ELF binaries
# only (gprbuild leaves auxiliary .ali / .o / .bexch / .stderr /
# .stdout files in the same directory).
#
# Per-process isolation gives every test a fresh libitb global state;
# tests that mutate process-global config (Set_Bit_Soup / Set_Lock_Soup
# / Set_Max_Workers / Set_Nonce_Bits / Set_Barrier_Fill) save and
# restore at procedure boundaries. No shared mutex helper needed --
# the natural process boundary is the serialisation.
#
# Usage:
#   ./run_tests.sh              -- runs every test
#   ./run_tests.sh test_blake3  -- runs a single test by base name
#
# Returns 0 if every executed test passed, non-zero otherwise.

set -u

cd "$(dirname "$0")"

OBJ_DIR="obj-tests"
if [ ! -d "$OBJ_DIR" ]; then
    echo "error: $OBJ_DIR/ not found -- run 'alr exec -- gprbuild -P itb_tests.gpr' first" >&2
    exit 2
fi

# Filter: ELF binaries only (skip .ali / .o / .bexch / .stderr / .stdout).
is_elf() {
    [ -x "$1" ] && [ -f "$1" ] && \
        file -b "$1" 2>/dev/null | grep -q '^ELF '
}

# Optional substring filter from arg 1.
FILTER="${1:-}"

PASS=0
FAIL=0
FAILED=()
START=$(date +%s)

for bin in "$OBJ_DIR"/test_*; do
    is_elf "$bin" || continue
    name=$(basename "$bin")
    if [ -n "$FILTER" ] && [ "$name" != "$FILTER" ]; then
        continue
    fi
    printf '%-32s ' "$name"
    log=$(mktemp)
    if "./$bin" >"$log" 2>&1; then
        printf 'PASS\n'
        PASS=$((PASS + 1))
        rm -f "$log"
    else
        rc=$?
        printf 'FAIL exit=%d\n' "$rc"
        FAIL=$((FAIL + 1))
        FAILED+=("$name")
        echo "  --- $name output ---"
        sed 's/^/  /' "$log"
        echo "  --- end ---"
        rm -f "$log"
    fi
done

END=$(date +%s)
ELAPSED=$((END - START))

echo
echo "ran $((PASS + FAIL)) tests in ${ELAPSED}s -- $PASS PASS, $FAIL FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "failed:"
    for t in "${FAILED[@]}"; do
        echo "  $t"
    done
    exit 1
fi
exit 0
