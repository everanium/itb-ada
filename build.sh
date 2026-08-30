#!/usr/bin/env bash
#
# build.sh -- one-step build for the Ada binding: libitb.so + gprbuild
# on the library, test, bench, and eitb projects. Prerequisites (Go,
# Alire with a selected gnat_native + gprbuild toolchain) must be
# installed separately; see README.md "Prerequisites" section.
#
# Usage:
#   ./build.sh                      # libitb.so + all four projects
#   ./build.sh --noitbasm           # ditto, with ITB asm off
#   ./build.sh --skip-libitb        # skip the Go libitb.so step
#
# A wrapper around `alr exec -- gprbuild` that filters the cosmetic
# ".sframe" linker notice emitted when the Alire-bundled binutils
# meets a system glibc Scrt1.o whose .sframe section is in an older
# format; the binary is produced correctly regardless.

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

SKIP_LIBITB=0
TAGS=()

while [ "${1:-}" != "" ]; do
    case "$1" in
        --noitbasm)    TAGS=(-tags=noitbasm); shift;;
        --skip-libitb) SKIP_LIBITB=1; shift;;
        -h|--help)     sed -n '4,16p' "$0"; exit 0;;
        *)             echo "unknown option: $1" >&2; exit 2;;
    esac
done

if [ "$SKIP_LIBITB" -eq 0 ]; then
    cd "$REPO_ROOT"
    echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
    go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
        -o dist/linux-amd64/libitb.so ./cmd/cshared
    cd "$REPO_ROOT/bindings/ada"
fi

# Merge stdout + stderr into one stream and filter through grep -v to
# strip the cosmetic .sframe notice; PIPESTATUS[0] preserves
# gprbuild's exit code through the pipe.
gpr() {
    echo "==> gprbuild -P $1"
    alr exec -- gprbuild -P "$1" 2>&1 \
        | grep -vE 'Scrt1\.o.*\.sframe|\.sframe.*Scrt1\.o' || true
    return "${PIPESTATUS[0]}"
}

gpr itb.gpr
gpr itb_tests.gpr
gpr itb_bench.gpr
gpr itb_eitb.gpr

echo "==> ready: ./run_tests.sh"
