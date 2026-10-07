#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Ada binding:
# builds the utility with its own gprbuild project (a no-op when it is
# up to date; libitb3.so and the binding library are assumed built by
# build.sh) and execs it with every argument passed through.
#
# The build output is captured rather than discarded: gprbuild reports
# progress on stdout and the cosmetic ".sframe" linker notice on
# stderr, and either would otherwise join the utility's own output.
# Nothing is printed unless the build fails, in which case everything
# it said is, minus that notice.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

set +e
build_output="$(alr exec -- gprbuild -P itb_loop.gpr 2>&1)"
build_status=$?
set -e

if [ "$build_status" -ne 0 ]; then
    printf '%s\n' "$build_output" \
        | grep -vE 'Scrt1\.o.*\.sframe|\.sframe.*Scrt1\.o' >&2
    exit 1
fi

exec ./loop/loop "$@"
