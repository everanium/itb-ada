#!/usr/bin/env bash
#
# run_tests.sh -- test runner for the Ada binding. Runs the driver
# built by itb_tests.gpr (see build.sh); the driver reports PASS /
# FAIL per test and exits non-zero on any failure. An optional
# positional argument filters by exact test name:
#
#   ./run_tests.sh              # runs every test
#   ./run_tests.sh smoke        # runs a single test by name

set -eu
set -o pipefail

cd "$(dirname "$0")"

DRIVER="obj-tests/test_driver"
if [ ! -x "$DRIVER" ]; then
    echo "error: $DRIVER not found -- run ./build.sh first" >&2
    exit 2
fi

exec "./$DRIVER" "$@"
