#!/usr/bin/env bash
#
# run_tests.sh -- test runner for the Ada binding. Invokes build.sh so
# the driver under test is always a product of this invocation, then
# runs it; the driver reports PASS / FAIL per test and exits non-zero on
# any failure. An optional positional argument filters by exact test
# name:
#
#   ./run_tests.sh              # runs every test
#   ./run_tests.sh smoke        # runs a single test by name
#
# ITB_SKIP_CLEAN=1 is honoured by build.sh for fast iteration.

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

DRIVER="obj-tests/test_driver"
if [ ! -x "$DRIVER" ]; then
    echo "error: $DRIVER not produced by ./build.sh" >&2
    exit 2
fi

exec "./$DRIVER" "$@"
