#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${TMPDIR:-/tmp}/aircnms-test-onbd-state
${CC:-cc} -std=c99 -Wall -Wextra -Werror \
    -I"$ROOT/src/managers/onbd/inc" \
    "$ROOT/tests/onbd/test_onbd_state.c" \
    "$ROOT/src/managers/onbd/src/onbd_state.c" \
    -o "$OUT"
"$OUT"
rm -f "$OUT"
echo "PASS: air-onbd state tests"
