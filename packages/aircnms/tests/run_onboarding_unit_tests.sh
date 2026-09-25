#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${TMPDIR:-/tmp}/test_cgw_decrypt
CC=${CC:-cc}
"$CC" -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -o "$OUT" "$ROOT/tests/test_cgw_decrypt.c" \
  "$ROOT/src/managers/cgwd/src/cgw_decrypt.c" -lcrypto
ASAN_OPTIONS=detect_leaks=1 "$OUT"
