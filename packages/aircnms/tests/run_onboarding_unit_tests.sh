#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${TMPDIR:-/tmp}/test_cgw_decrypt
CC=${CC:-cc}
"$CC" -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -o "$OUT" "$ROOT/tests/test_cgw_decrypt.c" \
  "$ROOT/src/managers/cgwd/src/cgw_decrypt.c" -lcrypto
ASAN_OPTIONS=detect_leaks=1 "$OUT"

REG_OUT=${TMPDIR:-/tmp}/test_cgw_registration_result
"$CC" -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -I"$ROOT/src/managers/cgwd/inc" \
  -o "$REG_OUT" "$ROOT/tests/test_cgw_registration_result.c" \
  "$ROOT/src/managers/cgwd/src/cgw_registration_result.c" -ljson-c
ASAN_OPTIONS=detect_leaks=1 "$REG_OUT"

ATTEMPT_OUT=${TMPDIR:-/tmp}/test_cgw_registration_attempt
"$CC" -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -I"$ROOT/src/managers/cgwd/inc" \
  -o "$ATTEMPT_OUT" "$ROOT/tests/test_cgw_registration_attempt.c" \
  "$ROOT/src/managers/cgwd/src/cgw_registration_attempt.c" \
  "$ROOT/src/managers/cgwd/src/cgw_registration_result.c" -ljson-c -lpthread
ASAN_OPTIONS=detect_leaks=1 "$ATTEMPT_OUT"

ROUTE_OUT=${TMPDIR:-/tmp}/test_cgw_topic_route
"$CC" -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -I"$ROOT/src/managers/cgwd/inc" \
  -o "$ROUTE_OUT" "$ROOT/tests/test_cgw_topic_route.c" \
  "$ROOT/src/managers/cgwd/src/cgw_topic_route.c" -ljson-c
ASAN_OPTIONS=detect_leaks=1 "$ROUTE_OUT"

JOB_OUT=${TMPDIR:-/tmp}/test_netconf_job
"$CC" -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -I"$ROOT/src/managers/netconfd/inc" \
  -o "$JOB_OUT" "$ROOT/tests/test_netconf_job.c" \
  "$ROOT/src/managers/netconfd/src/netconf_job.c" -lcrypto -ljson-c
ASAN_OPTIONS=detect_leaks=1 "$JOB_OUT"

ONBD_OUT=${TMPDIR:-/tmp}/test_onbd_state
"$CC" -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -I"$ROOT/src/managers/onbd/inc" \
  -o "$ONBD_OUT" "$ROOT/tests/onbd/test_onbd_state.c" \
  "$ROOT/src/managers/onbd/src/onbd_state.c"
ASAN_OPTIONS=detect_leaks=1 "$ONBD_OUT"
