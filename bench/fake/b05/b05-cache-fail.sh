#!/usr/bin/env bash
# Stand-in for the B05 cache driver used by the matrix tests. It runs the real driver (FAKE_REAL_BIN) and adds:
#   FAKE_FAIL_SHAPE=<shape>   exit 1 for that cell without running it (the cell wrapper once swallowed the status)
#   FAKE_TRACE=<file>         append "<shape> start|end <monotonic ns>" so a test can check that cells never overlap
#   FAKE_ORPHAN=1             leave a background sleep behind (its pid goes to FAKE_PIDS), to prove the lock is not inherited
#   BIN=bench/fake/b05/b05-cache-fail.sh FAKE_REAL_BIN=<real driver> bench/b05-cache.sh --profile smoke ...
shape=
prev=
for a in "$@"; do [ "$prev" = --shape ] && shape="$a"; prev="$a"; done
now() { python3 -c 'import time; print(time.monotonic_ns())'; }
trace() { [ -n "${FAKE_TRACE:-}" ] && printf '%s %s %s\n' "$shape" "$1" "$(now)" >> "$FAKE_TRACE"; return 0; }
if [ -n "${FAKE_FAIL_SHAPE:-}" ] && [ "$shape" = "$FAKE_FAIL_SHAPE" ]; then
  echo "b05-cache-fail: failing the $shape cell on request" >&2
  exit 1
fi
if [ -n "${FAKE_ORPHAN:-}" ]; then sleep 30 >/dev/null 2>&1 & echo $! >> "${FAKE_PIDS:-/dev/null}"; fi
trace start
"${FAKE_REAL_BIN:?set FAKE_REAL_BIN to the real driver}" "$@"
rc=$?
trace end
exit $rc
