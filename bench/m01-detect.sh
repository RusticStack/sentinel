#!/usr/bin/env bash
# M01: what `sentinel worker --check` states about this host for a worker configuration (docs/microvm.md).
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/sentinel SENTINEL_BENCH_HOST_LABEL=<label> bench/m01-detect.sh [DESCRIPTION=CONFIG_FILE ...] >> bench/m01-detection.jsonl
# One `sentinel-detection/m01/1` line per argument: the description says which configuration it is (for example
# "controller link and [microvm] setup configured"), the file is passed as `worker --check --config FILE`. With no
# argument the check runs once without a configuration. A line carries the build and host stamp of bench/stamp.sh and
# the CPU pressure when it was taken; `benchmark` is false because detection is a statement, not a timing.
# The line comes from the `runtime:` line of the check's own output. A check that fails, or that prints no such line,
# makes this script exit non-zero and print nothing for that configuration: an invented line would be a false record.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=stamp.sh
. "$here/stamp.sh"
stamp_init
bin="${SENTINEL_BIN:?set SENTINEL_BIN to the sentinel binary under test}"
[ "$#" -gt 0 ] || set -- "no controller, no [microvm]="
pressure=$(sed -n 's/^some .*avg10=\([0-9.]*\).*/\1/p' /proc/pressure/cpu 2>/dev/null | head -1 || true)
failed=0
for arg in "$@"; do
  description="${arg%%=*}"; config="${arg#*=}"
  [ "$arg" != "$description" ] || { echo "m01-detect: $arg is not DESCRIPTION=CONFIG_FILE" >&2; exit 2; }
  if [ -n "$config" ]; then cmd=("$bin" worker --check --config "$config"); else cmd=("$bin" worker --check); fi
  if ! text=$("${cmd[@]}" 2>&1); then echo "m01-detect: the check failed for \"$description\"" >&2; failed=1; continue; fi
  DESC="$description" TEXT="$text" PRESSURE="$pressure" BODY="$STAMP_BODY" python3 - <<'PY' || failed=1
import datetime, json, os, re, sys
m = re.search(r"runtime: kvm=(true|false) nested=(true|false) default=(\S+) capabilities=(\S*)", os.environ["TEXT"])
if not m:
    print("m01-detect: the check printed no runtime line for \"%s\"" % os.environ["DESC"], file=sys.stderr)
    sys.exit(1)
rec = {"schema": "sentinel-detection/m01/1", "date": datetime.date.today().isoformat(),
       "command": "sentinel worker --check (%s)" % os.environ["DESC"],
       "kvm": m.group(1) == "true", "nested": m.group(2) == "true", "default": m.group(3),
       "capabilities": [c for c in m.group(4).split(",") if c], "benchmark": False}
if os.environ["PRESSURE"]:
    rec["cpu_pressure_avg10"] = float(os.environ["PRESSURE"])
rec.update(json.loads("{" + os.environ["BODY"] + "}"))
print(json.dumps(rec, separators=(",", ":")))
PY
done
exit "$failed"
