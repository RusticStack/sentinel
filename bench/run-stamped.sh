#!/usr/bin/env bash
# Example caller: names the build under test once and hands it to a harness.
#   bench/run-stamped.sh /path/to/sentinel-checkout /path/to/sentinel-binary b03 ROOT OUT [args...]
#   bench/run-stamped.sh /path/to/sentinel-checkout /path/to/sentinel-binary k02
# SENTINEL_SRC is the checkout the binary was built from, SENTINEL_BIN the binary itself (hashed into the record).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SENTINEL_SRC="$1" SENTINEL_BIN="$2" harness="$3"; shift 3
case "$harness" in
  b03) exec python3 "$here/b03-latency.py" "$@" --source "$SENTINEL_SRC" --binary "$SENTINEL_BIN" ;;
  b02) exec "$here/b02-sentinel.sh" "$@" ;;
  k02) exec "$here/k02-cache-clone.sh" "$@" ;;
  f07) exec "$here/f07-storage.sh" "$@" ;;
  *) echo "unknown harness $harness (b03, b02, k02, f07)" >&2; exit 2 ;;
esac
