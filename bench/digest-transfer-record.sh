#!/usr/bin/env bash
# Digest-first transfer samples from a host whose kernel exposes no CPU pressure (no /proc/pressure/cpu), where
# bench/micro-run.sh refuses a measured run because it cannot prove a quiet start. The bench runs directly, the
# build and host are stamped by bench/stamp.sh, and each sample is appended in the harness's own envelope
# (build, host, contract, ordering, conditions) to bench/digest-transfer.jsonl.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/digest-transfer-bench \
#     SENTINEL_BENCH_HOST_LABEL=<label> bench/digest-transfer-record.sh
# FILES, FILE_BYTES and ROUNDS override the frozen arguments; OUT overrides the record file.
# On a verification host the canonical path stays bench/micro-run.sh bench/contracts/micro/digest-transfer.json.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${SENTINEL_SRC:?set SENTINEL_SRC to the checkout the measured build came from}"
: "${SENTINEL_BIN:?set SENTINEL_BIN to the digest-transfer-bench binary}"
: "${SENTINEL_BENCH_HOST_LABEL:?set SENTINEL_BENCH_HOST_LABEL to an anonymized host label}"
out="${OUT:-$here/digest-transfer.jsonl}"
samples="$(mktemp "${TMPDIR:-/tmp}/digest-transfer.XXXXXX")"
trap 'rm -f "$samples"' EXIT
stamp="$(bash "$here/stamp.sh")"
start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
"$SENTINEL_BIN" --files "${FILES:-48}" --file-bytes "${FILE_BYTES:-262144}" --rounds "${ROUNDS:-5}" > "$samples"
end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$stamp" "$start" "$end" "$samples" "$out" "$here/contracts/micro/digest-transfer.json" <<'PY'
import hashlib, json, sys
stamp, start, end, samples, out, contract = sys.argv[1:]
with open(contract, "rb") as f:
    sha = hashlib.sha256(f.read()).hexdigest()
stamp = json.loads(stamp)
envelope = {
    "build": stamp["build"],
    "host": stamp["host"],
    "contract": {"id": "digest-transfer", "revision": 1, "sha256": sha},
    "ordering": {"scheme": "abba", "seed": None},
    "conditions": {"start": start, "end": end},
}
lines = []
with open(samples) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if record.get("schema") != "sentinel-bench/digest-transfer/1":
            raise SystemExit(f"unexpected record {record.get('schema')!r}")
        record.update(envelope)
        lines.append(json.dumps(record, separators=(",", ":")))
with open(out, "a") as f:
    for line in lines:
        f.write(line + "\n")
print(f"{len(lines)} samples appended to {out}")
PY
