#!/usr/bin/env bash
# Tests scripts/release/verify-manifest.py against a synthetic release directory:
# the good manifest passes; a digest mismatch, a missing artifact, a size mismatch, an unknown
# manifest version, a tampered bundled helper and an unpinned helper digest are each rejected.
#   scripts/release/test-verify-manifest.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
verifier=$here/verify-manifest.py
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0

sha() { sha256sum "$1" | cut -d' ' -f1; }

# A worker package holding a fake microvm/firecracker, and a cli package.
mkdir -p "$work/src/sentinel-0.0.0-x86_64-linux-worker/microvm" "$work/src/sentinel-0.0.0-x86_64-linux-cli/bin"
printf 'fake firecracker' >"$work/src/sentinel-0.0.0-x86_64-linux-worker/microvm/firecracker"
printf 'fake kernel' >"$work/src/sentinel-0.0.0-x86_64-linux-worker/microvm/vmlinux"
printf 'fake cli' >"$work/src/sentinel-0.0.0-x86_64-linux-cli/bin/sentinel"
base=$work/good
mkdir -p "$base"
(cd "$work/src" && tar -czf "$base/sentinel-0.0.0-x86_64-linux-worker.tar.gz" sentinel-0.0.0-x86_64-linux-worker \
  && tar -czf "$base/sentinel-0.0.0-x86_64-linux-cli.tar.gz" sentinel-0.0.0-x86_64-linux-cli)
fc=$(sha "$work/src/sentinel-0.0.0-x86_64-linux-worker/microvm/firecracker")
kn=$(sha "$work/src/sentinel-0.0.0-x86_64-linux-worker/microvm/vmlinux")
tc=$(printf 'tailcat' | sha256sum | cut -d' ' -f1)
w=sentinel-0.0.0-x86_64-linux-worker.tar.gz
c=sentinel-0.0.0-x86_64-linux-cli.tar.gz
cat >"$base/release-manifest.json" <<EOF
{
  "schema": "sentinel.release/1",
  "version": "0.0.0",
  "commit": "$(printf '%040d' 1)",
  "artifacts": [
    {"file": "$w", "kind": "worker", "os": "linux", "arch": "x86_64", "sha256": "$(sha "$base/$w")", "bytes": $(wc -c <"$base/$w" | tr -d ' ')},
    {"file": "$c", "kind": "cli", "os": "linux", "arch": "x86_64", "sha256": "$(sha "$base/$c")", "bytes": $(wc -c <"$base/$c" | tr -d ' ')}
  ],
  "helpers": [
    {"name": "firecracker", "version": "v0", "arch": "x86_64", "sha256": "$fc", "license": "Apache-2.0", "package": "worker", "path": "microvm/firecracker"},
    {"name": "kernel", "version": "0", "arch": "x86_64", "sha256": "$kn", "license": "GPL-2.0-only", "package": "worker", "path": "microvm/vmlinux"},
    {"name": "tailcat", "version": "v0", "arch": "x86_64", "sha256": "$tc", "license": "BSD-3-Clause"}
  ]
}
EOF
cat >"$work/pins.env" <<EOF
FIRECRACKER_X86_64_SHA256=$fc
KERNEL_SHA256=$kn
TAILCAT_X86_64_SHA256=$tc
EOF

run() { python3 -I "$verifier" "$1/release-manifest.json" --dir "$1" --pins "${2:-$work/pins.env}"; }

expect_pass() {
  if run "$1" "${3:-}" >/dev/null 2>&1; then echo "ok   $2"; else echo "FAIL $2 was rejected"; fails=$((fails + 1)); fi
}
# expect_reject <dir> <name> <message fragment> [pins]
expect_reject() {
  local out
  if out=$(run "$1" "${4:-}" 2>&1); then echo "FAIL $2 was accepted"; fails=$((fails + 1))
  elif printf '%s' "$out" | grep -q -- "$3"; then echo "ok   $2"
  else echo "FAIL $2 was rejected for another reason: $out"; fails=$((fails + 1)); fi
}
variant() { rm -rf "$work/$1"; cp -r "$base" "$work/$1"; }

expect_pass "$base" "a consistent release"

variant digest; printf 'x' >>"$work/digest/$c"
expect_reject "$work/digest" "an archive whose bytes changed" "mismatch\|bytes on disk"

variant missing; rm "$work/missing/$c"
expect_reject "$work/missing" "a missing artifact" "missing from"

variant version
python3 -I -c "
import json,sys
p=sys.argv[1]; m=json.load(open(p)); m['schema']='sentinel.release/2'; json.dump(m,open(p,'w'))
" "$work/version/release-manifest.json"
expect_reject "$work/version" "an unknown manifest version" "unknown manifest version"

variant old
python3 -I -c "
import json,sys
p=sys.argv[1]; m=json.load(open(p)); m['schema']=1; json.dump(m,open(p,'w'))
" "$work/old/release-manifest.json"
expect_reject "$work/old" "the retired numeric schema" "unknown manifest version"

variant helper
python3 -I -c "
import json,sys
p=sys.argv[1]; m=json.load(open(p)); m['helpers'][0]['sha256']='0'*64; json.dump(m,open(p,'w'))
" "$work/helper/release-manifest.json"
expect_reject "$work/helper" "a bundled helper whose digest differs" "has sha256"

variant nomember
python3 -I -c "
import json,sys
p=sys.argv[1]; m=json.load(open(p)); m['helpers'][1]['path']='microvm/nothing'; json.dump(m,open(p,'w'))
" "$work/nomember/release-manifest.json"
expect_reject "$work/nomember" "a helper missing from its package" "missing from"

sed 's/^TAILCAT_X86_64_SHA256=.*/TAILCAT_X86_64_SHA256=deadbeef/' "$work/pins.env" >"$work/pins-other.env"
expect_reject "$base" "a helper digest that is not the pinned one" "is not the pinned" "$work/pins-other.env"

printf '{' >"$work/digest/release-manifest.json"
expect_reject "$work/digest" "an unreadable manifest" "cannot read manifest"

[ $fails = 0 ] || { echo "$fails failed" >&2; exit 1; }
echo "all passed"
