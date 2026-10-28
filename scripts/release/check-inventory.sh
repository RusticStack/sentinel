#!/usr/bin/env bash
# Check the dependency policy and the committed third-party inventory
# (docs/releasing.md#dependency-and-license-inventory).
#
#   scripts/release/check-inventory.sh           fail if THIRD-PARTY-LICENSES.md is stale
#   scripts/release/check-inventory.sh --write   regenerate it
#
# Needs cargo-deny and cargo-about. `cargo licenses` (the lint alias) runs only
# the policy half of this and needs only cargo-deny.
set -euo pipefail

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$root"
write=0
case "${1:-}" in
  --write) write=1 ;;
  "") ;;
  *) echo "usage: check-inventory.sh [--write]" >&2; exit 2 ;;
esac

cargo deny --locked check bans licenses sources
fresh=$(mktemp)
trap 'rm -f "$fresh"' EXIT
cargo about generate --locked --all-features -c about.toml about.hbs -o "$fresh"
if [ $write = 1 ]; then
  cp "$fresh" THIRD-PARTY-LICENSES.md
  echo "wrote THIRD-PARTY-LICENSES.md"
elif ! cmp -s "$fresh" THIRD-PARTY-LICENSES.md; then
  echo "error: THIRD-PARTY-LICENSES.md is out of date with Cargo.lock; run scripts/release/check-inventory.sh --write and commit it" >&2
  exit 1
else
  echo "ok  THIRD-PARTY-LICENSES.md matches Cargo.lock"
fi
