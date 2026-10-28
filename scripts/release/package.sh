#!/usr/bin/env bash
# Build and package a Sentinel release for this host's architecture, or verify
# one that was built (docs/deployment.md).
#
#   scripts/release/package.sh build  [--out DIR] [--allow-dirty] [--skip-agent]
#   scripts/release/package.sh verify [--out DIR]
#
# `build` runs `cargo build --locked --release` for each package from the
# checkout it is in and writes, for <arch> in x86_64|aarch64:
#
#   sentinel-<version>-<arch>-linux-server.tar.gz       sentinel with the server role
#   sentinel-<version>-<arch>-linux-worker.tar.gz       sentinel with the worker role
#   sentinel-<version>-<arch>-linux-cli.tar.gz          sentinel with default features
#   sentinel-agent-<version>-<arch>-linux-musl.tar.gz   the static microVM guest agent
#   SHA256SUMS
#
# Run it once on an x86_64 host and once on an arm64 host: each packages the
# architecture it builds on. The agent needs the <arch>-unknown-linux-musl
# standard library (`rustup target add`); --skip-agent leaves it out.
#
# The tarballs are deterministic for a given set of binaries (sorted entries,
# the commit's timestamp, root ownership, `gzip -n`); the binaries themselves
# are not claimed to be bit-for-bit reproducible.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "release packages are built on Linux"
case "$(uname -m)" in
  x86_64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

mode=${1:-}
[ -n "$mode" ] && shift
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
out=
allow_dirty=0
skip_agent=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out=${2:?--out needs a directory}; shift 2 ;;
    --allow-dirty) allow_dirty=1; shift ;;
    --skip-agent) skip_agent=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
target_dir=${CARGO_TARGET_DIR:-$root/target}
out=${out:-$target_dir/dist}

version=$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' "$root/Cargo.toml")
[ -n "$version" ] || die "no workspace version in Cargo.toml"

# Entries a package must contain, as paths relative to the archive's top directory.
expected() {
  case "$1" in
    server) echo "bin/sentinel BUILD-INFO LICENSE examples/server.toml examples/sentinel-server.service examples/sentinel-web.service" ;;
    worker) echo "bin/sentinel BUILD-INFO LICENSE examples/worker.toml" ;;
    cli) echo "bin/sentinel BUILD-INFO LICENSE" ;;
    agent) echo "bin/sentinel-agent BUILD-INFO LICENSE" ;;
  esac
}
archive_name() {
  if [ "$1" = agent ]; then echo "sentinel-agent-$version-$arch-linux-musl"
  else echo "sentinel-$version-$arch-linux-$1"; fi
}

verify() {
  [ -f "$out/SHA256SUMS" ] || die "$out/SHA256SUMS does not exist; run build first"
  (cd "$out" && sha256sum --check --strict SHA256SUMS) || die "checksum verification failed"
  local scratch status=0 kind name entry top
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' RETURN
  for kind in server worker cli agent; do
    name=$(archive_name $kind)
    [ -f "$out/$name.tar.gz" ] || { [ "$kind" = agent ] && [ $skip_agent = 1 ] && continue; die "$name.tar.gz is not in $out"; }
    grep -q " $name.tar.gz\$" "$out/SHA256SUMS" || die "$name.tar.gz is not listed in SHA256SUMS"
    tar -xzf "$out/$name.tar.gz" -C "$scratch"
    top=$scratch/$name
    for entry in $(expected $kind); do
      [ -f "$top/$entry" ] || { echo "error: $name.tar.gz lacks $entry" >&2; status=1; }
    done
    if [ $kind = agent ]; then
      if readelf -lW "$top/bin/sentinel-agent" | grep -q INTERP; then
        echo "error: $name is not statically linked" >&2; status=1
      fi
    else
      "$top/bin/sentinel" --version >/dev/null || { echo "error: $name: bin/sentinel does not run" >&2; status=1; }
    fi
    echo "ok  $name.tar.gz"
  done
  return $status
}

case "$mode" in
  verify) verify; exit ;;
  build) ;;
  *) die "usage: package.sh build|verify [--out DIR] [--allow-dirty] [--skip-agent]" ;;
esac

cd "$root"
commit=$(git rev-parse HEAD)
if [ $allow_dirty = 0 ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  die "the working tree has uncommitted changes; commit them, or pass --allow-dirty for a development package"
fi
dirty=false
[ -n "$(git status --porcelain --untracked-files=no)" ] && dirty=true
epoch=$(git log -1 --format=%ct)

rm -rf "$out"
mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# package <kind> <binary file> <extra file>...: stage and archive one package.
package() {
  local kind=$1 binary=$2 name top
  shift 2
  name=$(archive_name "$kind")
  top=$stage/$name
  mkdir -p "$top/bin"
  install -m 0755 "$binary" "$top/bin/"
  install -m 0644 LICENSE "$top/LICENSE"
  for file in "$@"; do
    mkdir -p "$top/examples"
    install -m 0644 "$file" "$top/examples/"
  done
  {
    echo "package: $kind"
    echo "version: $version"
    echo "commit: $commit"
    echo "dirty: $dirty"
    echo "arch: $arch"
    echo "rustc: $(rustc --version)"
  } >"$top/BUILD-INFO"
  chmod 0644 "$top/BUILD-INFO"
  (cd "$stage" && find "$name" -type d -exec chmod 0755 {} + \
    && tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -cf - "$name" \
      | gzip -n -9 >"$out/$name.tar.gz")
  echo "packaged $name.tar.gz"
}

cargo build --locked --release -p sentinel --features server
package server "$target_dir/release/sentinel" examples/server.toml examples/sentinel-server.service examples/sentinel-web.service
cargo build --locked --release -p sentinel --features worker
package worker "$target_dir/release/sentinel" examples/worker.toml
cargo build --locked --release -p sentinel
package cli "$target_dir/release/sentinel"
if [ $skip_agent = 0 ]; then
  triple=$arch-unknown-linux-musl
  cargo build --locked --release -p sentinel-agent --target "$triple"
  package agent "$target_dir/$triple/release/sentinel-agent"
fi

(cd "$out" && sha256sum -- *.tar.gz >SHA256SUMS)
verify
echo "release packages and SHA256SUMS are in $out"
