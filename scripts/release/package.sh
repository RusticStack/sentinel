#!/usr/bin/env bash
# Build and package a Sentinel release for this host's architecture, or verify
# one that was built (docs/deployment.md).
#
#   scripts/release/package.sh build  [--out DIR] [--allow-dirty] [--skip-agent]
#   scripts/release/package.sh assemble [--out DIR]
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
#   release-manifest.json                               machine-readable digests (docs/releasing.md)
#
# Run it once on an x86_64 host and once on an arm64 host: each packages the
# architecture it builds on. The agent needs the <arch>-unknown-linux-musl
# standard library (`rustup target add`); --skip-agent leaves it out.
#
# The Windows CLI is built by scripts/release/package.ps1 on a Windows host
# (sentinel-<version>-x86_64-windows-cli.zip). Copy the archives of every host
# into one directory and run `assemble` in the checkout of the release commit:
# it rewrites SHA256SUMS and release-manifest.json over everything in there.
#
# The tarballs are deterministic for a given set of binaries (sorted entries,
# the commit's timestamp, root ownership, `gzip -n`); the binaries themselves
# are not claimed to be bit-for-bit reproducible.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

mode=${1:-}
[ -n "$mode" ] && shift
if [ "$mode" = build ]; then
  [ "$(uname -s)" = Linux ] || die "the Linux packages are built on Linux (the Windows CLI: scripts/release/package.ps1)"
fi
case "$(uname -m)" in
  x86_64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) [ "$mode" = build ] && die "unsupported architecture $(uname -m)"; arch=$(uname -m) ;;
esac

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
    server) echo "bin/sentinel BUILD-INFO LICENSE THIRD-PARTY-LICENSES.md examples/server.toml examples/sentinel-server.service examples/sentinel-web.service" ;;
    worker) echo "bin/sentinel BUILD-INFO LICENSE THIRD-PARTY-LICENSES.md examples/worker.toml examples/sentinel-worker.service" ;;
    cli) echo "bin/sentinel BUILD-INFO LICENSE THIRD-PARTY-LICENSES.md" ;;
    agent) echo "bin/sentinel-agent BUILD-INFO LICENSE THIRD-PARTY-LICENSES.md" ;;
  esac
}
archive_name() {
  if [ "$1" = agent ]; then echo "sentinel-agent-$version-$arch-linux-musl"
  else echo "sentinel-$version-$arch-linux-$1"; fi
}

# assemble: SHA256SUMS and release-manifest.json over every release archive in $out.
assemble() {
  [ -d "$out" ] || die "$out does not exist"
  local commit file base rest first=1 sha bytes kind os a
  commit=$(git -C "$root" rev-parse HEAD)
  (cd "$out" && ls -1 | grep -E '^sentinel(-agent)?-.*\.(tar\.gz|zip)$' | LC_ALL=C sort | xargs sha256sum -- >SHA256SUMS) \
    || die "no release archives in $out"
  {
    printf '{\n  "schema": 1,\n  "version": "%s",\n  "commit": "%s",\n  "artifacts": [' "$version" "$commit"
    while read -r sha file; do
      file=${file#\*}
      base=${file%.tar.gz}; base=${base%.zip}
      case "$base" in
        sentinel-agent-"$version"-*) rest=${base#sentinel-agent-"$version"-}; kind=agent ;;
        sentinel-"$version"-*) rest=${base#sentinel-"$version"-}; kind=${rest##*-} ;;
        *) die "$file does not carry version $version" ;;
      esac
      a=${rest%%-*}; os=${rest#*-}; os=${os%%-*}
      bytes=$(wc -c <"$out/$file" | tr -d ' ')
      [ $first = 1 ] || printf ','
      first=0
      printf '\n    {"file": "%s", "kind": "%s", "os": "%s", "arch": "%s", "sha256": "%s", "bytes": %s}' \
        "$file" "$kind" "$os" "$a" "$sha" "$bytes"
    done <"$out/SHA256SUMS"
    printf '\n  ]\n}\n'
  } >"$out/release-manifest.json"
  echo "wrote SHA256SUMS and release-manifest.json in $out"
}

# listing <archive>: the entry names of a .tar.gz or .zip, one per line.
listing() {
  case "$1" in
    *.tar.gz) tar -tzf "$1" ;;
    *.zip) if command -v unzip >/dev/null; then unzip -Z1 "$1"; else tar -tf "$1"; fi ;;
  esac
}
# member <archive> <entry>: print one entry's content.
member() {
  case "$1" in
    *.tar.gz) tar -xzOf "$1" "$2" ;;
    *.zip) if command -v unzip >/dev/null; then unzip -p "$1" "$2"; else tar -xOf "$1" "$2"; fi ;;
  esac
}

verify() {
  [ -f "$out/SHA256SUMS" ] || die "$out/SHA256SUMS does not exist; run build or assemble first"
  [ -f "$out/release-manifest.json" ] || die "$out/release-manifest.json does not exist; run build or assemble first"
  (cd "$out" && sha256sum --check --strict SHA256SUMS) || die "checksum verification failed"
  local scratch status=0 kind name entry top sha file manifest_commit info
  manifest_commit=$(sed -n 's/^  "commit": "\(.*\)",$/\1/p' "$out/release-manifest.json")
  # Every archive in SHA256SUMS has the same digest in the manifest, and the reverse.
  while read -r sha file; do
    file=${file#\*}
    grep -q "\"file\": \"$file\".*\"sha256\": \"$sha\"" "$out/release-manifest.json" \
      || { echo "error: $file: release-manifest.json disagrees with SHA256SUMS" >&2; status=1; }
  done <"$out/SHA256SUMS"
  [ "$(grep -c '"file":' "$out/release-manifest.json")" = "$(wc -l <"$out/SHA256SUMS" | tr -d ' ')" ] \
    || { echo "error: release-manifest.json and SHA256SUMS list different numbers of archives" >&2; status=1; }
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' RETURN
  for kind in server worker cli agent; do
    name=$(archive_name $kind)
    [ -f "$out/$name.tar.gz" ] || { [ "$kind" = agent ] && [ $skip_agent = 1 ] && continue; die "$name.tar.gz is not in $out"; }
    grep -q " \*\?$name.tar.gz\$" "$out/SHA256SUMS" || die "$name.tar.gz is not listed in SHA256SUMS"
    tar -xzf "$out/$name.tar.gz" -C "$scratch"
    top=$scratch/$name
    for entry in $(expected $kind); do
      [ -f "$top/$entry" ] || { echo "error: $name.tar.gz lacks $entry" >&2; status=1; }
    done
    grep -q "^commit: $manifest_commit\$" "$top/BUILD-INFO" \
      || { echo "error: $name.tar.gz was not built from the manifest's commit" >&2; status=1; }
    if [ $kind = agent ]; then
      if readelf -lW "$top/bin/sentinel-agent" | grep -q INTERP; then
        echo "error: $name is not statically linked" >&2; status=1
      fi
    else
      "$top/bin/sentinel" --version >/dev/null || { echo "error: $name: bin/sentinel does not run" >&2; status=1; }
    fi
    echo "ok  $name.tar.gz"
  done
  # Windows CLI archives from package.ps1: checked by content only; they cannot run here.
  for file in "$out"/sentinel-"$version"-*-windows-cli.zip; do
    [ -f "$file" ] || continue
    name=$(basename "$file" .zip)
    for entry in bin/sentinel.exe BUILD-INFO LICENSE THIRD-PARTY-LICENSES.md; do
      listing "$file" | grep -qx "$name/$entry" || { echo "error: $name.zip lacks $entry" >&2; status=1; }
    done
    info=$(member "$file" "$name/BUILD-INFO" | tr -d '\r')
    printf '%s\n' "$info" | grep -q "^commit: $manifest_commit\$" \
      || { echo "error: $name.zip was not built from the manifest's commit" >&2; status=1; }
    echo "ok  $name.zip"
  done
  return $status
}

case "$mode" in
  verify) verify; exit ;;
  assemble) assemble; exit ;;
  build) ;;
  *) die "usage: package.sh build|assemble|verify [--out DIR] [--allow-dirty] [--skip-agent]" ;;
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
  install -m 0644 THIRD-PARTY-LICENSES.md "$top/THIRD-PARTY-LICENSES.md"
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
package worker "$target_dir/release/sentinel" examples/worker.toml examples/sentinel-worker.service
cargo build --locked --release -p sentinel
package cli "$target_dir/release/sentinel"
if [ $skip_agent = 0 ]; then
  triple=$arch-unknown-linux-musl
  cargo build --locked --release -p sentinel-agent --target "$triple"
  package agent "$target_dir/$triple/release/sentinel-agent"
fi

assemble
verify
echo "release packages and SHA256SUMS are in $out"
