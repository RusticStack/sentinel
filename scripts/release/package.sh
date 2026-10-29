#!/usr/bin/env bash
# Build and package a Sentinel release for this host's architecture, or verify
# one that was built (docs/deployment.md).
#
#   scripts/release/package.sh build  [--out DIR] [--allow-dirty] [--skip-agent] [--skip-microvm] [--assets DIR]
#   scripts/release/package.sh fetch-assets [--assets DIR]
#   scripts/release/package.sh assemble [--out DIR]
#   scripts/release/package.sh verify [--out DIR] [--skip-agent] [--skip-microvm]
#
# `build` runs `cargo build --locked --release` for each package from the
# checkout it is in and writes, for <arch> in x86_64|aarch64:
#
#   sentinel-<version>-<arch>-linux-server.tar.gz       sentinel with the server role
#   sentinel-<version>-<arch>-linux-worker.tar.gz       sentinel with the worker role
#   sentinel-<version>-<arch>-linux-cli.tar.gz          sentinel with default features
#   sentinel-agent-<version>-<arch>-linux-musl.tar.gz   the static microVM guest agent
#   SHA256SUMS
#   release-manifest.json                               sentinel.release/1: digests and pinned helpers (docs/releasing.md)
#
# Run it once on an x86_64 host and once on an arm64 host: each packages the
# architecture it builds on. The agent needs the <arch>-unknown-linux-musl
# standard library (`rustup target add`); --skip-agent leaves it out.
#
# The x86_64 worker package also carries microvm/: the pinned Firecracker, the guest kernel and the
# static agent (docs/releasing.md#microvm-assets). Their pinned digests are in scripts/release/pins.env.
# The inputs are in --assets DIR (default <target dir>/release-assets): `fetch-assets` downloads
# Firecracker and checks it against the pin; the kernel is built once by bench/microvm/build-kernel.sh,
# whose vmlinux-<version>, .config and .build files go in the same directory. --skip-microvm builds an
# x86_64 worker without them (development).
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
skip_microvm=0
assets=
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out=${2:?--out needs a directory}; shift 2 ;;
    --allow-dirty) allow_dirty=1; shift ;;
    --skip-agent) skip_agent=1; shift ;;
    --skip-microvm) skip_microvm=1; shift ;;
    --assets) assets=${2:?--assets needs a directory}; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
target_dir=${CARGO_TARGET_DIR:-$root/target}
out=${out:-$target_dir/dist}
assets=${assets:-$target_dir/release-assets}
# shellcheck source=pins.env
. "$root/scripts/release/pins.env"
# The x86_64 worker carries the microVM files unless told otherwise (they need the agent).
with_microvm=0
[ "$arch" = x86_64 ] && [ $skip_agent = 0 ] && [ $skip_microvm = 0 ] && with_microvm=1

version=$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' "$root/Cargo.toml")
[ -n "$version" ] || die "no workspace version in Cargo.toml"

# Entries a package must contain, as paths relative to the archive's top directory.
expected() {
  case "$1" in
    server) echo "bin/sentinel BUILD-INFO LICENSE THIRD-PARTY-LICENSES.md examples/server.toml examples/sentinel-server.service examples/sentinel-web.service examples/server-container.toml examples/Containerfile.server examples/compose.server.yaml examples/sentinel.nginx.conf examples/Caddyfile examples/sentinel-server.container examples/sentinel-data.volume" ;;
    worker)
      echo "bin/sentinel BUILD-INFO LICENSE THIRD-PARTY-LICENSES.md examples/worker.toml examples/sentinel-worker.service examples/Containerfile.worker examples/compose.worker.yaml"
      if [ $with_microvm = 1 ]; then echo "microvm/firecracker microvm/vmlinux microvm/vmlinux.config microvm/vmlinux.build microvm/sentinel-agent microvm/install.sh microvm/build-kernel.sh microvm/SOURCES.md microvm/SHA256SUMS microvm/licenses/firecracker-LICENSE microvm/licenses/firecracker-NOTICE microvm/licenses/firecracker-THIRD-PARTY"; fi
      ;;
    cli) echo "bin/sentinel BUILD-INFO LICENSE THIRD-PARTY-LICENSES.md" ;;
    agent) echo "bin/sentinel-agent BUILD-INFO LICENSE THIRD-PARTY-LICENSES.md" ;;
  esac
}
archive_name() {
  if [ "$1" = agent ]; then echo "sentinel-agent-$version-$arch-linux-musl"
  else echo "sentinel-$version-$arch-linux-$1"; fi
}

# helper <name> <version> <arch> <sha256> <license> <source> [<archive sha256> <package> <path in package>]:
# one entry of the manifest's helpers array. A helper with a package is inside that package
# (verify-manifest.py hashes it there); one without is only named, for an installer to download and check.
helper_sep=
helper() {
  printf '%s\n    {"name": "%s", "version": "%s", "arch": "%s", "sha256": "%s", "license": "%s", "source": "%s"' \
    "$helper_sep" "$1" "$2" "$3" "$4" "$5" "$6"
  [ -z "${7:-}" ] || printf ', "archive_sha256": "%s"' "$7"
  [ -z "${8:-}" ] || printf ', "package": "%s", "path": "%s"' "$8" "$9"
  printf '}'
  helper_sep=,
}
# helpers_json: Tailcat is always named; Firecracker and the kernel only when the x86_64 worker in $out carries them.
helpers_json() {
  local worker=$out/$(archive_name worker).tar.gz
  helper_sep=
  if [ "$arch" = x86_64 ] && [ -f "$worker" ] && [ -n "$(tar -tzf "$worker" | grep '/microvm/firecracker$')" ]; then
    helper firecracker "$FIRECRACKER_VERSION" x86_64 "$FIRECRACKER_X86_64_SHA256" Apache-2.0 \
      "https://github.com/firecracker-microvm/firecracker/releases/tag/$FIRECRACKER_VERSION" \
      "$FIRECRACKER_X86_64_TGZ_SHA256" worker microvm/firecracker
    helper kernel "$KERNEL_VERSION" x86_64 "$KERNEL_SHA256" GPL-2.0-only \
      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz" \
      "" worker microvm/vmlinux
  fi
  helper tailcat "$TAILCAT_VERSION" x86_64 "$TAILCAT_X86_64_SHA256" BSD-3-Clause \
    "https://github.com/tailscale/tailcat/releases/tag/$TAILCAT_VERSION" "$TAILCAT_X86_64_TGZ_SHA256"
  helper tailcat "$TAILCAT_VERSION" aarch64 "$TAILCAT_AARCH64_SHA256" BSD-3-Clause \
    "https://github.com/tailscale/tailcat/releases/tag/$TAILCAT_VERSION" "$TAILCAT_AARCH64_TGZ_SHA256"
}

# assemble: SHA256SUMS and release-manifest.json over every release archive in $out.
assemble() {
  [ -d "$out" ] || die "$out does not exist"
  local commit file base rest first=1 sha bytes kind os a
  commit=$(git -C "$root" rev-parse HEAD)
  (cd "$out" && ls -1 | grep -E '^sentinel(-agent)?-.*\.(tar\.gz|zip)$' | LC_ALL=C sort | xargs sha256sum -- >SHA256SUMS) \
    || die "no release archives in $out"
  {
    printf '{\n  "schema": "sentinel.release/1",\n  "version": "%s",\n  "commit": "%s",\n  "artifacts": [' "$version" "$commit"
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
    printf '\n  ],\n  "helpers": ['
    helpers_json
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

# check_digest <file> <expected sha256> <what>: die unless the file has the pinned digest.
check_digest() {
  local actual
  [ -n "$2" ] || die "$3 has no digest in scripts/release/pins.env"
  actual=$(sha256sum "$1" | cut -d' ' -f1)
  [ "$actual" = "$2" ] || die "$3: sha256 is $actual, pinned $2 ($1)"
}

# fetch-assets: download the pinned Firecracker release archive into $assets and check it.
fetch_assets() {
  local name=firecracker-$FIRECRACKER_VERSION-x86_64.tgz
  mkdir -p "$assets"
  curl -fsSL -o "$assets/$name.part" "https://github.com/firecracker-microvm/firecracker/releases/download/$FIRECRACKER_VERSION/$name" \
    || die "cannot download $name"
  check_digest "$assets/$name.part" "$FIRECRACKER_X86_64_TGZ_SHA256" "$name"
  mv "$assets/$name.part" "$assets/$name"
  echo "fetched $name into $assets; the kernel comes from bench/microvm/build-kernel.sh (docs/releasing.md#microvm-assets)"
}

# stage_microvm <top> <agent binary>: add microvm/ to the x86_64 worker package under <top>.
stage_microvm() {
  local top=$1 agent=$2 tgz kernel unpack fc f
  tgz=$assets/firecracker-$FIRECRACKER_VERSION-x86_64.tgz
  kernel=$assets/vmlinux-$KERNEL_VERSION
  for f in "$tgz" "$kernel" "$kernel.config" "$kernel.build"; do
    [ -f "$f" ] || die "$f is missing; run package.sh fetch-assets and bench/microvm/build-kernel.sh (docs/releasing.md#microvm-assets), or pass --skip-microvm"
  done
  check_digest "$tgz" "$FIRECRACKER_X86_64_TGZ_SHA256" "the Firecracker archive"
  check_digest "$kernel" "$KERNEL_SHA256" "the guest kernel"
  check_digest "$kernel.config" "$KERNEL_CONFIG_SHA256" "the guest kernel configuration"
  unpack=$stage/firecracker-unpacked
  mkdir -p "$unpack"
  tar -xzf "$tgz" -C "$unpack"
  fc=$unpack/release-$FIRECRACKER_VERSION-x86_64
  check_digest "$fc/firecracker-$FIRECRACKER_VERSION-x86_64" "$FIRECRACKER_X86_64_SHA256" "the Firecracker executable"
  mkdir -p "$top/microvm/licenses"
  install -m 0755 "$fc/firecracker-$FIRECRACKER_VERSION-x86_64" "$top/microvm/firecracker"
  install -m 0644 "$kernel" "$top/microvm/vmlinux"
  install -m 0644 "$kernel.config" "$top/microvm/vmlinux.config"
  install -m 0644 "$kernel.build" "$top/microvm/vmlinux.build"
  install -m 0755 "$agent" "$top/microvm/sentinel-agent"
  install -m 0755 scripts/release/microvm-install.sh "$top/microvm/install.sh"
  install -m 0755 bench/microvm/build-kernel.sh "$top/microvm/build-kernel.sh"
  install -m 0644 scripts/release/microvm-SOURCES.md "$top/microvm/SOURCES.md"
  for f in LICENSE NOTICE THIRD-PARTY; do
    install -m 0644 "$fc/$f" "$top/microvm/licenses/firecracker-$f"
  done
  (cd "$top/microvm" && sha256sum firecracker vmlinux vmlinux.config sentinel-agent >SHA256SUMS && chmod 0644 SHA256SUMS)
  rm -rf "$unpack"
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
  python3 -I "$root/scripts/release/verify-manifest.py" "$out/release-manifest.json" --dir "$out" --pins "$root/scripts/release/pins.env" \
    || status=1
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
    if [ $kind = worker ] && [ $with_microvm = 1 ]; then
      (cd "$top/microvm" && sha256sum --check --strict --quiet SHA256SUMS) \
        || { echo "error: $name.tar.gz: microvm/SHA256SUMS does not match its files" >&2; status=1; }
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
  fetch-assets) fetch_assets; exit ;;
  build) ;;
  *) die "usage: package.sh build|fetch-assets|assemble|verify [options; see the top of this file]" ;;
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
  if [ "$kind" = worker ] && [ $with_microvm = 1 ]; then stage_microvm "$top" "$agent_binary"; fi
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

agent_binary=
if [ $skip_agent = 0 ]; then
  triple=$arch-unknown-linux-musl
  cargo build --locked --release -p sentinel-agent --target "$triple"
  agent_binary=$target_dir/$triple/release/sentinel-agent
fi
cargo build --locked --release -p sentinel --features server
package server "$target_dir/release/sentinel" examples/server.toml examples/sentinel-server.service examples/sentinel-web.service \
  examples/server-container.toml examples/Containerfile.server examples/compose.server.yaml examples/sentinel.nginx.conf examples/Caddyfile examples/sentinel-server.container examples/sentinel-data.volume
cargo build --locked --release -p sentinel --features worker
package worker "$target_dir/release/sentinel" examples/worker.toml examples/sentinel-worker.service \
  examples/Containerfile.worker examples/compose.worker.yaml
cargo build --locked --release -p sentinel
package cli "$target_dir/release/sentinel"
if [ $skip_agent = 0 ]; then
  package agent "$agent_binary"
fi

assemble
verify
echo "release packages and SHA256SUMS are in $out"
