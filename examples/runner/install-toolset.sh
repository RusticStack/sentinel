#!/usr/bin/env bash
# Lay the pinned toolset (toolset.tsv) into the tool cache the setup actions resolve from
# (docs/runner-images.md). Runs as root while the Ubuntu 24.04 runner image builds.
#
#   install-toolset.sh <toolset.tsv> <x64|arm64>
#
# Every archive is checked against the checksum its row states before anything is unpacked, and a
# tool with no row for this architecture fails the build: an image never carries less than the
# published subset says it does.
set -euo pipefail

manifest=${1:?usage: install-toolset.sh <toolset.tsv> <x64|arm64>}
arch=${2:?usage: install-toolset.sh <toolset.tsv> <x64|arm64>}
cache=${RUNNER_TOOL_CACHE:?RUNNER_TOOL_CACHE is not set}
home=/home/runner
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # url checksum -> path of the checked download
  local url=$1 sum=$2 out="$work/${1##*/}"
  curl -fsSL --retry 3 -o "$out" "$url"
  case ${#sum} in
    64) echo "$sum  $out" | sha256sum --strict --check --status - ;;
    128) echo "$sum  $out" | sha512sum --strict --check --status - ;;
    *) false ;;
  esac || {
    echo "install-toolset: $url does not match its pinned checksum" >&2
    exit 1
  }
  printf '%s\n' "$out"
}

# The layout `@actions/tool-cache` finds: <cache>/<name>/<version>/<arch>, with a marker beside it.
slot() { # name version -> directory
  local dir="$cache/$1/$2/$arch"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}
complete() { touch "$1.complete"; }

env_arch=$(printf '%s' "$arch" | tr '[:lower:]' '[:upper:]')
: > "$home/.env"
installed=0

while IFS=$'\t' read -r tool version os row_arch sum url; do
  case $tool in '' | '#'*) continue ;; esac
  [ "$os" = linux ] && [ "$row_arch" = "$arch" ] || continue
  echo "install-toolset: $tool $version" >&2
  case $tool in
    node)
      dir=$(slot node "$version")
      tar -xJf "$(fetch "$url" "$sum")" -C "$dir" --strip-components=1 --no-same-owner
      complete "$dir"
      ;;
    go)
      dir=$(slot go "$version")
      tar -xzf "$(fetch "$url" "$sum")" -C "$dir" --strip-components=1 --no-same-owner
      complete "$dir"
      minor=${version%.*}
      echo "GOROOT_${minor/./_}_${env_arch}=$dir" >> "$home/.env"
      ;;
    python)
      # The archive is actions/python-versions' own and installs itself into the tool cache.
      mkdir "$work/python"
      tar -xzf "$(fetch "$url" "$sum")" -C "$work/python" --no-same-owner
      (cd "$work/python" && bash ./setup.sh >&2)
      rm -rf "$work/python"
      ;;
    temurin)
      dir=$(slot Java_Temurin-Hotspot_jdk "${version//+/-}")
      tar -xzf "$(fetch "$url" "$sum")" -C "$dir" --strip-components=1 --no-same-owner
      complete "$dir"
      echo "JAVA_HOME_${version%%.*}_${env_arch}=$dir" >> "$home/.env"
      ;;
    maven)
      mkdir -p /usr/share/apache-maven
      tar -xzf "$(fetch "$url" "$sum")" -C /usr/share/apache-maven --strip-components=1 --no-same-owner
      ln -sf /usr/share/apache-maven/bin/mvn /usr/local/bin/mvn
      ;;
    rust)
      init=$(fetch "$url" "$sum")
      chmod 0755 "$init"
      RUSTUP_HOME=$home/.rustup CARGO_HOME=$home/.cargo "$init" -y --no-modify-path \
        --profile minimal --component clippy,rustfmt --default-toolchain "$version" >&2
      ;;
    *)
      echo "install-toolset: no install for '$tool'" >&2
      exit 1
      ;;
  esac
  installed=$((installed + 1))
done < "$manifest"

[ "$installed" -gt 0 ] || {
  echo "install-toolset: $manifest has no linux/$arch rows" >&2
  exit 1
}
chown -R runner:runner "$cache" "$home"
