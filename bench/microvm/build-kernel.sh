#!/usr/bin/env bash
# Builds the pinned microVM guest kernel (plan 16.8, TODO M02/M03): Linux VERSION with Firecracker's own
# CI guest configuration (FC_TAG's resources/guest_configs/microvm-kernel-ci-x86_64-SERIES.config), booted
# directly by Firecracker and, through PVH, by Cloud Hypervisor. The compile runs in a throwaway rootless
# container (BUILDER), so the host needs no kernel build packages; the tarball is verified on the host.
#   build-kernel.sh OUT_DIR [CPUS]   writes OUT_DIR/vmlinux-VERSION, its .config and a SHA-256 manifest line
# KERNEL_BUILD_NETWORK sets the container network (default pasta, which rootless podman needs; root uses host).
# The release pins the digest this prints (scripts/release/pins.env, docs/releasing.md#microvm-assets). The kernel
# build stamp is fixed (KBUILD_BUILD_*), so the same source, config and compiler give the same bytes; the compiler
# comes from the builder image's apt, so vmlinux-VERSION.build also records its version and a different gcc may differ.
set -euo pipefail
VERSION=6.18.52 SERIES=6.18 FC_TAG=v1.17.0
BUILDER=docker.io/library/debian:trixie-slim
OUT=$1 CPUS=${2:-}
W=$(mktemp -d "${TMPDIR:-/tmp}/sentinel-kernel.XXXXXX")
trap 'rm -rf "$W"' EXIT
cd "$W"
curl -fsSLO "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$VERSION.tar.xz"
curl -fsSL https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc | grep " linux-$VERSION.tar.xz\$" | sha256sum -c -
curl -fsSL -o guest.config \
  "https://raw.githubusercontent.com/firecracker-microvm/firecracker/$FC_TAG/resources/guest_configs/microvm-kernel-ci-x86_64-$SERIES.config"
pin=()
[ -z "$CPUS" ] || pin=(taskset -c "$CPUS")
jobs=$("${pin[@]}" nproc)
# The container inherits the CPU affinity of the podman process that starts it.
"${pin[@]}" podman run --rm --network "${KERNEL_BUILD_NETWORK:-pasta}" -v "$W:/w" -e VERSION="$VERSION" -e JOBS="$jobs" "$BUILDER" bash -euc '
  apt-get update -qq && apt-get install -qq -y --no-install-recommends \
    build-essential flex bison bc libelf-dev libssl-dev xz-utils >/dev/null
  cd /w && tar xJf "linux-$VERSION.tar.xz" && cd "linux-$VERSION"
  cp ../guest.config .config
  export KBUILD_BUILD_USER=sentinel KBUILD_BUILD_HOST=sentinel KBUILD_BUILD_TIMESTAMP="Thu Jan  1 00:00:00 UTC 1970"
  make olddefconfig >/dev/null
  nice -n 10 make -j"$JOBS" vmlinux >/dev/null
  cp vmlinux .config /w/
  gcc --version | head -n 1 >/w/gcc-version'
mkdir -p "$OUT"
cp vmlinux "$OUT/vmlinux-$VERSION"
cp .config "$OUT/vmlinux-$VERSION.config"
cd "$OUT" && sha256sum "vmlinux-$VERSION" | tee -a MANIFEST.sha256
echo "# vmlinux-$VERSION built with $(cat "$W/gcc-version") from linux-$VERSION.tar.xz and Firecracker $FC_TAG guest config" >"vmlinux-$VERSION.build"
