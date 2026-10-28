#!/bin/sh
# Install the microVM files of the x86_64 worker package where examples/worker.toml expects them.
#
#   sudo ./microvm/install.sh            install, then print the [microvm] section to add
#   DESTDIR=/stage ./microvm/install.sh  install under a staging root (package builders, tests)
#
# Checks every file against microvm/SHA256SUMS first and refuses to install on a mismatch.
# Touches only the three paths below; it never edits worker.toml and never starts a service.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dest=${DESTDIR:-}
bin=/usr/local/bin
lib=/var/lib/sentinel-microvm

(cd "$here" && sha256sum --check --strict --quiet SHA256SUMS) \
  || { echo "error: the files next to this script do not match SHA256SUMS; fetch the package again" >&2; exit 1; }

install -d -m 0755 "$dest$bin" "$dest$lib"
install -m 0755 "$here/firecracker" "$dest$bin/firecracker"
install -m 0755 "$here/sentinel-agent" "$dest$bin/sentinel-agent"
install -m 0644 "$here/vmlinux" "$dest$lib/vmlinux"

cat <<TOML
installed Firecracker, the guest agent and the guest kernel. Add to the worker configuration:

[microvm]
firecracker = "$bin/firecracker"
kernel = "$lib/vmlinux"
agent = "$bin/sentinel-agent"

then check it: sentinel worker --config <worker.toml> --check   (it prints microvm=ready on a KVM host)
TOML
