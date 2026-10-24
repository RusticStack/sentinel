#!/usr/bin/env bash
# Build Podman and conmon from source with systemd, seccomp and journald support into /opt, as Ubuntu builds them
# (the podman-static bundle has no systemd cgroup manager, so a rootless `podman exec` never sees its process exit,
# and its conmon has no journald). Points ACCOUNT's containers.conf and PATH at them. Run as root; never removes a package.
#   sudo bash build-podman.sh ACCOUNT [PODMAN_VERSION] [CONMON_VERSION]
set -euo pipefail
ACCOUNT=$1 VERSION=${2:-v5.7.0} CONMON=${3:-v2.1.13}
GO=1.25.5
OPT=/opt/sentinel/toolchain
ARCH=$(dpkg --print-architecture)
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
want="libgpgme-dev libseccomp-dev libsystemd-dev libassuan-dev libgpg-error-dev libglib2.0-dev pkg-config build-essential git"
if apt-get -s install --no-install-recommends $want | grep -q '^Remv '; then
  echo "refusing: installing ($want) would remove packages" >&2; exit 1
fi
apt-get install -y -q --no-install-recommends $want >/dev/null
if [ ! -x "$OPT/go-$GO/bin/go" ]; then
  mkdir -p "$OPT/go-$GO"
  curl -fsSL "https://go.dev/dl/go$GO.linux-$ARCH.tar.gz" | tar xzf - -C "$OPT/go-$GO" --strip-components=1
fi
export PATH="$OPT/go-$GO/bin:$PATH" GOTOOLCHAIN=local GOPATH=/root/.cache/sentinel-go GOCACHE=/root/.cache/sentinel-go-build
work=$(mktemp -d)
git clone -q --depth 1 --branch "$VERSION" https://github.com/containers/podman "$work/podman"
make -s -C "$work/podman" BUILDTAGS="systemd seccomp exclude_graphdriver_btrfs exclude_graphdriver_devicemapper containers_image_openpgp" bin/podman bin/rootlessport bin/quadlet
dest="$OPT/podman-src-$VERSION"
install -D -m 755 "$work/podman/bin/podman" "$dest/bin/podman"
install -D -m 755 "$work/podman/bin/rootlessport" "$dest/libexec/podman/rootlessport"
git clone -q --depth 1 --branch "$CONMON" https://github.com/containers/conmon "$work/conmon"
make -s -C "$work/conmon"
install -D -m 755 "$work/conmon/bin/conmon" "$OPT/conmon-$CONMON/conmon"
rm -rf "$work"
home=$(getent passwd "$ACCOUNT" | cut -d: -f6)
conf="$home/.config/containers/containers.conf"
sed -i "s|^conmon_path = .*|conmon_path = [\"$OPT/conmon-$CONMON/conmon\"]|" "$conf"
grep -q "podman-src-$VERSION" "$conf" || sed -i "s|^helper_binaries_dir = \[|helper_binaries_dir = [\"$dest/libexec/podman\", |" "$conf"
ln -sf "$dest/bin/podman" "$home/.local/bin/podman"
chown -h "$ACCOUNT:" "$home/.local/bin/podman"
"$dest/bin/podman" --version
"$OPT/conmon-$CONMON/conmon" --version | head -1
