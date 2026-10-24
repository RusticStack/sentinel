#!/usr/bin/env bash
# Align a verification host's Sentinel toolchain with the reference host (reference-host) without touching the OS:
# Podman 5.7.0 and conmon 2.1.13 from the signed podman-static bundle under /opt, the host's runc (Docker CE's 1.5.1 where present),
# passt 2026_01_20.386b5f5 built from source under /opt, all wired through the account's containers.conf;
# Rust 1.97.0 and one cargo-nextest version in the account; Node 22.22.1 and pnpm 12.3.4 under the account.
#   sudo bash align-toolchain.sh ACCOUNT        (run as root; idempotent)
set -euo pipefail
ACCOUNT=$1
PODMAN=v5.7.0 RUNC=v1.5.1 PASST=2026_01_20.386b5f5 RUST=1.97.0 NEXTEST=0.9.149 NODE=22.22.1 PNPM=12.3.4
SIGNER=0CCF102C4F95D89E583FF1D4F8B5AF50344BB503
ARCH=$(dpkg --print-architecture)
OPT=/opt/sentinel/toolchain
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null

# Never a package that can displace the host's Docker: runc and containerd come from Docker CE where it is present
# (Ubuntu's runc conflicts with containerd.io, and installing it removes Docker). Refuse any plan that removes a package.
want="build-essential pkg-config uidmap git curl ca-certificates python3 gnupg zstd fuse-overlayfs"
if apt-get -s install --no-install-recommends $want | grep -q '^Remv '; then
  echo "refusing: installing ($want) would remove packages:" >&2
  apt-get -s install --no-install-recommends $want | grep '^Remv ' >&2
  exit 1
fi
apt-get install -y -q --no-install-recommends $want >/dev/null
id "$ACCOUNT" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$ACCOUNT"
getent group kvm >/dev/null && usermod -aG kvm "$ACCOUNT"
grep -q "^$ACCOUNT:" /etc/subuid || usermod --add-subuids 300000-365535 --add-subgids 300000-365535 "$ACCOUNT"
loginctl enable-linger "$ACCOUNT"
mkdir -p "$OPT"

if [ ! -x "$OPT/podman-$PODMAN/usr/local/bin/podman" ]; then
  work=$(mktemp -d)
  curl -fsSL -o "$work/p.tar.gz" "https://github.com/mgoltzsche/podman-static/releases/download/$PODMAN/podman-linux-$ARCH.tar.gz"
  curl -fsSL -o "$work/p.tar.gz.asc" "https://github.com/mgoltzsche/podman-static/releases/download/$PODMAN/podman-linux-$ARCH.tar.gz.asc"
  export GNUPGHOME="$work/gnupg"; mkdir -m 700 "$GNUPGHOME"
  gpg -q --keyserver hkps://keyserver.ubuntu.com --recv-keys "$SIGNER"
  gpg -q --batch --verify "$work/p.tar.gz.asc" "$work/p.tar.gz"
  mkdir -p "$OPT/podman-$PODMAN"
  tar -xzf "$work/p.tar.gz" -C "$OPT/podman-$PODMAN" --strip-components=1
  rm -rf "$work"
fi

# runc: the host's own when it is the pinned version (Docker CE ships it), otherwise upstream's, checksum-verified.
RUNC_BIN=/usr/bin/runc
if ! { [ -x "$RUNC_BIN" ] && "$RUNC_BIN" --version | grep -q "version ${RUNC#v}$"; }; then
  RUNC_BIN="$OPT/runc-$RUNC/runc"
  if [ ! -x "$RUNC_BIN" ]; then
    work=$(mktemp -d)
    curl -fsSL -o "$work/runc.$ARCH" "https://github.com/opencontainers/runc/releases/download/$RUNC/runc.$ARCH"
    curl -fsSL -o "$work/runc.sha256sum" "https://github.com/opencontainers/runc/releases/download/$RUNC/runc.sha256sum"
    (cd "$work" && grep " runc.$ARCH\$" runc.sha256sum | sha256sum -c -)
    install -D -m 755 "$work/runc.$ARCH" "$RUNC_BIN"
    rm -rf "$work"
  fi
fi

if [ ! -x "$OPT/passt-$PASST/pasta" ]; then
  work=$(mktemp -d)
  git clone -q https://passt.top/passt "$work/passt"
  git -C "$work/passt" checkout -q "${PASST##*.}"
  make -s -C "$work/passt" VERSION="$PASST"
  mkdir -p "$OPT/passt-$PASST"
  install -m 755 "$work/passt/passt" "$work/passt/pasta" "$OPT/passt-$PASST/"
  rm -rf "$work"
fi

home=$(getent passwd "$ACCOUNT" | cut -d: -f6)
install -d -o "$ACCOUNT" -g "$ACCOUNT" "$home/.config/containers" "$home/.local/bin"
chown "$ACCOUNT:" "$home/.config" "$home/.local"
cat > "$home/.config/containers/containers.conf" <<EOF
[engine]
runtime = "runc"
conmon_path = ["$OPT/podman-$PODMAN/usr/local/lib/podman/conmon"]
helper_binaries_dir = ["$OPT/passt-$PASST", "$OPT/podman-$PODMAN/usr/local/libexec/podman", "$OPT/podman-$PODMAN/usr/local/lib/podman"]
[engine.runtimes]
runc = ["$RUNC_BIN"]
[network]
network_backend = "netavark"
EOF
cat > "$home/.config/containers/storage.conf" <<EOF
[storage]
driver = "overlay"
EOF
chown "$ACCOUNT:" "$home/.config/containers/containers.conf" "$home/.config/containers/storage.conf"
# Hosts without the OS's Podman package have no image policy or registry list; use upstream's defaults from the bundle.
for f in policy.json registries.conf; do
  if [ ! -e "/etc/containers/$f" ] && [ ! -e "$home/.config/containers/$f" ]; then
    install -o "$ACCOUNT" -g "$ACCOUNT" -m 644 "$OPT/podman-$PODMAN/etc/containers/$f" "$home/.config/containers/$f"
  fi
done
ln -sf "$OPT/podman-$PODMAN/usr/local/bin/podman" "$home/.local/bin/podman"
chown -h "$ACCOUNT:" "$home/.local/bin/podman"

su - "$ACCOUNT" -c "
set -e
[ -x ~/.cargo/bin/rustup ] || curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain $RUST -c clippy,rustfmt
. ~/.cargo/env
rustup -q toolchain install $RUST -c clippy,rustfmt
case \$(uname -m) in x86_64) t=linux ;; aarch64) t=linux-arm ;; esac
cargo nextest --version 2>/dev/null | grep -q ' $NEXTEST ' || curl -fsSL https://get.nexte.st/$NEXTEST/\$t | tar zxf - -C ~/.cargo/bin
[ -x ~/node22/node_modules/.bin/node ] || npm --version >/dev/null 2>&1 || true
"
if ! su - "$ACCOUNT" -c "test -x ~/.local/node-$NODE/bin/node"; then
  case $ARCH in amd64) n=linux-x64 ;; arm64) n=linux-arm64 ;; esac
  su - "$ACCOUNT" -c "mkdir -p ~/.local && curl -fsSL https://nodejs.org/dist/v$NODE/node-v$NODE-$n.tar.xz | tar xJf - -C ~/.local && mv ~/.local/node-v$NODE-$n ~/.local/node-$NODE"
fi
su - "$ACCOUNT" -c "PATH=~/.local/node-$NODE/bin:\$PATH npm i -g -s --prefix ~/.local/pnpm-$PNPM pnpm@$PNPM"
grep -q sentinel-toolchain "$home/.profile" || cat >> "$home/.profile" <<EOF
# sentinel-toolchain: the pinned verification toolchain
PATH="\$HOME/.local/bin:\$HOME/.local/pnpm-$PNPM/bin:\$HOME/.local/node-$NODE/bin:\$HOME/.cargo/bin:\$PATH"
EOF

su - "$ACCOUNT" -c ". ~/.profile; export XDG_RUNTIME_DIR=/run/user/\$(id -u); rustc --version; cargo nextest --version | head -1; podman --version; podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}} | conmon {{.Host.Conmon.Version}} | {{.Host.NetworkBackend}} | {{.Host.Pasta.Version}}' ; node --version; pnpm --version"
