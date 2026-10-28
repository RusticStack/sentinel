#!/usr/bin/env bash
# Check examples/sentinel-worker.service (V02): systemd accepts it, its sandbox
# scores no worse than the recorded exposure, a copy of it started in the
# calling user's systemd instance, with every sandbox directive the instance can
# apply kept, runs `sentinel worker --check` to success, and, where rootless
# Podman answers, the worker started from a copy without the mount-namespace
# directives (a user instance cannot run Podman under them) reports
# `executor_ready` and stops cleanly on SIGTERM.
#
#   scripts/release/check-worker-unit.sh <path to a sentinel binary built with --features worker>
#
# Run it as the unprivileged worker account (or another unprivileged user) with
# its user systemd instance (`systemctl --user`, XDG_RUNTIME_DIR set, linger for
# an unattended host) and, for the executor step, rootless Podman with
# subordinate ids. As root the unit's own pre-start check would fail, which is
# the point of that check, so the script refuses to run as root.
#
# Only the test copy differs from the shipped unit: no User=/Group=, no
# capability sets or device policy (a user instance cannot apply them: exit
# status 218), another unit name, state directory and configuration paths, and a
# controller address nothing listens on. The executor step also points Podman's
# storage, runtime and temporary directories into the state directory
# (CONTAINERS_STORAGE_CONF, CONTAINERS_CONF), so it never touches the calling
# account's own containers or images. Nothing outside
# ~/.local/state/sentinel-worker-unit-check is written, and the test removes it.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
bin=${1:?usage: check-worker-unit.sh <sentinel binary built with --features worker>}
[ -x "$bin" ] || die "$bin is not an executable file"
bin=$(readlink -f "$bin")
[ "$(id -u)" != 0 ] || die "run this as an unprivileged user with a user systemd instance: the unit refuses root"
root=$(cd "$(dirname "$0")/../.." && pwd)
unit=$root/examples/sentinel-worker.service
# The worst exposure score `systemd-analyze security` may report (0 = best, 10 = worst).
# Rootless Podman needs setuid helpers, user namespaces and the ability to start
# other programs, so this unit scores far above the controller's; the ceiling
# stops it getting worse.
max_exposure=${MAX_EXPOSURE:-7.0}
name=sentinel-worker-unit-check
work=$(mktemp -d)
state=${XDG_STATE_HOME:-$HOME/.local/state}/$name
userdir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
cleanup() {
  systemctl --user stop "$name.service" >/dev/null 2>&1 || true
  systemctl --user reset-failed "$name.service" >/dev/null 2>&1 || true
  rm -f "$userdir/$name.service"
  systemctl --user daemon-reload >/dev/null 2>&1 || true
  rm -rf "$work" "$state"
}
trap cleanup EXIT

# 1. The shipped unit, with the binary where this machine has it. Diagnostics
# about other units on the host are not this unit's.
sed "s|/opt/sentinel/bin/sentinel|$bin|" "$unit" >"$work/sentinel-worker.service"
verify_output=$(systemd-analyze verify "$work/sentinel-worker.service" 2>&1 | grep -F "sentinel-worker" || true)
if [ -n "$verify_output" ]; then
  echo "$verify_output" >&2
  die "systemd-analyze verify is not clean"
fi
echo "ok  systemd-analyze verify is clean"

# 2. The sandbox score.
exposure=$(systemd-analyze security --offline=true --no-pager "$unit" 2>/dev/null \
  | sed -n 's/.*Overall exposure level for [^:]*: \([0-9.]*\).*/\1/p')
[ -n "$exposure" ] || die "systemd-analyze security gave no overall exposure level"
awk -v e="$exposure" -v m="$max_exposure" 'BEGIN { exit !(e <= m) }' \
  || die "overall exposure $exposure exceeds $max_exposure; run systemd-analyze security --offline=true $unit"
echo "ok  systemd-analyze security: overall exposure $exposure (limit $max_exposure)"

# 3. The unit in the user instance. `%S` is the user's state directory root.
mkdir -p "$userdir" "$state"
chmod 0700 "$state"
# PrivateTmp hides /var/tmp, where the binary may have been built.
install -m 0755 "$bin" "$state/sentinel"
data=%S/$name/data
cat >"$state/worker.toml" <<EOF
controller = '127.0.0.1:1'
controller_fingerprint = '0000000000000000000000000000000000000000000000000000000000000000'
worker_name = 'unit-check'
log_format = 'json'
EOF
# Podman's own directories, kept inside the state directory.
mkdir -p "$state/containers/graph" "$state/containers/run" "$state/containers/tmp" "$state/containers/static" "$state/containers/volumes"
cat >"$state/containers/storage.conf" <<EOF
[storage]
driver = "overlay"
graphroot = "$state/containers/graph"
runroot = "$state/containers/run"
EOF
cat >"$state/containers/containers.conf" <<EOF
[engine]
tmp_dir = "$state/containers/tmp"
static_dir = "$state/containers/static"
volume_path = "$state/containers/volumes"
EOF
# $1 = worker arguments appended to ExecStart, $2 = Type, $3 = "mounts" to keep
# the mount-namespace directives. A user instance builds a mount namespace inside
# an unprivileged user namespace of its own, and the setuid newuidmap/newgidmap
# helpers refuse to write id maps from there, so rootless Podman cannot start in
# it ("cannot clone: Operation not permitted"). The executor step therefore drops
# ProtectSystem, ProtectHome, PrivateTmp and PrivateMounts; a system unit has no
# such namespace (docs/deployment.md).
make_copy() {
  local drop=() rw='\nReadWritePaths=%t'
  if [ "${3:-}" != mounts ]; then
    drop=(-e '/^ProtectSystem=/d' -e '/^ProtectHome=/d' -e '/^PrivateTmp=/d' -e '/^PrivateMounts=/d')
    rw=
  fi
  sed "${drop[@]}" \
    -e '/^User=/d' -e '/^Group=/d' -e '/^CapabilityBoundingSet=/d' -e '/^AmbientCapabilities=/d' \
    -e '/^DevicePolicy=/d' -e '/^DeviceAllow=/d' \
    -e "s|^StateDirectory=.*|StateDirectory=$name $name/tmp|" \
    -e "s|^Environment=TMPDIR=.*|Environment=TMPDIR=%S/$name/tmp\nEnvironment=CONTAINERS_STORAGE_CONF=%S/$name/containers/storage.conf\nEnvironment=CONTAINERS_CONF=%S/$name/containers/containers.conf|" \
    -e "s|^WorkingDirectory=.*|WorkingDirectory=%S/$name|" \
    -e "s|^Type=simple|Type=$2|" \
    -e "s|^ExecStart=.*|ExecStart=%S/$name/sentinel worker --config %S/$name/worker.toml --data-dir $data $1|" \
    -e "s|^WantedBy=.*|WantedBy=default.target|" \
    -e "/^\[Service\]/a StandardError=file:%S/$name/stderr.log\nStandardOutput=file:%S/$name/stdout.log$rw" \
    "$unit" >"$userdir/$name.service"
  : >"$state/stderr.log"
  : >"$state/stdout.log"
  systemctl --user daemon-reload
}

make_copy --check oneshot mounts
systemctl --user start "$name.service" || { cat "$state/stderr.log" >&2 || true; systemctl --user status --no-pager "$name.service" >&2 || true; die "the unit's worker --check did not succeed"; }
grep -q 'worker configuration valid' "$state/stdout.log" || { cat "$state/stdout.log" "$state/stderr.log" >&2 || true; die "worker --check did not report a valid configuration"; }
echo "ok  started in the user instance; worker --check reported a valid configuration"

# 4. The executor, when this account has rootless Podman.
if [ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)" != true ]; then
  echo "skip  rootless Podman does not answer for this account; executor step not run"
  exit 0
fi
systemctl --user reset-failed "$name.service" >/dev/null 2>&1 || true
make_copy "" simple
systemctl --user start "$name.service" || { cat "$state/stderr.log" >&2 || true; systemctl --user status --no-pager "$name.service" >&2 || true; die "the unit did not start"; }
ready=
for _ in $(seq 1 300); do
  grep -q '"event":"executor_ready"' "$state/stderr.log" 2>/dev/null && { ready=1; break; }
  grep -q '"event":"executor_unavailable"' "$state/stderr.log" 2>/dev/null && break
  systemctl --user is-active --quiet "$name.service" || break
  sleep 0.1
done
if [ -z "$ready" ]; then
  cat "$state/stderr.log" >&2 || true
  systemctl --user status --no-pager "$name.service" >&2 || true
  die "the worker did not report executor_ready"
fi
echo "ok  started in the user instance; the worker reported executor_ready"

systemctl --user stop "$name.service"
result=$(systemctl --user show -p Result --value "$name.service")
[ "$result" = success ] || die "the service stopped with result $result"
echo "ok  SIGTERM stop is a clean exit"
