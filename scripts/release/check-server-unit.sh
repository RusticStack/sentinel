#!/usr/bin/env bash
# Check examples/sentinel-server.service (V02): systemd accepts it, its sandbox
# scores no worse than the recorded exposure, and a copy of it started in the
# calling user's systemd instance, with every sandbox directive kept, answers
# the API health route from a temporary data directory.
#
#   scripts/release/check-server-unit.sh <path to a sentinel binary built with --features server>
#
# Run it as an unprivileged user (as root SQLite calls fchown, which the
# unit's system call filter kills; the sentinel account never makes that call).
# Needs that user's systemd instance (`systemctl --user`, XDG_RUNTIME_DIR set)
# and curl. Only the test copy differs from the shipped unit: no User=/Group=
# and the directives that work by dropping capabilities (the capability sets,
# PrivateDevices, ProtectClock, ProtectKernelModules, ProtectKernelLogs), which
# an unprivileged user instance cannot apply (exit status 218),
# another unit name and state directory, configuration written to that state
# directory, ProtectHome=read-only (a user instance keeps its state under the
# home directory, which ProtectHome=yes hides), ephemeral ports, and stderr to
# a file in it so the chosen API address can be read back. Nothing outside
# ~/.local/state/<test name> is written, and the test removes it.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
bin=${1:?usage: check-server-unit.sh <sentinel binary built with --features server>}
[ -x "$bin" ] || die "$bin is not an executable file"
bin=$(readlink -f "$bin")
[ "$(id -u)" != 0 ] || die "run this as an unprivileged user with a user systemd instance: as root SQLite calls fchown, which the unit's system call filter (correctly, for the sentinel account) kills"
root=$(cd "$(dirname "$0")/../.." && pwd)
unit=$root/examples/sentinel-server.service
# The worst exposure score `systemd-analyze security` may report (0 = best, 10 = worst).
max_exposure=${MAX_EXPOSURE:-1.5}
name=sentinel-unit-check
work=$(mktemp -d)
state=${XDG_STATE_HOME:-$HOME/.local/state}/$name
userdir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
cleanup() {
  systemctl --user stop "$name.service" >/dev/null 2>&1 || true
  rm -f "$userdir/$name.service"
  systemctl --user daemon-reload >/dev/null 2>&1 || true
  rm -rf "$work" "$state"
}
trap cleanup EXIT

# 1. The shipped unit, with the binary where this machine has it. Diagnostics
# about other units on the host are not this unit's.
sed "s|/opt/sentinel/bin/sentinel|$bin|" "$unit" >"$work/sentinel-server.service"
verify_output=$(systemd-analyze verify "$work/sentinel-server.service" 2>&1 | grep -F "sentinel-server" || true)
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

# 3. A start in the user instance with the sandbox intact.
mkdir -p "$userdir" "$state"
chmod 0700 "$state"
# Private /tmp, /var/tmp and /home hide the binary where it was built.
install -m 0755 "$bin" "$state/sentinel"
printf "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'\nlog_format = 'json'\n" >"$state/server.toml"
sed \
  -e '/^User=/d' -e '/^Group=/d' -e '/^CapabilityBoundingSet=/d' -e '/^AmbientCapabilities=/d' \
  -e '/^PrivateDevices=/d' -e '/^ProtectClock=/d' -e '/^ProtectKernelModules=/d' -e '/^ProtectKernelLogs=/d' \
  -e "s|^StateDirectory=.*|StateDirectory=$name|" \
  -e "s|/opt/sentinel/bin/sentinel|%S/$name/sentinel|" \
  -e "s|/etc/sentinel/server.toml|%S/$name/server.toml|" \
  -e "s|/var/lib/sentinel\$|%S/$name/data|" \
  -e "s|^WantedBy=.*|WantedBy=default.target|" \
  -e "s|^ProtectHome=yes|ProtectHome=read-only|" \
  -e "/^\[Service\]/a StandardError=file:%S/$name/stderr.log" \
  "$unit" >"$userdir/$name.service"
systemctl --user daemon-reload
systemctl --user start "$name.service" || { systemctl --user status --no-pager "$name.service" >&2 || true; die "the unit did not start"; }

addr=
for _ in $(seq 1 100); do
  addr=$(sed -n 's/.*"event":"api_listening".*"addr":"\([^"]*\)".*/\1/p' "$state/stderr.log" 2>/dev/null | head -n 1 || true)
  [ -n "$addr" ] && break
  systemctl --user is-active --quiet "$name.service" || { cat "$state/stderr.log" >&2 || true; systemctl --user status --no-pager "$name.service" >&2 || true; die "the service stopped before listening"; }
  sleep 0.1
done
[ -n "$addr" ] || { cat "$state/stderr.log" >&2 || true; die "the API did not report a listening address"; }
health=$(curl -fsS --max-time 5 "http://$addr/api/v1/health") || die "GET /api/v1/health failed"
case "$health" in *'"ok":true'*) ;; *) die "unexpected health answer" ;; esac
echo "ok  started in the user instance; GET /api/v1/health answered"

systemctl --user stop "$name.service"
result=$(systemctl --user show -p Result --value "$name.service")
[ "$result" = success ] || die "the service stopped with result $result"
echo "ok  SIGTERM stop is a clean exit"
