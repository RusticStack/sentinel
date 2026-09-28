#!/usr/bin/env bash
# R06: the idle footprint of a controller and one enrolled worker on this host.
# Both processes start from scratch, the worker enrolls and stays connected,
# and after a settling minute the script measures each process's resident
# memory (sampled every 10 s: max and last) and the CPU time it and its
# waited-for children used over the window. Nothing else talks to them until
# the end, when one scrape of the worker's metrics listener, one of
# `/api/v1/ready` and one of `/metrics` confirm they are live.
#
# Run as an account with rootless Podman, so the worker's executor starts:
#   BIN=/path/to/sentinel WINDOW=600 bench/r06-idle.sh >> bench/r06-idle.jsonl
set -euo pipefail
BIN=${BIN:-$HOME/r06/sentinel}
WINDOW=${WINDOW:-600}
SETTLE=${SETTLE:-60}
D=$(mktemp -d)
SP="" WP=""
cleanup() {
  [ -n "$WP" ] && kill "$WP" 2>/dev/null && wait "$WP" 2>/dev/null || true
  [ -n "$SP" ] && kill "$SP" 2>/dev/null && wait "$SP" 2>/dev/null || true
  rm -rf "$D"
}
trap cleanup EXIT
C=$D/controller W=$D/worker
mkdir -p "$C"
admin() { printf 'correct horse battery staple' | "$BIN" admin "$@" --data-dir "$C"; }
admin bootstrap --username root >/dev/null
admin tenant create --slug acme >/dev/null
admin pool create --name builders --tenant acme >/dev/null
admin worker enroll --pool builders >"$D/enrollment"
TOKEN=$("$BIN" admin token issue --data-dir "$C" --user root --name r06 \
  --scope platform-admin --expires-in 1h)

printf "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'\nlog_format = 'json'\n" >"$D/server.toml"
"$BIN" server --config "$D/server.toml" --data-dir "$C" >"$D/server.log" 2>&1 &
SP=$!
event() { # event <log> <name>: the first such record's fields, as JSON
  for _ in $(seq 1 300); do
    line=$(grep -m1 "\"$2\"" "$1" 2>/dev/null || true)
    [ -n "$line" ] && { printf '%s' "$line"; return; }
    sleep 0.1
  done
  echo "no $2 in $1" >&2; cat "$1" >&2; exit 1
}
LINK=$(event "$D/server.log" link_listening)
API=$(event "$D/server.log" api_listening)
field() { python3 -c "import json,sys; print(json.loads(sys.argv[1])['fields'][sys.argv[2]])" "$1" "$2"; }
ADDR=$(field "$LINK" addr) FP=$(field "$LINK" fingerprint) API=$(field "$API" addr)

cat >"$D/worker.toml" <<EOF
controller = '$ADDR'
controller_fingerprint = '$FP'
worker_name = 'r06-idle'
enrollment_file = '$D/enrollment'
log_format = 'json'
metrics_listen = '127.0.0.1:0'
EOF
"$BIN" worker --config "$D/worker.toml" --data-dir "$W" >"$D/worker.log" 2>&1 &
WP=$!
event "$D/worker.log" link_connected >/dev/null
MET=$(field "$(event "$D/worker.log" metrics_listening)" address)
EXEC=$(grep -c '"executor_ready"' "$D/worker.log" || true)
sleep "$SETTLE"

ticks=$(getconf CLK_TCK)
cpu() { # utime + stime + cutime + cstime, in ticks
  awk '{ sub(/^.*\) /, ""); print $12 + $13 + $14 + $15 }' "/proc/$1/stat"
}
rss() { awk '/^VmRSS:/ { print $2 * 1024 }' "/proc/$1/status"; }
s0=$(cpu "$SP") w0=$(cpu "$WP") t0=$(date +%s%N)
smax=0 wmax=0
for _ in $(seq 1 $((WINDOW / 10))); do
  sleep 10
  s=$(rss "$SP") w=$(rss "$WP")
  [ "$s" -gt "$smax" ] && smax=$s
  [ "$w" -gt "$wmax" ] && wmax=$w
done
s1=$(cpu "$SP") w1=$(cpu "$WP") t1=$(date +%s%N)
slast=$(rss "$SP") wlast=$(rss "$WP")

ready=$(curl -fsS "http://$API/api/v1/ready")
worker_up=$(curl -fsS "http://$MET/metrics" | grep -c '^sentinel_worker_connected 1$' || true)
scraped=$(curl -fsS -H "authorization: Bearer $TOKEN" "http://$API/metrics" | grep -c '^sentinel_workers{state="connected"} 1$' || true)

python3 - "$s0" "$s1" "$w0" "$w1" "$t0" "$t1" "$ticks" "$smax" "$slast" "$wmax" "$wlast" \
  "$ready" "$worker_up" "$scraped" "$EXEC" "$("$BIN" --version)" <<'PY'
import json, os, platform, sys, time
s0, s1, w0, w1, t0, t1, ticks, smax, slast, wmax, wlast = (int(x) for x in sys.argv[1:12])
ready, worker_up, scraped, executor, version = sys.argv[12:17]
wall = (t1 - t0) / 1e9
def pct(a, b):
    return round((b - a) / ticks / wall * 100, 4)
mib = lambda b: round(b / 1048576, 1)
cpu_model = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), None)
print(json.dumps({
    "schema": "sentinel-bench/1", "workload": "r06-idle", "version": version,
    "started_at_unix_ms": int(time.time() * 1000) - int(wall * 1000),
    "host": {"kernel": platform.release(), "cpu_model": cpu_model, "cpus_online": os.cpu_count()},
    "window_s": round(wall, 1),
    "controller": {"rss_max_mib": mib(smax), "rss_last_mib": mib(slast), "cpu_pct_of_core": pct(s0, s1)},
    "worker": {"rss_max_mib": mib(wmax), "rss_last_mib": mib(wlast), "cpu_pct_of_core": pct(w0, w1),
               "executor_ready": executor == "1"},
    "combined_cpu_pct_of_core": round(pct(s0, s1) + pct(w0, w1), 4),
    "targets": {"controller_rss_mib": 150, "worker_rss_mib": 75, "combined_cpu_pct_of_core": 1},
    "checks": {"ready": json.loads(ready), "worker_metrics_connected": worker_up == "1",
               "controller_metrics_sees_worker": scraped == "1"},
}))
PY
