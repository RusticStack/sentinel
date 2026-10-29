#!/usr/bin/env bash
# Runs one command and appends a b05-rebuild record with its monotonic wall time and the host load around it.
# usage (under the exclusive lock): b05-timed.sh <out.jsonl> '<json fields without braces>' <log file> -- <command...>
# B05_STAMP holds the `"build":{...},"host":{...}` fields of bench/stamp.sh (b05-workloads.sh sets it); without it
# the record would name no commit and no host, so nothing is run.
set -u
out="$1" fields="$2" log="$3"
shift 4
[ -n "${B05_STAMP:-}" ] || { echo "b05-timed: B05_STAMP is not set; run through b05-workloads.sh with SENTINEL_SRC and SENTINEL_BENCH_HOST_LABEL" >&2; exit 2; }

psi() {
    printf '{"loadavg":"%s","cpu":"%s","io":"%s"}' \
        "$(cut -d' ' -f1-3 /proc/loadavg)" "$(head -1 /proc/pressure/cpu)" "$(head -1 /proc/pressure/io)"
}

start="$(psi)"
t0="$(date +%s%N)"
"$@" > "$log" 2>&1
rc=$?
t1="$(date +%s%N)"
end="$(psi)"
printf '{"record":"b05-rebuild",%s,"rc":%s,"duration_ns":%s,%s,"load_start":%s,"load_end":%s}\n' \
    "$fields" "$rc" "$((t1 - t0))" "$B05_STAMP" "$start" "$end" >> "$out"
exit "$rc"
