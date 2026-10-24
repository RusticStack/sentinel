#!/usr/bin/env bash
# Runs one command and appends a b05-rebuild record with its monotonic wall time and the host load around it.
# usage (under the exclusive lock): b05-timed.sh <out.jsonl> '<json fields without braces>' <log file> -- <command...>
set -u
out="$1" fields="$2" log="$3"
shift 4

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
printf '{"record":"b05-rebuild",%s,"rc":%s,"duration_ns":%s,"build":{"commit":"%s","dirty":"%s"},"host":%s,"load_start":%s,"load_end":%s}\n' \
    "$fields" "$rc" "$((t1 - t0))" "${B05_COMMIT:-}" "${B05_DIRTY:-}" "${B05_HOST:-null}" "$start" "$end" >> "$out"
exit "$rc"
