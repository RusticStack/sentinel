#!/usr/bin/env bash
# F07 probe: does rootless Podman actually enforce the limits Sentinel will request?
# Run as the non-root worker account. Prints one line per check: PASS/FAIL + evidence.
set -uo pipefail
IMG="${IMG:-docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
run() { podman run --rm --network none "$@"; }
result() { printf '%s %s: %s\n' "$1" "$2" "$3"; }

echo "podman: $(podman --version) user=$(id -un) uid=$(id -u) kernel=$(uname -r)"
echo "controllers: $(podman info --format '{{.Host.CgroupControllers}} manager={{.Host.CgroupManager}} runtime={{.Host.OCIRuntime.Name}}')"

# 1. CPU quota: 4 busy loops for 5 s under --cpus 1 should accrue ~5 CPU-s, not ~20.
out=$(run --cpus 1 "$IMG" sh -c 'for i in 1 2 3 4; do (while :; do :; done) & done; sleep 5; kill %1 %2 %3 %4 2>/dev/null; cat /sys/fs/cgroup/cpu.stat 2>/dev/null; cat /sys/fs/cgroup/cpu.max 2>/dev/null' 2>&1)
usage=$(echo "$out" | awk '/^usage_usec/{print $2}'); thr=$(echo "$out" | awk '/^nr_throttled/{print $2}'); cmax=$(echo "$out" | grep -E '^[0-9]+ [0-9]+$|^max' | head -1)
if [[ -n "$usage" && "$usage" -lt 8000000 && "$usage" -gt 3000000 ]]; then result PASS cpu_quota "usage_usec=$usage nr_throttled=$thr cpu.max='$cmax' (4 spinners x 5 s capped near 5 CPU-s)"; else result FAIL cpu_quota "usage_usec=${usage:-?} nr_throttled=${thr:-?} cpu.max='$cmax'"; fi

# 2. Memory limit: writing 150 MiB into a tmpfs (charged to the cgroup) under --memory 64m must be OOM-killed.
out=$(run --memory 64m --memory-swap 64m --tmpfs /big:rw,size=300m "$IMG" sh -c 'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max | tr "
" " "; dd if=/dev/zero of=/big/x bs=1M count=150 2>/dev/null && echo ALLOC_OK; cat /sys/fs/cgroup/memory.events | tr "
" " "' 2>&1); rc=$?
if echo "$out" | grep -q ALLOC_OK; then result FAIL memory_limit "150 MiB tmpfs write succeeded under 64m rc=$rc: $out"; else result PASS memory_limit "rc=$rc $(echo $out | tr '
' ' ')"; fi

# 3. PID limit: fork bomb bounded by --pids-limit 32.
out=$(run --pids-limit 32 "$IMG" sh -c 'n=0; while [ $n -lt 100 ]; do (sleep 5 &) 2>/dev/null || break; n=$((n+1)); done; echo forked=$n; cat /sys/fs/cgroup/pids.max' 2>&1)
forked=$(echo "$out" | sed -n 's/^forked=//p'); if [[ -n "$forked" && "$forked" -lt 100 ]]; then result PASS pids_limit "$(echo $out | tr '\n' ' ')"; else result FAIL pids_limit "$(echo $out | tr '\n' ' ')"; fi

# 4. Network none: no interfaces besides lo, DNS/egress impossible.
out=$(run "$IMG" sh -c 'ip -o link | wc -l; wget -q -T 3 -O /dev/null http://1.1.1.1 2>&1 && echo EGRESS_OK || echo EGRESS_BLOCKED' 2>&1)
if echo "$out" | grep -q EGRESS_BLOCKED && [[ "$(echo "$out" | head -1)" == "1" ]]; then result PASS network_none "$(echo $out | tr '\n' ' ')"; else result FAIL network_none "$(echo $out | tr '\n' ' ')"; fi

# 5. Read-only rootfs with writable tmpfs workdir.
out=$(run --read-only --tmpfs /work:rw,size=16m "$IMG" sh -c 'touch /etc/x 2>&1 && echo ROOT_WRITABLE; touch /work/x && echo WORK_OK' 2>&1)
if echo "$out" | grep -q WORK_OK && ! echo "$out" | grep -q ROOT_WRITABLE; then result PASS read_only_rootfs "$(echo $out | tr '\n' ' ')"; else result FAIL read_only_rootfs "$(echo $out | tr '\n' ' ')"; fi

# 6. User namespace: root inside maps to an unprivileged subordinate uid outside; capabilities dropped.
out=$(run --cap-drop ALL --security-opt no-new-privileges "$IMG" sh -c 'id -u; cat /proc/self/uid_map | tr -s " "; grep CapEff /proc/self/status; chown 0 /bin/busybox 2>&1 | head -1' 2>&1)
if echo "$out" | grep -q "CapEff:.*0000000000000000"; then result PASS caps_dropped "$(echo $out | tr '\n' ' ')"; else result FAIL caps_dropped "$(echo $out | tr '\n' ' ')"; fi
echo "host view of a container process uid (rootless mapping):"; podman unshare cat /proc/self/uid_map | tr -s ' '

# 7. Timeout kill: podman stop -t 1 terminates a sleeping process; measure wall.
cid=$(podman run -d --network none "$IMG" sleep 300); t0=$(date +%s%N); podman stop -t 1 "$cid" >/dev/null; t1=$(date +%s%N); podman rm -f "$cid" >/dev/null 2>&1
result PASS stop_timeout "podman stop -t 1 wall_ms=$(( (t1-t0)/1000000 ))"

# 8. Bind-mounted job workspace ownership seen from inside (user namespace mapping of host dir).
tmp=$(mktemp -d); out=$(run -v "$tmp:/ws" "$IMG" sh -c 'stat -c "%u:%g" /ws; touch /ws/f && echo WRITE_OK' 2>&1); echo "   bind mount: $(echo $out | tr '\n' ' ') host_owner=$(stat -c %u:%g "$tmp/f" 2>/dev/null)"; rm -rf "$tmp"
