#!/usr/bin/env python3
"""B04a: disk wait and CPU throttling over the phases of a Sentinel attempt.

    b04a_profile.py sample --out RAW --worker-pid PID --data-dir DIR [--interval S]
    b04a_profile.py summarize RECORDS.jsonl > SUMMARY.json

`sample` polls, until SIGTERM, the kernel counters that say where time went
besides running: pressure stall information (PSI) of the host and of two
cgroups, `cpu.stat` throttling of both cgroups, the block device behind
DIR, and hypervisor steal. Every counter is cumulative, so a phase's cost is
the counter's value at its end minus at its start (linear interpolation
between the two samples around a boundary). `reduce_run` does that for the
phase windows of one run (b02-sentinel.sh calls it). A value the kernel does
not expose, or a window the samples do not cover, is absent from the profile,
never zero. A container's cgroup is reported for a window only when the
samples saw it at both ends, so the step window has one and the
container-start window does not.

Phase windows are the controller's wall-clock stamps (milliseconds, the same
clock as this sampler) cut by the worker's own monotonic phase durations.
Checkout and the image pull overlap, so the restore window is what remains of
preparation between the checkout's end and the container start.
"""
import argparse
import json
import math
import os
import signal
import sys
import time

CGROUP = "/sys/fs/cgroup"
PSI_RESOURCES = ("cpu", "io", "memory")


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def parse_psi(text):
    """{'some': {'avg10', 'avg60', 'total_us'}, 'full': ...}; lines the kernel omits are absent."""
    out = {}
    for line in (text or "").splitlines():
        kind, _, rest = line.partition(" ")
        fields = dict(f.split("=", 1) for f in rest.split() if "=" in f)
        try:
            out[kind] = {
                "avg10": float(fields["avg10"]),
                "avg60": float(fields["avg60"]),
                "total_us": int(fields["total"]),
            }
        except (KeyError, ValueError):
            pass
    return out


def parse_kv(text):
    out = {}
    for line in (text or "").splitlines():
        key, _, value = line.partition(" ")
        try:
            out[key] = int(value)
        except ValueError:
            pass
    return out


def cpu_max_cpus(text):
    """CPUs a `cpu.max` line allows, None when unlimited or unreadable."""
    parts = (text or "").split()
    if len(parts) != 2 or parts[0] == "max":
        return None
    try:
        return int(parts[0]) / int(parts[1])
    except (ValueError, ZeroDivisionError):
        return None


def cgroup_dir(pid):
    text = read(f"/proc/{pid}/cgroup")
    for line in (text or "").splitlines():
        if line.startswith("0::"):
            return CGROUP + line[3:]
    return None


def quota_chain(path):
    """The smallest CPU quota on the path from the cgroup to the root: None means no ancestor limits it."""
    best = None
    while path and path.startswith(CGROUP):
        cpus = cpu_max_cpus(read(os.path.join(path, "cpu.max")))
        if cpus is not None and (best is None or cpus < best):
            best = cpus
        if path == CGROUP:
            break
        path = os.path.dirname(path)
    return best


def disk_name(data_dir):
    """The whole-disk name behind DIR, as /proc/diskstats lists it."""
    try:
        dev = os.stat(data_dir).st_dev
    except OSError:
        return None
    link = f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}"
    try:
        real = os.path.realpath(link)
    except OSError:
        return None
    if os.path.exists(os.path.join(real, "partition")):
        real = os.path.dirname(real)
    name = os.path.basename(real)
    return name if os.path.exists(f"/sys/block/{name}") else None


def read_disk(name):
    for line in (read("/proc/diskstats") or "").splitlines():
        f = line.split()
        if len(f) >= 14 and f[2] == name:
            return {
                "read_bytes": int(f[5]) * 512,
                "write_bytes": int(f[9]) * 512,
                "busy_ms": int(f[12]),
                "queue_ms": int(f[13]),
            }
    return None


def steal_ns():
    for line in (read("/proc/stat") or "").splitlines():
        if line.startswith("cpu "):
            f = line.split()
            try:
                return int(f[8]) * (1_000_000_000 // os.sysconf("SC_CLK_TCK"))
            except (IndexError, ValueError):
                return None
    return None


def read_cgroup(path):
    cpu = parse_kv(read(os.path.join(path, "cpu.stat")))
    cg = {}
    for key in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec"):
        if key in cpu:
            cg[key] = cpu[key]
    for res in PSI_RESOURCES:
        psi = parse_psi(read(os.path.join(path, f"{res}.pressure")))
        if psi:
            cg[f"psi_{res}"] = psi
    return cg


def libpod_scopes(manager):
    try:
        return [
            os.path.join(manager, e)
            for e in os.listdir(manager)
            if e.startswith("libpod-") and e.endswith(".scope")
        ]
    except OSError:
        return []


def take(worker, manager, disk):
    w0, m0 = time.time_ns(), time.monotonic_ns()
    s = {"host": {}, "cg": {}}
    for res in PSI_RESOURCES:
        psi = parse_psi(read(f"/proc/pressure/{res}"))
        if psi:
            s["host"][f"psi_{res}"] = psi
    steal = steal_ns()
    if steal is not None:
        s["host"]["steal_ns"] = steal
    if disk:
        d = read_disk(disk)
        if d:
            s["host"]["disk"] = d
    if worker:
        s["cg"]["worker"] = read_cgroup(worker)
    for scope in libpod_scopes(manager) if manager else []:
        s["cg"]["c:" + os.path.basename(scope)] = read_cgroup(scope)
    w1 = time.time_ns()
    s["t"] = (w0 + w1) // 2
    s["span_ns"] = w1 - w0
    s["mono_ns"] = m0
    return s


def sample(args):
    worker = cgroup_dir(args.worker_pid)
    manager = None
    if worker:
        parts = worker.split("/")
        for i, p in enumerate(parts):
            if p.startswith("user@") and p.endswith(".service"):
                manager = "/".join(parts[: i + 1]) + "/user.slice"
    disk = disk_name(args.data_dir)
    meta = {
        "worker_cgroup": worker and worker[len(CGROUP):],
        "worker_cpu_quota_cpus": quota_chain(worker) if worker else None,
        "disk": disk,
        "interval_s": args.interval,
    }
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    samples = []
    quotas = {}
    next_tick = time.monotonic()
    while not stop:
        s = take(worker, manager, disk)
        for name in s["cg"]:
            if name.startswith("c:") and name not in quotas:
                quotas[name] = cpu_max_cpus(read(os.path.join(manager, name[2:], "cpu.max")))
        samples.append(s)
        next_tick += args.interval
        pause = next_tick - time.monotonic()
        if pause > 0:
            time.sleep(pause)
        else:
            next_tick = time.monotonic()
    meta["container_cpu_quota_cpus"] = {k: v for k, v in quotas.items() if v is not None}
    with open(args.out, "w") as f:
        json.dump({"meta": meta, "samples": samples}, f, separators=(",", ":"))


def value_at(series, t):
    """Piecewise-linear value of a cumulative series [(t, v)] at t; None outside the observed span."""
    if not series or t < series[0][0] or t > series[-1][0]:
        return None
    lo, hi = 0, len(series) - 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if series[mid][0] <= t:
            lo = mid
        else:
            hi = mid
    (t0, v0), (t1, v1) = series[lo], series[hi]
    if t1 == t0 or t <= t0:
        return v0
    return v0 + (v1 - v0) * (t - t0) / (t1 - t0)


def delta(series, t0, t1):
    """Growth of a cumulative counter over [t0, t1]; None when unobserved or when it went backwards."""
    a, b = value_at(series, t0), value_at(series, t1)
    if a is None or b is None or b < a:
        return None
    return b - a


def series_of(samples, getter):
    """[(t, v)] for the samples where getter finds a value."""
    out = []
    for s in samples:
        try:
            v = getter(s)
        except (KeyError, TypeError):
            v = None
        if v is not None:
            out.append((s["t"], v))
    return out


def put(out, key, value, scale=1):
    if value is not None:
        out[key] = round(value * scale)


def host_window(samples, t0, t1):
    out = {}
    for res in PSI_RESOURCES:
        for kind in ("some", "full"):
            ser = series_of(samples, lambda s: s["host"][f"psi_{res}"][kind]["total_us"])
            put(out, f"{res}_{kind}_stall_us", delta(ser, t0, t1))
    put(out, "steal_ns", delta(series_of(samples, lambda s: s["host"]["steal_ns"]), t0, t1))
    for key in ("read_bytes", "write_bytes", "busy_ms", "queue_ms"):
        put(out, f"disk_{key}", delta(series_of(samples, lambda s: s["host"]["disk"][key]), t0, t1))
    return out


def cgroup_window(samples, name, t0, t1):
    out = {}
    for key in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec"):
        ser = series_of(samples, lambda s: s["cg"][name][key])
        put(out, {"usage_usec": "cpu_usage_us", "nr_periods": "periods",
                  "nr_throttled": "throttled_periods", "throttled_usec": "throttled_us"}[key],
            delta(ser, t0, t1))
    for res in PSI_RESOURCES:
        for kind in ("some", "full"):
            ser = series_of(samples, lambda s: s["cg"][name][f"psi_{res}"][kind]["total_us"])
            put(out, f"{res}_{kind}_stall_us", delta(ser, t0, t1))
    return out


def observed_through(samples, name, t0, t1):
    """True when the cgroup was seen at or before t0 and at or after t1: only then its deltas cover the window."""
    seen = [s["t"] for s in samples if name in s["cg"]]
    return bool(seen) and seen[0] <= t0 + 1 and seen[-1] >= t1 - 1


def windows(ts, timings, dispatched_ns=None):
    """Phase windows (wall ns) from the job's controller stamps and the worker's phase durations."""
    ms = lambda v: None if v is None else int(v) * 1_000_000
    prep, run, fin, term = (ms(ts.get(k)) for k in
                            ("preparing_ms", "running_ms", "finalizing_ms", "terminal_ms"))
    t = lambda k: timings.get(k)
    out = {}
    if prep is not None and run is not None:
        out["prepare"] = (prep, run)
        if t("checkout"):
            out["checkout"] = (prep, prep + t("checkout"))
        cs = t("container_start")
        if cs:
            out["container_start"] = (run - cs, run)
        start = prep + max(t("checkout") or 0, t("image_pull") or 0)
        end = run - (cs or 0)
        if end > start:
            out["cache_restore_etc"] = (start, end)
    if run is not None and fin is not None:
        out["steps"] = (run, fin)
    if fin is not None and term is not None:
        out["finalize"] = (fin, term)
        if t("finalize"):
            out["finalize_work"] = (fin, min(term, fin + t("finalize")))
    return out


def reduce_run(raw, ts, timings):
    """The profile of one run from a `sample` dump, the job's stamps and its attempt timings."""
    samples = raw["samples"]
    meta = raw["meta"]
    out = {"meta": meta, "samples": len(samples),
           "max_read_span_ns": max((s["span_ns"] for s in samples), default=None)}
    if not samples:
        return out
    first, last = samples[0], samples[-1]
    ends = {}
    for label, s in (("start", first), ("end", last)):
        for res in PSI_RESOURCES:
            for kind in ("some", "full"):
                try:
                    p = s["host"][f"psi_{res}"][kind]
                except KeyError:
                    continue
                ends[f"{res}_{kind}_avg10_{label}"] = p["avg10"]
                ends[f"{res}_{kind}_avg60_{label}"] = p["avg60"]
    out["host_pressure"] = ends
    out["host_total"] = host_window(samples, first["t"], last["t"])
    containers = sorted({n for s in samples for n in s["cg"] if n.startswith("c:")})
    phases = {}
    for name, (t0, t1) in windows(ts, timings).items():
        phase = {"duration_ns": t1 - t0, "host": host_window(samples, t0, t1)}
        if "worker" in first["cg"]:
            phase["worker_cgroup"] = cgroup_window(samples, "worker", t0, t1)
        mine = [c for c in containers if observed_through(samples, c, t0, t1)]
        if len(mine) == 1:
            phase["container_cgroup"] = cgroup_window(samples, mine[0], t0, t1)
        phases[name] = phase
    out["phases"] = phases
    out["containers_seen"] = len(containers)
    return out


def percentile(sorted_values, q):
    return sorted_values[max(1, math.ceil(q * len(sorted_values))) - 1]


def distribution(values):
    v = sorted(values)
    if not v:
        return None
    return {"n": len(v), "min": v[0], "p50": percentile(v, 0.5), "p95": percentile(v, 0.95),
            "p99": percentile(v, 0.99), "max": v[-1], "p95_is_max": len(v) < 20}


def summarize(records):
    """Per phase and metric: the distribution over the records that measured it (absent values do not count as zero)."""
    cells = {}
    for rec in records:
        for phase, body in (rec.get("profile", {}).get("phases") or {}).items():
            dur = cells.setdefault((phase, "duration_ns"), [])
            dur.append(body["duration_ns"])
            for scope in ("host", "worker_cgroup", "container_cgroup"):
                for metric, value in (body.get(scope) or {}).items():
                    cells.setdefault((phase, f"{scope}.{metric}"), []).append(value)
    out = {}
    for (phase, metric), values in sorted(cells.items()):
        out.setdefault(phase, {})[metric] = distribution(values)
    return out


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--out", required=True)
    s.add_argument("--worker-pid", type=int, required=True)
    s.add_argument("--data-dir", required=True)
    s.add_argument("--interval", type=float, default=0.02)
    z = sub.add_parser("summarize")
    z.add_argument("records")
    args = ap.parse_args()
    if args.cmd == "sample":
        sample(args)
    else:
        with open(args.records) as f:
            records = [json.loads(line) for line in f if line.strip()]
        records = [r for r in records if not r.get("warmup")]
        json.dump({"schema": "sentinel-bench/sentinel-profile-summary/1", "runs": len(records),
                   "phases": summarize(records)}, sys.stdout, indent=1, sort_keys=True)
        print()


if __name__ == "__main__":
    main()
