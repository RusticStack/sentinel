#!/usr/bin/env python3
"""M08: microVM overhead against rootless Podman, per lane and condition, against the B09 gate.

    python3 bench/m08_overhead.py RECORDS.jsonl [...] [--gate 0.10] [--min-samples 10] [--json]

Reads pilot records (bench/p14-pilot.sh) taken under contract pilots-ci-isolation revision 1 and pairs the
series of each lane and condition by their stated isolation. Warm-up samples and samples whose jobs did not
pass are left out. Per series it reports the count, min, median, nearest-rank p95 and max of intake to
finished, plus the median of two phases (queue to first running, running to terminal). The overhead is
microvm / container - 1 on the p95 (the gate) and on the median.

Exit status: 0 every compared series is within the gate, 1 at least one is over it, 2 a series is missing
or holds fewer than --min-samples samples (development evidence, not a gate result), 3 bad input. Records of
any other contract are refused, so revision-4 records are never mixed in. The contract pairs the two series by
binary, host and day, so bad input also means: a record without build.commit, build.binary_sha256, host.hostname,
host.cpu_model or cpu_pressure_avg60; a start pressure at or over 2 %; a container and a microvm series (or
one series) that differ in commit, binary, host label, CPU model or UTC day. The message names the field,
never its value.
"""
import argparse
import json
import math
import statistics
import sys
from datetime import datetime, timezone

ID, REVISION = "pilots-ci-isolation", 1
START_PRESSURE_LIMIT = 2.0  # percent, "some" avg60 at the start of each sample (the contract's pairing rule)
# What the contract's pairing requires to be the same on both sides of a comparison: the binary (and the
# commit it came from), the host and its CPU. The day comes from the job timestamps.
PAIRED_FIELDS = (("build", "commit"), ("build", "binary_sha256"), ("host", "hostname"), ("host", "cpu_model"))


def p95(values):
    """Nearest-rank 95th percentile."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def phases(jobs):
    """(queue to first running, first running to last terminal) in seconds, from the job timestamps."""
    ts = [j["timestamps"] for j in jobs if j.get("timestamps")]
    try:
        queued = min(t["queued_ms"] for t in ts)
        running = min(t["running_ms"] for t in ts)
        terminal = max(t["terminal_ms"] for t in ts)
    except (KeyError, ValueError):
        return None
    return (running - queued) / 1000, (terminal - running) / 1000


def load(paths):
    series = {}
    for path in paths:
        with open(path) as f:
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                r = json.loads(line)
                c = r.get("contract", {})
                if (c.get("id"), c.get("revision")) != (ID, REVISION) or c.get("isolation") not in ("container", "microvm"):
                    raise ValueError(f"{path}:{n}: not a {ID} revision {REVISION} record (got {c.get('id')} {c.get('revision')})")
                if r.get("warmup") or r.get("job_state") != "passed":
                    continue
                where = f"{path}:{n}"
                pressure = r.get("cpu_pressure_avg60")
                if not isinstance(pressure, (int, float)) or isinstance(pressure, bool):
                    raise ValueError(f"{where}: cpu_pressure_avg60 missing; the start condition is unverified")
                if pressure >= START_PRESSURE_LIMIT:
                    raise ValueError(f"{where}: cpu_pressure_avg60 is at or over the contract's {START_PRESSURE_LIMIT:g} % start limit")
                s = series.setdefault((c["lane"], c["condition"], c["isolation"]),
                                      {"total": [], "start": [], "run": [], "prov": {}, "days": set()})
                for section, key in PAIRED_FIELDS:
                    value = (r.get(section) or {}).get(key)
                    if not value:
                        raise ValueError(f"{where}: {section}.{key} missing; the record cannot be paired")
                    s["prov"].setdefault(f"{section}.{key}", set()).add(value)
                for j in r["jobs"]:
                    queued = (j.get("timestamps") or {}).get("queued_ms")
                    if queued is not None:
                        s["days"].add(datetime.fromtimestamp(queued / 1000, timezone.utc).date().isoformat())
                s["total"].append(r["intake_to_finished_ns"] / 1e9)
                ph = phases(r["jobs"])
                if ph:
                    s["start"].append(ph[0])
                    s["run"].append(ph[1])
    return series


def check_pairing(series):
    """The contract compares a container series with a microvm series taken with the same binary, on the same host
    and the same day. Raises ValueError naming the field (never the values) when the two sides differ, or when one
    side mixes builds or hosts."""
    for lane, condition in sorted({(k[0], k[1]) for k in series}):
        sides = [series[k] for k in ((lane, condition, "container"), (lane, condition, "microvm")) if k in series]
        for field in [f"{a}.{b}" for a, b in PAIRED_FIELDS]:
            seen = set().union(*(s["prov"][field] for s in sides))
            if len(seen) > 1:
                raise ValueError(f"{lane} {condition}: the series differ in {field}; a comparison needs one binary, host and CPU")
        days = set().union(*(s["days"] for s in sides))
        if len(days) > 1:
            raise ValueError(f"{lane} {condition}: the series were taken on different days; the contract pairs one day")


def summarize(s):
    t = s["total"]
    return {"n": len(t), "p95_is_max": len(t) < 20, "min": min(t), "median": statistics.median(t), "p95": p95(t), "max": max(t),
            "start_median": statistics.median(s["start"]) if s["start"] else None,
            "run_median": statistics.median(s["run"]) if s["run"] else None}


def compare(series, gate, min_samples):
    rows, status = [], 0
    for lane, condition in sorted({(k[0], k[1]) for k in series}):
        row = {"lane": lane, "condition": condition}
        for iso in ("container", "microvm"):
            s = series.get((lane, condition, iso))
            row[iso] = summarize(s) if s else None
        c, m = row["container"], row["microvm"]
        if not c or not m or min(c["n"], m["n"]) < min_samples:
            row["verdict"] = "insufficient"
            status = max(status, 2)
        else:
            row["p95_overhead"] = m["p95"] / c["p95"] - 1
            row["median_overhead"] = m["median"] / c["median"] - 1
            row["verdict"] = "within" if row["p95_overhead"] <= gate else "OVER"
            if row["verdict"] == "OVER":
                status = 1
        rows.append(row)
    return rows, status


def render(rows, gate):
    def num(v):
        return "-" if v is None else f"{v:.2f}"

    def pct(v):
        return "-" if v is None else f"{v:+.1%}"

    out = [f"M08 microVM vs container, B09 gate: p95 overhead <= {gate:.0%}",
           f"{'lane':8} {'condition':10} {'n c/m':7} {'p95 c':>8} {'p95 m':>8} {'p95 ovh':>8} {'med ovh':>8} {'start c/m':>12}  verdict"]
    for r in rows:
        c, m = r["container"], r["microvm"]
        n = f"{c['n'] if c else 0}/{m['n'] if m else 0}"
        start = f"{num(c and c['start_median'])}/{num(m and m['start_median'])}"
        out.append(f"{r['lane']:8} {r['condition']:10} {n:7} {num(c and c['p95']):>8} {num(m and m['p95']):>8} "
                   f"{pct(r.get('p95_overhead')):>8} {pct(r.get('median_overhead')):>8} {start:>12}  {r['verdict']}")
    if any(side and side["p95_is_max"] for r in rows for side in (r["container"], r["microvm"])):
        out.append("note: with fewer than 20 samples a series' p95 is its maximum (development evidence, see the contract)")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("records", nargs="+")
    p.add_argument("--gate", type=float, default=0.10)
    p.add_argument("--min-samples", type=int, default=10)
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    try:
        series = load(a.records)
        check_pairing(series)
    except (OSError, ValueError, KeyError) as e:
        print(e, file=sys.stderr)
        return 3
    if not series:
        print("no usable samples", file=sys.stderr)
        return 3
    rows, status = compare(series, a.gate, a.min_samples)
    print(json.dumps(rows, indent=1) if a.json else render(rows, a.gate))
    return status


if __name__ == "__main__":
    sys.exit(main())
