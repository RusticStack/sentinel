#!/usr/bin/env python3
"""B03a: distributions of the push -> ready and push -> first-process figures.

    python3 bench/b03a-summary.py RECORDS.jsonl [--host-start FILE --host-end FILE] [--label TEXT] > SUMMARY.jsonl

Reads the `first` samples `bench/b03-latency.py` wrote and prints one JSON line:
n, min, p50, p95, p99, max (nearest-rank) for each B03a metric, the build and
host blocks copied from the records, and the host load snapshots taken at the
start and end of the run.
"""
import argparse
import json
import math
import sys

METRICS = ["intake_ack_ms", "intake_to_ready_ms", "ready_to_first_ms", "intake_to_first_ms"]


def nearest_rank(values, q):
    return values[max(math.ceil(q * len(values)) - 1, 0)]


def distribution(values):
    values = sorted(values)
    return {"n": len(values), "min": values[0], "p50": nearest_rank(values, 0.50),
            "p95": nearest_rank(values, 0.95), "p99": nearest_rank(values, 0.99), "max": values[-1]}


def snapshot(path):
    if not path:
        return None
    with open(path) as f:
        return f.read().strip().splitlines()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("records")
    p.add_argument("--host-start")
    p.add_argument("--host-end")
    p.add_argument("--label", default="")
    a = p.parse_args()
    rows = []
    with open(a.records) as f:
        for line in f:
            row = json.loads(line)
            if row.get("budget") == "first" and row.get("state") == "passed":
                row["intake_ack_ms"] = row["intake_ack_ns"] / 1e6
                rows.append(row)
    if not rows:
        sys.exit("no successful first-process samples")
    out = {"schema": "sentinel-bench/b03a-summary/1", "label": a.label, "records": a.records,
           "build": rows[0].get("build"), "host": rows[0].get("host"),
           "cpu_pressure_avg60_before_samples": distribution([r["cpu_pressure_avg60"] for r in rows]),
           "host_load_start": snapshot(a.host_start), "host_load_end": snapshot(a.host_end),
           "unit": "ms", "percentile": "nearest-rank"}
    for metric in METRICS:
        out[metric] = distribution([r[metric] for r in rows])
    print(json.dumps(out, separators=(",", ":")))


if __name__ == "__main__":
    main()
