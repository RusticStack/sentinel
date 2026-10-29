#!/usr/bin/env python3
"""B09 regression gate: candidate against baseline `sentinel-bench/b09/1` records.

    python3 bench/b09-gate.py BASELINE.jsonl CANDIDATE.jsonl [--max-regression 0.10] [--min-repeats 3] [--json]

Only `kind: perf` records are compared (reliability records are pass/fail in
their own checks). Per scenario the unit is one repeat's p95 of `overhead_ns`;
a repeat whose p95 is the maximum of fewer than 20 runs (`p95_is_max`) or that
has no passed run is unusable and is refused, not averaged in.

For each side the scenario's figure is the MEDIAN of its repeats' p95s, and
its noise is the SPREAD (max - min) of those same p95s. The noise comes from
repeats, never from one run's jitter, so a side with fewer than --min-repeats
usable repeats has no noise estimate and the scenario is `insufficient`.

Verdicts per scenario:
  pass          candidate median <= baseline median * (1 + max_regression)
  fail          over that limit AND the difference exceeds the larger of the two spreads
  inconclusive  over the limit but within the noise: more repeats are needed
  insufficient  too few usable repeats on either side (or the scenario is absent on one)
  incomparable  the two sides did not run the same scenario shape, or the baseline
                carries an injected handicap

Exit status: 1 any fail; else 2 any insufficient or incomparable scenario or
unreadable input; else 3 any inconclusive; else 0. A failure outranks the
rest. The gate never turns a missing or noisy result into a pass.
"""
import argparse
import json
import statistics
import sys

SCHEMA = "sentinel-bench/b09/1"
SHAPE_KEYS = ("workers", "mode", "runs_per_repeat", "link", "link_shape", "disk", "job")


class GateError(Exception):
    pass


def load(path):
    """Group usable perf repeats by scenario id: id -> {shape, handicap, p95s, unusable}."""
    scenarios = {}
    try:
        fh = open(path, encoding="utf-8")
    except OSError as e:
        raise GateError(f"{path}: {e.strerror or e}")
    with fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                raise GateError(f"{path}:{n}: not JSON")
            if not isinstance(rec, dict) or rec.get("schema") != SCHEMA:
                raise GateError(f"{path}:{n}: schema is not {SCHEMA}")
            if rec.get("kind") != "perf":
                continue
            sc = rec.get("scenario") or {}
            sid = sc.get("id")
            if not sid:
                raise GateError(f"{path}:{n}: perf record without a scenario id")
            shape = {k: sc.get(k) for k in SHAPE_KEYS}
            entry = scenarios.setdefault(sid, {"shape": shape, "handicap": sc.get("injected_handicap"),
                                               "p95s": [], "unusable": 0})
            if shape != entry["shape"] or sc.get("injected_handicap") != entry["handicap"]:
                raise GateError(f"{path}:{n}: scenario {sid} changes shape between repeats")
            ov = (rec.get("summary") or {}).get("overhead_ns") or {}
            p95 = ov.get("p95")
            if not isinstance(p95, (int, float)) or ov.get("n", 0) < 1 or ov.get("p95_is_max"):
                entry["unusable"] += 1
                continue
            entry["p95s"].append(p95)
    return scenarios


def compare(base, cand, max_regression, min_repeats):
    """One scenario's verdict and the figures behind it."""
    out = {"baseline_repeats": len(base["p95s"]), "candidate_repeats": len(cand["p95s"]),
           "baseline_unusable": base["unusable"], "candidate_unusable": cand["unusable"]}
    if base["handicap"]:
        return {**out, "verdict": "incomparable", "why": "the baseline carries an injected handicap"}
    if base["shape"] != cand["shape"]:
        return {**out, "verdict": "incomparable", "why": "scenario shape differs (workers, mode, runs, link, disk or job)"}
    if len(base["p95s"]) < min_repeats or len(cand["p95s"]) < min_repeats:
        return {**out, "verdict": "insufficient",
                "why": f"needs {min_repeats} usable repeats on each side to estimate noise"}
    b, c = statistics.median(base["p95s"]), statistics.median(cand["p95s"])
    noise = max(max(base["p95s"]) - min(base["p95s"]), max(cand["p95s"]) - min(cand["p95s"]))
    limit = b * (1 + max_regression)
    out.update(baseline_p95_ns=b, candidate_p95_ns=c, delta_ns=c - b, regression=(c - b) / b if b else None,
               noise_ns=noise, limit_ns=limit)
    if c <= limit:
        out["verdict"] = "pass"
    elif c - b > noise:
        out["verdict"] = "fail"
    else:
        out["verdict"] = "inconclusive"
        out["why"] = "over the limit but within the repeat spread; take more repeats"
    return out


def gate(base_path, cand_path, max_regression=0.10, min_repeats=3):
    base, cand = load(base_path), load(cand_path)
    results = {}
    for sid in sorted(set(base) | set(cand)):
        if sid not in base or sid not in cand:
            side = "candidate" if sid in base else "baseline"
            results[sid] = {"verdict": "insufficient", "why": f"scenario absent from the {side}"}
        else:
            results[sid] = compare(base[sid], cand[sid], max_regression, min_repeats)
    if not results:
        raise GateError("no perf records in either file")
    return results


def exit_status(results):
    verdicts = {r["verdict"] for r in results.values()}
    if "fail" in verdicts:
        return 1
    if verdicts & {"insufficient", "incomparable"}:
        return 2
    return 3 if "inconclusive" in verdicts else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("baseline")
    ap.add_argument("candidate")
    ap.add_argument("--max-regression", type=float, default=0.10, help="allowed p95 overhead growth (default 0.10)")
    ap.add_argument("--min-repeats", type=int, default=3, help="usable repeats per side to estimate noise (default 3)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.max_regression < 0 or a.min_repeats < 2:
        ap.error("--max-regression must be >= 0 and --min-repeats >= 2")
    try:
        results = gate(a.baseline, a.candidate, a.max_regression, a.min_repeats)
    except GateError as e:
        print(f"b09-gate: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(results, indent=1, sort_keys=True))
    else:
        for sid, r in results.items():
            line = f"{r['verdict']:<12} {sid}"
            if "baseline_p95_ns" in r:
                line += (f"  p95 {r['baseline_p95_ns'] / 1e6:.1f} -> {r['candidate_p95_ns'] / 1e6:.1f} ms"
                         f" ({r['regression'] * 100:+.1f}%), noise {r['noise_ns'] / 1e6:.1f} ms")
            if r.get("why"):
                line += f"  [{r['why']}]"
            print(line)
    return exit_status(results)


if __name__ == "__main__":
    sys.exit(main())
