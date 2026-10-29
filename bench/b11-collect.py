#!/usr/bin/env python3
"""B11 collector: paired, interleaved Sentinel and Blacksmith executions of one SHA.

    python bench/b11-collect.py collect LANE CONDITION PAIRS [--config FILE] [--records FILE] [--start N] [--no-warmup]
    python bench/b11-collect.py pairs RECORDS... [--dry-run] [--output FILE]   sentinel.b11-samples/1 for sentinel-b11
    python bench/b11-collect.py replay LANE [--baseline FILE]                 dry run on the GitHub self-hosted baseline

`collect` drives one series (lane and condition of bench/contracts/b11-blacksmith.json).
Every pair is a fresh commit: an empty commit (cold, warm) or a one-line edit of the
lane's compiled source (small-edit), pushed to the Sentinel mirror and to the
Blacksmith-backed mirror back to back, the first of the two alternating every pair
(Sentinel first in even pairs: ABBA). The commit's SHA is unique to the pair, so
the checks GitHub shows for it on each mirror are exactly that execution's. A
pair finishes before the next one starts; warm and small-edit series start with one
unrecorded warm-up pair (`warmup: true` in its records, never paired).

The clock is GitHub's own, for both sides: the trigger is `created_at` of the check
suite of the side's app (the instant GitHub records for the push), the end is the
latest `completed_at` among the side's required check runs, `job_ns` is the latest
completion minus the earliest start of those checks, and the `queue` and `run` phases
split the two. GitHub stamps have one-second resolution (`resolution_ns` in the
record); a figure that rounds to zero is absent, never zero. A required check that
fails (or was cancelled, timed out) is outcome `fail`; one that is missing, skipped
or neutral is `incorrect`; one that never completes within the timeout is `fail` with
`censored: true`, its duration the observation window (a lower bound), and it stays in
every distribution.

Records (`sentinel-bench/b11/1`) hold one execution per line with anonymized
provenance only. Repository names, remotes and hooks live in the git-ignored CONFIG
(`SENTINEL_B11_CONFIG`, default `.local/b11-config.json`; see
bench/b11-config.example.json), never in a record. `pairs` joins the two executions of
every pair into the file `sentinel-b11` reads, refusing anything unpaired or mixed.

`replay` is the plumbing dry run: it reads a committed GitHub self-hosted baseline
(bench/b01a-github-LANE.jsonl) and writes records whose two sides are that same
recorded run, labelled `dry_run`. It exercises the extraction, the record format, the
pairing and the harness; its ratio is 1.0 by construction and it is not evidence of
anything. No Blacksmith result is produced or claimed here.
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CONTRACT_PATH = os.path.join(HERE, "contracts", "b11-blacksmith.json")
RECORD = "sentinel-bench/b11/1"
SAMPLES = "sentinel.b11-samples/1"
CONFIG = "sentinel.b11-collector-config/1"
SIDES = ("sentinel", "blacksmith")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SECOND_NS = 1_000_000_000
# GitHub's one-second timestamps
RESOLUTION_NS = SECOND_NS
FAILED = {"failure", "cancelled", "timed_out", "action_required", "stale", "startup_failure"}
LABEL = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _load_b01a():
    """b01a-github.py's GitHub plumbing (gh api, subprocess runner, timestamps), reused rather than copied."""
    spec = importlib.util.spec_from_file_location("b01a_github", os.path.join(HERE, "b01a-github.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def contract():
    with open(CONTRACT_PATH) as f:
        return json.load(f)


def parse_ns(value):
    """ISO 8601 -> integer nanoseconds since the epoch, exact (no float)."""
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (stamp - EPOCH) // timedelta(microseconds=1) * 1000


def iso(ns):
    return (EPOCH + timedelta(microseconds=ns // 1000)).strftime("%Y-%m-%dT%H:%M:%SZ")


def label(value, what):
    """A provenance label is anonymized: lowercase words, never a repository, address or account."""
    if not isinstance(value, str) or not LABEL.match(value):
        raise SystemExit(f"{what}: {value!r} is not an anonymized label ({LABEL.pattern})")
    return value


# ---- the extraction: GitHub check data -> one execution -----------------------------------------


def execution(trigger_ns, checks, required):
    """Judge one side's execution from its check runs; None while a required check is missing or running.

    `checks` are check runs (`name`, `status`, `conclusion`, `started_at`, `completed_at`). Only the
    names in `required` count. Returns the measured fields of a record."""
    latest = {}
    for c in checks:
        if c["name"] in required:
            # the newest attempt of a name decides, as GitHub's `filter=latest` does
            previous = latest.get(c["name"])
            if previous is None or (c.get("started_at") or "") >= (previous.get("started_at") or ""):
                latest[c["name"]] = c
    if len(latest) < len(required) or any(c.get("status") != "completed" or not c.get("completed_at") for c in latest.values()):
        return None
    runs = [latest[n] for n in sorted(latest)]
    ends = [parse_ns(c["completed_at"]) for c in runs]
    starts = [parse_ns(c["started_at"]) for c in runs if c.get("started_at")]
    conclusions = {c.get("conclusion") for c in runs}
    if conclusions & FAILED:
        outcome = "fail"
    elif conclusions != {"success"}:
        outcome = "incorrect"  # skipped or neutral: a required check that did not run its assertions
    else:
        outcome = "pass"
    end = max(ends)
    if end <= trigger_ns:
        raise SystemExit(f"a required check completed at or before its trigger ({iso(end)} <= {iso(trigger_ns)}); refusing the sample")
    out = {"outcome": outcome, "trigger_to_required_ns": end - trigger_ns, "required_complete": iso(end)}
    first = min(starts) if starts else None
    # Absent, never zero: a figure under the clock's resolution is not a measurement.
    if first is not None and end > first:
        out["job_ns"] = end - first
        out["phases"] = {"run": end - first}
        if first > trigger_ns:
            out["phases"]["queue"] = first - trigger_ns
    out["checks"] = [{"name": c["name"], "conclusion": c.get("conclusion"),
                      "started": c.get("started_at"), "completed": c["completed_at"]} for c in runs]
    return out


def censored(window_ns, required):
    """A required check that never completed: a failed, right-censored execution (the window is a lower bound)."""
    return {"outcome": "fail", "censored": True, "trigger_to_required_ns": max(window_ns, 1), "checks": [],
            "required": sorted(required)}


# ---- records ------------------------------------------------------------------------------------


def make_record(c, lane, condition, pair, order, side, sha, measured, provenance, trigger_ns, warmup=False, dry_run=None):
    rec = {
        "schema": RECORD,
        "contract": {"id": c["id"], "revision": c["revision"], "lane": lane, "condition": condition},
        "repository": f"pilot/{lane}",
        "warmup": warmup,
        "order": order,
        "side": side,
        "sha": sha,
        "resolution_ns": RESOLUTION_NS,
        "provenance": provenance,
    }
    # A warm-up has no pair number and an execution that never triggered no trigger instant: absent, not null.
    if not warmup:
        rec["pair"] = pair
    if trigger_ns is not None:
        rec["trigger"] = iso(trigger_ns)
    rec.update(measured)
    if dry_run:
        rec["dry_run"] = True
        rec["dry_run_source"] = dry_run
    return rec


def order_of(pair):
    return "sentinel-first" if pair % 2 == 0 else "blacksmith-first"


def build_provenance(cfg, lane_cfg, side, condition, collector):
    s = lane_cfg[side]
    env = s["envelope"]
    if not all(isinstance(env.get(k), int) and env[k] > 0 for k in ("vcpu", "memory_mib")):
        raise SystemExit(f"{side}: envelope needs positive integer vcpu and memory_mib")
    return {
        "label": label(s["label"], f"{side}.label"),
        "host": label(s["host"], f"{side}.host"),
        "build": label(s.get("build", cfg.get("build", "")), f"{side}.build"),
        "envelope": {"vcpu": env["vcpu"], "memory_mib": env["memory_mib"]},
        "cache_state": label(s["cache_state"][condition], f"{side}.cache_state.{condition}"),
        "collector": collector,
    }


def collector_provenance():
    try:
        commit = subprocess.run(["git", "-C", HERE, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown"
    return {"commit": commit, "python": ".".join(map(str, sys.version_info[:3]))}


# ---- pairing: records -> sentinel.b11-samples/1 ---------------------------------------------------


def pair_records(records, c, allow_dry_run=False):
    """The pair lines `sentinel-b11` reads. Refuses unpaired, mixed or foreign records instead of repairing them."""
    lanes, conditions = set(c["series"]["lanes"]), set(c["series"]["conditions"])
    dry = {bool(r.get("dry_run")) for r in records}
    if len(dry) > 1:
        raise SystemExit("dry-run and live records in one input: refusing to mix them")
    if dry == {True} and not allow_dry_run:
        raise SystemExit("these are dry-run records (plumbing only, not evidence); pass --dry-run to pair them")
    if dry == {False} and allow_dry_run:
        raise SystemExit("--dry-run given but the records are live")
    groups = {}
    for r in records:
        if r.get("schema") != RECORD:
            raise SystemExit(f"not a {RECORD} record: {str(r)[:80]}")
        if r["warmup"]:
            continue
        k = r["contract"]
        if k["id"] != c["id"] or k["revision"] != c["revision"]:
            raise SystemExit(f"records were taken under {k['id']} revision {k['revision']}, the contract is {c['id']} revision {c['revision']}; never combined")
        if k["lane"] not in lanes or k["condition"] not in conditions:
            raise SystemExit(f"unknown series {k['lane']}/{k['condition']}")
        if r["side"] not in SIDES:
            raise SystemExit(f"unknown side {r['side']!r}")
        slot = groups.setdefault((k["lane"], k["condition"], r["pair"]), {})
        if r["side"] in slot:
            raise SystemExit(f"duplicate {r['side']} execution for {k['lane']}/{k['condition']} pair {r['pair']}")
        slot[r["side"]] = r
    lines = []
    for (lane, condition, pair), slot in sorted(groups.items()):
        if set(slot) != set(SIDES):
            raise SystemExit(f"{lane}/{condition} pair {pair} has only the {sorted(slot)[0]} execution: an unpaired sample is never dropped silently")
        s, b = slot["sentinel"], slot["blacksmith"]
        if s["order"] != b["order"]:
            raise SystemExit(f"{lane}/{condition} pair {pair}: the two executions disagree on the order")
        lines.append({"lane": lane, "condition": condition, "pair": pair, "order": s["order"],
                      "sentinel": sample_side(s), "blacksmith": sample_side(b)})
    return {"format": SAMPLES, "contract": c["id"], "revision": c["revision"]}, lines


def sample_side(r):
    if not SHA.match(r["sha"]):
        raise SystemExit(f"malformed SHA in a {r['side']} record")
    side = {"sha": r["sha"], "trigger_to_required_ns": r["trigger_to_required_ns"], "outcome": r["outcome"]}
    if r.get("censored"):
        side["censored"] = True
    if r.get("job_ns"):
        side["job_ns"] = r["job_ns"]
    if r.get("phases"):
        side["phases"] = {k: v for k, v in r["phases"].items() if v}
    return side


# ---- replay: the dry run on the committed baseline -------------------------------------------------


def replay(lane, baseline_path, c):
    """Records from a committed b01a baseline: both sides are the same recorded run; plumbing only."""
    source = os.path.relpath(baseline_path, os.path.dirname(HERE)).replace(os.sep, "/")
    provenance = {"label": "github-selfhosted-baseline", "host": "kvm-host", "build": "baseline",
                  "envelope": {"vcpu": 10, "memory_mib": 26 * 1024}, "cache_state": "caches-kept",
                  "collector": {"commit": "replay", "python": ".".join(map(str, sys.version_info[:3]))}}
    out, pair = [], 0
    with open(baseline_path) as f:
        runs = [json.loads(line) for line in f if line.strip()]
    for run in runs:
        if run.get("warmup"):
            continue
        if run["contract"]["lane"] != lane:
            raise SystemExit(f"{baseline_path} holds lane {run['contract']['lane']}, not {lane}")
        jobs = [j for j in run["jobs"] if j["conclusion"] != "skipped"]
        checks = [{"name": j["name"], "status": "completed", "conclusion": j["conclusion"],
                   "started_at": j["started"], "completed_at": j["completed"]} for j in jobs]
        trigger = parse_ns(run["created"])
        measured = execution(trigger, checks, {j["name"] for j in jobs})
        if measured is None:
            raise SystemExit(f"run {run['sha']} in {baseline_path} has an incomplete job")
        for side in SIDES:
            out.append(make_record(c, lane, "warm", pair, order_of(pair), side, run["sha"], dict(measured),
                                   provenance, trigger, dry_run=source))
        pair += 1
    return out


# ---- collect: the live series ------------------------------------------------------------------------


class Gh:
    """The GitHub reads of one side: its check suite (the trigger) and its check runs."""

    def __init__(self, b01a, repo, app):
        self.b01a, self.repo, self.app = b01a, repo, app

    def paged(self, path, key):
        items, page = [], 1
        while True:
            sep = "&" if "?" in path else "?"
            data = self.b01a.gh_json(f"{path}{sep}per_page=100&page={page}")
            items += data[key]
            if len(data[key]) < 100:
                return items
            page += 1

    def poll(self, sha, required):
        """(trigger_ns or None, measured or None) for the commit as it stands now."""
        suites = [s for s in self.paged(f"repos/{self.repo}/commits/{sha}/check-suites", "check_suites")
                  if (s.get("app") or {}).get("slug") == self.app]
        if not suites:
            return None, None
        trigger = min(parse_ns(s["created_at"]) for s in suites)
        checks = [r for r in self.paged(f"repos/{self.repo}/commits/{sha}/check-runs?filter=latest", "check_runs")
                  if (r.get("app") or {}).get("slug") == self.app]
        return trigger, execution(trigger, checks, set(required))


def load_config(path, lane):
    with open(path) as f:
        cfg = json.load(f)
    if cfg.get("format") != CONFIG:
        raise SystemExit(f"{path} is not a {CONFIG} file")
    if lane not in cfg["lanes"]:
        raise SystemExit(f"{path} has no lane {lane}")
    lane_cfg = cfg["lanes"][lane]
    s, b = lane_cfg["sentinel"], lane_cfg["blacksmith"]
    if s["repo"] == b["repo"]:
        raise SystemExit("both sides name one repository: they would trigger on a single push, not back to back; use two mirrors")
    for side in SIDES:
        if not lane_cfg[side].get("required"):
            raise SystemExit(f"{side}: list the required checks by name")
    return cfg, lane_cfg


def sh(*cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"{list(cmd[:4])} failed: {(r.stderr or '').strip()[:400]}")
    return r.stdout.strip()


def series_tree(lane_cfg, lane, condition):
    """A worktree on the series' own branch: samples never commit on what the clone has checked out."""
    branch = f"sentinel-bench/b11/{lane}-{condition}"
    clone = lane_cfg["clone"]
    tree = os.path.join(os.path.dirname(os.path.abspath(clone)), f"{lane}-b11-{condition}")
    if not os.path.isdir(tree):
        sh("git", "-C", clone, "worktree", "add", "-q", "-b", branch, tree, lane_cfg.get("base", "HEAD"))
    if sh("git", "-C", tree, "rev-parse", "--abbrev-ref", "HEAD") != branch:
        raise SystemExit(f"{tree} is not on {branch}")
    return tree, branch


def commit_for(tree, lane_cfg, condition, n, nonce):
    """The pair's commit: unchanged tree (cold, warm) or one marker line in a compiled source (small-edit)."""
    message = f"bench: b11 {condition} pair {n}"
    if condition == "small-edit":
        target = os.path.join(tree, lane_cfg["small_edit_file"])
        marker = f"{lane_cfg.get('small_edit_comment', '//')} sentinel-bench b11 nonce {nonce}"
        with open(target) as f:
            lines = [ln for ln in f.read().split("\n") if "sentinel-bench b11 nonce" not in ln]
        while lines and lines[-1] == "":
            lines.pop()
        with open(target, "w", newline="\n") as f:
            f.write("\n".join(lines + [marker]) + "\n")
        sh("git", "-C", tree, "add", "--", lane_cfg["small_edit_file"])
    sh("git", "-C", tree, "commit", "-q", "--allow-empty", "-m", message)
    return sh("git", "-C", tree, "rev-parse", "HEAD")


def run_pair(b01a, cfg, lane_cfg, c, lane, condition, n, warmup, tree, branch, collector):
    nonce = f"{int(time.time())}-{n}"
    sha = commit_for(tree, lane_cfg, condition, n, nonce)
    order = order_of(0 if warmup else n)
    first = order.split("-")[0]
    sequence = [first, "blacksmith" if first == "sentinel" else "sentinel"]
    # Cache and worker preparation first, so the two pushes are not separated by it.
    for side in sequence:
        for argv in lane_cfg[side].get("prepare", {}).get(condition, []):
            sh(*argv)
    pushed = {}
    for side in sequence:
        sh("git", "-C", tree, "push", "-q", lane_cfg[side]["remote"], f"HEAD:refs/heads/{branch}")
        pushed[side] = time.monotonic_ns()
    gh = {s: Gh(b01a, lane_cfg[s]["repo"], lane_cfg[s]["app"]) for s in SIDES}
    timeout_ns = int(cfg.get("timeout_seconds", 1800)) * SECOND_NS
    results, triggers = {}, {}
    while len(results) < 2:
        for side in sequence:
            if side in results:
                continue
            trigger, measured = gh[side].poll(sha, lane_cfg[side]["required"])
            if trigger is not None:
                triggers[side] = trigger
            if measured is not None:
                results[side] = measured
            elif time.monotonic_ns() - pushed[side] > timeout_ns:
                results[side] = censored(time.monotonic_ns() - pushed[side], lane_cfg[side]["required"])
        if len(results) < 2:
            time.sleep(int(cfg.get("poll_seconds", 10)))
    records = []
    for side in sequence:
        records.append(make_record(c, lane, condition, n, order, side, sha, results[side],
                                   build_provenance(cfg, lane_cfg, side, condition, collector),
                                   triggers.get(side), warmup=warmup))
    return records


def append(path, records):
    with open(path, "a") as f:
        for r in records:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())


def collect(args):
    c = contract()
    if args.lane not in c["series"]["lanes"] or args.condition not in c["series"]["conditions"]:
        raise SystemExit(f"{args.lane}/{args.condition} is not a series of {c['id']} revision {c['revision']}")
    cfg, lane_cfg = load_config(args.config, args.lane)
    b01a = _load_b01a()
    tree, branch = series_tree(lane_cfg, args.lane, args.condition)
    collector = collector_provenance()
    if args.condition != "cold" and not args.no_warmup and args.start == 0:
        append(args.records, run_pair(b01a, cfg, lane_cfg, c, args.lane, args.condition, 0, True, tree, branch, collector))
        print(f"{args.lane}/{args.condition}: warm-up pair done", file=sys.stderr)
    for n in range(args.start, args.start + args.pairs):
        records = run_pair(b01a, cfg, lane_cfg, c, args.lane, args.condition, n, False, tree, branch, collector)
        append(args.records, records)
        print(f"{args.lane}/{args.condition} pair {n}: " + ", ".join(f"{r['side']} {r['outcome']} {r['trigger_to_required_ns'] / SECOND_NS:.0f}s" for r in records), file=sys.stderr)


def read_records(paths):
    out = []
    for p in paths:
        with open(p) as f:
            out += [json.loads(line) for line in f if line.strip()]
    return out


def emit(header, lines, output):
    text = "\n".join(json.dumps(x, separators=(",", ":")) for x in [header] + lines) + "\n"
    if output:
        with open(output, "w", newline="\n") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("collect")
    s.add_argument("--config", default=os.environ.get("SENTINEL_B11_CONFIG", os.path.join(".local", "b11-config.json")))
    s.add_argument("lane")
    s.add_argument("condition")
    s.add_argument("pairs", type=int)
    s.add_argument("--records", default="b11-records.jsonl")
    s.add_argument("--start", type=int, default=0)
    s.add_argument("--no-warmup", action="store_true")
    s = sub.add_parser("pairs")
    s.add_argument("records", nargs="+")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--output")
    s = sub.add_parser("replay")
    s.add_argument("lane")
    s.add_argument("--baseline")
    s.add_argument("--output")
    args = p.parse_args(argv)
    if args.mode == "collect":
        if args.pairs < 1 or args.start < 0:
            raise SystemExit("pairs must be at least 1")
        collect(args)
    elif args.mode == "pairs":
        header, lines = pair_records(read_records(args.records), contract(), args.dry_run)
        emit(header, lines, args.output)
    else:
        baseline = args.baseline or os.path.join(HERE, f"b01a-github-{args.lane}.jsonl")
        emit_records = replay(args.lane, baseline, contract())
        text = "\n".join(json.dumps(r, separators=(",", ":")) for r in emit_records) + "\n"
        if args.output:
            with open(args.output, "w", newline="\n") as f:
                f.write(text)
        else:
            sys.stdout.write(text)


if __name__ == "__main__":
    main(sys.argv[1:])
