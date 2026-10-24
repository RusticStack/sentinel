#!/usr/bin/env python3
"""B01a: a pilot's same-hardware GitHub Actions baseline on the reference host.

    python bench/b01a-github.py sample PILOT CLONE SAMPLES   push SAMPLES commits to the bench branch, one run at a time
    python bench/b01a-github.py collect PILOT [SINCE] > bench/b01a-github-PILOT.jsonl   runs since SINCE (ISO 8601) only

The pilot's runners (labelled p14-PILOT, one per job Sentinel runs at once:
cli 1, ripgrep 1, gson 3) live on the reference host in the systemd slice
sentinel-gh.slice (CPUQuota 1000 %, MemoryMax 26G, no swap): the contract's total
allocation, on the CPUs the contract gives the baseline. `sample` brings them
online only while it holds the baseline lock there (GH_DIR/sentinel-run-gh.sh) and
takes them down after the last run. SENTINEL_GH_DIR (default /srv/sentinel/runs)
is that directory and SENTINEL_SSH_CONFIG an optional ssh config file (from Git Bash,
export MSYS2_ENV_CONV_EXCL=SENTINEL_GH_DIR, or it arrives as a Windows path).
CLONE is a local clone of the fork; samples commit in a worktree of it pinned to
sentinel-bench/b01a, never on what CLONE has checked out, and only the lane's own
workflow run counts; a run whose jobs did not all use the p14-PILOT runners is refused. The first
run after the runners start is the warm-up (it fills the runner tool cache and
any actions/cache entry) and is marked so by `collect`.

`collect` writes one JSON line per run: its commit, the run's created and
updated stamps, and every job's and step's start and end. GitHub's stamps have
one-second resolution; durations are seconds from them, never monotonic.
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime

BRANCH = "sentinel-bench/b01a"
REPOS = {pilot: os.environ.get(f"SENTINEL_PILOT_{pilot.upper()}_REPO", "") for pilot in ("cli", "ripgrep", "gson")}
# The lane's own workflow: a push to the branch may start others, and only this one is the baseline.
WORKFLOWS = {"cli": "go.yml", "ripgrep": "ci.yml", "gson": "build.yml"}
# The benchmark host, from the git-ignored .env (SENTINEL_VPS_USER@SENTINEL_VPS_HOST).
VPS = os.environ.get("SENTINEL_VPS_HOST", "")
if user := os.environ.get("SENTINEL_VPS_USER", ""):
    VPS = f"{user}@{VPS}"
GH_DIR = os.environ.get("SENTINEL_GH_DIR", "/srv/sentinel/runs")
CONTRACT = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "contracts", "pilots-ci.json")))


def sh(*cmd, capture=True):
    r = subprocess.run(cmd, capture_output=capture, text=True)
    if r.returncode != 0:
        raise SystemExit(f"{cmd[:4]} failed: {(r.stderr or '').strip()[:400]}")
    return (r.stdout or "").strip()


def ssh(command):
    config = os.environ.get("SENTINEL_SSH_CONFIG")
    return sh("ssh", *(["-F", config] if config else []), "-o", "BatchMode=yes", VPS, command)


def gh_json(path):
    return json.loads(sh("gh", "api", path))


def runs_of(pilot, query):
    return gh_json(f"repos/{REPOS[pilot]}/actions/workflows/{WORKFLOWS[pilot]}/runs?branch={BRANCH}&{query}")["workflow_runs"]


def run_for(pilot, sha):
    for _ in range(120):
        runs = runs_of(pilot, f"head_sha={sha}&per_page=5")
        if runs:
            return runs[0]["id"]
        time.sleep(5)
    raise SystemExit(f"no {WORKFLOWS[pilot]} run appeared for {sha}")


def bench_tree(pilot, clone):
    """A worktree of the clone pinned to the bench branch: samples never commit on whatever the clone has checked out."""
    tree = os.path.join(os.path.dirname(os.path.abspath(clone)), f"{pilot}-b01a")
    if not os.path.isdir(tree):
        sh("git", "-C", clone, "worktree", "add", "-q", tree, BRANCH)
    if sh("git", "-C", tree, "rev-parse", "--abbrev-ref", "HEAD") != BRANCH:
        raise SystemExit(f"{tree} is not on {BRANCH}")
    return tree


def sample(pilot, clone, count):
    repo = REPOS[pilot]
    if not repo:
        raise SystemExit(f"set SENTINEL_PILOT_{pilot.upper()}_REPO to the private mirror's owner/repository")
    if not os.environ.get("SENTINEL_VPS_HOST"):
        raise SystemExit("set SENTINEL_VPS_HOST (and optionally SENTINEL_VPS_USER) to the benchmark host")
    tree = bench_tree(pilot, clone)
    # A transient system unit, so the holder never depends on this ssh session outliving it.
    ssh(f"systemd-run --quiet --collect --unit=sentinel-run-gh-{pilot}-$(date +%s) {GH_DIR}/sentinel-run-gh.sh {pilot}")
    print(f"{pilot}: waiting for the lock and the runners", file=sys.stderr)
    for _ in range(4320):
        if ssh(f"test -f {GH_DIR}/sentinel-run-gh-{pilot}.online && echo y || true") == "y":
            break
        time.sleep(20)
    else:
        raise SystemExit("the runners never came online")
    try:
        for n in range(count):
            sh("git", "-C", tree, "commit", "-q", "--allow-empty", "-m", f"bench: b01a sample {n}")
            sha = sh("git", "-C", tree, "rev-parse", "HEAD")
            sh("git", "-C", tree, "push", "-q", "origin", f"HEAD:{BRANCH}")
            run = run_for(pilot, sha)
            # `gh run watch` returns at once for a run that has not started; poll until GitHub says it is done.
            while (state := gh_json(f"repos/{repo}/actions/runs/{run}"))["status"] != "completed":
                time.sleep(15)
            conclusion = state["conclusion"]
            jobs = gh_json(f"repos/{repo}/actions/runs/{run}/jobs?per_page=100")["jobs"]
            foreign = sorted({j.get("runner_name") or "none" for j in jobs if j.get("conclusion") != "skipped"
                              and not (j.get("runner_name") or "").startswith(f"p14-{pilot}-")})
            if foreign:
                raise SystemExit(f"run {run} used runners outside p14-{pilot}: {foreign}; not a baseline sample")
            print(f"{pilot} sample {n}: run {run} {conclusion}", file=sys.stderr)
    finally:
        ssh(f"touch {GH_DIR}/sentinel-run-gh-{pilot}.done")


def ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() if value else None


def collect(pilot, since=None):
    """Runs created at or after `since` (ISO 8601), when given: an earlier series on the same branch is not this one."""
    repo = REPOS[pilot]
    if not repo:
        raise SystemExit(f"set SENTINEL_PILOT_{pilot.upper()}_REPO to the private mirror's owner/repository")
    runs, page = [], 1
    while True:
        batch = runs_of(pilot, f"per_page=100&page={page}")
        runs += batch
        if len(batch) < 100:
            break
        page += 1
    runs.sort(key=lambda r: r["created_at"])
    first_started = None
    sample = 0
    for r in runs:
        if r["status"] != "completed" or (since and ts(r["created_at"]) < ts(since)):
            continue
        jobs = gh_json(f"repos/{repo}/actions/runs/{r['id']}/jobs?per_page=100")["jobs"]
        if any(j.get("conclusion") != "skipped" and not (j.get("runner_name") or "").startswith(f"p14-{pilot}-") for j in jobs):
            continue
        started = min((ts(j["started_at"]) for j in jobs if j.get("started_at")), default=None)
        ended = max((ts(j["completed_at"]) for j in jobs if j.get("completed_at")), default=None)
        warmup = first_started is None
        first_started = first_started or started
        sample += 1
        print(json.dumps({
            "schema": "sentinel-bench/b01a-github/1",
            "contract": {"id": "pilots-ci", "revision": CONTRACT["revision"], "lane": pilot},
            "repository": f"pilot/{pilot}", "run": sample, "sha": r["head_sha"], "message": r["head_commit"]["message"],
            "conclusion": r["conclusion"], "warmup": warmup,
            "created": r["created_at"], "updated": r["updated_at"],
            "push_to_last_job_s": ended - ts(r["created_at"]) if ended else None,
            "first_job_to_last_job_s": ended - started if ended and started else None,
            "jobs": [{"name": j["name"], "runner": j.get("runner_name"), "conclusion": j["conclusion"],
                      "started": j["started_at"], "completed": j["completed_at"],
                      "steps": [{"name": s["name"], "conclusion": s["conclusion"],
                                 "started": s.get("started_at"), "completed": s.get("completed_at")}
                                for s in j.get("steps", [])]} for j in jobs],
        }, separators=(",", ":")))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "sample" and len(sys.argv) == 5:
        sample(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    elif mode == "collect" and len(sys.argv) in (3, 4):
        collect(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)
    else:
        raise SystemExit(__doc__)
