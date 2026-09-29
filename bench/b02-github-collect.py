#!/usr/bin/env python3
"""B02: turn the bench branch's GitHub Actions runs into raw records.

    python bench/b02-github-collect.py > bench/b02-github-runner.jsonl

One JSON line per run of the sentinel-bench-b02 workflow: its commit
message, which carries the condition, the run's and job's timestamps, and
every step's. GitHub's timestamps have one-second resolution. The first run
of the branch primed the runner (setup-go's download) and is marked
`warmup`. A summary per condition goes to stderr.
"""
import json
import subprocess
import sys
from datetime import datetime

REPO = "RusticStack/lockwell"
BRANCH = "sentinel-bench/b02"


def ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() if value else None


def main():
    runs = []
    page = 1
    while True:
        batch = json.loads(subprocess.run(
            ["gh", "api", f"repos/{REPO}/actions/runs?branch={BRANCH}&per_page=100&page={page}"],
            check=True, capture_output=True, text=True).stdout)["workflow_runs"]
        runs += [r for r in batch if r["name"] == "sentinel-bench-b02"]
        if len(batch) < 100:
            break
        page += 1
    runs.sort(key=lambda r: r["created_at"])
    by = {}
    for i, run in enumerate(runs):
        jobs = json.loads(subprocess.run(
            ["gh", "api", f"repos/{REPO}/actions/runs/{run['id']}/jobs"],
            check=True, capture_output=True, text=True).stdout)["jobs"]
        job = jobs[0]
        message = run["head_commit"]["message"]
        condition = message.split("bench: condition ")[-1].strip() if "bench: condition" in message \
            else message.split("bench: ")[-1].replace(" sample", "").strip() if message.startswith("bench: ") else "warm"
        steps = [{
            "name": s["name"], "conclusion": s["conclusion"],
            "started_at": s["started_at"], "completed_at": s["completed_at"],
            "seconds": (ts(s["completed_at"]) - ts(s["started_at"])) if s["started_at"] and s["completed_at"] else None,
        } for s in job["steps"]]
        record = {
            "schema": "sentinel-bench/github-run/1",
            "contract": {"id": "lockwell-ci", "revision": 1, "lane": "unit", "condition": condition},
            "warmup": i == 0,
            "runner": {"name": job["runner_name"], "labels": job["labels"]},
            "run_id": run["id"], "head_sha": run["head_sha"], "conclusion": run["conclusion"],
            "created_at": run["created_at"], "job_started_at": job["started_at"],
            "job_completed_at": job["completed_at"],
            "queue_seconds": ts(job["started_at"]) - ts(run["created_at"]),
            "job_seconds": ts(job["completed_at"]) - ts(job["started_at"]),
            "steps": steps,
        }
        print(json.dumps(record, separators=(",", ":")))
        if not record["warmup"] and run["conclusion"] == "success":
            unit = next(s["seconds"] for s in steps if s["name"] == "Test (unit)")
            by.setdefault(condition, []).append((unit, record["job_seconds"], record["queue_seconds"]))
    for condition, rows in by.items():
        for k, name in enumerate(["Test (unit) step", "job", "queue"]):
            xs = sorted(r[k] for r in rows)
            rank = lambda p: xs[max(1, -(-int(p * len(xs) * 100) // 100)) - 1]
            print(f"{condition:10} {name:17} n={len(xs):2} min {xs[0]:5.0f} median {rank(0.5):5.0f} p95 {rank(0.95):5.0f} max {xs[-1]:5.0f} s", file=sys.stderr)


if __name__ == "__main__":
    main()
