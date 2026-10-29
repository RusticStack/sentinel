#!/usr/bin/env python3
"""B06: list the workflows of each pilot at its pinned commit, from the operator mirror.

    b06_inventory.py [--contract bench/contracts/pilots-ci.json] [--only NAME]

The mirror URL of each pilot comes from SENTINEL_PILOT_CLI_URL,
SENTINEL_PILOT_RIPGREP_URL or SENTINEL_PILOT_GSON_URL, the variables
p14-pilot.sh reads. The script never contacts the upstream address in the
contract. Per pilot it makes a blob-less shallow fetch of the pinned commit
into a scratch repository (under TMPDIR), lists `.github/workflows/`, reads
each file by blob id and prints one JSON line:

    {"pilot", "commit", "workflows": [{"path", "blob", "name", "jobs": [...]}]}

The line carries no URL and no host. A missing variable, a mirror without the
pinned commit, or a fetch failure is an error line with the reason on stderr
and exit status 1; it is never an empty inventory.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

VARIABLES = {"cli": "SENTINEL_PILOT_CLI_URL", "ripgrep": "SENTINEL_PILOT_RIPGREP_URL", "gson": "SENTINEL_PILOT_GSON_URL"}
WORKFLOWS = ".github/workflows/"


def git(repo, *args):
    out = subprocess.run(["git", "-C", repo, *args], capture_output=True, check=False)
    if out.returncode != 0:
        # the command line can hold the mirror URL, so only git's own message is reported
        raise RuntimeError(out.stderr.decode(errors="replace").strip().splitlines()[-1:] or ["git failed"])
    return out.stdout


def workflow_summary(text):
    """The workflow's `name:` and the job ids under the top-level `jobs:` key."""
    name = None
    jobs = []
    in_jobs = False
    for line in text.splitlines():
        if re.match(r"^name:", line) and name is None:
            name = line.split(":", 1)[1].strip().strip("\"'") or None
        if re.match(r"^jobs:\s*(#.*)?$", line):
            in_jobs = True
            continue
        if in_jobs:
            if re.match(r"^\S", line) and not line.startswith("#"):
                in_jobs = False
                continue
            m = re.match(r"^  ([A-Za-z0-9_][A-Za-z0-9_-]*):\s*(#.*)?$", line)
            if m:
                jobs.append(m.group(1))
    return name, jobs


def inventory(repo, commit):
    names = git(repo, "ls-tree", "-r", "--full-tree", commit, "--", WORKFLOWS).decode().splitlines()
    out = []
    for line in names:
        meta, _, path = line.partition("\t")
        blob = meta.split()[2]
        name, jobs = workflow_summary(git(repo, "cat-file", "blob", blob).decode(errors="replace"))
        out.append({"path": path, "blob": blob, "name": name, "jobs": jobs})
    return sorted(out, key=lambda w: w["path"])


def fetch(url, commit, scratch):
    repo = os.path.join(scratch, "repo")
    subprocess.run(["git", "init", "-q", repo], check=True, capture_output=True)
    git(repo, "remote", "add", "origin", url)
    git(repo, "config", "remote.origin.promisor", "true")
    git(repo, "config", "remote.origin.partialclonefilter", "blob:none")
    git(repo, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit)
    if git(repo, "rev-parse", "FETCH_HEAD^{commit}").decode().strip() != commit:
        raise RuntimeError(["the mirror answered with a different commit than the pinned one"])
    return repo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", default=os.path.join(os.path.dirname(__file__), "contracts", "pilots-ci.json"))
    ap.add_argument("--only")
    args = ap.parse_args()
    sources = {s["name"]: s["commit"] for s in json.load(open(args.contract))["sources"]}
    failed = False
    for pilot, commit in sources.items():
        if args.only and pilot != args.only:
            continue
        url = os.environ.get(VARIABLES.get(pilot, ""), "")
        if not url:
            print(f"{pilot}: {VARIABLES.get(pilot)} is not set; no mirror, no inventory", file=sys.stderr)
            failed = True
            continue
        try:
            with tempfile.TemporaryDirectory(prefix="b06-") as scratch:
                repo = fetch(url, commit, scratch)
                print(json.dumps({"pilot": pilot, "commit": commit, "workflows": inventory(repo, commit)}, sort_keys=True))
        except (RuntimeError, subprocess.CalledProcessError) as e:
            reason = e.args[0] if isinstance(e, RuntimeError) else ["git failed"]
            print(f"{pilot}: {' '.join(map(str, reason))[:300].replace(url, '<mirror>')}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
