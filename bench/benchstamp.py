#!/usr/bin/env python3
"""The build and host stamp every benchmark record writer in Python shares (and the shell writers reach through
`bench/stamp.sh`), so the rules live in one place:

  * the record names the commit of the checkout the measured build came from, and whether a tracked file
    differed from it; a commit or a dirty state git cannot report refuses the run, never a null in the record;
  * the host is named by an anonymized label from SENTINEL_BENCH_HOST_LABEL (lower-case letters, digits and
    hyphens, no address); a missing or malformed label refuses the run before the first sample, so a quiet-host
    window is not spent on records that cannot be committed.

    python3 bench/benchstamp.py --check-label            exits 1 with a one-line reason when the label is unusable
    python3 bench/benchstamp.py --source DIR [--binary FILE]   prints the stamp object

The rules are enforced on committed records by `bench/test_bench_hygiene.py`, which imports HOST_LABEL and IPV4.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HOST_LABEL = re.compile(r"^[a-z][a-z0-9-]*$")
IPV4 = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
LABEL_ENV = "SENTINEL_BENCH_HOST_LABEL"


def label_problem(label):
    """Why `label` cannot name a host in a committed record, or None."""
    if not label:
        return f"{LABEL_ENV} is not set; name the host with an anonymized label (for example reference-host)"
    if not HOST_LABEL.match(label) or IPV4.search(label):
        return f"{LABEL_ENV} must be an anonymized label (lower-case letters, digits and hyphens, no address)"
    return None


def host_label(environ=None):
    """The validated host label; raises SystemExit with the reason when it is missing or malformed."""
    label = (os.environ if environ is None else environ).get(LABEL_ENV, "")
    problem = label_problem(label)
    if problem:
        raise SystemExit(problem)
    return label


def read_first(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def field(path, key):
    try:
        with open(path) as f:
            for line in f:
                k, _, v = line.partition(":")
                if k.strip() == key:
                    return v.strip()
    except OSError:
        pass
    return None


def build(source, binary=None, sha256=hashlib.sha256):
    """`{"commit", "dirty"[, "binary_sha256"]}` of the checkout `source`. Dirty means a tracked file differs from
    HEAD (untracked files are ignored: a scratch file does not change what was built)."""
    def git(*args):
        r = subprocess.run(["git", "-C", source, *args], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    if not commit:
        raise SystemExit(f"cannot read the source commit of {source}; no record is written without it")
    status = git("status", "--porcelain", "--untracked-files=no")
    if status is None:
        raise SystemExit(f"cannot read the tracked-change state of {source}; no record is written without it")
    out = {"commit": commit, "dirty": bool(status)}
    if binary:
        with open(binary, "rb") as f:
            out["binary_sha256"] = sha256(f.read()).hexdigest()
    return out


def host(label=None):
    """The host block: the validated label plus what the kernel says about the machine. A value the kernel does
    not expose is absent, never a default."""
    mem = field("/proc/meminfo", "MemTotal")
    block = {
        "hostname": host_label() if label is None else label,
        "kernel": read_first("/proc/sys/kernel/osrelease"),
        "cpu_model": field("/proc/cpuinfo", "model name"),
        "cpus_online": os.cpu_count(),
        "mem_total_kib": int(mem.split()[0]) if mem else None,
        "cpu_governor": read_first("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
    }
    return {k: v for k, v in block.items() if v is not None}


def stamp(source, binary=None):
    """`{"build": {...}, "host": {...}}`, refusing (SystemExit) before anything is measured when either half is
    incomplete."""
    label = host_label()
    return {"build": build(source, binary), "host": host(label)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check-label", action="store_true")
    ap.add_argument("--source")
    ap.add_argument("--binary")
    a = ap.parse_args(argv)
    if a.check_label:
        problem = label_problem(os.environ.get(LABEL_ENV, ""))
        if problem:
            print(problem, file=sys.stderr)
            return 1
        return 0
    if not a.source:
        ap.error("--source or --check-label is required")
    print(json.dumps(stamp(a.source, a.binary), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
