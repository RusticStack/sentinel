#!/usr/bin/env python3
"""Runs one `#[ignore]` measurement test under a micro-contract and prints one record.

    python3 bench/run_ignored.py [--list-only] PACKAGE TEST_TARGET TEST_NAME

It is the script harness of the q09-fleet-load, queue-explain, backup-drill, remote-cost and tailcat-live contracts
(bench/contracts/micro/): `cargo test --release --locked -p PACKAGE --test TEST_TARGET -- --ignored --nocapture
--exact TEST_NAME`, run from SENTINEL_SRC (default: the checkout this script is in). The test's own stdout lines that
start with `{` are JSON reports; they come back inside one record

    {"schema": "sentinel-bench/ignored-test/1", "package": ..., "test_target": ..., "test": ..., "outcome": "ok",
     "test_elapsed_ns": <monotonic, the whole cargo test, build included when the binary was not built>, "reports": [...]}

so the runner stamps and appends it like any other record. SENTINEL_BENCH_OUT is removed from the test's environment:
the tests append an unstamped line to it, and the runner is the only writer of a record.

Nothing is printed, and the exit status is not 0, when the test failed, when it did not run exactly once, or when it
skipped itself (a line of its stderr says "skipping"; exit 75, pending, because a skipped test measured nothing). With
`--list-only` the test is not run: the script checks that the target lists the name as an ignored test and prints a
`"outcome": "listed"` record. That is the smoke check of a measurement that has no tiny parameters.
"""
import json
import os
import re
import subprocess
import sys
import time

SCHEMA = "sentinel-bench/ignored-test/1"
NAME = re.compile(r"^[A-Za-z0-9_:.-]+$")
SKIP = re.compile(r"\bskipp(?:ing|ed)\b", re.IGNORECASE)


def usage(msg):
    print(f"run_ignored: {msg}", file=sys.stderr)
    return 2


def cargo(src, package, target, tail, env):
    cmd = ["cargo", "test", "--release", "--locked", "-p", package, "--test", target, "--", *tail]
    return subprocess.run(cmd, cwd=src, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def main(argv):
    list_only = False
    args = list(argv)
    if args and args[0] == "--list-only":
        list_only = True
        args.pop(0)
    if len(args) != 3:
        return usage("expected PACKAGE TEST_TARGET TEST_NAME")
    package, target, test = args
    for value in args:
        if not NAME.match(value):
            return usage("a package, target or test name has characters a cargo name does not")
    src = os.environ.get("SENTINEL_SRC") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {k: v for k, v in os.environ.items() if k != "SENTINEL_BENCH_OUT"}

    if list_only:
        r = cargo(src, package, target, ["--list", "--ignored", "--format", "terse"], env)
        sys.stderr.write(r.stderr[-4000:])
        listed = [line.split(":")[0] for line in r.stdout.splitlines() if line.endswith(": test")]
        if r.returncode != 0:
            return r.returncode
        if listed.count(test) != 1:
            return usage(f"{target} does not list exactly one ignored test named {test} (it lists {len(listed)})")
        print(json.dumps({"schema": SCHEMA, "package": package, "test_target": target, "test": test, "outcome": "listed"}))
        return 0

    started = time.monotonic_ns()
    r = cargo(src, package, target, ["--ignored", "--nocapture", "--exact", test], env)
    elapsed = time.monotonic_ns() - started
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        return r.returncode
    if SKIP.search(r.stderr):
        print("run_ignored: the test skipped itself, so it measured nothing", file=sys.stderr)
        return 75
    result = re.search(r"test result: ok\. (\d+) passed; 0 failed", r.stdout + r.stderr)
    if not result or int(result.group(1)) != 1:
        return usage(f"{test} did not run exactly once")
    reports = []
    for line in r.stdout.splitlines():
        if line.startswith("{"):
            try:
                reports.append(json.loads(line))
            except ValueError:
                return usage("a report line is not JSON")
    print(json.dumps({"schema": SCHEMA, "package": package, "test_target": target, "test": test,
                      "outcome": "ok", "test_elapsed_ns": elapsed, "reports": reports}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
