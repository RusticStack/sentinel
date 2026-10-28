"""Hygiene checks for the benchmark scripts and committed records (RW10).

    python3 -m unittest bench/test_bench_hygiene.py        (run on a verification host, see docs/benchmarking.md)

Three rules, each with its exceptions written down here:
  * a script that takes the benchmark lock uses `flock -o`, so the command it starts does not inherit the lock;
  * every committed record under bench/*.jsonl carries `build.commit` and an anonymized `host.hostname`,
    except the files in LEGACY_UNSTAMPED, which predate the stamp and are kept as measured;
  * every record writer that exists today names the stamp it uses.
"""
import glob
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

# Committed before the build and host stamp existed (or, for GitHub-collected baselines and the
# development-host files, measuring nothing Sentinel built), so they cannot be stamped after the
# fact without inventing the commit. The set is exact: a file that gains a stamp must leave it.
LEGACY_UNSTAMPED = {
    "b01-isolation.jsonl": "taken before the stamp; host label present, no build",
    "b01a-github-cli-cached-tests.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b01a-github-cli.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b01a-github-gson.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b01a-github-ripgrep.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b02-github-runner.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b02-sentinel.jsonl": "taken before the stamp (commit null in the tracker)",
    "b02-woodpecker.jsonl": "Woodpecker baseline; no Sentinel build is measured",
    "b03-before-fixes.jsonl": "the pre-fix run; the build it ran is not recoverable",
    "b03-latency.jsonl": "taken before the stamp; superseded by b03-rerun*.jsonl",
    "b04-pipeline-fetch.jsonl": "taken before the stamp",
    "b04-transfer-copies.jsonl": "taken before the stamp",
    "b11-dryrun-records.jsonl": "dry-run output of the paired harness; no measured build",
    "b11-dryrun-samples.jsonl": "dry-run samples of the paired harness; no measured build",
    "c02-engines.jsonl": "taken before the stamp",
    "f05-noop-baseline.jsonl": "taken before the stamp (host label present)",
    "f05-noop-vps.jsonl": "taken before the stamp (host label present)",
    "f06-legacy-go-ci-runs.jsonl": "legacy Go CI runs; no Sentinel build is measured",
    "f07-storage.jsonl": "taken before the stamp",
    "k02-cache-clone.jsonl": "taken before the stamp",
    "k07-recipes.jsonl": "taken before the stamp",
    "k09-before-after.jsonl": "taken before the stamp",
    "m02-boot.jsonl": "taken before the stamp (host label present)",
    "q09-fleet-load.jsonl": "taken before the stamp; a `code` field names the build in prose",
    "r04-backup-drill.jsonl": "taken before the stamp",
    "r06-idle.jsonl": "taken before the stamp",
    "u01-log-view.jsonl": "taken before the stamp",
}

# Writers that stamp, and the marker that shows how.
STAMPED_WRITERS = {
    "b02-sentinel.sh": '"build"',
    "b03-latency.py": "def stamp(",
    "c02-engines.sh": "stamp.sh",
    "f07-storage.sh": "stamp.sh",
    "k02-cache-clone.sh": "stamp.sh",
    "k07-recipes.sh": "stamp.sh",
    "k09-before-after.sh": "stamp.sh",
    "p14-pilot.sh": '"build"',
    "r06-idle.sh": "stamp.sh",
}

HOST_LABEL = re.compile(r"^[a-z][a-z0-9-]*$")
IPV4 = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")


def records(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def stamp_problems(rec):
    out = []
    build, host = rec.get("build"), rec.get("host")
    if not isinstance(build, dict) or not build.get("commit"):
        out.append("build.commit missing or null")
    if not isinstance(host, dict) or not host.get("hostname"):
        out.append("host.hostname missing")
    elif not HOST_LABEL.match(host["hostname"]) or IPV4.search(host["hostname"]):
        out.append(f"host.hostname {host['hostname']!r} is not an anonymized label")
    return out


class LockHandling(unittest.TestCase):
    def test_every_flock_on_a_command_uses_o(self):
        offenders = []
        for path in sorted(glob.glob(os.path.join(HERE, "*.sh")) + glob.glob(os.path.join(HERE, "*.py"))):
            if os.path.basename(path) == os.path.basename(__file__):
                continue
            with open(path, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    code = line.split("#", 1)[0] if path.endswith(".sh") else line
                    m = re.search(r"(?<![\w./-])flock\s+(.*)", code)
                    if not m:
                        continue
                    args = m.group(1).split()
                    # `flock FD` / `flock -n FD` hold a descriptor the shell owns; only the command form forks a child.
                    positional = [a for a in args if not a.startswith("-")]
                    if len(positional) < 2:
                        continue
                    flags = " ".join(a for a in args if a.startswith("-"))
                    if not re.search(r"(^|\s)-\w*o\w*(\s|$)|--close", flags):
                        offenders.append(f"{os.path.basename(path)}:{n}: {line.strip()}")
        self.assertEqual(offenders, [], "flock without -o lets the started command inherit the benchmark lock")

    def test_the_known_lock_users_still_take_it(self):
        for name in ("b05-cache.sh", "b05-workloads.sh"):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                self.assertRegex(f.read(), r"flock -x -o ", name)

    def test_b01a_names_the_reference_host(self):
        with open(os.path.join(HERE, "b01a-github.py"), encoding="utf-8") as f:
            doc = f.read().split('"""')[1]
        self.assertIn("reference host", doc)
        self.assertNotIn("verification VPS", doc)


class RecordStamps(unittest.TestCase):
    def files(self):
        return sorted(glob.glob(os.path.join(HERE, "*.jsonl")))

    def test_legacy_table_names_only_existing_files_that_are_still_unstamped(self):
        names = {os.path.basename(p) for p in self.files()}
        self.assertEqual(sorted(set(LEGACY_UNSTAMPED) - names), [], "exception for a file that does not exist")
        now_clean = [n for n in LEGACY_UNSTAMPED
                     if all(not stamp_problems(r) for r in records(os.path.join(HERE, n)))]
        self.assertEqual(now_clean, [], "fully stamped now: remove from LEGACY_UNSTAMPED")

    def test_every_other_file_is_stamped_on_every_record(self):
        bad = []
        for path in self.files():
            name = os.path.basename(path)
            if name in LEGACY_UNSTAMPED:
                continue
            for n, rec in enumerate(records(path), 1):
                for p in stamp_problems(rec):
                    bad.append(f"{name}:{n}: {p}")
        self.assertEqual(bad[:10], [], f"{len(bad)} unstamped records outside LEGACY_UNSTAMPED")

    def test_no_record_names_a_host_by_address(self):
        # Kernel versions look like addresses (6.18.33.2), so only host.hostname is checked.
        for path in self.files():
            for n, rec in enumerate(records(path), 1):
                host = rec.get("host")
                if not isinstance(host, dict):
                    continue
                self.assertIsNone(IPV4.search(str(host.get("hostname", ""))), f"{os.path.basename(path)}:{n}")

    def test_stamp_detection_rejects_what_it_should(self):
        ok = {"build": {"commit": "a" * 40}, "host": {"hostname": "reference-host"}}
        self.assertEqual(stamp_problems(ok), [])
        self.assertTrue(stamp_problems({**ok, "build": {"commit": None}}))
        self.assertTrue(stamp_problems({**ok, "host": {"hostname": "10.0.0.1"}}))
        self.assertTrue(stamp_problems({**ok, "host": {"hostname": "Node.example.com"}}))
        self.assertTrue(stamp_problems({"host": ok["host"]}))

    def test_writers_carry_their_stamp(self):
        for name, marker in STAMPED_WRITERS.items():
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                self.assertIn(marker, f.read(), name)


if __name__ == "__main__":
    unittest.main()
