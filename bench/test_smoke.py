"""bench/smoke.sh counts passes, pending runs, missing binaries and failures apart, and fails only on a failure."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LINUX = sys.platform.startswith("linux")


def contract(name, script, build="cargo build"):
    return {"format": "sentinel.bench-micro-contract/1", "id": name, "revision": 1,
            "harness": {"script": script, "build": build},
            "run": {"args": [], "smoke_args": []},
            "ordering": {"scheme": "single", "seed": None},
            "quiet_start": {"max_cpu_pressure_avg60": 5.0},
            "record": {"schema": "fake/1", "out": f"bench/{name}.jsonl"}}


@unittest.skipUnless(LINUX, "needs Linux and bash")
class Smoke(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="smoke-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.dir = os.path.join(self.tmp, "contracts")
        os.makedirs(self.dir)

    def bench(self, name, body):
        path = os.path.join(self.tmp, name + ".sh")
        with open(path, "w", newline="\n") as f:
            f.write(body)
        return path

    def add(self, name, script, **kw):
        with open(os.path.join(self.dir, name + ".json"), "w") as f:
            json.dump(contract(name, script, **kw), f)

    def run_smoke(self, **env):
        pressure = os.path.join(self.tmp, "pressure")
        with open(pressure, "w") as f:
            f.write("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
        e = dict(os.environ, SMOKE_CONTRACTS=self.dir, SMOKE_SKIP_PY="1", TMPDIR=self.tmp,
                 SENTINEL_VERIFY_LOCK=os.path.join(self.tmp, "verify.lock"), SENTINEL_PRESSURE_FILE=pressure, **env)
        return subprocess.run(["bash", os.path.join(HERE, "smoke.sh")], capture_output=True, text=True, env=e)

    def test_the_four_outcomes_are_counted_apart_and_only_a_failure_is_red(self):
        self.add("a-pass", self.bench("ok", 'echo \'{"schema":"fake/1"}\'\n'))
        self.add("b-pending", self.bench("busy", "echo busy >&2; exit 75\n"))
        missing = contract("c-missing", "x")
        missing["harness"] = {"example": "does-not-exist", "build": "cargo build"}
        with open(os.path.join(self.dir, "c-missing.json"), "w") as f:
            json.dump(missing, f)
        self.add("e-compiles", self.bench("never", "exit 9\n"), build="cargo test --release --no-run")
        r = self.run_smoke(CARGO_TARGET_DIR=os.path.join(self.tmp, "target"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        self.assertIn("PASS a-pass", out)
        self.assertIn("SKIP(pending) b-pending", out)
        self.assertIn("SKIP(compiles a test binary", out)
        self.assertIn("SKIP(no binary) c-missing", out)
        self.assertIn("smoke: 1 passed, 3 skipped (1 pending, 2 without a binary), 0 failed", out)

    def test_a_failing_harness_turns_the_run_red(self):
        self.add("a-fail", self.bench("bad", "echo boom >&2; exit 1\n"))
        self.add("b-pass", self.bench("ok", 'echo \'{"schema":"fake/1"}\'\n'))
        r = self.run_smoke()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FAIL a-fail", r.stdout)
        self.assertIn("PASS b-pass", r.stdout)
        self.assertIn("1 passed, 0 skipped (0 pending, 0 without a binary), 1 failed", r.stdout)

    def test_an_unknown_argument_is_a_usage_error(self):
        r = subprocess.run(["bash", os.path.join(HERE, "smoke.sh"), "--bogus"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
