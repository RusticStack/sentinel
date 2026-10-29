"""bench/run_ignored.py against a stand-in `cargo`: the record it builds and the three ways it refuses to build one."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "run_ignored.py")
LINUX = sys.platform.startswith("linux")

FAKE_CARGO = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_ARGS"
printf '%s\n' "${SENTINEL_BENCH_OUT-unset}" >> "$FAKE_OUT_ENV"
case "$*" in
  *--list*) printf 'tests::a_test: test\nother_test: test\n'; exit 0 ;;
esac
case "${FAKE_MODE:-ok}" in
  ok) echo 'running 1 test' >&2; echo '{"test":"t","value":7}'; echo 'plain line'; echo '{"test":"t","value":8}'
      echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' ;;
  skip) echo 'SENTINEL_TAILCAT_LIVE unset; skipping live tailcat test' >&2
        echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' ;;
  fail) echo 'test result: FAILED. 0 passed; 1 failed' ; exit 101 ;;
  none) echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out' ;;
  badjson) echo '{not json'; echo 'test result: ok. 1 passed; 0 failed; 0 ignored' ;;
esac
"""


@unittest.skipUnless(LINUX, "needs Linux and bash")
class RunIgnored(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="run-ignored-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        cargo = os.path.join(self.bin, "cargo")
        with open(cargo, "w") as f:
            f.write(FAKE_CARGO)
        os.chmod(cargo, os.stat(cargo).st_mode | stat.S_IXUSR)
        self.args = os.path.join(self.tmp, "args")
        self.out_env = os.path.join(self.tmp, "out-env")

    def run_script(self, *argv, mode="ok", **env):
        e = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_ARGS=self.args,
                 FAKE_OUT_ENV=self.out_env, FAKE_MODE=mode, SENTINEL_SRC=self.tmp, **env)
        return subprocess.run([sys.executable, SCRIPT, *argv], capture_output=True, text=True, env=e)

    def test_the_reports_come_back_inside_one_record(self):
        r = self.run_script("sentinel-store", "fleet_load", "the_test", SENTINEL_BENCH_OUT="/should/not/reach/the/test")
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = json.loads(r.stdout)
        self.assertEqual(r.stdout.count("\n"), 1)
        self.assertEqual(rec["schema"], "sentinel-bench/ignored-test/1")
        self.assertEqual((rec["package"], rec["test_target"], rec["test"], rec["outcome"]), ("sentinel-store", "fleet_load", "the_test", "ok"))
        self.assertEqual([x["value"] for x in rec["reports"]], [7, 8])
        self.assertGreater(rec["test_elapsed_ns"], 0)
        with open(self.args) as f:
            self.assertIn("test --release --locked -p sentinel-store --test fleet_load -- --ignored --nocapture --exact the_test", f.read())
        with open(self.out_env) as f:
            self.assertEqual(f.read().strip(), "unset", "the test must not append an unstamped line itself")

    def test_a_failed_test_prints_no_record_and_keeps_its_status(self):
        r = self.run_script("p", "t", "n", mode="fail")
        self.assertEqual(r.returncode, 101)
        self.assertEqual(r.stdout, "")

    def test_a_test_that_skipped_itself_is_pending_not_a_measurement(self):
        r = self.run_script("p", "t", "n", mode="skip")
        self.assertEqual(r.returncode, 75)
        self.assertEqual(r.stdout, "")

    def test_a_filter_that_matched_nothing_is_refused(self):
        r = self.run_script("p", "t", "n", mode="none")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_a_report_that_is_not_json_is_refused(self):
        r = self.run_script("p", "t", "n", mode="badjson")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_list_only_checks_the_name_and_runs_nothing(self):
        r = self.run_script("--list-only", "p", "t", "other_test")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["outcome"], "listed")
        with open(self.args) as f:
            calls = f.read().splitlines()
        self.assertEqual(len(calls), 1)
        self.assertNotIn("--nocapture", calls[0])
        r = self.run_script("--list-only", "p", "t", "no_such_test")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_names_and_argument_counts_are_checked(self):
        for argv in (("p", "t"), ("p", "t", "n; rm -rf /"), ("p", "t", "n", "extra")):
            r = self.run_script(*argv)
            self.assertEqual(r.returncode, 2, argv)
            self.assertEqual(r.stdout, "")
        self.assertFalse(os.path.exists(self.args), "nothing reached cargo")


if __name__ == "__main__":
    unittest.main()
