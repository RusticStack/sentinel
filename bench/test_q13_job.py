"""bench/q13-job.py against a stdlib fake of the controller API and a local Git remote.

    python3 -m unittest bench/test_q13_job.py

The fake answers the five calls the driver makes (workers, intake, the repository's runs by commit, queue, cancel).
What is proved: the probe pipeline pushed carries the requested `runs_on` and `resources`, the worker that took the
probe or the queue reason is reported, a failure of the API or of Git exits non-zero with nothing on stdout (never a
null worker), the tokens are not echoed, `--keep` and `--release` pair up.
"""
import http.server
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
JOB = os.path.join(HERE, "q13-job.py")
TOKEN, HOOK = "tok-secret-value", "hook-secret-value"


class Fake(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    srv = None

    def log_message(self, *_):
        pass

    def reply(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def auth(self, want):
        if self.headers.get("authorization") != "Bearer " + want:
            self.reply(401, {})
            return False
        return True

    def do_GET(self):
        s = self.srv
        s.calls.append(("GET", self.path))
        if s.fail_workers and self.path.startswith("/api/v1/workers"):
            return self.reply(500, {})
        if not self.auth(TOKEN):
            return
        if self.path.startswith("/api/v1/workers"):
            return self.reply(200, {"workers": [{"id": w, "held_attempts": n} for w, n in sorted(s.held.items())]})
        m = re.match(r"/api/v1/tenants/acme/repos/probe/runs\?sha=(\w+)", self.path)
        if m:
            run = s.runs_by_sha.get(m.group(1))
            return self.reply(200, {"runs": [{"id": run}] if run else []})
        if self.path.startswith("/api/v1/queue"):
            return self.reply(200, {"jobs": [{"run": r, "reason": {"code": s.reason}} for r in s.queued]})
        self.reply(404, {})

    def do_POST(self):
        s = self.srv
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        s.calls.append(("POST", self.path))
        if self.path == "/api/v1/intake/repo_x":
            if not self.auth(HOOK):
                return
            run = f"run_{len(s.runs_by_sha) + 1}"
            s.runs_by_sha[body["new_sha"]] = run
            s.intakes.append(body)
            if s.takes:
                s.held[s.takes] = s.held.get(s.takes, 0) + 1
                s.on_worker[run] = s.takes
            else:
                s.queued.append(run)
            return self.reply(202, {"delivery": body["delivery_id"]})
        m = re.fullmatch(r"/api/v1/runs/(run_\d+)/cancel", self.path)
        if m and self.auth(TOKEN):
            w = s.on_worker.pop(m.group(1), None)
            if w:
                s.held[w] -= 1
            s.cancelled.append(m.group(1))
            return self.reply(200, {})
        self.reply(404, {})


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Fake)
        Fake.srv = self
        self.calls, self.held, self.runs_by_sha, self.queued, self.intakes = [], {"wrk_a": 0, "wrk_b": 0}, {}, [], []
        self.on_worker, self.cancelled = {}, []
        self.takes, self.reason, self.fail_workers = "wrk_b", "arch_mismatch", False


def sh(*a, **kw):
    return subprocess.run(a, capture_output=True, text=True, **kw)


class Job(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.d = self.tmp.name
        self.srv = Server()
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.remote, self.work = os.path.join(d, "remote.git"), os.path.join(d, "work")
        ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
        sh("git", "init", "-q", "--bare", self.remote)
        sh("git", "init", "-q", "-b", "main", self.work)
        with open(os.path.join(self.work, "README"), "w") as f:
            f.write("x\n")
        sh("git", "-C", self.work, "add", "README")
        self.assertEqual(sh("git", *ident, "-C", self.work, "commit", "-q", "-m", "base").returncode, 0)
        sh("git", "-C", self.work, "remote", "add", "bench", self.remote)
        for name, val in (("token", TOKEN), ("hook", HOOK)):
            with open(os.path.join(d, name), "w") as f:
                f.write(val + "\n")
        self.cfg = {"api": f"http://127.0.0.1:{self.srv.server_address[1]}/api/v1", "token_file": os.path.join(d, "token"),
                    "hook_token_file": os.path.join(d, "hook"), "tenant": "acme", "repo_id": "repo_x", "repo_name": "probe",
                    "git_work": self.work, "git_remote": "bench", "image": "docker.io/library/busybox@sha256:" + "0" * 64,
                    "wait_s": 2, "hold_s": 60, "state_file": os.path.join(d, "kept.json")}
        self.write_cfg()

    def write_cfg(self):
        self.cfg_path = os.path.join(self.d, "job.json")
        with open(self.cfg_path, "w") as f:
            json.dump(self.cfg, f)

    def run_job(self, *probe, extra=()):
        return subprocess.run([sys.executable, JOB, "--config", self.cfg_path, *extra, *probe], capture_output=True, text=True)

    def test_a_placed_probe_reports_its_worker_and_pushes_the_requested_shape(self):
        r = self.run_job("aarch64", "linux", "container", "2000", str(512 << 20), str(2 << 30))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {"worker": "wrk_b", "reason": None})
        sha = self.srv.intakes[0]["new_sha"]
        yml = sh("git", "--git-dir", self.remote, "show", f"{sha}:.sentinel.yml").stdout
        self.assertIn("runs_on: {arch: arm64, os: linux, isolation: container}", yml)
        self.assertIn('cpu: "2"', yml)
        self.assertIn("memory: 512MiB", yml)
        self.assertIn("disk: 2048MiB", yml)
        self.assertEqual(self.srv.cancelled, ["run_1"], "a probe that was placed is cancelled again")
        self.assertNotIn(TOKEN, r.stdout + r.stderr)
        self.assertNotIn(HOOK, r.stdout + r.stderr)

    def test_a_probe_nothing_takes_reports_the_queue_reason(self):
        self.srv.takes = None
        r = self.run_job("aarch64", "linux", "container", "1000", str(1 << 30), str(1 << 30))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {"worker": None, "reason": "arch_mismatch"})

    def test_a_failing_api_is_an_error_not_a_null_worker(self):
        self.srv.fail_workers = True
        r = self.run_job("x86_64", "linux", "container", "1000", str(1 << 30), str(1 << 30))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")
        self.assertIn("500", r.stderr)
        self.assertEqual(self.srv.intakes, [], "nothing was pushed after the first call failed")

    def test_an_unreachable_controller_is_an_error(self):
        self.cfg["api"] = "http://127.0.0.1:9/api/v1"
        self.write_cfg()
        r = self.run_job("x86_64", "linux", "container", "1000", str(1 << 30), str(1 << 30))
        self.assertEqual((r.returncode, r.stdout), (2, ""))

    def test_a_wrong_token_is_an_error_that_does_not_echo_it(self):
        with open(self.cfg["token_file"], "w") as f:
            f.write("wrong-token-value")
        r = self.run_job("x86_64", "linux", "container", "1000", str(1 << 30), str(1 << 30))
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        self.assertNotIn("wrong-token-value", r.stderr)

    def test_a_remote_that_refuses_the_push_is_an_error(self):
        self.cfg["git_remote"] = "absent"
        self.write_cfg()
        r = self.run_job("x86_64", "linux", "container", "1000", str(1 << 30), str(1 << 30))
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        self.assertIn("git", r.stderr)

    def test_an_unknown_arch_is_refused_before_any_call_that_changes_anything(self):
        r = self.run_job("sparc", "linux", "container", "1000", str(1 << 30), str(1 << 30))
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        self.assertEqual(self.srv.intakes, [])

    def test_keep_leaves_the_probe_running_and_release_cancels_it(self):
        r = self.run_job("x86_64", "linux", "container", "1000", str(1 << 30), str(1 << 30), extra=["--keep"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.cancelled, [])
        self.assertEqual(self.srv.held["wrk_b"], 1)
        rel = self.run_job(extra=["--release"])
        self.assertEqual(rel.returncode, 0, rel.stderr)
        self.assertEqual(json.loads(rel.stdout), {"released": 1})
        self.assertEqual(self.srv.cancelled, ["run_1"])
        self.assertEqual(self.srv.held["wrk_b"], 0)
        again = self.run_job(extra=["--release"])
        self.assertEqual(json.loads(again.stdout), {"released": 0})

    def test_a_job_config_without_a_field_names_it(self):
        del self.cfg["repo_id"]
        self.write_cfg()
        r = self.run_job("x86_64", "linux", "container", "1000", str(1 << 30), str(1 << 30))
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        self.assertIn("repo_id", r.stderr)


class RealFleetUsesTheDriver(unittest.TestCase):
    """bench/q13-fleet.py's RealFleet.start_job / finish_jobs go through the driver instead of staying Blocked."""

    def fleet(self, tmp, worker):
        import importlib.util
        spec = importlib.util.spec_from_file_location("q13_fleet", os.path.join(HERE, "q13-fleet.py"))
        q = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(q)
        log = os.path.join(tmp, "calls")
        driver = os.path.join(tmp, "driver.py")
        with open(driver, "w") as f:
            f.write("\n".join([
                "import json, sys",
                "open(%r, 'a').write(' '.join(sys.argv[1:]) + chr(10))" % log,
                "print(json.dumps({'released': 1}) if '--release' in sys.argv else json.dumps({'worker': %r, 'reason': None}))" % worker,
            ]) + "\n")
        return q, q.RealFleet({"controller": {"exec": [], "sentinel": "s"}, "job_driver": [sys.executable, driver]}), log

    def test_start_and_finish_hold_and_release_a_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            q, f, log = self.fleet(tmp, "wrk_a")
            f.start_job("wrk_a")
            f.finish_jobs("wrk_a")
            with open(log) as fh:
                calls = fh.read().splitlines()
        self.assertTrue(calls[0].startswith("--keep x86_64 linux container"), calls)
        self.assertEqual(calls[1], "--release")

    def test_a_probe_placed_elsewhere_is_blocked_not_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            q, f, log = self.fleet(tmp, "wrk_other")
            with self.assertRaises(q.Blocked):
                f.start_job("wrk_a")
            with open(log) as fh:
                self.assertEqual(fh.read().splitlines()[-1], "--release", "the misplaced probe is released again")

    def test_without_a_driver_it_stays_blocked(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("q13_fleet", os.path.join(HERE, "q13-fleet.py"))
        q = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(q)
        f = q.RealFleet({"controller": {"exec": [], "sentinel": "s"}})
        with self.assertRaises(q.Blocked):
            f.start_job("wrk_a")


if __name__ == "__main__":
    unittest.main()
