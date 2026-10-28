import importlib.util
import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("b11_collect", os.path.join(HERE, "b11-collect.py"))
b11 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b11)

S = 1_000_000_000
SHA = "0123456789abcdef0123456789abcdef01234567"
CONTRACT = b11.contract()


def run(name, start, end, conclusion="success", status="completed"):
    return {"name": name, "status": status, "conclusion": conclusion, "started_at": start, "completed_at": end}


def write_json(path, value):
    with open(path, "w") as f:
        json.dump(value, f)


TRIGGER = b11.parse_ns("2026-10-28T10:00:00Z")


class Extraction(unittest.TestCase):
    def test_duration_and_phases_come_from_github_stamps(self):
        got = b11.execution(TRIGGER, [run("build", "2026-10-28T10:00:05Z", "2026-10-28T10:00:35Z"),
                                      run("lint", "2026-10-28T10:00:07Z", "2026-10-28T10:00:20Z"),
                                      run("docs", "2026-10-28T10:00:01Z", "2026-10-28T10:00:02Z")], {"build", "lint"})
        self.assertEqual(got["outcome"], "pass")
        self.assertEqual(got["trigger_to_required_ns"], 35 * S)
        self.assertEqual(got["job_ns"], 30 * S)  # earliest required start 10:00:05 to last finish
        self.assertEqual(got["phases"], {"run": 30 * S, "queue": 5 * S})
        self.assertEqual([c["name"] for c in got["checks"]], ["build", "lint"])  # the unrequired check is not counted

    def test_a_figure_under_the_clock_resolution_is_absent_not_zero(self):
        got = b11.execution(TRIGGER, [run("build", "2026-10-28T10:00:03Z", "2026-10-28T10:00:03Z")], {"build"})
        self.assertNotIn("job_ns", got)
        self.assertNotIn("phases", got)
        started_at_trigger = b11.execution(TRIGGER, [run("build", "2026-10-28T10:00:00Z", "2026-10-28T10:00:09Z")], {"build"})
        self.assertNotIn("queue", started_at_trigger["phases"])
        self.assertEqual(started_at_trigger["phases"]["run"], 9 * S)

    def test_pending_until_every_required_check_is_present_and_complete(self):
        done = run("build", "2026-10-28T10:00:05Z", "2026-10-28T10:00:35Z")
        self.assertIsNone(b11.execution(TRIGGER, [done], {"build", "lint"}))
        self.assertIsNone(b11.execution(TRIGGER, [done, run("lint", "2026-10-28T10:00:05Z", None, None, "in_progress")], {"build", "lint"}))

    def test_a_failed_check_is_a_failure_and_keeps_its_duration(self):
        got = b11.execution(TRIGGER, [run("build", "2026-10-28T10:00:05Z", "2026-10-28T10:00:35Z", "failure"),
                                      run("lint", "2026-10-28T10:00:05Z", "2026-10-28T10:00:20Z")], {"build", "lint"})
        self.assertEqual(got["outcome"], "fail")
        self.assertEqual(got["trigger_to_required_ns"], 35 * S)
        for conclusion in ("cancelled", "timed_out"):
            self.assertEqual(b11.execution(TRIGGER, [run("a", "2026-10-28T10:00:05Z", "2026-10-28T10:00:06Z", conclusion)], {"a"})["outcome"], "fail")

    def test_a_skipped_or_neutral_required_check_is_incorrect_not_a_pass(self):
        for conclusion in ("skipped", "neutral"):
            got = b11.execution(TRIGGER, [run("a", "2026-10-28T10:00:05Z", "2026-10-28T10:00:06Z", conclusion)], {"a"})
            self.assertEqual(got["outcome"], "incorrect")
        # a failure outranks an incorrect check
        got = b11.execution(TRIGGER, [run("a", "2026-10-28T10:00:05Z", "2026-10-28T10:00:06Z", "skipped"),
                                      run("b", "2026-10-28T10:00:05Z", "2026-10-28T10:00:07Z", "failure")], {"a", "b"})
        self.assertEqual(got["outcome"], "fail")

    def test_the_newest_attempt_of_a_name_decides(self):
        old = run("build", "2026-10-28T10:00:05Z", "2026-10-28T10:00:15Z", "failure")
        new = run("build", "2026-10-28T10:01:00Z", "2026-10-28T10:01:30Z")
        got = b11.execution(TRIGGER, [new, old], {"build"})
        self.assertEqual(got["outcome"], "pass")
        self.assertEqual(got["trigger_to_required_ns"], 90 * S)

    def test_a_check_finishing_before_its_trigger_is_refused(self):
        with self.assertRaises(SystemExit):
            b11.execution(TRIGGER, [run("a", "2026-10-27T10:00:00Z", "2026-10-27T10:00:01Z")], {"a"})

    def test_a_censored_execution_is_a_failure_with_a_lower_bound_duration(self):
        got = b11.censored(1800 * S, {"b", "a"})
        self.assertEqual((got["outcome"], got["censored"], got["trigger_to_required_ns"]), ("fail", True, 1800 * S))
        self.assertEqual(got["required"], ["a", "b"])

    def test_labels_refuse_repositories_addresses_and_accounts(self):
        for ok in ("kvm-host", "hosted-blacksmith", "sentinel-1a2b3c4"):
            self.assertEqual(b11.label(ok, "x"), ok)
        for bad in ("owner/repo", "user@host", "Host", "", "a b", None, "x" * 65):
            with self.assertRaises(SystemExit):
                b11.label(bad, "x")


class FakeGh:
    """gh_json over canned pages, to check the app filter, the trigger and the paging."""

    def __init__(self, suites, runs):
        self.suites, self.runs, self.calls = suites, runs, []

    def gh_json(self, path):
        self.calls.append(path)
        page = int(path.split("page=")[-1])
        src, key = (self.suites, "check_suites") if "check-suites" in path else (self.runs, "check_runs")
        return {key: src[(page - 1) * 100: page * 100]}


class Poll(unittest.TestCase):
    def test_only_the_sides_own_app_counts_and_the_trigger_is_its_suite(self):
        suites = [{"app": {"slug": "other"}, "created_at": "2026-10-28T09:00:00Z"},
                  {"app": {"slug": "sentinel-ci"}, "created_at": "2026-10-28T10:00:00Z"}]
        runs = [dict(run("build", "2026-10-28T10:00:05Z", "2026-10-28T10:00:35Z"), app={"slug": "sentinel-ci"}),
                dict(run("build", "2026-10-28T10:00:05Z", "2026-10-28T10:09:35Z", "failure"), app={"slug": "other"})]
        trigger, got = b11.Gh(FakeGh(suites, runs), "o/r", "sentinel-ci").poll(SHA, ["build"])
        self.assertEqual(trigger, TRIGGER)
        self.assertEqual((got["outcome"], got["trigger_to_required_ns"]), ("pass", 35 * S))

    def test_no_suite_yet_is_not_a_measurement(self):
        self.assertEqual(b11.Gh(FakeGh([], []), "o/r", "sentinel-ci").poll(SHA, ["build"]), (None, None))

    def test_more_than_a_page_of_check_runs_is_read_in_full(self):
        suites = [{"app": {"slug": "a"}, "created_at": "2026-10-28T10:00:00Z"}]
        runs = [dict(run(f"job-{i}", "2026-10-28T10:00:05Z", "2026-10-28T10:00:35Z"), app={"slug": "a"}) for i in range(120)]
        fake = FakeGh(suites, runs)
        _, got = b11.Gh(fake, "o/r", "a").poll(SHA, [f"job-{i}" for i in range(120)])
        self.assertEqual(len(got["checks"]), 120)


class Interleave(unittest.TestCase):
    def test_the_first_trigger_alternates_every_pair(self):
        self.assertEqual([b11.order_of(n) for n in range(4)], ["sentinel-first", "blacksmith-first", "sentinel-first", "blacksmith-first"])

    def test_pushes_follow_the_pair_order_and_a_stuck_side_is_censored_not_dropped(self):
        pushes = []
        done = {"outcome": "pass", "trigger_to_required_ns": 10 * S, "checks": []}

        def fake_poll(self, sha, required):
            if self.app == "bs":  # the Blacksmith side never completes
                return None, None
            return TRIGGER, dict(done)

        saved = (b11.sh, b11.commit_for, b11.Gh.poll, b11.time.sleep)
        b11.sh = lambda *cmd: pushes.append(cmd[-2:]) or ""
        b11.commit_for = lambda *a: SHA
        b11.Gh.poll = fake_poll
        b11.time.sleep = lambda s: None
        try:
            side = lambda app, remote: {"repo": remote, "remote": remote, "app": app, "required": ["build"], "label": remote, "host": "kvm-host",
                                        "envelope": {"vcpu": 2, "memory_mib": 1024}, "cache_state": {"warm": "caches-kept"}}
            lane_cfg = {"sentinel": side("st", "sentinel"), "blacksmith": side("bs", "blacksmith")}
            cfg = {"build": "build-1", "timeout_seconds": -1, "poll_seconds": 0}
            recs = b11.run_pair(None, cfg, lane_cfg, CONTRACT, "cli", "warm", 1, False, "tree", "br", {})
        finally:
            b11.sh, b11.commit_for, b11.Gh.poll, b11.time.sleep = saved
        self.assertEqual([p[0] for p in pushes], ["blacksmith", "sentinel"])  # odd pair: Blacksmith first
        by = {r["side"]: r for r in recs}
        self.assertEqual(by["sentinel"]["outcome"], "pass")
        self.assertTrue(by["blacksmith"]["censored"])
        self.assertEqual(by["blacksmith"]["outcome"], "fail")
        self.assertEqual({r["order"] for r in recs}, {"blacksmith-first"})
        self.assertEqual({r["sha"] for r in recs}, {SHA})

    def test_small_edit_keeps_one_marker_line_and_commits_only_that_file(self):
        with tempfile.TemporaryDirectory() as d:
            def git(*a):
                return subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a],
                                      check=True, capture_output=True, text=True).stdout.strip()
            git("init", "-q")
            with open(os.path.join(d, "main.go"), "w", newline="\n") as f:
                f.write("package main\n")
            with open(os.path.join(d, "other.txt"), "w") as f:
                f.write("x")
            git("add", "main.go", "other.txt")
            git("commit", "-q", "-m", "base")
            with open(os.path.join(d, "other.txt"), "w") as f:
                f.write("dirty but unrelated")
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                       GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
            saved = os.environ.copy()
            os.environ.update(env)
            try:
                a = b11.commit_for(d, {"small_edit_file": "main.go"}, "small-edit", 0, "n1")
                b = b11.commit_for(d, {"small_edit_file": "main.go"}, "small-edit", 1, "n2")
                c = b11.commit_for(d, {"small_edit_file": "main.go"}, "warm", 2, "n3")
            finally:
                os.environ.clear()
                os.environ.update(saved)
            self.assertEqual(len({a, b, c}), 3)
            with open(os.path.join(d, "main.go")) as f:
                text = f.read()
            self.assertEqual(text, "package main\n// sentinel-bench b11 nonce n2\n")
            self.assertEqual(git("diff-tree", "--no-commit-id", "--name-only", "-r", b), "main.go")
            self.assertEqual(git("diff-tree", "--no-commit-id", "--name-only", "-r", c), "")  # warm: the tree is unchanged
            self.assertEqual(git("status", "--short"), "M other.txt")  # unrelated work is never staged


def record(lane, condition, pair, side, sha=SHA, **kw):
    base = {"schema": b11.RECORD, "contract": {"id": CONTRACT["id"], "revision": CONTRACT["revision"], "lane": lane, "condition": condition},
            "warmup": False, "pair": pair, "order": b11.order_of(pair), "side": side, "sha": sha,
            "outcome": "pass", "trigger_to_required_ns": 10 * S}
    base.update(kw)
    return base


class Pairing(unittest.TestCase):
    def both(self, n):
        return [record("cli", "warm", n, s) for s in b11.SIDES]

    def test_a_pair_joins_both_executions_and_drops_the_warmup(self):
        warm = dict(record("cli", "warm", 0, "sentinel"), warmup=True)
        del warm["pair"]
        recs = [warm] + self.both(0) + [record("cli", "warm", 1, "sentinel", job_ns=3 * S, phases={"run": 3 * S, "queue": 0}),
                                        record("cli", "warm", 1, "blacksmith")]
        header, lines = b11.pair_records(recs, CONTRACT)
        self.assertEqual(header, {"format": b11.SAMPLES, "contract": "b11-blacksmith", "revision": CONTRACT["revision"]})
        self.assertEqual([(l["pair"], l["order"]) for l in lines], [(0, "sentinel-first"), (1, "blacksmith-first")])
        self.assertEqual(lines[1]["sentinel"], {"sha": SHA, "trigger_to_required_ns": 10 * S, "outcome": "pass", "job_ns": 3 * S, "phases": {"run": 3 * S}})

    def test_an_unpaired_execution_is_refused_not_dropped(self):
        with self.assertRaises(SystemExit):
            b11.pair_records(self.both(0) + [record("cli", "warm", 1, "sentinel")], CONTRACT)

    def test_a_duplicate_execution_is_refused(self):
        with self.assertRaises(SystemExit):
            b11.pair_records(self.both(0) + [record("cli", "warm", 0, "sentinel")], CONTRACT)

    def test_foreign_or_mixed_input_is_refused(self):
        other = self.both(0)
        other[0]["contract"] = dict(other[0]["contract"], revision=99)
        with self.assertRaises(SystemExit):
            b11.pair_records(other, CONTRACT)
        bad_lane = [record("nope", "warm", 0, s) for s in b11.SIDES]
        with self.assertRaises(SystemExit):
            b11.pair_records(bad_lane, CONTRACT)
        disagree = self.both(0)
        disagree[1]["order"] = "blacksmith-first"
        with self.assertRaises(SystemExit):
            b11.pair_records(disagree, CONTRACT)
        dry = [dict(r, dry_run=True) for r in self.both(1)]
        with self.assertRaises(SystemExit):
            b11.pair_records(self.both(0) + dry, CONTRACT, True)
        with self.assertRaises(SystemExit):
            b11.pair_records(dry, CONTRACT)  # a dry run never pairs by accident
        with self.assertRaises(SystemExit):
            b11.pair_records(self.both(0), CONTRACT, True)

    def test_failures_and_sha_mismatches_travel_to_the_harness_unchanged(self):
        recs = [record("cli", "warm", 0, "sentinel", outcome="incorrect"), record("cli", "warm", 0, "blacksmith", sha="f" * 40)]
        _, lines = b11.pair_records(recs, CONTRACT)
        self.assertEqual(lines[0]["sentinel"]["outcome"], "incorrect")
        self.assertNotEqual(lines[0]["sentinel"]["sha"], lines[0]["blacksmith"]["sha"])


class Replay(unittest.TestCase):
    def test_the_committed_baselines_replay_into_a_pairable_dry_run(self):
        for lane in CONTRACT["series"]["lanes"]:
            path = os.path.join(HERE, f"b01a-github-{lane}.jsonl")
            with open(path) as f:
                source = [json.loads(l) for l in f if l.strip()]
            recs = b11.replay(lane, path, CONTRACT)
            measured = [r for r in source if not r["warmup"]]
            self.assertEqual(len(recs), 2 * len(measured), lane)
            self.assertTrue(all(r["dry_run"] and r["provenance"]["label"] == "github-selfhosted-baseline" for r in recs))
            runners = {j["runner"] for r in source for j in r["jobs"] if j.get("runner")}
            self.assertFalse([n for n in runners if n in json.dumps(recs)], lane)  # runner names are not carried over
            _, lines = b11.pair_records(recs, CONTRACT, True)
            self.assertEqual([l["pair"] for l in lines], list(range(len(measured))))
            for line, run_ in zip(lines, measured):
                self.assertEqual(line["sentinel"], line["blacksmith"])  # one recorded run, both sides
                skipped = any(j["conclusion"] == "skipped" for j in run_["jobs"])
                if not skipped:
                    # independently derived by b01a-github.py collect from the same stamps
                    self.assertEqual(line["sentinel"]["trigger_to_required_ns"], round(run_["push_to_last_job_s"] * S), lane)
                self.assertEqual(line["sentinel"]["outcome"], "pass" if run_["conclusion"] == "success" else "fail")

    def test_a_baseline_of_another_lane_is_refused(self):
        with self.assertRaises(SystemExit):
            b11.replay("gson", os.path.join(HERE, "b01a-github-cli.jsonl"), CONTRACT)


class Config(unittest.TestCase):
    def test_the_example_config_loads_and_two_sides_need_two_repositories(self):
        cfg, lane = b11.load_config(os.path.join(HERE, "b11-config.example.json"), "cli")
        self.assertEqual(cfg["format"], b11.CONFIG)
        with tempfile.TemporaryDirectory() as d:
            same = json.loads(json.dumps(cfg))
            same["lanes"]["cli"]["blacksmith"]["repo"] = same["lanes"]["cli"]["sentinel"]["repo"]
            path = os.path.join(d, "c.json")
            write_json(path, same)
            with self.assertRaises(SystemExit):
                b11.load_config(path, "cli")
            no_required = json.loads(json.dumps(cfg))
            no_required["lanes"]["cli"]["sentinel"]["required"] = []
            write_json(path, no_required)
            with self.assertRaises(SystemExit):
                b11.load_config(path, "cli")

    def test_provenance_carries_only_anonymized_labels(self):
        cfg, lane = b11.load_config(os.path.join(HERE, "b11-config.example.json"), "cli")
        got = b11.build_provenance(cfg, lane, "blacksmith", "cold", {"commit": "x", "python": "3"})
        self.assertEqual((got["label"], got["host"], got["cache_state"]), ("hosted-blacksmith", "hosted-blacksmith", "cache-scope-rotated"))
        lane["sentinel"]["host"] = "203.0.113.7"
        with self.assertRaises(SystemExit):
            b11.build_provenance(cfg, lane, "sentinel", "cold", {})


if __name__ == "__main__":
    unittest.main()
