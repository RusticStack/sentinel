import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location("b09_gate", os.path.join(HERE, "b09-gate.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

MS = 1_000_000


def scenario(handicap_ms=0, **over):
    sc = {"id": "steady-1", "workers": 1, "mode": "steady", "runs_per_repeat": 20, "link": "direct",
          "link_shape": {}, "disk": {}, "job": {"step": "true"}}
    sc.update(over)
    if handicap_ms:
        sc["injected_handicap"] = {"delay_ms_each_way": handicap_ms}
    return sc


def repeat(p95_ms, n=20, sc=None, kind="perf"):
    return {"schema": g.SCHEMA, "kind": kind, "scenario": sc or scenario(),
            "summary": {"overhead_ns": {"n": n, "p95": int(p95_ms * MS), "p95_is_max": n < 20}}}


def handicapped(p95_ms, delay_ms):
    """--handicap-delay-ms adds the delay each way to the link, so a run's overhead grows by twice it."""
    return repeat(p95_ms + 2 * delay_ms, sc=scenario(handicap_ms=delay_ms))


def write(path, recs):
    with open(path, "w") as f:
        f.write("".join(json.dumps(r) + "\n" for r in recs))


class Gate(unittest.TestCase):
    def run_gate(self, base, cand, **kw):
        with tempfile.TemporaryDirectory() as d:
            b, c = os.path.join(d, "b.jsonl"), os.path.join(d, "c.jsonl")
            write(b, base)
            write(c, cand)
            return g.gate(b, c, **kw)["steady-1"]

    def test_equal_runs_pass(self):
        r = self.run_gate([repeat(p) for p in (100, 101, 99)], [repeat(p) for p in (100, 102, 98)])
        self.assertEqual(r["verdict"], "pass")

    def test_exactly_ten_percent_passes_and_just_over_with_quiet_repeats_fails(self):
        base = [repeat(100)] * 3
        self.assertEqual(self.run_gate(base, [repeat(110)] * 3)["verdict"], "pass")
        self.assertEqual(self.run_gate(base, [repeat(111)] * 3)["verdict"], "fail")

    def test_a_regression_inside_the_repeat_spread_is_inconclusive(self):
        r = self.run_gate([repeat(p) for p in (80, 100, 120)], [repeat(p) for p in (95, 115, 135)])
        self.assertEqual(r["verdict"], "inconclusive")
        self.assertEqual(g.exit_status({"x": r}), 3)

    def test_one_slow_repeat_cannot_move_the_median(self):
        base = [repeat(p) for p in (100, 100, 100)]
        cand = [repeat(p) for p in (100, 100, 400)]
        self.assertEqual(self.run_gate(base, cand)["verdict"], "pass")

    def test_too_few_repeats_is_insufficient_never_a_pass(self):
        r = self.run_gate([repeat(100)] * 2, [repeat(100)] * 3)
        self.assertEqual(r["verdict"], "insufficient")
        self.assertEqual(g.exit_status({"x": r}), 2)

    def test_repeats_whose_p95_is_the_maximum_are_not_counted(self):
        r = self.run_gate([repeat(100)] * 3, [repeat(100)] * 2 + [repeat(100, n=10)])
        self.assertEqual(r["verdict"], "insufficient")
        self.assertEqual(r["candidate_unusable"], 1)

    def test_a_different_scenario_shape_is_incomparable(self):
        cand = [repeat(100, sc=scenario(workers=3))] * 3
        self.assertEqual(self.run_gate([repeat(100)] * 3, cand)["verdict"], "incomparable")

    def test_a_different_fleet_is_incomparable_and_the_same_fleet_compares(self):
        fa = {"a": {"identities": 3, "per_identity_ceilings": {"cpu_millis": 1000}, "priority": 0, "arch": "x86_64"}}
        fb = {"b": {"identities": 3, "per_identity_ceilings": {"cpu_millis": 1000}, "priority": 0, "arch": "x86_64"}}
        base = [repeat(100, sc=scenario(workers=3, fleet=fa))] * 3
        same = [repeat(100, sc=scenario(workers=3, fleet=fa))] * 3
        other = [repeat(100, sc=scenario(workers=3, fleet=fb))] * 3
        self.assertEqual(self.run_gate(base, same)["verdict"], "pass")
        self.assertEqual(self.run_gate(base, other)["verdict"], "incomparable")
        self.assertEqual(self.run_gate(base, [repeat(100, sc=scenario(workers=3))] * 3)["verdict"],
                         "incomparable")

    def test_a_handicapped_baseline_is_refused(self):
        r = self.run_gate([handicapped(100, 5)] * 3, [repeat(100)] * 3)
        self.assertEqual(r["verdict"], "incomparable")

    def test_sensitivity_to_the_handicap_delay(self):
        base = [repeat(p) for p in (100, 102, 98, 101, 99)]
        # 6 ms each way is +12 ms on a 100 ms baseline: over the 10% rule and beyond the 4 ms spread
        over = [handicapped(p, 6) for p in (100, 102, 98, 101, 99)]
        self.assertEqual(self.run_gate(base, over)["verdict"], "fail")
        # 4 ms each way is +8 ms: under the rule, so it is not a regression
        under = [handicapped(p, 4) for p in (100, 102, 98, 101, 99)]
        self.assertEqual(self.run_gate(base, under)["verdict"], "pass")

    def test_exit_status_ranks_fail_above_everything(self):
        def v(*names):
            return {str(i): {"verdict": n} for i, n in enumerate(names)}
        self.assertEqual(g.exit_status(v("pass", "fail", "insufficient")), 1)
        self.assertEqual(g.exit_status(v("pass", "insufficient", "inconclusive")), 2)
        self.assertEqual(g.exit_status(v("pass", "inconclusive")), 3)
        self.assertEqual(g.exit_status(v("pass")), 0)

    def test_a_scenario_missing_on_one_side_is_insufficient(self):
        with tempfile.TemporaryDirectory() as d:
            b, c = os.path.join(d, "b"), os.path.join(d, "c")
            write(b, [repeat(100)])
            write(c, [repeat(100, sc=scenario(id="other"))])
            res = g.gate(b, c)
            self.assertEqual({r["verdict"] for r in res.values()}, {"insufficient"})

    def test_bad_input_is_an_error_not_a_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x")
            write(p, [{}])
            with self.assertRaises(g.GateError):
                g.load(p)
            with self.assertRaises(g.GateError):
                g.load(os.path.join(d, "missing"))


if __name__ == "__main__":
    unittest.main()
