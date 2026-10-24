import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import b04a_profile as p

S = 1_000_000_000


def sample(t, cpu_total=None, container=None, io_total=0):
    s = {"t": t, "span_ns": 1000, "host": {}, "cg": {}}
    if cpu_total is not None:
        s["host"]["psi_cpu"] = {"some": {"avg10": 1.0, "avg60": 2.0, "total_us": cpu_total}}
    s["host"]["psi_io"] = {"some": {"avg10": 0.0, "avg60": 0.0, "total_us": io_total}}
    s["cg"]["worker"] = {"usage_usec": t // 1000, "nr_throttled": 0, "throttled_usec": 0}
    if container is not None:
        s["cg"]["c:libpod-a.scope"] = {"usage_usec": container, "nr_throttled": 2, "throttled_usec": container // 2}
    return s


class Profile(unittest.TestCase):
    def test_psi_parse_keeps_only_well_formed_lines(self):
        text = "some avg10=0.50 avg60=1.00 avg300=2.00 total=77\nfull avg10=x avg60=1 avg300=1 total=3\n"
        self.assertEqual(p.parse_psi(text), {"some": {"avg10": 0.5, "avg60": 1.0, "total_us": 77}})
        self.assertEqual(p.parse_psi(None), {})

    def test_delta_interpolates_between_samples(self):
        series = [(0, 0), (10, 100)]
        self.assertEqual(p.delta(series, 2, 7), 50)

    def test_unobserved_or_reset_counters_are_absent_not_zero(self):
        series = [(10, 5), (20, 9)]
        self.assertIsNone(p.delta(series, 0, 15))
        self.assertIsNone(p.delta(series, 15, 25))
        self.assertIsNone(p.delta([(0, 50), (10, 3)], 0, 10))
        self.assertIsNone(p.delta([], 0, 1))

    def test_a_missing_counter_is_left_out_of_the_phase(self):
        samples = [sample(0), sample(S, cpu_total=10), sample(2 * S, cpu_total=40)]
        host = p.host_window(samples, 0, 2 * S)
        self.assertNotIn("cpu_some_stall_us", host)
        self.assertEqual(p.host_window(samples, S, 2 * S)["cpu_some_stall_us"], 30)
        self.assertNotIn("memory_some_stall_us", host)
        self.assertNotIn("steal_ns", host)

    def test_a_container_counts_only_where_both_ends_are_observed(self):
        samples = [sample(0), sample(S, container=0), sample(2 * S, container=100), sample(3 * S)]
        self.assertTrue(p.observed_through(samples, "c:libpod-a.scope", S, 2 * S))
        self.assertFalse(p.observed_through(samples, "c:libpod-a.scope", 0, 2 * S))
        self.assertFalse(p.observed_through(samples, "c:libpod-a.scope", S, 3 * S))
        self.assertEqual(p.cgroup_window(samples, "c:libpod-a.scope", S, 2 * S)["throttled_us"], 50)

    def test_windows_follow_the_stamps_and_phase_durations(self):
        ts = {"preparing_ms": 1000, "running_ms": 5000, "finalizing_ms": 9000, "terminal_ms": 12000}
        w = p.windows(ts, {"checkout": 2 * S, "image_pull": S // 10, "container_start": S // 2, "finalize": 2 * S})
        self.assertEqual(w["checkout"], (1 * S, 3 * S))
        self.assertEqual(w["cache_restore_etc"], (3 * S, 5 * S - S // 2))
        self.assertEqual(w["container_start"], (5 * S - S // 2, 5 * S))
        self.assertEqual(w["steps"], (5 * S, 9 * S))
        self.assertEqual(w["finalize_work"], (9 * S, 11 * S))
        self.assertEqual(w["finalize"], (9 * S, 12 * S))

    def test_a_phase_the_worker_did_not_report_has_no_window(self):
        w = p.windows({"preparing_ms": 1000, "running_ms": 2000}, {})
        self.assertEqual(set(w), {"prepare", "cache_restore_etc"})
        self.assertEqual(p.windows({}, {}), {})

    def test_reduce_attaches_the_single_container_seen_through_the_step(self):
        samples = [sample(i * S // 10, cpu_total=i * 100, container=i * 1000) for i in range(0, 41)]
        raw = {"meta": {}, "samples": samples}
        ts = {"preparing_ms": 500, "running_ms": 1000, "finalizing_ms": 3000, "terminal_ms": 3500}
        out = p.reduce_run(raw, ts, {})
        steps = out["phases"]["steps"]
        self.assertEqual(steps["host"]["cpu_some_stall_us"], 2000)
        self.assertEqual(steps["container_cgroup"]["cpu_usage_us"], 20000)
        self.assertEqual(steps["worker_cgroup"]["throttled_us"], 0)
        self.assertEqual(out["host_pressure"]["cpu_some_avg60_start"], 2.0)

    def test_two_containers_in_a_window_are_not_guessed_between(self):
        a, b = sample(0, container=0), sample(S, container=5)
        for s in (a, b):
            s["cg"]["c:libpod-b.scope"] = dict(s["cg"]["c:libpod-a.scope"])
        out = p.reduce_run({"meta": {}, "samples": [a, b]}, {"running_ms": 0, "finalizing_ms": 1000}, {})
        self.assertNotIn("container_cgroup", out["phases"]["steps"])

    def test_no_samples_is_a_profile_without_phases(self):
        out = p.reduce_run({"meta": {}, "samples": []}, {"preparing_ms": 1, "running_ms": 2}, {})
        self.assertNotIn("phases", out)

    def test_quota_chain_is_the_tightest_limit_or_none(self):
        self.assertIsNone(p.cpu_max_cpus("max 100000"))
        self.assertEqual(p.cpu_max_cpus("1000000 100000"), 10.0)
        self.assertIsNone(p.cpu_max_cpus("garbage"))

    def test_summary_ignores_runs_that_did_not_measure_a_metric(self):
        def rec(stall):
            host = {} if stall is None else {"io_some_stall_us": stall}
            return {"profile": {"phases": {"steps": {"duration_ns": 5, "host": host}}}}

        out = p.summarize([rec(10), rec(None), rec(30)])
        cell = out["steps"]["host.io_some_stall_us"]
        self.assertEqual((cell["n"], cell["p50"], cell["max"]), (2, 10, 30))
        self.assertEqual(out["steps"]["duration_ns"]["n"], 3)
        self.assertTrue(cell["p95_is_max"])


if __name__ == "__main__":
    unittest.main()
