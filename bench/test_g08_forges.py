"""The G08 fixture harness, checked without starting a container.

What this covers is the part that decides whether a fixture run is meaningful: the display of bindings,
the refusals that must happen before an image is pulled, and the self-test the harness itself offers.
Container behaviour is exercised by `python3 bench/g08-forges.py up <fixture>` on a host with Podman;
docs/generic-git-verification.md says which rows were exercised and where.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("g08_forges", os.path.join(HERE, "g08-forges.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class Bindings(unittest.TestCase):
    def test_every_fixture_states_the_repository_and_the_hook_it_runs(self):
        for name in ("gitea", "forgejo", "gitlab", "bare"):
            binding = g.converge(name)
            self.assertIn("repo", binding, name)
            self.assertIn("hook", binding, name)

    def test_the_hook_location_is_the_one_each_forge_runs(self):
        self.assertEqual(g.converge("gitea")["hook"], "post-receive.d/sentinel")
        self.assertEqual(g.converge("forgejo")["hook"], "post-receive.d/sentinel")
        self.assertEqual(g.converge("bare")["hook"], "hooks/post-receive")
        self.assertEqual(g.converge("gitlab")["hook"], "custom_hooks/post-receive")

    def test_an_unknown_fixture_is_refused_by_name(self):
        with self.assertRaises(g.FixtureError) as refused:
            g.converge("bitbucket")
        self.assertIn("unknown fixture", str(refused.exception))

    def test_no_two_fixtures_share_a_port(self):
        seen = {}
        for name, ports in g.PORTS.items():
            for kind, port in ports.items():
                other = seen.setdefault(port, f"{name}.{kind}")
                self.assertEqual(other, f"{name}.{kind}", f"port {port} is used twice")

    def test_a_fixture_that_needs_more_memory_than_another_asks_for_it(self):
        self.assertGreater(g.NEEDS["gitlab"]["memory_gib"], g.NEEDS["gitea"]["memory_gib"])


class Refusals(unittest.TestCase):
    def test_an_unknown_fixture_fails_before_anything_is_pulled(self):
        with self.assertRaises(g.FixtureError) as refused:
            g.preflight("nonexistent")
        self.assertIn("unknown fixture", str(refused.exception))

    def test_a_host_without_a_runtime_refuses_every_fixture(self):
        saved = dict(os.environ)
        try:
            os.environ["PATH"] = "/nonexistent"
            for name in ("gitea", "forgejo", "bare"):
                with self.assertRaises(g.FixtureError):
                    g.preflight(name)
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_a_bind_without_a_secret_is_refused(self):
        with self.assertRaises(g.FixtureError):
            g.bind("gitea", "http://127.0.0.1:1/intake", "/nonexistent-secret")


class SelfTest(unittest.TestCase):
    def test_the_harness_self_test_passes(self):
        self.assertEqual(g.selftest(), [])

    def test_the_runtime_directory_is_set_when_the_account_has_none(self):
        saved = os.environ.pop("XDG_RUNTIME_DIR", None)
        try:
            g.ensure_runtime_dir()
            self.assertTrue(os.environ.get("XDG_RUNTIME_DIR", "").startswith("/run/user/"))
        finally:
            if saved is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = saved


if __name__ == "__main__":
    unittest.main()
