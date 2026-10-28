import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import b06_inventory as b

WF = "name: CI\non: push\njobs:\n  build:\n    runs-on: x\n  lint: # c\n    steps:\n      - run: a\n  deploy:\n    runs-on: y\nenv:\n  other:\n"


def git(repo, *a):
    subprocess.run(["git", "-C", repo, *a], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


class Inventory(unittest.TestCase):
    def test_summary_lists_job_ids_only_under_jobs(self):
        self.assertEqual(b.workflow_summary(WF), ("CI", ["build", "lint", "deploy"]))
        self.assertEqual(b.workflow_summary("on: push\n"), (None, []))

    def test_inventory_reads_the_workflows_at_the_commit(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            os.makedirs(os.path.join(d, ".github/workflows"))
            for n in ("b.yml", "a.yml"):
                with open(os.path.join(d, ".github/workflows", n), "w") as f:
                    f.write(WF)
            with open(os.path.join(d, "README"), "w") as f:
                f.write("x")
            git(d, "add", "."); git(d, "commit", "-qm", "c")
            commit = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            inv = b.inventory(d, commit)
            self.assertEqual([w["path"] for w in inv], [".github/workflows/a.yml", ".github/workflows/b.yml"])
            self.assertEqual(inv[0]["jobs"], ["build", "lint", "deploy"])

    def test_a_mirror_without_the_commit_is_an_error_not_an_empty_inventory(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as s:
            subprocess.run(["git", "init", "-q", d], check=True)
            with self.assertRaises(RuntimeError):
                b.fetch(d, "0" * 40, s)


if __name__ == "__main__":
    unittest.main()
