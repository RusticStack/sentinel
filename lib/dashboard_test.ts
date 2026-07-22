import { assertEquals } from "@std/assert";
import { filterRuns } from "./dashboard.ts";
import type { WorkflowRun } from "./github.ts";

function run(
  partial: Partial<WorkflowRun> & Pick<WorkflowRun, "id">,
): WorkflowRun {
  return {
    name: "CI",
    headBranch: "main",
    headSha: "abc1234deadbeef",
    path: ".github/workflows/ci.yml",
    runNumber: 1,
    event: "push",
    status: "completed",
    conclusion: "success",
    htmlUrl: "https://github.com/org/repo/actions/runs/1",
    createdAt: "2026-07-22T00:00:00Z",
    updatedAt: "2026-07-22T00:01:00Z",
    actorLogin: "octocat",
    repository: "org/repo",
    ...partial,
  };
}

Deno.test("filterRuns by repo name and full name", () => {
  const runs = [
    run({ id: 1, repository: "acme/sentinel" }),
    run({ id: 2, repository: "acme/other" }),
  ];
  assertEquals(filterRuns(runs, { repo: "sentinel" }).map((r) => r.id), [1]);
  assertEquals(
    filterRuns(runs, { repo: "acme/other" }).map((r) => r.id),
    [2],
  );
});

Deno.test("filterRuns by status and conclusion", () => {
  const runs = [
    run({ id: 1, status: "in_progress", conclusion: null }),
    run({ id: 2, status: "completed", conclusion: "failure" }),
    run({ id: 3, status: "completed", conclusion: "success" }),
  ];
  assertEquals(
    filterRuns(runs, { status: "in_progress" }).map((r) => r.id),
    [1],
  );
  assertEquals(
    filterRuns(runs, { status: "failure" }).map((r) => r.id),
    [2],
  );
  assertEquals(
    filterRuns(runs, { status: "completed" }).map((r) => r.id),
    [2, 3],
  );
});
