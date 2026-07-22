import { assertEquals } from "@std/assert";
import { cache } from "./cache.ts";
import {
  checkOrgMembership,
  listOrgRepos,
  listOrgRunners,
  listRecentOrgRuns,
  listRepoRuns,
  listRunJobs,
} from "./github.ts";

Deno.env.set("GH_ORG", "acme");
Deno.env.set("GITHUB_PAT", "ghp_test");

function mockFetchOnce(
  impl: (input: string | URL | Request) => Promise<Response> | Response,
): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (input, _init) =>
    Promise.resolve(impl(input as string | URL | Request));
  return () => {
    globalThis.fetch = original;
  };
}

function urlOf(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

Deno.test("checkOrgMembership treats active membership as active", async () => {
  cache.clear();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () =>
    Promise.resolve(
      Response.json({ state: "active", role: "member" }, { status: 200 }),
    );
  try {
    assertEquals(await checkOrgMembership("alice"), "active");
    globalThis.fetch = () => {
      throw new Error("should use cache");
    };
    assertEquals(await checkOrgMembership("alice"), "active");
  } finally {
    globalThis.fetch = originalFetch;
    cache.clear();
  }
});

Deno.test("checkOrgMembership rejects pending and 404 as inactive", async () => {
  cache.clear();
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = () =>
      Promise.resolve(Response.json({ state: "pending" }, { status: 200 }));
    assertEquals(await checkOrgMembership("bob"), "inactive");

    cache.clear();
    globalThis.fetch = () =>
      Promise.resolve(new Response(null, { status: 404 }));
    assertEquals(await checkOrgMembership("carol"), "inactive");
  } finally {
    globalThis.fetch = originalFetch;
    cache.clear();
  }
});

Deno.test("checkOrgMembership returns error on upstream failure without caching", async () => {
  cache.clear();
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = () =>
      Promise.resolve(new Response("nope", { status: 500 }));
    assertEquals(await checkOrgMembership("dave"), "error");
    assertEquals(cache.get("org-member:acme:dave"), undefined);

    globalThis.fetch = () => Promise.reject(new Error("network"));
    assertEquals(await checkOrgMembership("erin"), "error");
  } finally {
    globalThis.fetch = originalFetch;
    cache.clear();
  }
});

Deno.test("listOrgRunners maps runners and caches for TTL", async () => {
  cache.clear();
  let calls = 0;
  const restore = mockFetchOnce((input) => {
    calls++;
    assertEquals(
      urlOf(input).includes("/orgs/acme/actions/runners"),
      true,
    );
    return Response.json({
      total_count: 1,
      runners: [{
        id: 7,
        name: "runner-1",
        os: "Linux",
        status: "online",
        busy: false,
        labels: [{ id: 1, name: "self-hosted", type: "read-only" }],
        ephemeral: false,
      }],
    });
  });
  try {
    const first = await listOrgRunners();
    assertEquals(first, [{
      id: 7,
      name: "runner-1",
      os: "Linux",
      status: "online",
      busy: false,
      labels: [{ id: 1, name: "self-hosted", type: "read-only" }],
      ephemeral: false,
    }]);
    assertEquals(calls, 1);

    globalThis.fetch = () => {
      throw new Error("should use cache");
    };
    const second = await listOrgRunners();
    assertEquals(second[0]?.name, "runner-1");
    assertEquals(calls, 1);
  } finally {
    restore();
    cache.clear();
  }
});

Deno.test("listOrgRepos maps and caches", async () => {
  cache.clear();
  let calls = 0;
  const restore = mockFetchOnce((input) => {
    calls++;
    assertEquals(urlOf(input).includes("/orgs/acme/repos"), true);
    return Response.json([{
      id: 1,
      name: "sentinel",
      full_name: "acme/sentinel",
      private: true,
      html_url: "https://github.com/acme/sentinel",
      default_branch: "main",
    }]);
  });
  try {
    const repos = await listOrgRepos();
    assertEquals(repos[0]?.fullName, "acme/sentinel");
    assertEquals(calls, 1);
    globalThis.fetch = () => {
      throw new Error("should use cache");
    };
    assertEquals((await listOrgRepos())[0]?.name, "sentinel");
  } finally {
    restore();
    cache.clear();
  }
});

Deno.test("listRepoRuns maps workflow runs and caches", async () => {
  cache.clear();
  let calls = 0;
  const restore = mockFetchOnce((input) => {
    calls++;
    assertEquals(
      urlOf(input).includes("/repos/acme/sentinel/actions/runs"),
      true,
    );
    return Response.json({
      total_count: 1,
      workflow_runs: [{
        id: 99,
        name: "CI",
        head_branch: "main",
        head_sha: "abc123",
        path: ".github/workflows/ci.yml",
        run_number: 12,
        event: "push",
        status: "completed",
        conclusion: "success",
        html_url: "https://github.com/acme/sentinel/actions/runs/99",
        created_at: "2026-07-22T10:00:00Z",
        updated_at: "2026-07-22T10:05:00Z",
        actor: { login: "alice" },
        repository: { full_name: "acme/sentinel" },
      }],
    });
  });
  try {
    const runs = await listRepoRuns("sentinel");
    assertEquals(runs[0]?.id, 99);
    assertEquals(runs[0]?.actorLogin, "alice");
    assertEquals(calls, 1);
    globalThis.fetch = () => {
      throw new Error("should use cache");
    };
    assertEquals((await listRepoRuns("sentinel")).length, 1);
  } finally {
    restore();
    cache.clear();
  }
});

Deno.test("listRunJobs maps jobs and caches", async () => {
  cache.clear();
  let calls = 0;
  const restore = mockFetchOnce((input) => {
    calls++;
    assertEquals(
      urlOf(input).includes("/repos/acme/sentinel/actions/runs/99/jobs"),
      true,
    );
    return Response.json({
      total_count: 1,
      jobs: [{
        id: 5,
        run_id: 99,
        name: "build",
        status: "completed",
        conclusion: "success",
        html_url: "https://github.com/acme/sentinel/actions/runs/99/job/5",
        started_at: "2026-07-22T10:01:00Z",
        completed_at: "2026-07-22T10:04:00Z",
        labels: ["self-hosted", "linux"],
        runner_id: 7,
        runner_name: "runner-1",
      }],
    });
  });
  try {
    const jobs = await listRunJobs("sentinel", 99);
    assertEquals(jobs[0]?.runnerName, "runner-1");
    assertEquals(calls, 1);
    globalThis.fetch = () => {
      throw new Error("should use cache");
    };
    assertEquals((await listRunJobs("sentinel", 99))[0]?.id, 5);
  } finally {
    restore();
    cache.clear();
  }
});

Deno.test("listRecentOrgRuns merges runs across repos", async () => {
  cache.clear();
  const restore = mockFetchOnce((input) => {
    const url = urlOf(input);
    if (url.includes("/orgs/acme/repos")) {
      return Response.json([
        {
          id: 1,
          name: "a",
          full_name: "acme/a",
          private: false,
          html_url: "https://github.com/acme/a",
          default_branch: "main",
        },
        {
          id: 2,
          name: "b",
          full_name: "acme/b",
          private: false,
          html_url: "https://github.com/acme/b",
          default_branch: "main",
        },
      ]);
    }
    if (url.includes("/repos/acme/a/actions/runs")) {
      return Response.json({
        total_count: 1,
        workflow_runs: [{
          id: 1,
          name: "A",
          head_branch: "main",
          head_sha: "aaa",
          path: ".github/workflows/a.yml",
          run_number: 1,
          event: "push",
          status: "completed",
          conclusion: "success",
          html_url: "https://github.com/acme/a/actions/runs/1",
          created_at: "2026-07-22T09:00:00Z",
          updated_at: "2026-07-22T09:00:00Z",
          actor: { login: "alice" },
          repository: { full_name: "acme/a" },
        }],
      });
    }
    if (url.includes("/repos/acme/b/actions/runs")) {
      return Response.json({
        total_count: 1,
        workflow_runs: [{
          id: 2,
          name: "B",
          head_branch: "main",
          head_sha: "bbb",
          path: ".github/workflows/b.yml",
          run_number: 2,
          event: "push",
          status: "completed",
          conclusion: "failure",
          html_url: "https://github.com/acme/b/actions/runs/2",
          created_at: "2026-07-22T10:00:00Z",
          updated_at: "2026-07-22T10:00:00Z",
          actor: { login: "bob" },
          repository: { full_name: "acme/b" },
        }],
      });
    }
    return new Response("unexpected", { status: 500 });
  });
  try {
    const runs = await listRecentOrgRuns({ limit: 10 });
    assertEquals(runs[0]?.repository, "acme/b");
    assertEquals(runs[1]?.repository, "acme/a");
  } finally {
    restore();
    cache.clear();
  }
});
