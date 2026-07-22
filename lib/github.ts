/**
 * GitHub API helpers: identity, org membership, runners/repos/runs/jobs.
 *
 * Security: ongoing membership checks and org-scoped queries use GITHUB_PAT
 * (admin:org + repo). Never expose the PAT to the client. User OAuth tokens
 * are used only during login for GET /user, then discarded.
 */
import type { SessionUser } from "../utils.ts";
import { cache } from "./cache.ts";
import { githubOrg, githubPat } from "./env.ts";

const API = "https://api.github.com";
const API_VERSION = "2022-11-28";

const MEMBERSHIP_TTL_MS = 5 * 60 * 1000;
const RUNNERS_TTL_MS = 15 * 1000;
const REPOS_TTL_MS = 5 * 60 * 1000;
const RUNS_TTL_MS = 30 * 1000;
const JOBS_TTL_MS = 30 * 1000;

export type MembershipStatus = "active" | "inactive" | "error";

export type RunnerLabel = {
  id: number;
  name: string;
  type: string;
};

export type OrgRunner = {
  id: number;
  name: string;
  os: string;
  status: string;
  busy: boolean;
  labels: RunnerLabel[];
  ephemeral: boolean;
};

export type OrgRepo = {
  id: number;
  name: string;
  fullName: string;
  private: boolean;
  htmlUrl: string;
  defaultBranch: string;
};

export type WorkflowRun = {
  id: number;
  name: string | null;
  headBranch: string | null;
  headSha: string;
  path: string;
  runNumber: number;
  event: string;
  status: string | null;
  conclusion: string | null;
  htmlUrl: string;
  createdAt: string;
  updatedAt: string;
  actorLogin: string | null;
  repository: string;
};

export type WorkflowJob = {
  id: number;
  runId: number;
  name: string;
  status: string;
  conclusion: string | null;
  htmlUrl: string | null;
  startedAt: string | null;
  completedAt: string | null;
  labels: string[];
  runnerId: number | null;
  runnerName: string | null;
};

type GitHubUser = {
  id: number;
  login: string;
  avatar_url?: string;
  name?: string | null;
};

type OrgMembership = {
  state: "active" | "pending";
  role?: string;
};

type GhRunner = {
  id: number;
  name: string;
  os: string;
  status: string;
  busy: boolean;
  labels?: { id: number; name: string; type: string }[];
  ephemeral?: boolean;
};

type GhRepo = {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  html_url: string;
  default_branch?: string;
};

type GhWorkflowRun = {
  id: number;
  name: string | null;
  head_branch: string | null;
  head_sha: string;
  path: string;
  run_number: number;
  event: string;
  status: string | null;
  conclusion: string | null;
  html_url: string;
  created_at: string;
  updated_at: string;
  actor?: { login?: string } | null;
  repository?: { full_name?: string } | null;
};

type GhJob = {
  id: number;
  run_id: number;
  name: string;
  status: string;
  conclusion: string | null;
  html_url: string | null;
  started_at: string | null;
  completed_at: string | null;
  labels?: string[];
  runner_id?: number | null;
  runner_name?: string | null;
};

export class GitHubApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "GitHubApiError";
    this.status = status;
  }
}

function ghHeaders(token: string): HeadersInit {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": API_VERSION,
    "User-Agent": "Sentinel-Dashboard",
  };
}

async function ghGet<T>(
  path: string,
  token = githubPat(),
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, { headers: ghHeaders(token) });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new GitHubApiError(`GitHub network error: ${msg}`, 502);
  }
  if (!res.ok) {
    throw new GitHubApiError(
      `GitHub ${path} failed (${res.status})`,
      res.status,
    );
  }
  return await res.json() as T;
}

export async function getAuthenticatedUser(
  accessToken: string,
): Promise<SessionUser> {
  const res = await fetch(`${API}/user`, {
    headers: ghHeaders(accessToken),
  });
  if (!res.ok) {
    throw new Error(`GitHub /user failed (${res.status})`);
  }
  const data = await res.json() as GitHubUser;
  return {
    id: data.id,
    login: data.login,
    avatarUrl: data.avatar_url,
    name: data.name,
  };
}

/**
 * Org membership via PAT: never requires storing the user's OAuth token.
 * - active: 200 + state=active
 * - inactive: 404, or 200 + pending, or confirmed forbidden for this user
 * - error: upstream/network failure (do not treat as logout)
 *
 * @see https://docs.github.com/en/rest/orgs/members#get-organization-membership-for-a-user
 */
export async function checkOrgMembership(
  login: string,
  org = githubOrg(),
): Promise<MembershipStatus> {
  const cacheKey = `org-member:${org}:${login}`;
  const cached = cache.get<MembershipStatus>(cacheKey);
  if (cached === "active" || cached === "inactive") return cached;

  let res: Response;
  try {
    res = await fetch(
      `${API}/orgs/${encodeURIComponent(org)}/memberships/${
        encodeURIComponent(login)
      }`,
      { headers: ghHeaders(githubPat()) },
    );
  } catch {
    return "error";
  }

  if (res.status === 200) {
    const membership = await res.json() as OrgMembership;
    const status: MembershipStatus = membership.state === "active"
      ? "active"
      : "inactive";
    cache.set(cacheKey, status, MEMBERSHIP_TTL_MS);
    return status;
  }

  if (res.status === 404) {
    cache.set(cacheKey, "inactive", MEMBERSHIP_TTL_MS);
    return "inactive";
  }

  // 401/403 on the PAT usually means misconfiguration: fail closed as error
  // so we do not wipe valid sessions when the PAT is broken.
  return "error";
}

/** Convenience for login callback (confirmed active only). */
export async function isActiveOrgMember(login: string): Promise<boolean> {
  return (await checkOrgMembership(login)) === "active";
}

export function invalidateMembershipCache(login: string, org = githubOrg()) {
  cache.delete(`org-member:${org}:${login}`);
}

/**
 * List org self-hosted runners (PAT needs admin:org).
 * @see https://docs.github.com/en/rest/actions/self-hosted-runners#list-self-hosted-runners-for-an-organization
 */
export async function listOrgRunners(
  org = githubOrg(),
): Promise<OrgRunner[]> {
  const cacheKey = `org-runners:${org}`;
  const cached = cache.get<OrgRunner[]>(cacheKey);
  if (cached) return cached;

  const data = await ghGet<{ total_count: number; runners: GhRunner[] }>(
    `/orgs/${encodeURIComponent(org)}/actions/runners?per_page=100`,
  );

  const runners: OrgRunner[] = (data.runners ?? []).map((r) => ({
    id: r.id,
    name: r.name,
    os: r.os,
    status: r.status,
    busy: r.busy,
    labels: (r.labels ?? []).map((l) => ({
      id: l.id,
      name: l.name,
      type: l.type,
    })),
    ephemeral: Boolean(r.ephemeral),
  }));

  cache.set(cacheKey, runners, RUNNERS_TTL_MS);
  return runners;
}

/**
 * List organization repositories (PAT needs repo for private).
 * @see https://docs.github.com/en/rest/repos/repos#list-organization-repositories
 */
export async function listOrgRepos(
  org = githubOrg(),
): Promise<OrgRepo[]> {
  const cacheKey = `org-repos:${org}`;
  const cached = cache.get<OrgRepo[]>(cacheKey);
  if (cached) return cached;

  const data = await ghGet<GhRepo[]>(
    `/orgs/${encodeURIComponent(org)}/repos?per_page=100&sort=updated&type=all`,
  );

  const repos: OrgRepo[] = (data ?? []).map((r) => ({
    id: r.id,
    name: r.name,
    fullName: r.full_name,
    private: r.private,
    htmlUrl: r.html_url,
    defaultBranch: r.default_branch ?? "main",
  }));

  cache.set(cacheKey, repos, REPOS_TTL_MS);
  return repos;
}

/**
 * List recent workflow runs for a repository.
 * @see https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-repository
 */
export async function listRepoRuns(
  repo: string,
  options: { org?: string; perPage?: number } = {},
): Promise<WorkflowRun[]> {
  const org = options.org ?? githubOrg();
  const perPage = options.perPage ?? 5;
  const cacheKey = `repo-runs:${org}/${repo}:${perPage}`;
  const cached = cache.get<WorkflowRun[]>(cacheKey);
  if (cached) return cached;

  const data = await ghGet<{
    total_count: number;
    workflow_runs: GhWorkflowRun[];
  }>(
    `/repos/${encodeURIComponent(org)}/${
      encodeURIComponent(repo)
    }/actions/runs?per_page=${perPage}`,
  );

  const runs: WorkflowRun[] = (data.workflow_runs ?? []).map((r) => ({
    id: r.id,
    name: r.name,
    headBranch: r.head_branch,
    headSha: r.head_sha,
    path: r.path,
    runNumber: r.run_number,
    event: r.event,
    status: r.status,
    conclusion: r.conclusion,
    htmlUrl: r.html_url,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    actorLogin: r.actor?.login ?? null,
    repository: r.repository?.full_name ?? `${org}/${repo}`,
  }));

  cache.set(cacheKey, runs, RUNS_TTL_MS);
  return runs;
}

/**
 * List jobs for a workflow run.
 * @see https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run
 */
export async function listRunJobs(
  repo: string,
  runId: number,
  org = githubOrg(),
): Promise<WorkflowJob[]> {
  const cacheKey = `run-jobs:${org}/${repo}:${runId}`;
  const cached = cache.get<WorkflowJob[]>(cacheKey);
  if (cached) return cached;

  const data = await ghGet<{ total_count: number; jobs: GhJob[] }>(
    `/repos/${encodeURIComponent(org)}/${
      encodeURIComponent(repo)
    }/actions/runs/${runId}/jobs?per_page=100`,
  );

  const jobs: WorkflowJob[] = (data.jobs ?? []).map((j) => ({
    id: j.id,
    runId: j.run_id,
    name: j.name,
    status: j.status,
    conclusion: j.conclusion,
    htmlUrl: j.html_url,
    startedAt: j.started_at,
    completedAt: j.completed_at,
    labels: j.labels ?? [],
    runnerId: j.runner_id ?? null,
    runnerName: j.runner_name ?? null,
  }));

  cache.set(cacheKey, jobs, JOBS_TTL_MS);
  return jobs;
}

/**
 * Recent workflow runs across org repos (newest first).
 * Caps repos scanned to avoid rate-limit spikes.
 */
export async function listRecentOrgRuns(options: {
  org?: string;
  perRepo?: number;
  maxRepos?: number;
  limit?: number;
} = {}): Promise<WorkflowRun[]> {
  const org = options.org ?? githubOrg();
  const perRepo = options.perRepo ?? 5;
  const maxRepos = options.maxRepos ?? 20;
  const limit = options.limit ?? 30;
  const cacheKey = `org-recent-runs:${org}:${perRepo}:${maxRepos}:${limit}`;
  const cached = cache.get<WorkflowRun[]>(cacheKey);
  if (cached) return cached;

  const repos = (await listOrgRepos(org)).slice(0, maxRepos);
  const batches = await Promise.all(
    repos.map((r) => listRepoRuns(r.name, { org, perPage: perRepo })),
  );
  const merged = batches.flat().sort((a, b) =>
    b.updatedAt.localeCompare(a.updatedAt)
  );
  const runs = merged.slice(0, limit);
  cache.set(cacheKey, runs, RUNS_TTL_MS);
  return runs;
}
