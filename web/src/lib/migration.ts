// The guided migration's wizard: the steps it walks, the answers it reads them from, and the two
// translations it makes between them — the shadow's job pairs to compare, and the pre-switch
// required-check document a native rollback puts back. The shapes are the controller's
// (docs/api.md); nothing here decides anything the controller would refuse.
import { ApiError } from "./api.ts";

export type Mode = "runner" | "native";

export interface MigrationSwitch { enabled: boolean; settings: boolean; missing: string[] }

export interface WorkflowFile { path: string; text: string }
export interface WorkflowsAnswer { schema: string; branch: string | null; commit: string; workflows: WorkflowFile[] }

export interface PlannedChange { job: string; line: number; before: string; after: string }
/** A job that stays on GitHub's runners, with the reason codes and the sentences they stand for. */
export interface KeptJob { job: string; reasons: string[]; notes: string[]; varies: boolean }
export interface NativeStep { github: string | null; kind: string; env: string[]; native: string | null; script: string | null }
export interface NativeJob { github: string; jobs: string[]; kept: string[]; env: string[]; steps: NativeStep[] }
export interface NativePlan { path: string; text: string; secrets: string[]; notes: string[]; jobs: NativeJob[] }
export interface WorkflowPlan {
  path: string;
  diff: string;
  changes: PlannedChange[];
  kept: KeptJob[];
  native: NativePlan | null;
  native_refused: string | null;
}
export interface PreviewAnswer {
  schema: string;
  revision: string;
  label_table: number;
  rule_table: number;
  docker: "microvm_guests" | "container_only";
  workflows: WorkflowPlan[];
}

export interface Pull { number: number; url: string; head: string; base: string; state: string }
export interface PullRequestAnswer {
  schema: string;
  branch: string;
  revision: string | null;
  pull_request: Pull | null;
  changed: { path: string; jobs: string[] }[];
  kept: KeptJob[];
}

export interface Required { required: string[]; strict: boolean }
export interface SettingsView {
  branch: string;
  before: Required;
  change: { added: string[]; removed: string[]; replaced: { context: string; check: string }[] };
  expected: Required;
  protected: boolean;
  after: Required | null;
  verdict: "equal" | "moved" | "unread";
  rulesets: string[];
  from_rulesets: string[];
}
export interface SwitchCopy { job: string; original: string; name: string; class: string | null }
export interface SwitchAnswer {
  schema: string;
  mode: Mode;
  revision: string;
  settings: SettingsView | null;
  permitted: { settings: boolean; administration: boolean; reason?: string };
  pull_request: Pull | null;
  shadow?: SwitchCopy[];
  dropped?: SwitchCopy[];
  disabled?: string[];
  changed?: { path: string; jobs: string[] }[];
  kept?: KeptJob[];
}

export interface PairSide {
  conclusion: string | null;
  duration_ms: number | null;
  tests: { format: string | null; total: number; failed: number; skipped: number } | null;
}
export interface PairReport {
  sha: string;
  job: string;
  shadow: string;
  mode: "native" | "runner" | "actions" | null;
  original: PairSide | null;
  shadow_side: PairSide | null;
  queue_ms: number | null;
  verdict: "match" | "mismatch";
  mismatches: string[];
}
export interface ParityAnswer {
  schema: string;
  shadow_prefix: string;
  pairs: PairReport[];
  jobs: { job: string; samples: number; matched: number; mismatched: number; original: { p50_ms: number | null; p95_ms: number | null }; shadow: { p50_ms: number | null; p95_ms: number | null } }[];
  unpaired: { sha: string; shadow: string }[];
}
export interface Pair { sha: string; original: string; shadow: string }

export interface CheckText { context: string; app_id?: number | null }
export interface RollbackSettings {
  branch: string;
  protected: boolean | null;
  current: { strict: boolean; checks: CheckText[] } | null;
  target: { strict: boolean; checks: CheckText[] };
  changed: boolean;
  remove: CheckText[] | null;
  restore: CheckText[] | null;
  strict: boolean | null;
  applied: boolean;
  reason: string | null;
  verified: boolean | null;
}
export interface RollbackAnswer {
  schema: string;
  action: "revert" | "shadow";
  branch: string;
  revision: string;
  from: string;
  pull_request: Pull | null;
  workflows: { path: string; jobs: string[] }[];
  deleted: string[];
  settings: RollbackSettings | null;
}

/** The wizard's steps, in the order the migration happens; the list is the page's step list too. */
export const STEPS = [
  { id: "connect", label: "Connect" },
  { id: "repositories", label: "Repositories" },
  { id: "analysis", label: "Analysis" },
  { id: "preview", label: "Preview" },
  { id: "pull-request", label: "Pull request" },
  { id: "shadow", label: "Shadow parity" },
  { id: "switch", label: "Switch" },
  { id: "rollback", label: "Rollback" },
] as const;
export type Step = (typeof STEPS)[number]["id"];

const repo = (slug: string, name: string) =>
  `/api/v1/tenants/${encodeURIComponent(slug)}/repos/${encodeURIComponent(name)}/migration`;

export const tenantPath = (slug: string) => `/api/v1/tenants/${encodeURIComponent(slug)}/migration`;
export const workflowsPath = (slug: string, name: string, commit?: string) =>
  `${repo(slug, name)}/workflows${commit ? `?commit=${encodeURIComponent(commit)}` : ""}`;
export const previewPath = (slug: string, name: string) => `${repo(slug, name)}/preview`;
export const pullRequestPath = (slug: string, name: string) => `${repo(slug, name)}/pull-request`;
export const switchPath = (slug: string, name: string) => `${repo(slug, name)}/switch`;
export const parityPath = (slug: string, name: string) => `${repo(slug, name)}/parity`;
export const rollbackPath = (slug: string, name: string) => `${repo(slug, name)}/rollback`;

/**
 * The pairs a parity report compares, from what the step before it stated: the copies the shadow
 * pull request added (runner mode), or the checks the required-check change replaces (native path,
 * where Sentinel's own `sentinel / <job>` check stands in for the workflow job). Nothing is derived
 * for a job whose copy no answer names, because a pair invented here would be compared as if it had
 * run.
 */
export function parityPairs(mode: Mode, commit: string, answer: SwitchAnswer | null): Pair[] {
  if (!answer) return [];
  const copies = mode === "runner"
    ? (answer.shadow ?? []).map((copy) => ({ original: copy.job, shadow: copy.name }))
    : (answer.settings?.change.replaced ?? []).map((pair) => ({ original: pair.context, shadow: pair.check }));
  return copies.map((copy) => ({ sha: commit, original: copy.original, shadow: copy.shadow }));
}

/**
 * The pre-switch required checks a native rollback restores, as the switch's own preview stated them:
 * its `before` set, which is the document a person reviewed before Sentinel or they changed it.
 */
export function preSwitchDocument(settings: SettingsView): { required_checks: { strict: boolean; checks: CheckText[] } } {
  return {
    required_checks: {
      strict: settings.before.strict,
      checks: settings.before.required.map((context) => ({ context })),
    },
  };
}

/** Whether this deployment may make the required-check change itself: the opt-in and the grant, both. */
export function mayApply(answer: SwitchAnswer | null): boolean {
  if (!answer) return false;
  const { settings, administration, reason } = answer.permitted;
  return settings && administration && !reason;
}

const REASONS: Record<string, string> = {
  off: "guided migration is off for this tenant",
  not_configured: "the controller has no GitHub App in force",
  unbound: "the repository is bound through no live installation",
  remote: "the repository is bound to a remote that is not a GitHub repository",
  no_workflows: "the commit holds no workflow to migrate",
  no_change: "no runs-on: line changes at this commit",
  required_check: "a required check names one of the copies the switch would drop",
  branch_protected: "the sentinel/migrate branch's protection declined the update",
  pull_request_refused: "GitHub declined the pull request",
  not_permitted: "the App's installation does not grant what this step writes with",
  settings: "the tenant has not opted into Sentinel changing its required checks",
  administration: "the App's installation does not hold repository administration",
  unprotected: "the branch has no protection rule to change",
  ruleset: "a required check the change removes is stated by a ruleset this deployment does not edit",
  no_pre_switch: "the revision named is already migrated",
  no_shadow: "the revision named holds no shadow copy",
  unchanged: "the required checks already state the document",
  mismatch: "GitHub read back a required-check set that is not the one stated",
  not_requested: "the change was shown, not applied",
  not_protected: "the branch has no protection rule",
};

/**
 * The controller's refusal in its own words: the reason it names, the permissions it says are
 * missing, and the checks it names when a merge gate would move. A step never invents a success the
 * controller did not state, so every failure the page shows comes through here.
 */
export function refusalWords(error: ApiError): string {
  const details = (error.details ?? {}) as { reason?: string; missing?: string[]; checks?: string[] };
  const parts: string[] = [];
  const named = details.reason ? REASONS[details.reason] : undefined;
  if (named) parts.push(named);
  if (details.missing?.length) parts.push(`the App's installations still lack ${details.missing.join(", ")}`);
  if (details.checks?.length) parts.push(`the checks: ${details.checks.join(", ")}`);
  if (!parts.length) parts.push(error.message);
  return `${error.message}: ${parts.join("; ")}`;
}
