// Guided migration's wizard: one page that walks a repository from connect to rollback along the
// controller's own routes, each step reading what the one before it wrote. It consumes the API
// (docs/api.md); it invents no step the controller does not answer, and a step advances only on an
// answer that confirmed it — a refusal is shown in the controller's own words.
import { useEffect, useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { api, ApiError } from "../../../../lib/api.ts";
import { attempt, useLoad } from "../../../../lib/loaded.ts";
import { loadRepos } from "../../../../lib/repos.ts";
import { fmtBytes } from "../../../../lib/format.ts";
import {
  mayApply, parityPairs, preSwitchDocument, previewPath, pullRequestPath, refusalWords,
  rollbackPath, parityPath, switchPath, tenantPath, workflowsPath, STEPS,
  type MigrationSwitch, type Mode, type Pair, type ParityAnswer, type PreviewAnswer, type Pull,
  type PullRequestAnswer, type Required, type RollbackAnswer, type SettingsView, type Step,
  type SwitchAnswer, type WorkflowsAnswer,
} from "../../../../lib/migration.ts";
import { Page } from "../../../../components/Page.tsx";
import { LoadFailed } from "../../../../components/LoadFailed.tsx";
import {
  Alert, Badge, Button, Card, Checkbox, cx, Field, Icon, Input, Table, TextLink,
} from "../../../../components/ui.tsx";

export const Route = createFileRoute("/_app/t/$slug/migration")({
  loader: async ({ params }) => ({
    migration: await attempt(() => api<MigrationSwitch>(tenantPath(params.slug))),
    repos: await attempt(() => loadRepos(params.slug)),
  }),
  head: ({ params }) => ({ meta: [{ title: `Migration · ${params.slug} · Sentinel` }] }),
  component: MigrationWizard,
});

const stepIndex = (step: Step) => STEPS.findIndex((s) => s.id === step);

function MigrationWizard() {
  const { slug } = Route.useParams();
  const loaded = Route.useLoaderData();
  const migration = useLoad(loaded.migration);
  const repos = useLoad(loaded.repos);
  const [step, setStep] = useState<Step>("connect");
  const [repo, setRepo] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("runner");
  const [images, setImages] = useState({ linux: "", arm64: "", windows: "" });
  const [optIn, setOptIn] = useState<boolean | null>(null);
  const [workflows, setWorkflows] = useState<WorkflowsAnswer | null>(null);
  const [plan, setPlan] = useState<PreviewAnswer | null>(null);
  const [pull, setPull] = useState<PullRequestAnswer | null>(null);
  // Runner mode: the shadow pull request's answer. Native path: the required-check change, which is
  // the same preview the switch then applies or the person does.
  const [shadow, setShadow] = useState<SwitchAnswer | null>(null);
  const [parity, setParity] = useState<ParityAnswer | null>(null);
  const [switched, setSwitched] = useState<SwitchAnswer | null>(null);
  const [rolled, setRolled] = useState<RollbackAnswer | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [refused, setRefused] = useState<string | null>(null);
  const [connectAt, setConnectAt] = useState<number | null>(null);
  const [shadowAt, setShadowAt] = useState<number | null>(null);

  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, [step]);
  useEffect(() => { if (migration.data) setOptIn((v) => v ?? migration.data!.settings); }, [migration.data]);

  const commit = plan?.revision ?? workflows?.commit ?? null;
  // Another repository or another mode is another migration: nothing an answer described before
  // still describes what the next request will be made of.
  const forget = () => {
    setWorkflows(null);
    setPlan(null);
    setPull(null);
    setShadow(null);
    setParity(null);
    setSwitched(null);
    setRolled(null);
    setShadowAt(null);
    setRefused(null);
  };

  /** One request; the answer or the controller's refusal in words, never both. */
  async function run<T>(work: string, request: () => Promise<T>): Promise<T | null> {
    setBusy(work);
    setRefused(null);
    try {
      return await request();
    } catch (e) {
      setRefused(refusalWords(e instanceof ApiError ? e : new ApiError(0, null)));
      return null;
    } finally {
      setBusy(null);
    }
  }

  async function connect() {
    const answer = await run("connect", () => api<{ enabled: boolean; settings: boolean }>(tenantPath(slug), {
      method: "POST",
      body: { enabled: true, settings: optIn ?? false },
    }));
    if (!answer) return;
    migration.setData({ ...migration.data!, enabled: answer.enabled, settings: answer.settings });
    setOptIn(answer.settings);
    setConnectAt((v) => v ?? Date.now());
  }

  async function analyse() {
    if (!repo) return;
    const read = await run("analysis", () => api<WorkflowsAnswer>(workflowsPath(slug, repo)));
    if (!read) return;
    setWorkflows(read);
    setPlan(null);
    if (!read.workflows.length) {
      setRefused(`the revision ${read.commit} holds no workflow file: there is nothing to migrate`);
      return;
    }
    const native = mode === "native"
      ? { images: { linux: images.linux || null, linux_arm64: images.arm64 || null, windows: images.windows || null } }
      : undefined;
    const planned = await run("analysis", () => api<PreviewAnswer>(previewPath(slug, repo), {
      method: "POST",
      body: { commit: read.commit, workflows: read.workflows, ...(native ? { native } : {}) },
    }));
    if (!planned) return;
    setPlan(planned);
  }

  async function openPullRequest() {
    if (!repo || !commit) return;
    const answer = await run("pull-request", () => api<PullRequestAnswer>(pullRequestPath(slug, repo), {
      method: "POST",
      body: { action: "open", commit },
    }));
    if (answer) setPull(answer);
  }

  /** The native path's required-check preview: what the switch will change, before anything changes. */
  function nativePlan() {
    return { images: { linux: images.linux || null, linux_arm64: images.arm64 || null, windows: images.windows || null } };
  }

  async function openShadow() {
    if (!repo || !commit) return;
    const answer = await run("shadow", () => api<SwitchAnswer>(switchPath(slug, repo), {
      method: "POST",
      body: mode === "runner"
        ? { action: "shadow", commit }
        : { action: "preview", commit, native: nativePlan() },
    }));
    if (!answer) return;
    setShadow(answer);
    setShadowAt((v) => v ?? Date.now());
  }

  async function readParity() {
    if (!repo || !commit) return;
    const pairs: Pair[] = parityPairs(mode, commit, shadow);
    if (!pairs.length) {
      setRefused("no job pair is named yet: the shadow step stated no copy to compare");
      return;
    }
    const answer = await run("parity", () => api<ParityAnswer>(parityPath(slug, repo), {
      method: "POST",
      body: { pairs },
    }));
    if (answer) setParity(answer);
  }

  async function switchOver() {
    if (!repo || !commit) return;
    const answer = await run("switch", () => api<SwitchAnswer>(switchPath(slug, repo), {
      method: "POST",
      body: mode === "runner"
        ? { action: "switch", commit }
        : { action: mayApply(shadow) ? "apply" : "verify", commit, native: nativePlan() },
    }));
    if (answer) setSwitched(answer);
  }

  async function rollBack() {
    if (!repo || !commit) return;
    const stated = shadow?.settings ?? switched?.settings ?? null;
    const settings = mode === "native" && stated
      ? { ...preSwitchDocument(stated), apply: mayApply(shadow) }
      : undefined;
    const answer = await run("rollback", () => api<RollbackAnswer>(rollbackPath(slug, repo), {
      method: "POST",
      body: { action: "revert", commit, ...(settings ? { settings } : {}) },
    }));
    if (answer) setRolled(answer);
  }

  if (migration.failure) {
    return (
      <Page id="migration" title="Guided migration">
        <LoadFailed what="the tenant's migration switch" words={migration.failure} />
      </Page>
    );
  }

  const done: Record<Step, boolean> = {
    connect: !!migration.data?.enabled,
    repositories: !!repo,
    analysis: !!plan,
    preview: !!plan,
    "pull-request": mode === "native" ? !!plan : !!pull,
    shadow: !!shadow,
    switch: !!switched,
    rollback: !!rolled,
  };

  // The step being worked on and every step already answered are open; nothing ahead of an answer is.
  const canOpen = (id: Step) => done[id] || id === step;
  const go = (id: Step) => { if (canOpen(id)) setStep(id); };
  const next = () => { const after = STEPS[stepIndex(step) + 1]; if (after) setStep(after.id); };
  const current = STEPS[stepIndex(step)]!.label;

  return (
    <Page id="migration" title={`Guided migration · ${slug}`}>
      <p className="max-w-3xl text-sm text-muted">
        One repository at a time: connect the App, pick the repository, analyse its workflows, review the exact
        change, open the pull request, watch the shadow, switch over and roll back. Every step answers from the
        controller, and a refusal is the controller's own words.
      </p>
      <nav aria-label="Migration steps">
        <ol className="flex flex-wrap gap-2">
          {STEPS.map((s, i) => (
            <li key={s.id}>
              <button type="button" onClick={() => go(s.id)} disabled={!canOpen(s.id)} aria-current={s.id === step ? "step" : undefined}
                className={cx("flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-sm disabled:opacity-50",
                  s.id === step ? "border-primary bg-primary/10 font-medium text-primary" : "border-line bg-canvas text-fg", canOpen(s.id) && "cursor-pointer")}>
                <span className="text-xs text-muted">{i + 1}</span>{s.label}
                {done[s.id] ? <Icon name="circle-check" className="size-3.5 text-success" /> : null}
              </button>
            </li>
          ))}
        </ol>
      </nav>
      {refused ? <Alert color="error" role="alert" title="The controller refused this step" description={refused} /> : null}

      <Card titleId="step-h">
        <h2 id="step-h" tabIndex={-1} ref={heading} className="mb-3 text-base font-semibold text-strong focus:outline-none">
          {current}
        </h2>

        {step === "connect" ? <Connect current={migration.data!} optIn={optIn ?? migration.data!.settings} setOptIn={setOptIn}
          busy={busy === "connect"} onConnect={connect} onNext={next} next={done.connect} /> : null}

        {step === "repositories" ? (
          repos.failure ? <LoadFailed what="the tenant's repositories" words={repos.failure} /> : (
            <Repositories names={(repos.data?.repos ?? []).map((r) => r.name)} chosen={repo}
              choose={(name) => { setRepo(name); forget(); }} onNext={next} next={done.repositories} />
          )
        ) : null}

        {step === "analysis" ? (
          <Analysis
            mode={mode} setMode={(m) => { setMode(m); forget(); }}
            images={images} setImages={(k, v) => setImages((i) => ({ ...i, [k]: v }))}
            workflows={workflows} plan={plan} busy={busy === "analysis"} onAnalyse={analyse} onNext={next} />
        ) : null}

        {step === "preview" ? (
          <Preview mode={mode} plan={plan} onNext={next} next={done.preview} />
        ) : null}

        {step === "pull-request" ? (
          <PullRequestStep mode={mode} plan={plan} pull={pull} busy={busy === "pull-request"}
            onOpen={openPullRequest} onNext={next} next={done["pull-request"]} />
        ) : null}

        {step === "shadow" ? (
          <ShadowParity mode={mode} shadow={shadow} parity={parity} busy={busy} onShadow={openShadow} onParity={readParity}
            onNext={next} next={done.shadow} elapsed={connectAt && shadowAt ? (shadowAt - connectAt) / 1000 : null} />
        ) : null}

        {step === "switch" ? (
          <SwitchStep mode={mode} preview={shadow} switched={switched} busy={busy === "switch"} onSwitch={switchOver}
            onNext={next} next={done.switch} optIn={migration.data!.settings} />
        ) : null}

        {step === "rollback" ? (
          <RollbackStep mode={mode} switched={switched} rolled={rolled} busy={busy === "rollback"} onRollback={rollBack}
            commit={commit} />
        ) : null}
      </Card>
    </Page>
  );
}

function Next({ onNext, disabled, label = "Continue" }: { onNext: () => void; disabled: boolean; label?: string }) {
  return (
    <div className="flex items-center gap-2 pt-1">
      <Button label={label} trailingIcon="arrow-right" onClick={onNext} disabled={disabled} />
      {disabled ? <span className="text-xs text-muted">This step has not been answered by the controller yet.</span> : null}
    </div>
  );
}

function Connect({ current, optIn, setOptIn, busy, onConnect, onNext, next }: {
  current: MigrationSwitch; optIn: boolean; setOptIn: (v: boolean) => void; busy: boolean;
  onConnect: () => void; onNext: () => void; next: boolean;
}) {
  return (
    <div className="space-y-4">
      <dl className="grid gap-2 text-sm sm:grid-cols-3">
        <div><dt className="text-muted">Guided migration</dt><dd id="connect-state"><Badge color={current.enabled ? "success" : "neutral"}>{current.enabled ? "on" : "off"}</Badge></dd></div>
        <div><dt className="text-muted">Sentinel changes required checks</dt><dd id="connect-optin">{current.settings ? "opted in" : "not opted in"}</dd></div>
        <div><dt className="text-muted">The App's installations lack</dt><dd id="connect-missing">{current.missing.length ? current.missing.join(", ") : "nothing"}</dd></div>
      </dl>
      {current.missing.length ? (
        <Alert color="warning" title="A migration write would be refused"
          description={`The App's installations still lack ${current.missing.join(", ")}. Grant them in GitHub's App settings; the write steps refuse until then, each naming what it lacks.`} />
      ) : null}
      <Checkbox id="connect-optin-box" checked={optIn} onChange={setOptIn} label="Let Sentinel change a branch's required checks itself"
        description="Off by default. With the native path on and this off, the switch shows the exact change and a person applies it in GitHub; nothing is written without both this opt-in and the installation's repository administration." />
      <Button label={current.enabled ? "Save the opt-in" : "Start the migration"} icon="shield-check" loading={busy} onClick={onConnect} />
      <Next onNext={onNext} disabled={!next} />
    </div>
  );
}

function Repositories({ names, chosen, choose, onNext, next }: {
  names: string[]; chosen: string | null; choose: (name: string) => void; onNext: () => void; next: boolean;
}) {
  if (!names.length) return <p className="text-sm text-muted">This namespace has no repository to migrate yet.</p>;
  return (
    <div className="space-y-4">
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium text-strong">A repository of this namespace</legend>
        {names.map((name) => (
          <div key={name} className="flex items-center gap-2">
            <input type="radio" id={`repo-${name}`} name="migration-repo" value={name} checked={chosen === name}
              onChange={() => choose(name)} onClick={() => choose(name)} className="size-4 accent-[var(--s-primary)]" />
            <label htmlFor={`repo-${name}`} className="text-sm text-fg"><Icon name="folder-git-2" className="mr-1 inline size-4 text-muted" />{name}</label>
          </div>
        ))}
      </fieldset>
      <Next onNext={onNext} disabled={!next} />
    </div>
  );
}

function Analysis({ mode, setMode, images, setImages, workflows, plan, busy, onAnalyse, onNext }: {
  mode: Mode; setMode: (m: Mode) => void; images: { linux: string; arm64: string; windows: string };
  setImages: (key: "linux" | "arm64" | "windows", value: string) => void;
  workflows: WorkflowsAnswer | null; plan: PreviewAnswer | null; busy: boolean; onAnalyse: () => void; onNext: () => void;
}) {
  return (
    <div className="space-y-4">
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium text-strong">How this repository moves</legend>
        <div className="flex items-center gap-2">
          <input type="radio" id="mode-runner" name="migration-mode" checked={mode === "runner"} onChange={() => setMode("runner")} className="size-4 accent-[var(--s-primary)]" />
          <label htmlFor="mode-runner" className="text-sm text-fg">Runner mode — the default: the `runs-on:` labels move, nothing else changes</label>
        </div>
        <div className="flex items-center gap-2">
          <input type="radio" id="mode-native" name="migration-mode" checked={mode === "native"} onChange={() => setMode("native")} className="size-4 accent-[var(--s-primary)]" />
          <label htmlFor="mode-native" className="text-sm text-fg">Native path — optional: a generated `.sentinel.yml` replaces the workflow jobs</label>
        </div>
        {mode === "native" ? (
          <div className="grid gap-3 pt-2 sm:grid-cols-3">
            <Field label="Linux image" htmlFor="image-linux" hint="digest-pinned"><Input id="image-linux" value={images.linux} onChange={(e) => setImages("linux", e.target.value)} placeholder="ghcr.io/org/image:tag@sha256:…" /></Field>
            <Field label="arm64 image" htmlFor="image-arm64" hint="optional"><Input id="image-arm64" value={images.arm64} onChange={(e) => setImages("arm64", e.target.value)} /></Field>
            <Field label="Windows image" htmlFor="image-windows" hint="optional"><Input id="image-windows" value={images.windows} onChange={(e) => setImages("windows", e.target.value)} /></Field>
          </div>
        ) : null}
      </fieldset>
      <Button label="Analyse the workflows" icon="search" loading={busy} onClick={onAnalyse} />
      {workflows ? (
        <div className="space-y-3">
          <p className="text-sm text-muted">
            Read from <code className="font-mono text-xs">{workflows.branch ?? "the default branch"}</code> at commit{" "}
            <code id="analysed-commit" className="font-mono text-xs">{workflows.commit}</code>.
          </p>
          <Table caption="The workflow files the analysis read">
            <thead><tr><th>Workflow</th><th>Size</th></tr></thead>
            <tbody>
              {workflows.workflows.map((file) => (
                <tr key={file.path}><td className="font-mono text-xs">{file.path}</td><td>{fmtBytes(file.text.length)}</td></tr>
              ))}
            </tbody>
          </Table>
        </div>
      ) : null}
      {plan ? <Findings plan={plan} /> : null}
      <Next onNext={onNext} disabled={!plan} />
    </div>
  );
}

/** The analysis's findings: the jobs that move and, for every job that stays, the reasons in words. */
function Findings({ plan }: { plan: PreviewAnswer }) {
  return (
    <div id="analysis-findings" className="space-y-3">
      <p className="text-sm text-muted">
        Label table {plan.label_table}, rule table {plan.rule_table}; the deployment runs Docker jobs {plan.docker === "microvm_guests" ? "in micro-VM guests" : "on container-only workers"}.
      </p>
      {plan.workflows.map((workflow) => (
        <div key={workflow.path} className="space-y-2">
          <h3 className="font-mono text-sm text-strong">{workflow.path}</h3>
          <Table caption={`Jobs of ${workflow.path}`}>
            <thead><tr><th>Job</th><th>Finding</th></tr></thead>
            <tbody>
              {workflow.changes.map((change) => (
                <tr key={change.job}><td className="font-mono text-xs">{change.job}</td><td><Badge color="success">moves</Badge> <span className="text-muted">{change.before.trim()} → {change.after.trim()}</span></td></tr>
              ))}
              {workflow.kept.map((kept) => (
                <tr key={kept.job}><td className="font-mono text-xs">{kept.job}</td><td><Badge color="neutral">stays</Badge> <span className="text-muted">{kept.notes.join("; ")}</span></td></tr>
              ))}
              {!workflow.changes.length && !workflow.kept.length ? <tr><td colSpan={2} className="text-center text-muted">No job</td></tr> : null}
            </tbody>
          </Table>
          {workflow.native_refused ? (
            <Alert color="warning" title="No native pipeline for this workflow" description={workflow.native_refused} />
          ) : null}
        </div>
      ))}
    </div>
  );
}

function Preview({ mode, plan, onNext, next }: { mode: Mode; plan: PreviewAnswer | null; onNext: () => void; next: boolean }) {
  if (!plan) return <p className="text-sm text-muted">Analyse the repository first: there is nothing to preview.</p>;
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">This is the plan at commit <code className="font-mono text-xs">{plan.revision}</code>, exactly as the write applies it.</p>
      {plan.workflows.map((workflow) => (
        <div key={workflow.path} className="space-y-2">
          <h3 className="font-mono text-sm text-strong">{workflow.path}</h3>
          {workflow.diff ? (
            <pre id={`diff-${workflow.path.split("/").pop()}`} aria-label={`The runs-on: diff of ${workflow.path}`}
              className="max-h-80 overflow-auto rounded-md border border-line bg-subtle p-3 font-mono text-xs whitespace-pre">{workflow.diff}</pre>
          ) : <p className="text-sm text-muted">No `runs-on:` line changes in this workflow.</p>}
          {workflow.kept.length ? (
            <p className="text-sm text-muted">Stays on GitHub's runners: {workflow.kept.map((k) => `${k.job} (${k.notes.join("; ")})`).join(", ")}</p>
          ) : null}
          {mode === "native" && workflow.native ? (
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-sm font-medium text-strong">The generated pipeline: <code className="font-mono text-xs">{workflow.native.path}</code></h4>
                <Copy text={workflow.native.text} label={`the pipeline for ${workflow.path}`} />
              </div>
              <pre aria-label={`The generated pipeline for ${workflow.path}`} className="max-h-80 overflow-auto rounded-md border border-line bg-subtle p-3 font-mono text-xs whitespace-pre">{workflow.native.text}</pre>
              {workflow.native.secrets.length ? <p className="text-sm text-muted">Secrets to provision (names only): {workflow.native.secrets.join(", ")}</p> : null}
              {workflow.native.notes.length ? <p className="text-sm text-muted">{workflow.native.notes.join("; ")}</p> : null}
            </div>
          ) : null}
        </div>
      ))}
      <Next onNext={onNext} disabled={!next} />
    </div>
  );
}

function PullLink({ pull }: { pull: Pull }) {
  return <p className="text-sm">Pull request #{pull.number} <code className="font-mono text-xs">{pull.head} → {pull.base}</code>,{" "}<Badge color="info">{pull.state}</Badge>{" "}
    <TextLink to={pull.url} className="text-sm" aria-label={`Pull request ${pull.number} on GitHub`}>Open on GitHub <Icon name="external-link" className="inline size-3.5" /></TextLink></p>;
}

function PullRequestStep({ mode, plan, pull, busy, onOpen, onNext, next }: {
  mode: Mode; plan: PreviewAnswer | null; pull: PullRequestAnswer | null; busy: boolean;
  onOpen: () => void; onNext: () => void; next: boolean;
}) {
  if (mode === "native") {
    const paths = (plan?.workflows ?? []).flatMap((w) => (w.native ? [w.native.path] : []));
    return (
      <div className="space-y-4">
        <Alert color="info" title="The native path opens no label pull request"
          description="The generated pipeline is committed by you, in the file named here; the pull request that disables the replaced workflow jobs is opened by the switch step, and only after the required checks that replace them are in place." />
        <p className="text-sm text-muted">Add these files to the repository: {paths.length ? paths.map((p) => <code key={p} className="mr-2 font-mono text-xs">{p}</code>) : "no workflow produced a pipeline."}</p>
        <Next onNext={onNext} disabled={!next} label="Continue to the shadow" />
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">One pull request on <code className="font-mono text-xs">sentinel/migrate</code>, never a push to the default branch. Re-running updates it.</p>
      <Button label={pull ? "Update the pull request" : "Open the pull request"} icon="git-merge" loading={busy} onClick={onOpen} disabled={!plan} />
      {pull ? (
        <div className="space-y-2">
          {pull.pull_request ? <PullLink pull={pull.pull_request} /> : null}
          <Table caption="What the pull request changes">
            <thead><tr><th>Workflow</th><th>Jobs</th></tr></thead>
            <tbody>{pull.changed.map((c) => <tr key={c.path}><td className="font-mono text-xs">{c.path}</td><td>{c.jobs.join(", ")}</td></tr>)}</tbody>
          </Table>
        </div>
      ) : null}
      <Next onNext={onNext} disabled={!next} label="Continue to the shadow" />
    </div>
  );
}

function SetList({ title, set, color }: { title: string; set: Required; color: "neutral" | "success" }) {
  return (
    <div>
      <h4 className="text-sm font-medium text-strong">{title}</h4>
      {set.required.length ? (
        <ul className="mt-1 flex flex-wrap gap-1">{set.required.map((context) => <li key={context}><Badge color={color}>{context}</Badge></li>)}</ul>
      ) : <p className="text-sm text-muted">no required check</p>}
      <p className="text-xs text-muted">strict: {set.strict ? "yes" : "no"}</p>
    </div>
  );
}

/** The required-check change one switch answer states: what it adds, removes and replaces. */
function ChangeTable({ settings }: { settings: SettingsView }) {
  const rows = [
    ...settings.change.added.map((context) => ({ what: "added", context, check: null })),
    ...settings.change.removed.map((context) => ({ what: "removed", context, check: null })),
    ...settings.change.replaced.map((pair) => ({ what: "replaced", context: pair.context, check: pair.check })),
  ];
  return (
    <Table caption={`The required-check change on ${settings.branch}`}>
      <thead><tr><th>Change</th><th>Required check</th><th>Replaced by</th></tr></thead>
      <tbody>
        {rows.length ? rows.map((row) => (
          <tr key={`${row.what}-${row.context}`}><td><Badge color={row.what === "removed" ? "warning" : "success"}>{row.what}</Badge></td>
            <td className="font-mono text-xs">{row.context}</td><td className="font-mono text-xs">{row.check ?? "—"}</td></tr>
        )) : <tr><td colSpan={3} className="text-center text-muted">No required check changes: every copy this migration adds is non-required by construction.</td></tr>}
      </tbody>
    </Table>
  );
}

function ShadowParity({ mode, shadow, parity, busy, onShadow, onParity, onNext, next, elapsed }: {
  mode: Mode; shadow: SwitchAnswer | null; parity: ParityAnswer | null; busy: string | null;
  onShadow: () => void; onParity: () => void; onNext: () => void; next: boolean; elapsed: number | null;
}) {
  return (
    <div className="space-y-4">
      {mode === "runner" ? (
        <div className="space-y-2">
          <p className="text-sm text-muted">The shadow pull request adds one non-required copy per migrating job, beside the unchanged original, so both run on the same commits while GitHub's runners stay authoritative.</p>
          <Button label={shadow ? "Update the shadow pull request" : "Open the shadow pull request"} icon="git-merge"
            loading={busy === "shadow"} onClick={onShadow} />
          {shadow?.pull_request ? <PullLink pull={shadow.pull_request} /> : null}
          {shadow?.shadow?.length ? (
            <Table caption="The copies the shadow pull request adds">
              <thead><tr><th>Original job</th><th>Copy</th><th>Class</th></tr></thead>
              <tbody>{shadow.shadow.map((copy) => (
                <tr key={copy.name}><td className="font-mono text-xs">{copy.job}</td><td className="font-mono text-xs">{copy.name}</td><td>{copy.class ?? "—"}</td></tr>
              ))}</tbody>
            </Table>
          ) : null}
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-sm text-muted">On the native path the shadow is Sentinel's own <code className="font-mono text-xs">sentinel / &lt;job&gt;</code> check, so nothing is added to the workflow. Reading the required-check change now shows what the switch will do.</p>
          <Button label={shadow ? "Read the change again" : "Read the required-check change"} icon="shield" loading={busy === "shadow"} onClick={onShadow} />
          {shadow?.settings ? <ChangeTable settings={shadow.settings} /> : null}
          {shadow?.disabled?.length ? <p className="text-sm text-muted">The jobs Sentinel's pipeline replaces: {shadow.disabled.join(", ")}</p> : null}
        </div>
      )}
      {elapsed !== null ? (
        <p id="migration-elapsed" className="text-sm text-muted">
          {(elapsed).toFixed(1)} s from connect to the shadow step. The first shadow run itself is the controller's to report; this page cannot see it.
        </p>
      ) : null}

      <div className="space-y-2 border-t border-line pt-3">
        <Button label="Read parity" icon="scale" loading={busy === "parity"} onClick={onParity} disabled={!shadow} />
        {parity ? (
          <div className="space-y-2">
            <Table caption="Parity per job pair">
              <thead><tr><th>Commit</th><th>Original</th><th>Copy</th><th>Run by</th><th>Sentinel's side</th><th>Verdict</th></tr></thead>
              <tbody>
                {parity.pairs.length ? parity.pairs.map((pair) => (
                  <tr key={`${pair.sha}-${pair.shadow}`}>
                    <td className="font-mono text-xs">{pair.sha.slice(0, 7)}</td>
                    <td className="font-mono text-xs">{pair.job}</td>
                    <td className="font-mono text-xs">{pair.shadow}</td>
                    <td>{pair.mode ?? "—"}</td>
                    <td>{pair.shadow_side ? `${pair.shadow_side.conclusion ?? "no conclusion"}${pair.shadow_side.duration_ms !== null ? ` · ${(pair.shadow_side.duration_ms / 1000).toFixed(1)} s` : ""}` : "not run yet"}</td>
                    <td><Badge color={pair.verdict === "match" ? "success" : "warning"}>{pair.verdict}</Badge>{" "}
                      {pair.mismatches.length ? <span className="text-xs text-muted">{pair.mismatches.join(", ")}</span> : null}</td>
                  </tr>
                )) : <tr><td colSpan={6} className="text-center text-muted">No pair</td></tr>}
              </tbody>
            </Table>
            {parity.pairs.some((p) => p.mismatches.includes("no_original")) ? (
              <Alert color="neutral" description="GitHub's Actions side is not read by this deployment, so a pair whose page was never supplied says `no_original` rather than matching: a pair is a match only when both sides were compared." />
            ) : null}
            {parity.unpaired.length ? <p className="text-sm text-muted">Copies no pair names: {parity.unpaired.map((u) => `${u.shadow} at ${u.sha.slice(0, 7)}`).join(", ")}</p> : null}
          </div>
        ) : null}
      </div>
      <Next onNext={onNext} disabled={!next} label="Continue to the switch" />
    </div>
  );
}

function SwitchStep({ mode, preview, switched, busy, onSwitch, onNext, next, optIn }: {
  mode: Mode; preview: SwitchAnswer | null; switched: SwitchAnswer | null; busy: boolean;
  onSwitch: () => void; onNext: () => void; next: boolean; optIn: boolean;
}) {
  const change = preview?.settings ?? switched?.settings ?? null;
  const readBack = switched?.settings ?? null;
  return (
    <div className="space-y-4">
      {mode === "runner" ? (
        <p className="text-sm text-muted">The switch drops the copies and moves the originals' `runs-on:` labels. Job names, and so the checks a required check names, do not change; the protection is read before the pull request and again after it.</p>
      ) : (
        <p className="text-sm text-muted">On the native path the switch changes the branch's required checks first and then opens the pull request that disables the replaced jobs, because a job must not be disabled before the check that replaces it is required.</p>
      )}
      {change ? (
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-strong">The change the preview stated{change.branch ? ` on ${change.branch}` : ""}</h3>
          <ChangeTable settings={change} />
          <div className="grid gap-3 sm:grid-cols-2">
            <SetList title="Required checks before" set={change.before} color="neutral" />
            <SetList title="Required checks the change expects" set={change.expected} color="success" />
          </div>
        </div>
      ) : <p className="text-sm text-muted">{mode === "native" ? "Read the required-check change in the shadow step first." : "The preview states no required-check change: there is none to state in runner mode."}</p>}

      {mode === "native" && !mayApply(preview) ? (
        <Alert color="info" title="This is a person's action, not Sentinel's"
          description={`${optIn ? "The App's installation does not hold repository administration" : "The tenant has not opted into Sentinel changing its required checks"}, so Sentinel will not write them. Apply the change above in GitHub, then check it here; the comparison is what the switch would have proven.`} />
      ) : null}

      <Button
        label={mode === "runner" ? "Switch this repository over" : mayApply(preview) ? "Apply the change and disable the replaced jobs" : "Check the change I made"}
        icon={mode === "runner" ? "git-merge" : mayApply(preview) ? "shield-check" : "refresh-cw"} loading={busy} onClick={onSwitch}
        disabled={mode === "native" && !preview} />

      {switched?.pull_request ? <PullLink pull={switched.pull_request} /> : null}
      {readBack ? (
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-strong">What GitHub states now</h3>
          <Table caption="The protection read back after the switch">
            <thead><tr><th>Required checks read back</th><th>strict</th><th>Verdict</th></tr></thead>
            <tbody>
              <tr>
                <td>{readBack.after?.required.length ? readBack.after.required.map((c) => <Badge key={c} className="mr-1">{c}</Badge>) : <span className="text-muted">no required check</span>}</td>
                <td>{readBack.after ? (readBack.after.strict ? "yes" : "no") : "—"}</td>
                <td><Badge color={readBack.verdict === "equal" ? "success" : readBack.verdict === "moved" ? "error" : "warning"}>{readBack.verdict}</Badge></td>
              </tr>
            </tbody>
          </Table>
          {readBack.verdict === "moved" ? <Alert color="error" role="alert" description="The set GitHub reads back is not the set the change stated. The switch reports it rather than asserting the gate held." /> : null}
          {readBack.verdict === "equal" ? <p className="text-sm text-muted">The set read back is the set the change stated: the merge gate is what the preview promised.</p> : null}
        </div>
      ) : null}
      <Next onNext={onNext} disabled={!next} label="Continue to the rollback" />
    </div>
  );
}

function RollbackStep({ mode, switched, rolled, busy, onRollback, commit }: {
  mode: Mode; switched: SwitchAnswer | null; rolled: RollbackAnswer | null; busy: boolean; onRollback: () => void; commit: string | null;
}) {
  const readBack = switched?.settings ?? null;
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        One action puts the pre-switch workflows back on <code className="font-mono text-xs">sentinel/migrate</code> over the default branch's head
        {mode === "native" ? ", and the same action states the required-check change back: the pre-switch document the switch's preview promised." : ", and the required checks are read before and after it."}
        {commit ? <> The revision it restores is <code className="font-mono text-xs">{commit}</code>.</> : null}
      </p>
      {mode === "native" && readBack ? (
        <div className="grid gap-3 sm:grid-cols-2">
          <SetList title="Required checks now" set={readBack.after ?? readBack.before} color="neutral" />
          <SetList title="Required checks the rollback restores" set={readBack.before} color="success" />
        </div>
      ) : null}
      <Button label="Roll this back" icon="rotate-cw" color="warning" loading={busy} onClick={onRollback} disabled={!switched} />
      {rolled ? (
        <div className="space-y-2">
          {rolled.pull_request ? <PullLink pull={rolled.pull_request} /> : null}
          <Table caption="What the rollback restores">
            <thead><tr><th>Workflow</th><th>Jobs</th></tr></thead>
            <tbody>{rolled.workflows.map((w) => <tr key={w.path}><td className="font-mono text-xs">{w.path}</td><td className="font-mono text-xs">{w.jobs.join(", ")}</td></tr>)}</tbody>
          </Table>
          {rolled.deleted.length ? <p className="text-sm text-muted">Removed with it: {rolled.deleted.join(", ")}</p> : null}
          {rolled.settings ? (
            <div className="space-y-1">
              <p className="text-sm">Required checks: <Badge color={rolled.settings.applied ? "success" : "info"}>{rolled.settings.applied ? "applied" : "shown, not applied"}</Badge>{" "}
                <span className="text-muted">{rolled.settings.reason ?? "no reason stated"}</span></p>
              {rolled.settings.restore?.length ? <p className="text-sm text-muted">Restores: {rolled.settings.restore.map((c) => c.context).join(", ")}</p> : null}
              {rolled.settings.remove?.length ? <p className="text-sm text-muted">Removes: {rolled.settings.remove.map((c) => c.context).join(", ")}</p> : null}
              {rolled.settings.verified !== null ? <p className="text-sm text-muted">GitHub reads it back {rolled.settings.verified ? "exactly" : "differently"}.</p> : null}
            </div>
          ) : null}
          <p className="text-sm text-muted">Shadow mode can be re-entered at any time from the shadow step of a new migration.</p>
        </div>
      ) : null}
    </div>
  );
}

function Copy({ text, label }: { text: string; label: string }) {
  const [note, setNote] = useState("");
  return (
    <span className="flex items-center gap-2">
      <Button color="neutral" variant="outline" size="sm" icon="copy" label="Copy" aria-label={`Copy ${label}`} onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setNote("Copied.");
        } catch {
          setNote("The browser refused the clipboard; select the pipeline instead.");
        }
      }} />
      <span role="status" aria-live="polite" className="text-xs text-muted">{note}</span>
    </span>
  );
}
