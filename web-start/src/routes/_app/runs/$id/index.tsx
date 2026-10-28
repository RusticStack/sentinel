import { useEffect, useState } from "react";
import { createFileRoute, notFound } from "@tanstack/react-router";
import type { Explanation, JobStatus, Run } from "../../../../lib/types";
import { api, ApiError } from "../../../../lib/api.ts";
import { act } from "../../../../lib/act.tsx";
import { useSession } from "../../../../lib/session.ts";
import { loadRepos, type RepoList } from "../../../../lib/repos.ts";
import { useLoaded } from "../../../../lib/hooks.ts";
import { useRunStream } from "../../../../lib/runStream.ts";
import { fmtBytes, fmtNs, shortId, words } from "../../../../lib/format.ts";
import { Page, rememberTenant } from "../../../../components/Page.tsx";
import { StateBadge } from "../../../../components/StateBadge.tsx";
import { RelTime } from "../../../../components/RelTime.tsx";
import { JobGraph } from "../../../../components/run/JobGraph.tsx";
import { PhaseBar, phasesOf } from "../../../../components/run/PhaseBar.tsx";
import { FailureSummary } from "../../../../components/run/FailureSummary.tsx";
import { Alert, Badge, Button, ButtonLink, Table, TextLink } from "../../../../components/ui.tsx";

const RUN_ID = /^run_[0-9a-f-]{36}$/;

interface Artifacts { tenant: string; artifacts: any[] }

export const Route = createFileRoute("/_app/runs/$id/")({
  loader: async ({ params }) => {
    if (!RUN_ID.test(params.id)) throw notFound();
    let run: Run;
    try {
      run = await api<Run>(`/api/v1/runs/${params.id}`);
    } catch (e) {
      if (e instanceof ApiError && (e.status === 404 || e.status === 403)) throw notFound();
      throw e;
    }
    const [explain, arts] = await Promise.all([
      api<Explanation>(`/api/v1/runs/${params.id}/pipeline`).catch(() => null),
      api<Artifacts>(`/api/v1/runs/${params.id}/artifacts`).catch(() => null),
    ]);
    const repos: RepoList | null = arts?.tenant ? await loadRepos(arts.tenant).catch(() => null) : null;
    // The clock travels with the page so the server and browser first renders match.
    return { run, explain, arts, repos, now: Date.now() };
  },
  head: ({ params }) => ({ meta: [{ title: `Run ${shortId(params.id)} · Sentinel` }] }),
  component: RunView,
});

interface CacheRow { job: string; name: string; outcome: string; backend: string; bytes: number | null; copied: number | null; restore: number | null; publish: string | null; costly: boolean }

function RunView() {
  const { id } = Route.useParams();
  const loaded = Route.useLoaderData();
  const { me } = useSession();
  const [run, setRun] = useLoaded<Run>(loaded.run);
  const { status, refused } = useRunStream(id, loaded.run, setRun);
  const [now, setNow] = useState(loaded.now);
  const [caches, setCaches] = useState<CacheRow[] | null>(null);
  const [manifests, setManifests] = useState<Record<string, any>>({});
  const slug = loaded.arts?.tenant ?? null;
  const repoName = loaded.repos?.repos.find((r) => r.id === run.repo)?.name ?? null;

  useEffect(() => { if (slug) rememberTenant(slug); }, [slug]);
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  useEffect(() => {
    let live = true;
    (async () => {
      const rows: CacheRow[] = [];
      const jobs = loaded.run.jobs.filter((j) => j.attempt);
      const summaries = await Promise.all(jobs.map((j) => api<any>(`/api/v1/attempts/${j.attempt}/summary`).then((s) => [j, s] as const).catch(() => [j, null] as const)));
      for (const [j, s] of summaries) {
        if (!s?.present) continue;
        for (const c of s.caches) rows.push({ job: j.name, name: c.name, outcome: c.outcome, backend: c.reflink ? "reflink" : "copy", bytes: c.bytes, copied: c.copied_bytes, restore: c.clone_ns, publish: c.publish, costly: c.costly_hit });
        if (s.image_present !== null && s.image_present !== undefined) rows.push({ job: j.name, name: "image", outcome: s.image_present ? "hit" : "miss", backend: "image store", bytes: null, copied: null, restore: null, publish: null, costly: false });
      }
      if (live) setCaches(rows);
    })();
    return () => { live = false; };
  }, [loaded.run]);

  const finished = run.jobs.every((j) => j.terminal);
  const scale = Math.max(1, ...run.jobs.map((j) => phasesOf(j.timestamps, now).reduce((a, p) => a + p.ms, 0)));
  const failed = run.jobs.filter((j) => j.attempt && j.terminal && !["passed", "skipped", "canceled"].includes(j.state));

  const cancelRun = () => act(me, "Cancel run", () => api(`/api/v1/runs/${id}/cancel`, { method: "POST", body: {} }));
  const jobAction = (job: JobStatus) =>
    act(me, `${job.terminal ? "Rerun" : "Cancel"} ${job.name}`, () => api(`/api/v1/jobs/${job.id}/${job.terminal ? "rerun" : "cancel"}`, { method: "POST", body: {} }));
  async function toggleManifest(a: any) {
    if (manifests[a.id]) { const { [a.id]: _, ...rest } = manifests; setManifests(rest); return; }
    const detail = await act(me, `Files of ${a.name}`, () => api<any>(`/api/v1/runs/${id}/artifacts/${a.id}`));
    if (detail?.manifest) setManifests((m) => ({ ...m, [a.id]: detail }));
  }

  return (
    <Page id="run" title={`Run ${shortId(id)}`} actions={<>
      {status === "busy" ? <Badge color="warning" icon="hourglass">Updates paused: controller busy</Badge>
        : status === "lost" || status === "reconnecting" ? <Badge color="warning" icon="wifi-off">Reconnecting…</Badge>
        : status === "live" && !finished ? <Badge color="info" icon="radio">Live</Badge> : null}
      {!finished ? <Button color="error" variant="soft" icon="square" label="Cancel run" onClick={cancelRun} /> : null}
    </>}>
      {refused ? (
        <Alert color="error" icon="lock" title={refused} description="The page stopped following this run." role="alert">
          <ButtonLink to="/" size="sm" variant="outline" color="neutral" label="Back to your tenants" />
        </Alert>
      ) : null}

      <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-sm">
        <dt className="text-muted">State</dt>
        <dd className="flex items-center gap-2"><StateBadge state={run.state} />{run.cancel_requested && !finished ? <span className="text-muted">cancel requested</span> : null}</dd>
        <dt className="text-muted">Trigger</dt><dd>{words(run.trigger)}</dd>
        <dt className="text-muted">Commit</dt><dd><code className="break-all text-xs">{run.sha}</code></dd>
        <dt className="text-muted">Repository</dt>
        <dd>{slug && repoName ? <TextLink to={`/t/${slug}`} search={{ repo: repoName }} className="underline">{slug}/{repoName}</TextLink> : <span>{shortId(run.repo)}</span>}</dd>
        <dt className="text-muted">Created</dt><dd><RelTime ms={run.created_ms} /></dd>
      </dl>

      <section aria-labelledby="jobs-h" className="space-y-3">
        <h2 id="jobs-h" className="text-base font-semibold text-strong">Jobs</h2>
        {loaded.explain ? <JobGraph explain={loaded.explain} jobs={run.jobs} run={id} /> : null}
        <Table caption="Jobs">
          <thead><tr><th>Job</th><th>State</th><th>Failure class</th><th>Phases</th><th>Log</th><th>Actions</th></tr></thead>
          <tbody>
            {run.jobs.map((j) => (
              <tr key={j.id}>
                <td>{j.name}</td>
                <td>
                  <div className="flex flex-col items-start gap-1">
                    <StateBadge state={j.state} />
                    {j.cancel_requested && !j.terminal ? <span className="text-xs text-muted">cancel requested</span> : null}
                  </div>
                </td>
                <td>{words(j.failure_class)}</td>
                <td><PhaseBar t={j.timestamps} scale={scale} now={now} /></td>
                <td>
                  {j.attempt ? <TextLink to={`/runs/${id}/logs/${j.attempt}`} aria-label={`Log of ${j.name}`} className="underline">Log</TextLink> : <span className="text-muted">—</span>}
                  {j.log_state && j.log_state !== "complete" && j.terminal ? <span className="text-xs text-muted"> ({j.log_state})</span> : null}
                </td>
                <td>
                  <Button size="sm" color={j.terminal ? "neutral" : "error"} variant={j.terminal ? "outline" : "soft"} icon={j.terminal ? "rotate-cw" : "square"}
                    aria-label={`${j.terminal ? "Rerun" : "Cancel"} ${j.name}`} onClick={() => jobAction(j)}>{j.terminal ? "Rerun" : "Cancel"}</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </section>

      {failed.map((j) => <FailureSummary key={j.attempt!} job={j} run={id} />)}

      {caches?.length ? (
        <section aria-labelledby="caches-h" className="space-y-3">
          <h2 id="caches-h" className="text-base font-semibold text-strong">Caches</h2>
          <Table caption="Cache outcomes">
            <thead><tr><th>Job</th><th>Cache</th><th>Outcome</th><th>Backend</th><th>Size</th><th>Copied</th><th>Restore</th><th>Publish</th></tr></thead>
            <tbody>
              {caches.map((c, i) => (
                <tr key={i}>
                  <td>{c.job}</td><td>{c.name}</td>
                  <td><StateBadge state={c.outcome === "hit" ? "hit" : "miss"} label={c.outcome === "hit" ? "hit" : `miss: ${words(c.outcome)}`} />{c.costly ? <span className="text-xs text-muted"> costly hit</span> : null}</td>
                  <td>{c.backend}</td><td>{fmtBytes(c.bytes)}</td><td>{fmtBytes(c.copied)}</td><td>{fmtNs(c.restore)}</td><td>{c.publish ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </section>
      ) : null}

      {loaded.arts?.artifacts.length ? (
        <section aria-labelledby="artifacts-h" className="space-y-3">
          <h2 id="artifacts-h" className="text-base font-semibold text-strong">Artifacts</h2>
          <Table caption="Artifacts">
            <thead><tr><th>Artifact</th><th>Job</th><th>State</th><th>Entries</th><th>Size</th><th>Kept until</th><th>Files</th></tr></thead>
            <tbody>
              {loaded.arts.artifacts.map((a) => (
                <tr key={a.id}>
                  <td>{a.name}</td><td>{a.job_name}</td>
                  <td><StateBadge state={a.state === "captured" ? "passed" : a.state === "failed" ? "failed" : "skipped"} label={a.state} /></td>
                  <td>{a.entries}</td><td>{fmtBytes(a.bytes)}</td><td><RelTime ms={a.retain_until_ms} /></td>
                  <td>
                    {a.state === "captured" ? (
                      <div>
                        <Button size="sm" color="neutral" variant="outline" aria-expanded={!!manifests[a.id]} aria-label={`Files of ${a.name}`} onClick={() => toggleManifest(a)}>Files</Button>
                        {manifests[a.id] ? (
                          <ul className="mt-2 space-y-1 text-xs">
                            {manifests[a.id].manifest.entries.slice(0, 500).map((en: any) => (
                              <li key={en.path}>
                                <a href={`/api/v1/tenants/${manifests[a.id].tenant}/objects/${en.digest}`} download={en.path.split("/").pop()} className="text-primary underline">{en.path}</a>
                                <span className="text-muted"> {fmtBytes(en.len)}</span>
                              </li>
                            ))}
                          </ul>
                        ) : null}
                      </div>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </section>
      ) : null}
    </Page>
  );
}
