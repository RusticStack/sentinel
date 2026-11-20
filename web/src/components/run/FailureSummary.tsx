// The same bounded failure view an agent reads from /attempts/{id}/failure, read in the browser after the page shows.
import { useEffect, useState } from "react";
import type { JobStatus } from "../../lib/types";
import { api } from "../../lib/api.ts";
import { words } from "../../lib/format.ts";
import { Badge, Icon, TextLink } from "../ui.tsx";

const ANSI = new RegExp("\\x1b\\[[0-?]*[ -/]*[@-~]", "g");

export function FailureSummary({ job, run }: { job: JobStatus; run: string }) {
  const [f, setF] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    api<any>(`/api/v1/attempts/${job.attempt}/failure?budget=6144&limit=10`).then((v) => { if (live) setF(v); }, (e) => { if (live) setError((e as Error).message); });
    return () => { live = false; };
  }, [job.attempt]);
  const diagnostics: any[] = [];
  for (const r of f?.reports || []) for (const d of r.report?.diagnostics || []) diagnostics.push(d);
  const tail = (f?.tail?.frames || []) as any[];
  const tailText = tail.map((fr) => (fr.binary ? `[${fr.bytes} bytes of binary output]` : fr.text)).join("").replace(ANSI, "");
  const logLink = (step: number, seq: number) => `/runs/${run}/logs/${job.attempt}?step=${step}&seq=${seq}`;
  return (
    <section aria-label={`Failure of ${job.name}`} className="rounded-lg border border-line bg-canvas">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <Icon name="octagon-alert" className="size-5 text-error" />
        <h2 className="font-semibold text-strong">Why {job.name} {words(job.state)}</h2>
      </header>
      <div className="space-y-3 p-4">
        {error ? <p className="text-sm text-muted">Failure summary unavailable: {error}</p>
          : !f ? <div className="h-16 w-full animate-pulse rounded-md bg-elevated" />
          : <>
            {f.failed_step ? (
              <p className="text-sm">
                Failed step <strong>{f.failed_step.id}</strong> ({words(f.failed_step.outcome)}
                {f.failed_step.exit_code != null ? `, exit ${f.failed_step.exit_code}` : ""}{f.failed_step.signal ? `, signal ${f.failed_step.signal}` : ""})
              </p>
            ) : null}
            {diagnostics.length ? (
              <ul className="space-y-1.5 text-sm">
                {diagnostics.map((d, i) => (
                  <li key={i} className="flex flex-wrap items-baseline gap-2">
                    <Badge color={d.severity === "warning" ? "warning" : "error"}>{d.severity}</Badge>
                    {d.source ? <code className="text-xs">{d.source.path}{d.source.line ? `:${d.source.line}` : ""}</code> : d.test ? <code className="text-xs">{d.test.name}</code> : null}
                    <span className="break-words">{d.message.length > 400 ? d.message.slice(0, 400) + "…" : d.message}</span>
                    {d.evidence?.[0] ? <TextLink to={logLink(d.evidence[0].step_index, d.evidence[0].start.sequence)} className="underline">evidence</TextLink> : null}
                  </li>
                ))}
              </ul>
            ) : null}
            {tail.length ? <>
              <h3 className="text-sm font-semibold text-strong">Output tail</h3>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md bg-subtle p-2 font-mono text-xs">{tailText}</pre>
              <TextLink to={logLink(tail[0].step, tail[0].sequence)} className="text-sm underline">Open this in the log</TextLink>
            </> : null}
            {f.truncated ? <p className="text-xs text-muted">Summary cut to its budget; the full log has everything.</p> : null}
            {!f.log_complete ? <p className="text-xs text-muted">The log is incomplete or still being written.</p> : null}
            {!f.failed_step && !diagnostics.length && !tail.length ? (
              <p className="text-sm">No diagnostics were found. <TextLink to={`/runs/${run}/logs/${job.attempt}`} className="underline">Open the log</TextLink></p>
            ) : null}
            {/* The deterministic account above is the finding; this is only ever below it. */}
            {job.attempt ? <Analysis attempt={job.attempt} /> : null}
          </>}
      </div>
    </section>
  );
}

/**
 * The advisory analysis of one attempt (Y05), under the deterministic summary and nowhere else. It is
 * always labelled inference, and every citation opens the log at the line it names. No analysis — AI
 * off, nothing asked for yet, an answer whose every citation was dropped, or one whose log has gone —
 * renders nothing at all: a claim nobody can check must not look like a finding.
 */
function Analysis({ attempt }: { attempt: string }) {
  const [a, setA] = useState<any>(null);
  useEffect(() => {
    let live = true;
    api<any>(`/api/v1/attempts/${attempt}/ai-analysis`).then((v) => { if (live) setA(v); }, () => { if (live) setA({ present: false }); });
    return () => { live = false; };
  }, [attempt]);
  if (!a) return null;
  if (!a.present) {
    return a.reason === "pending" ? (
      <p className="text-xs text-muted">An analysis was requested and is still being written.</p>
    ) : null;
  }
  const cited = (c: any) =>
    c.sequence == null ? "" : `/runs/${c.run}/logs/${c.attempt}?step=${c.step ?? 0}&seq=${c.sequence}`;
  return (
    <section aria-label="AI analysis" className="space-y-2 rounded-md border border-line bg-subtle p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold text-strong">AI analysis</h3>
        <Badge color="neutral" icon="sparkles">inference</Badge>
      </div>
      <p className="text-xs text-muted">A model's reading of this attempt's evidence, below the summary above. It is not evidence and it cannot change this run's result.</p>
      <p className="text-sm">{a.summary}</p>
      <ul className="space-y-1.5 text-sm">
        {(a.claims || []).map((claim: any, i: number) => (
          <li key={i} className="flex flex-wrap items-baseline gap-2">
            <span className="break-words">{claim.text}</span>
            <span className="flex flex-wrap gap-2">
              {(claim.citations || []).map((c: any, j: number) => {
                const to = cited(c);
                return to ? <TextLink key={j} to={to} className="font-mono text-xs underline">{c.evidence}</TextLink> : null;
              })}
            </span>
          </li>
        ))}
      </ul>
      {a.reused ? <p className="text-xs text-muted">Computed from an earlier attempt of this same failure; its citations name that attempt's log.</p> : null}
      {a.dropped_citations ? <p className="text-xs text-muted">{a.dropped_citations} citation{a.dropped_citations === 1 ? "" : "s"} did not resolve against the stored log and {a.dropped_citations === 1 ? "is" : "are"} not shown.</p> : null}
    </section>
  );
}
