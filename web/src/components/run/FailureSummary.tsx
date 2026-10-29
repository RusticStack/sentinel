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
          </>}
      </div>
    </section>
  );
}
