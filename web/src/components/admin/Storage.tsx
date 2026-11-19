import { useState } from "react";
import type { StorageClasses, StorageItem, StorageTrendDay, TenantStorage } from "../../lib/types";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { attempt, useLoad, type Load } from "../../lib/loaded.ts";
import { fmtBytes } from "../../lib/format.ts";
import { LoadFailed } from "../LoadFailed.tsx";
import { StoragePolicyForm, type StoragePolicyBody } from "../StoragePolicyForm.tsx";
import { Alert, Badge, Button, Card, DialogModal, Table } from "../ui.tsx";
import { Until } from "../RelTime.tsx";

const DAY = 86_400_000;
const readStorage = (slug: string) => api<TenantStorage>(`/api/v1/tenants/${encodeURIComponent(slug)}/storage`);
export const loadStorage = (slug: string) => attempt(() => readStorage(slug));
const days = (ms: number) => Math.round((ms / DAY) * 10) / 10;
const percent = (of: number, total: number) => (total > 0 ? Math.round((100 * of) / total) : 0);

const CLASS_LABEL: Record<string, string> = {
  artifacts: "Artifacts",
  uploads: "Uploads",
  logs: "Logs",
  remote_cache: "Remote cache",
  actions_cache: "Runner-mode cache",
  worker_cache: "Worker caches",
};
const CLASS_NOTE: Record<string, string> = {
  artifacts: "objects at least one artifact manifest references",
  uploads: "open upload sessions and objects no artifact references",
  logs: "attempt logs not yet expired",
  remote_cache: "the remote cache bundles of the tenant's repositories",
  actions_cache: "runner-mode cache entries on worker hosts",
  worker_cache: "each live worker's own cache, as it last reported",
};

/** Stored bytes against the quota, with the two lines the controller measures it against. */
function Quota({ data }: { data: TenantStorage }) {
  const total = data.classes.artifacts + data.classes.uploads + data.classes.logs;
  const quota = data.effective.tenant_quota_bytes;
  const { state, soft_limit_bytes, hard_limit_bytes } = data.thresholds;
  return (
    <Card title="Stored against the quota" titleId="storage-quota-h">
      <p className="text-lg font-semibold text-strong">{fmtBytes(total)}</p>
      {quota ? (
        <>
          <div className="mt-2 space-y-1" role="meter" aria-valuenow={Math.min(100, percent(total, quota))} aria-valuemin={0}
            aria-valuemax={100} aria-valuetext={`${fmtBytes(total)} of ${fmtBytes(quota)}`}
            aria-label={`${fmtBytes(total)} of ${fmtBytes(quota)} quota used`}>
            <div className="relative h-2 overflow-hidden rounded bg-elevated">
              <div className="h-full bg-primary" style={{ width: `${Math.min(100, percent(total, quota))}%` }} />
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
              <span>{percent(total, quota)}% of {fmtBytes(quota)}</span>
              <Badge color={state === "hard" ? "error" : state === "soft" ? "warning" : "success"}>{state === "hard" ? "over the hard threshold" : state === "soft" ? "over the soft threshold" : "inside the thresholds"}</Badge>
            </div>
          </div>
          <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted">Warned at</dt><dd>{data.effective.soft_percent} % · {fmtBytes(soft_limit_bytes)}</dd>
            <dt className="text-muted">Refused at</dt><dd>{data.effective.hard_percent} % · {fmtBytes(hard_limit_bytes)}</dd>
          </dl>
        </>
      ) : (
        <p className="mt-2 text-xs text-muted">No quota: the tenant is bounded by the deployment's disk only, and has no threshold.</p>
      )}
    </Card>
  );
}

/** One bar per recorded day, the newest last; the same figures are in the caption so the chart is never the only copy. */
function Trend({ days: trend }: { days: StorageTrendDay[] }) {
  if (trend.length === 0) {
    return <p className="text-sm text-muted">No daily snapshot yet: the controller records one per UTC day, and the trend starts with the first.</p>;
  }
  const ordered = [...trend].reverse();
  const peak = Math.max(...ordered.map((d) => d.stored_bytes), 1);
  const first = ordered[0]!;
  const last = ordered[ordered.length - 1]!;
  return (
    <>
      <div role="img" aria-label={`Stored bytes over ${ordered.length} snapshots, from ${fmtBytes(first.stored_bytes)} to ${fmtBytes(last.stored_bytes)}, at most ${fmtBytes(peak)}`}
        className="flex h-24 items-end gap-1">
        {ordered.map((d) => (
          <div key={d.day} title={new Date(d.taken_ms).toISOString().slice(0, 10) + ": " + fmtBytes(d.stored_bytes)}
            aria-hidden="true" className="min-w-1 flex-1 rounded-t bg-primary"
            style={{ height: `${Math.max(2, (100 * d.stored_bytes) / peak)}%` }} />
        ))}
      </div>
      <p className="mt-2 text-sm text-muted">
        {ordered.length === 1
          ? `One snapshot, ${fmtBytes(last.stored_bytes)} on ${new Date(last.taken_ms).toISOString().slice(0, 10)}.`
          : `${fmtBytes(first.stored_bytes)} on ${new Date(first.taken_ms).toISOString().slice(0, 10)} to ${fmtBytes(last.stored_bytes)} on ${new Date(last.taken_ms).toISOString().slice(0, 10)}, at most ${fmtBytes(peak)}.`}
      </p>
    </>
  );
}

function Items({ caption, items, empty }: { caption: string; items: StorageItem[]; empty: string }) {
  if (!items.length) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <Table caption={caption}>
      <thead><tr><th>Artifact</th><th>Repository</th><th>Class</th><th>Bytes</th><th>Expires</th></tr></thead>
      <tbody>
        {items.map((a) => (
          <tr key={a.id}>
            <td className="text-strong">{a.name}</td>
            <td>{a.repo ?? "—"}</td>
            <td>{a.class}</td>
            <td>{fmtBytes(a.bytes)}</td>
            <td>{a.pinned ? <Badge color="info">pinned</Badge> : <Until ms={a.expires_ms} />}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function ClassRow({ name, bytes, stored, counted }: { name: string; bytes: number; stored: number; counted: boolean }) {
  return (
    <tr>
      <th scope="row" className="font-medium text-strong">{CLASS_LABEL[name] ?? name}</th>
      <td>{fmtBytes(bytes)}</td>
      {/* A cache is held elsewhere, so its share of what is stored would be meaningless. */}
      <td>{counted ? `${percent(bytes, stored)} %` : "—"}</td>
      <td>{counted ? "counted" : "reported"}</td>
      <td className="text-muted">{CLASS_NOTE[name] ?? ""}</td>
    </tr>
  );
}

function Classes({ data }: { data: TenantStorage }) {
  const classes: StorageClasses = data.classes;
  const stored = classes.artifacts + classes.uploads + classes.logs;
  return (
    <Table caption="Stored bytes by class">
      <thead><tr><th scope="col">Class</th><th scope="col">Bytes</th><th scope="col">Share</th><th scope="col">Quota</th><th scope="col">What it holds</th></tr></thead>
      <tbody>
        {(["artifacts", "uploads", "logs", "remote_cache", "actions_cache", "worker_cache"] as const).map((name) => (
          <ClassRow key={name} name={name} bytes={classes[name]} stored={stored} counted={classes.counted.includes(name)} />
        ))}
      </tbody>
    </Table>
  );
}

export function Storage({ slug, initial }: { slug: string; initial: Load<TenantStorage> }) {
  const { me } = useSession();
  const { data, setData, failure } = useLoad(initial);
  const refresh = () => readStorage(slug).then(setData, () => {});
  const [editing, setEditing] = useState<string | null>(null);

  async function save(repo: string, body: StoragePolicyBody) {
    if (await act(me, `Storage policy of ${repo}`, () => api(`/api/v1/tenants/${encodeURIComponent(slug)}/repos/${encodeURIComponent(repo)}/storage`, { method: "PUT", body }))) {
      setEditing(null);
      await refresh();
    }
  }

  if (!data) {
    return (
      <section aria-labelledby="storage-h" className="space-y-3">
        <h2 id="storage-h" className="text-base font-semibold text-strong">Storage</h2>
        <LoadFailed what="the storage figures" words={failure ?? ""} />
      </section>
    );
  }
  const edited = editing ? data.repos.find((r) => r.name === editing) : undefined;
  const expiring = data.expiring;

  return (
    <section aria-labelledby="storage-h" className="space-y-4">
      <h2 id="storage-h" className="text-base font-semibold text-strong">Storage</h2>
      {data.notice ? (
        <Alert color="warning" icon="hard-drive" role="status" title={`Told about the ${data.notice.threshold_percent} % threshold`}
          description={`${fmtBytes(data.notice.used_bytes)} of ${fmtBytes(data.notice.limit_bytes)} on ${new Date(data.notice.notified_ms).toISOString().slice(0, 10)}, ${data.notice.delivery === "mail" ? "by mail to the administrators" : "on this page"}.`} />
      ) : null}
      <div className="grid gap-3 sm:grid-cols-3">
        <Quota data={data} />
        <Card title="Expiring within 7 days" titleId="storage-expiring-h">
          <p className="text-lg font-semibold text-strong">{fmtBytes(expiring.artifact_bytes + expiring.log_bytes)}</p>
          <p className="text-sm text-muted">
            {fmtBytes(expiring.artifact_bytes)} in {expiring.artifacts} {expiring.artifacts === 1 ? "artifact" : "artifacts"} ·{" "}
            {fmtBytes(expiring.log_bytes)} in {expiring.logs} {expiring.logs === 1 ? "log" : "logs"}
          </p>
          <p className="mt-2 text-xs text-muted">Removed by retention unless a later run or a pin keeps them; logs go on their own deadline.</p>
        </Card>
        <Card title="Kept at most" titleId="storage-kept-h">
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted">Logs</dt><dd>{days(data.effective.log_retention_ms)} days after the attempt finishes</dd>
            <dt className="text-muted">Artifacts</dt><dd>{days(data.effective.artifact_retention_ms)} days, shortened by a pipeline's <code>retain</code></dd>
          </dl>
        </Card>
      </div>
      <Card title="By class" titleId="storage-classes-h" description="Artifacts, uploads and logs are what the quota counts; the cache classes are reported and bounded elsewhere.">
        <Classes data={data} />
      </Card>
      <Card title="Trend" titleId="storage-trend-h" description="One snapshot per UTC day, the last 90 kept.">
        <Trend days={data.trend} />
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Largest artifacts" titleId="storage-largest-h" description="The heaviest of what the tenant stores.">
          <Items caption="Largest artifacts" items={data.largest} empty="No captured artifact yet." />
        </Card>
        <Card title="Expires soonest" titleId="storage-soonest-h" description="Artifacts due within 7 days, by deadline.">
          <Items caption="Artifacts expiring within 7 days" items={expiring.soonest} empty="No artifact expires in the next 7 days." />
        </Card>
      </div>
      <h3 className="text-sm font-semibold text-strong">By repository</h3>
      <p className="text-sm text-muted">The platform sets the tenant's limits. Each repository can have its own quota and shorter retention.</p>
      <Table caption="Repository storage">
        <thead><tr><th>Repository</th><th>Artifacts</th><th>Logs</th><th>Quota</th><th>Retention</th><th>Actions</th></tr></thead>
        <tbody>
          {data.repos.length ? data.repos.map((r) => (
            <tr key={r.id}>
              <td>{r.name}</td>
              <td>{fmtBytes(r.usage.artifact_bytes)}</td>
              <td>{fmtBytes(r.usage.log_bytes)}</td>
              <td>{r.effective.repo_quota_bytes ? fmtBytes(r.effective.repo_quota_bytes) : "tenant's"}</td>
              <td>logs {days(r.effective.log_retention_ms)}d · artifacts {days(r.effective.artifact_retention_ms)}d</td>
              <td>
                <Button size="sm" color="neutral" variant="outline" icon="sliders-horizontal" aria-label={`Storage policy of ${r.name}`} onClick={() => setEditing(r.name)}>Policy</Button>
              </td>
            </tr>
          )) : <tr><td colSpan={6} className="text-center text-muted">No data</td></tr>}
        </tbody>
      </Table>
      <DialogModal isOpen={!!edited} onClose={() => setEditing(null)} title={`Storage policy · ${editing}`} description="Blank fields inherit the tenant's limits.">
        {edited ? (
          <StoragePolicyForm id={`repo-${edited.name}`} policy={edited.policy}
            inherited={{ quota_bytes: 0, log_retention_ms: data.effective.log_retention_ms, artifact_retention_ms: data.effective.artifact_retention_ms }}
            maxLogDays={data.effective.log_retention_ms / DAY} maxArtifactDays={data.effective.artifact_retention_ms / DAY}
            onSave={(body) => void save(edited.name, body)} />
        ) : null}
      </DialogModal>
    </section>
  );
}
