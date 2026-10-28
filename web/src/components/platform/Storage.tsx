import type { DeploymentStorage } from "../../lib/types";
import { api } from "../../lib/api.ts";
import { fmtBytes } from "../../lib/format.ts";
import { RelTime } from "../RelTime.tsx";
import { StateBadge } from "../StateBadge.tsx";
import { Alert, Card } from "../ui.tsx";

const DAY = 86_400_000;
export const loadDeploymentStorage = () => api<DeploymentStorage>("/api/v1/admin/storage").catch(() => null);

function Tile({ label, value, note }: { label: string; value: React.ReactNode; note: React.ReactNode }) {
  return (
    <Card>
      <p className="text-sm text-muted">{label}</p>
      <div className="text-lg font-semibold text-strong">{value}</div>
      <p className="text-xs text-muted">{note}</p>
    </Card>
  );
}

export function Storage({ data }: { data: DeploymentStorage | null }) {
  if (!data) return null;
  const used = data.filesystem_bytes && data.free_bytes !== null ? data.filesystem_bytes - data.free_bytes : null;
  const s3 = data.s3;

  return (
    <>
      <section aria-labelledby="disk-h" className="space-y-3">
        <h2 id="disk-h" className="text-base font-semibold text-strong">Disk</h2>
        {data.admission_open === false ? (
          <Alert color="warning" icon="hard-drive" role="alert" title="Storage admission is closed"
            description="Free space fell below the low watermark: new artifacts and uploads are refused and no new work is placed until space frees above the high watermark." />
        ) : null}
        <div className="grid gap-3 sm:grid-cols-3">
          <Tile label="Data filesystem" value={`${fmtBytes(data.free_bytes)} free`}
            note={<>of {fmtBytes(data.filesystem_bytes)}{used !== null ? ` · ${fmtBytes(used)} used` : null}</>} />
          <Tile label="Metadata database" value={fmtBytes(data.metadata_bytes)} note={`reserve held for it: ${fmtBytes(data.watermarks?.reserve_bytes)}`} />
          <Tile label="Stored by tenants" value={fmtBytes(data.stored_bytes)} note={data.quota_bytes ? `deployment cap ${fmtBytes(data.quota_bytes)}` : "no deployment cap"} />
        </div>
        {data.watermarks ? (
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
            <dt className="text-muted">Reserve</dt><dd>{fmtBytes(data.watermarks.reserve_bytes)} (configured {fmtBytes(data.watermarks.configured_reserve_bytes)})</dd>
            <dt className="text-muted">Closes below</dt><dd>{fmtBytes(data.watermarks.low_watermark_bytes)} free above the reserve</dd>
            <dt className="text-muted">Reopens above</dt><dd>{fmtBytes(data.watermarks.high_watermark_bytes)}</dd>
            <dt className="text-muted">Logs refused below</dt><dd>{fmtBytes(data.watermarks.log_floor_bytes)} free</dd>
            <dt className="text-muted">Tenant default quota</dt><dd>{data.tenant_quota_bytes ? fmtBytes(data.tenant_quota_bytes) : "none"}</dd>
            <dt className="text-muted">Logs kept</dt><dd>{Math.round(data.log_retention_ms / DAY)} days by default</dd>
            <dt className="text-muted">Artifacts kept at most</dt><dd>{Math.round(data.artifact_retention_ms / DAY)} days by default</dd>
            <dt className="text-muted">Artifacts per run</dt><dd>{fmtBytes(data.run_artifact_bytes)}</dd>
          </dl>
        ) : null}
        <p className="text-sm text-muted">Deployment limits come from the controller's <code>[storage]</code> configuration; a tenant's own limits are set from Tenants.</p>
      </section>
      <section aria-labelledby="s3-h" className="space-y-3">
        <h2 id="s3-h" className="text-base font-semibold text-strong">External copy (S3)</h2>
        {!s3 ? (
          <p className="text-sm text-muted">Not configured: objects and logs live on the controller's disk only. See <code>[s3]</code> in the configuration.</p>
        ) : (
          <>
            {s3.state === "degraded" ? (
              <Alert color="warning" icon="cloud-off" role="alert"
                title={s3.backlog_full ? "New artifacts and uploads are paused: the external copy is behind" : "The external copy is failing"}
                description={s3.last_error ?? "Local copies are kept until it catches up."} />
            ) : null}
            <div className="grid gap-3 sm:grid-cols-3">
              <Tile label="State" value={<StateBadge state={s3.state === "healthy" ? "online" : s3.state === "degraded" ? "failed" : "pending"} label={s3.state} />}
                note={<>last success <RelTime ms={s3.last_success_ms} /></>} />
              <Tile label="Waiting to be copied" value={fmtBytes(s3.backlog_bytes)} note={<>{s3.unreplicated_logs} logs · oldest <RelTime ms={s3.oldest_unreplicated_ms} /></>} />
              <Tile label="Copied" value={fmtBytes(s3.replicated_bytes)} note={`${s3.replicated_objects} objects · ${s3.replicated_logs} logs since start`} />
            </div>
            <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
              <dt className="text-muted">Held locally</dt><dd>{fmtBytes(s3.local_bytes)}</dd>
              <dt className="text-muted">Evicted / fetched back</dt><dd>{s3.evicted_objects} / {s3.fetched_objects} since start</dd>
              <dt className="text-muted">Copies deleted</dt><dd>{s3.deleted_copies}</dd>
              <dt className="text-muted">Abandoned uploads aborted</dt><dd>{s3.aborted_uploads}</dd>
              <dt className="text-muted">Failures in a row</dt><dd>{s3.consecutive_failures}</dd>
            </dl>
          </>
        )}
      </section>
    </>
  );
}
