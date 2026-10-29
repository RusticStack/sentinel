// Blank means inherit: the tenant's value for a repository, the deployment's for a tenant. The fields are read when
// the form is saved, so a value typed and left with Tab counts; an out-of-range value is brought within bounds.
import { useRef } from "react";
import type { StoragePolicy } from "../lib/types";
import { fmtBytes } from "../lib/format.ts";
import { Button, Field, Input } from "./ui.tsx";

export interface StoragePolicyBody { quota_bytes: number | null; log_retention_secs: number | null; artifact_retention_secs: number | null }

const DAY = 86_400_000;
const GIB = 2 ** 30;
const days = (ms: number) => `${Math.round((ms / DAY) * 10) / 10} days`;

export function StoragePolicyForm({ id, policy, inherited, maxLogDays, maxArtifactDays, onSave }: {
  id: string;
  policy: StoragePolicy;
  inherited: { quota_bytes: number; log_retention_ms: number; artifact_retention_ms: number };
  // A repository may only narrow: its retentions cap at these.
  maxLogDays?: number;
  maxArtifactDays?: number;
  onSave: (body: StoragePolicyBody) => void;
}) {
  const form = useRef<HTMLFormElement>(null);
  const field = (suffix: string) => form.current?.querySelector<HTMLInputElement>(`#${CSS.escape(`${id}-${suffix}`)}`) ?? null;
  function read(suffix: string, min: number, max: number): number | null {
    const text = field(suffix)?.value.trim() ?? "";
    const v = text ? Number(text) : NaN;
    if (!Number.isFinite(v) || v === 0) return null;
    return Math.min(max, Math.max(min, v));
  }

  function save(e?: React.FormEvent) {
    e?.preventDefault();
    const quota = read("quota", 0.001, Infinity);
    const logs = read("logs", 0.05, maxLogDays ?? 366);
    const artifacts = read("artifacts", 0.05, maxArtifactDays ?? 366);
    onSave({
      quota_bytes: quota ? Math.round(quota * GIB) : null,
      log_retention_secs: logs ? Math.round(logs * 86_400) : null,
      artifact_retention_secs: artifacts ? Math.round(artifacts * 86_400) : null,
    });
  }
  function inheritAll() {
    for (const s of ["quota", "logs", "artifacts"]) { const el = field(s); if (el) el.value = ""; }
    save();
  }

  return (
    <form ref={form} className="space-y-3" aria-label={`Storage policy ${id}`} noValidate onSubmit={save}>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Quota (GiB)" htmlFor={`${id}-quota`} help={`Blank: ${inherited.quota_bytes ? fmtBytes(inherited.quota_bytes) : "no limit"}`}>
          <Input id={`${id}-quota`} name={`${id}-quota`} type="number" inputMode="decimal" min={0.001} step="any" placeholder="inherit"
            defaultValue={policy.quota_bytes ? String(policy.quota_bytes / GIB) : ""} />
        </Field>
        <Field label="Keep logs (days)" htmlFor={`${id}-logs`} help={`Blank: ${days(inherited.log_retention_ms)}`}>
          <Input id={`${id}-logs`} name={`${id}-logs`} type="number" inputMode="decimal" min={0.05} max={maxLogDays ?? 366} step="any" placeholder="inherit"
            defaultValue={policy.log_retention_ms ? String(policy.log_retention_ms / DAY) : ""} />
        </Field>
        <Field label="Keep artifacts at most (days)" htmlFor={`${id}-artifacts`} help={`Blank: ${days(inherited.artifact_retention_ms)}`}>
          <Input id={`${id}-artifacts`} name={`${id}-artifacts`} type="number" inputMode="decimal" min={0.05} max={maxArtifactDays ?? 366} step="any" placeholder="inherit"
            defaultValue={policy.artifact_retention_ms ? String(policy.artifact_retention_ms / DAY) : ""} />
        </Field>
      </div>
      <div className="flex gap-2">
        <Button type="submit" size="sm" label="Save" />
        <Button size="sm" color="neutral" variant="ghost" label="Inherit everything" onClick={inheritAll} />
      </div>
      <p className="text-xs text-muted">A shorter retention applies to what is already stored, from the next maintenance pass.</p>
    </form>
  );
}
