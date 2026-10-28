import type { Backups as BackupsData } from "../../lib/types";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { useLoaded } from "../../lib/hooks.ts";
import { fmtBytes, fmtMs } from "../../lib/format.ts";
import { RelTime } from "../RelTime.tsx";
import { Alert, Button, Table, useInterval } from "../ui.tsx";

const readBackups = () => api<BackupsData>("/api/v1/admin/backups");
export const loadBackups = () => readBackups().catch(() => null);

export function Backups({ initial }: { initial: BackupsData | null }) {
  const { me } = useSession();
  const [data, setData] = useLoaded(initial);
  const refresh = () => readBackups().then(setData, () => {});
  useInterval(() => { void refresh(); }, 5000);
  async function now() {
    if (await act(me, "Backup", () => api("/api/v1/admin/backups", { method: "POST", body: {} }))) await refresh();
  }

  if (!data) return null;
  const scheduler = data.scheduler;
  return (
    <section aria-labelledby="backups-h" className="space-y-3">
      <h2 id="backups-h" className="text-base font-semibold text-strong">Backups</h2>
      {!data.configured ? (
        <p className="text-sm text-muted">Not configured: set <code>[backup] dir</code> in the controller's configuration, on another disk. Until then use <code>sentinel admin backup create</code> beside a stopped controller.</p>
      ) : scheduler ? (
        <>
          {scheduler.last_failure ? <Alert color="error" icon="archive-x" role="alert" title="The last backup failed" description={scheduler.last_failure} /> : null}
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span>Every {Math.round(scheduler.interval_secs / 60)} min into <code>{scheduler.target}</code>, the newest {scheduler.keep} kept.</span>
            <span>Last success <RelTime ms={scheduler.last_success_ms} />.</span>
            <Button size="sm" icon="archive" loading={scheduler.running} disabled={scheduler.running} label={scheduler.running ? "Backing up" : "Back up now"} onClick={() => void now()} />
          </div>
          <Table caption="Backups">
            <thead><tr><th>Backup</th><th>Database</th><th>Objects</th><th>Took</th><th>Key</th></tr></thead>
            <tbody>
              {data.backups.length ? data.backups.map((b) => (
                <tr key={b.id}>
                  <td><code>{b.id}</code></td>
                  <td>{fmtBytes(b.metadata_bytes)}</td>
                  <td>{b.objects}</td>
                  <td>{fmtMs(b.took_ms)}</td>
                  <td>{b.key_required ? `key ids ${b.key_ids.join(", ")}` : "not needed"}</td>
                </tr>
              )) : <tr><td colSpan={5} className="text-center text-muted">No backup yet.</td></tr>}
            </tbody>
          </Table>
          <p className="text-sm text-muted">The master key is never in a backup: keep <code>master.key</code> in a separate, offline place. Verify with <code>sentinel admin backup verify</code>; restore with <code>sentinel admin restore</code> (<a className="text-primary underline" href="https://github.com/RusticStack/sentinel/blob/main/docs/backup.md">backup and restore</a>).</p>
        </>
      ) : null}
    </section>
  );
}
