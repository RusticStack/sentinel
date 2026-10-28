import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { useLoaded } from "../../lib/hooks.ts";
import { shortId } from "../../lib/format.ts";
import { RelTime } from "../RelTime.tsx";
import { Button, Table } from "../ui.tsx";

interface Applicant { user: string; display_name: string; applied_ms: number | null }
export interface RegistrationsPage { pending: Applicant[] }
const readRegistrations = () => api<RegistrationsPage>("/api/v1/admin/registrations?limit=100");
export const loadRegistrations = () => readRegistrations().catch(() => null);

export function Registrations({ initial }: { initial: RegistrationsPage | null }) {
  const { me } = useSession();
  const [data, setData] = useLoaded(initial);
  async function decide(a: Applicant, approve: boolean) {
    if (await act(me, `${approve ? "Approve" : "Reject"} ${a.display_name}`, () => api(`/api/v1/admin/registrations/${a.user}/${approve ? "approve" : "reject"}`, { method: "POST", body: {} }))) {
      await readRegistrations().then(setData, () => {});
    }
  }
  const pending = data?.pending ?? [];

  return (
    <section aria-labelledby="reg-h" className="space-y-3">
      <h2 id="reg-h" className="text-base font-semibold text-strong">Pending registrations</h2>
      <Table caption="Pending registrations">
        <thead><tr><th>Applicant</th><th>Applied</th><th>Actions</th></tr></thead>
        <tbody>
          {pending.length ? pending.map((a) => (
            <tr key={a.user}>
              <td>
                <div className="font-medium text-strong">{a.display_name}</div>
                <div className="font-mono text-xs text-muted">{shortId(a.user)}</div>
              </td>
              <td><RelTime ms={a.applied_ms} /></td>
              <td>
                <div className="flex justify-end gap-2">
                  <Button size="sm" icon="check" aria-label={`Approve ${a.display_name}`} onClick={() => void decide(a, true)}>Approve</Button>
                  <Button size="sm" color="error" variant="soft" icon="x" aria-label={`Reject ${a.display_name}`} onClick={() => void decide(a, false)}>Reject</Button>
                </div>
              </td>
            </tr>
          )) : <tr><td colSpan={3} className="text-center text-muted">No applications are waiting.</td></tr>}
        </tbody>
      </Table>
    </section>
  );
}
