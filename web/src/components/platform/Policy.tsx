import { useState } from "react";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { attempt, type Load } from "../../lib/loaded.ts";
import { LoadFailed } from "../LoadFailed.tsx";
import { Button, Select } from "../ui.tsx";

export interface AdmissionPolicy { registration: string; tenant_creation: string; installation_binding: string }
export const loadPolicy = () => attempt(() => api<AdmissionPolicy>("/api/v1/admin/policy"));

const REGISTRATION = [{ label: "Closed", value: "closed" }, { label: "Invitation only", value: "invite_only" }, { label: "Anyone may apply; an admin approves", value: "approval_required" }];
const TENANT_CREATION = [{ label: "Platform administrators only", value: "super_admin_only" }, { label: "Approved users may create organizations and a personal namespace", value: "approved_users" }];
const INSTALLATION = [{ label: "Platform administrators only", value: "super_admin_only" }, { label: "Tenant administrators, for their tenant", value: "tenant_admins" }];

export function Policy({ initial }: { initial: Load<AdmissionPolicy> }) {
  const { me } = useSession();
  const [form, setForm] = useState<AdmissionPolicy>({
    registration: initial.value?.registration ?? "invite_only",
    tenant_creation: initial.value?.tenant_creation ?? "super_admin_only",
    installation_binding: initial.value?.installation_binding ?? "super_admin_only",
  });
  async function save(e: React.FormEvent) {
    e.preventDefault();
    await act(me, "Admission policy", () => api("/api/v1/admin/policy", { method: "PUT", body: { ...form } }));
  }

  return (
    <section aria-labelledby="policy-h" className="max-w-lg space-y-3">
      <h2 id="policy-h" className="text-base font-semibold text-strong">Admission policy</h2>
      {/* Without the stored policy the form would show defaults, and saving them would overwrite it. */}
      {!initial.value ? <LoadFailed what="the admission policy" words={initial.failure ?? ""} /> : <form className="space-y-4" onSubmit={save}>
        <Select id="pol-reg" label="Registration" ariaLabel="Registration" value={form.registration} items={REGISTRATION}
          onChange={(registration) => setForm({ ...form, registration })} />
        <Select id="pol-tenant" label="Tenant creation" ariaLabel="Tenant creation" value={form.tenant_creation} items={TENANT_CREATION}
          onChange={(tenant_creation) => setForm({ ...form, tenant_creation })} />
        <Select id="pol-install" label="GitHub installation binding" ariaLabel="GitHub installation binding" value={form.installation_binding} items={INSTALLATION}
          onChange={(installation_binding) => setForm({ ...form, installation_binding })} />
        <Button type="submit" icon="save" label="Save policy" />
      </form>}
    </section>
  );
}
