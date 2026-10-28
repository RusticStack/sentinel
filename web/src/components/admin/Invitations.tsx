import { useRef, useState } from "react";
import type { Invitation, NamespaceSettings } from "../../lib/types";
import { api, ApiError } from "../../lib/api.ts";
import { act, refusal } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { useOverride } from "../../lib/override.ts";
import { useLoaded } from "../../lib/hooks.ts";
import { looksLikeEmail } from "../../lib/onboarding.ts";
import { showOnce } from "../ShowOnceDialog.tsx";
import { Alert, Badge, Button, ButtonLink, Field, Input, Select, Table } from "../ui.tsx";
import { confirmChange } from "./Confirm.tsx";

// A GitHub-managed organization, or one with a GitHub App installed, takes no email invitations.
export interface InvitationsLoad { invitations: Invitation[]; failure: string | null }
const ROLES = [{ label: "Reader", value: "reader" }, { label: "Operator", value: "operator" }, { label: "Admin", value: "admin" }];
const LIFETIMES = [{ label: "1 day", value: String(86_400) }, { label: "7 days", value: String(7 * 86_400) }, { label: "30 days", value: String(30 * 86_400) }];
const STATE_LOOK: Record<Invitation["state"], { color: "info" | "success" | "neutral" | "warning"; label: string }> = {
  pending: { color: "info", label: "Pending" },
  redeemed: { color: "success", label: "Accepted" },
  revoked: { color: "neutral", label: "Revoked" },
  expired: { color: "warning", label: "Expired" },
};

const applies = (settings: NamespaceSettings | null) => settings?.kind === "organization" && settings.membership === "app" && !settings.github_installation;

export async function loadInvitations(slug: string, settings: NamespaceSettings | null): Promise<InvitationsLoad> {
  if (!applies(settings)) return { invitations: [], failure: null };
  try {
    return { ...(await api<{ invitations: Invitation[] }>(`/api/v1/tenants/${encodeURIComponent(slug)}/invitations`)), failure: null };
  } catch (e) {
    return { invitations: [], failure: refusal(e instanceof ApiError ? e : new ApiError(0, null)) };
  }
}

export function Invitations({ slug, settings, settingsFailure, retrySettings, initial }: {
  slug: string; settings: NamespaceSettings | null; settingsFailure: { code: string; words: string } | null; retrySettings: () => void; initial: InvitationsLoad;
}) {
  const { me } = useSession();
  const { ready, withReason } = useOverride(slug);
  const [data, setData] = useLoaded(initial);
  const refresh = async () => setData(await loadInvitations(slug, settings));
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("reader");
  const [lifetime, setLifetime] = useState(String(7 * 86_400));
  const [formError, setFormError] = useState("");
  const [sending, setSending] = useState(false);
  const emailInput = useRef<HTMLInputElement>(null);
  const base = `/api/v1/tenants/${encodeURIComponent(slug)}/invitations`;

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    setFormError("");
    if (!looksLikeEmail(email)) {
      setFormError("Enter an email address such as name@example.com.");
      setTimeout(() => emailInput.current?.focus(), 0);
      return;
    }
    if (sending || !ready()) return;
    setSending(true);
    const address = email.trim();
    try {
      const done = await act(me, `Invite ${address}`, () => api<{ delivery: "email" | "link"; token?: string }>(base, {
        method: "POST",
        body: withReason({ email: address, role, expires_in_secs: Number(lifetime) }),
      }));
      if (!done) return;
      setEmail("");
      if (done.delivery === "link" && done.token) {
        const link = `${location.origin}/invitations/accept#token=${done.token}`;
        await showOnce({
          title: "Send this invitation link",
          description: `This instance does not send email. Give ${address} this link yourself; it works once.`,
          secrets: [link],
          filename: `sentinel-invitation-${slug}.txt`,
          note: "Only the person who holds that address can use it, once it is confirmed.",
        });
      }
      await refresh();
    } finally {
      setSending(false);
    }
  }

  async function revoke(inv: Invitation) {
    const who = inv.email ?? "a link";
    const sure = await confirmChange({
      title: `Revoke the invitation for ${who}?`, description: "The link stops working at once. You can invite the person again later.", action: "Revoke",
    });
    if (!sure || !ready()) return;
    const body = withReason({});
    if (await act(me, `Revoke the invitation for ${who}`, () => api(`${base}/${inv.id}`, { method: "DELETE", body }))) await refresh();
  }

  return (
    <section aria-labelledby="invite-h" className="space-y-3">
      <h2 id="invite-h" className="text-base font-semibold text-strong">Invite people</h2>

      {settingsFailure ? (
        <Alert color="error" icon="circle-alert" role="alert" title="Could not load namespace settings." description={settingsFailure.words}>
          <div className="pt-1"><Button size="sm" color="neutral" variant="outline" label="Try again" onClick={retrySettings} /></div>
        </Alert>
      ) : settings?.kind === "personal" ? (
        <Alert color="neutral" icon="user" title="A personal namespace has no other members." description="Create an organization to work with others.">
          <div className="pt-1"><ButtonLink to="/organizations" size="sm" color="neutral" variant="outline" label="Organizations" /></div>
        </Alert>
      ) : settings && !applies(settings) ? (
        <Alert color="neutral" icon="github" title="Membership of this organization is managed by GitHub."
          description={settings.membership === "github"
            ? "People join and leave on GitHub, and Sentinel follows. Email invitations and email domains do not apply."
            : "A GitHub App is installed for this organization, so email invitations do not apply to it."} />
      ) : settings ? (
        <>
          <form className="flex flex-wrap items-end gap-3" aria-label="Invite by email" noValidate onSubmit={invite}>
            <Field label="Email address" htmlFor="inv-email">
              <Input id="inv-email" ref={emailInput} name="invite-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                autoComplete="off" autoCapitalize="off" spellCheck={false} required className="w-64 max-w-full" />
            </Field>
            <Select id="inv-role" label="Role" ariaLabel="Role" value={role} onChange={setRole} items={ROLES} className="w-36" />
            <Select id="inv-lifetime" label="Expires after" ariaLabel="Expires after" value={lifetime} onChange={setLifetime} items={LIFETIMES} className="w-32" />
            <Button type="submit" icon="mail-plus" label="Send invitation" loading={sending} />
          </form>
          {formError ? <Alert color="error" icon="circle-alert" title={formError} role="alert" /> : null}
          <p className="text-xs text-muted">The invitation works once and only for the account that confirms that address. Readers can see runs and logs; operators can also start and cancel them; admins manage the organization.</p>

          <h3 className="pt-2 text-sm font-medium text-strong">Invitations</h3>
          {data.failure ? (
            <Alert color="error" icon="circle-alert" role="alert" title="Could not load the invitations." description={data.failure}>
              <div className="pt-1"><Button size="sm" color="neutral" variant="outline" label="Try again" onClick={() => void refresh()} /></div>
            </Alert>
          ) : !data.invitations.length ? (
            <p className="text-sm text-muted">No invitations yet.</p>
          ) : (
            <Table caption="Invitations">
              <thead><tr><th>Invited</th><th>Role</th><th>State</th><th>Expires</th><th>Actions</th></tr></thead>
              <tbody>
                {data.invitations.map((inv) => {
                  const iso = new Date(inv.expires_ms).toISOString();
                  return (
                    <tr key={inv.id}>
                      <td><span className="break-all">{inv.email ?? "Link invitation"}</span></td>
                      <td>{ROLES.find((r) => r.value === inv.role)?.label ?? "—"}</td>
                      <td><Badge color={STATE_LOOK[inv.state].color}>{STATE_LOOK[inv.state].label}</Badge></td>
                      <td><time dateTime={iso}>{iso.slice(0, 16).replace("T", " ")} UTC</time></td>
                      <td>
                        {inv.state === "pending" ? (
                          <Button size="sm" color="error" variant="ghost" icon="x" aria-label={`Revoke the invitation for ${inv.email ?? "a link"}`} label="Revoke"
                            onClick={() => void revoke(inv)} />
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          )}
        </>
      ) : null}
    </section>
  );
}
