import { useRef, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import type { Security, TenantChoice } from "../../lib/types";
import { api, ApiError } from "../../lib/api.ts";
import { refusal, retryAfter, useRetryWait } from "../../lib/act.tsx";
import { refreshTenants, useSession } from "../../lib/session.ts";
import { slugProblem } from "../../lib/onboarding.ts";
import { Page, rememberTenant } from "../../components/Page.tsx";
import { Alert, Badge, Button, ButtonLink, Card, Empty, Field, Icon, Input, TextLink } from "../../components/ui.tsx";

// Nothing here lists a namespace the person is not a member of.
export const Route = createFileRoute("/_app/organizations")({
  loader: async () => ({ security: await api<Security>("/api/v1/me/security").catch(() => null) }),
  head: () => ({ meta: [{ title: "Organizations · Sentinel" }] }),
  component: OrganizationsView,
});

const ROLE_NAMES: Record<string, string> = { reader: "Reader", operator: "Operator", admin: "Admin" };
type GroupKey = "personal" | "app" | "github";
const GROUPS: { key: GroupKey; title: string; icon: string; note: string }[] = [
  { key: "personal", title: "Personal", icon: "user", note: "Your own space. Only you are a member." },
  { key: "app", title: "Organizations", icon: "building-2", note: "Membership is managed in Sentinel: by invitation, by an administrator, or by the operator's email-domain rule." },
  { key: "github", title: "GitHub organizations", icon: "github", note: "Membership is managed by GitHub: Sentinel follows who belongs to the GitHub organization." },
];
const heading = (icon: string, text: string) => <span className="flex items-center gap-2 text-base"><Icon name={icon} />{text}</span>;

function OrganizationsView() {
  const { security } = Route.useLoaderData();
  const { me, tenants } = useSession();
  const navigate = useNavigate();
  const githubLinked = !!security?.identities.some((i) => i.provider === "github");

  const groups: Record<GroupKey, TenantChoice[]> = { personal: [], app: [], github: [] };
  for (const t of tenants) groups[t.kind === "personal" ? "personal" : t.membership === "github" ? "github" : "app"].push(t);
  const visibleGroups = GROUPS.filter((g) => groups[g.key].length);

  const [refreshing, setRefreshing] = useState(false);
  async function refreshList() {
    setRefreshing(true);
    try { await refreshTenants(); } finally { setRefreshing(false); }
  }

  const [slug, setSlug] = useState("");
  const [touched, setTouched] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");
  const [notAllowed, setNotAllowed] = useState(false);
  const { waiting, start: wait } = useRetryWait();
  const shapeProblem = touched && slug ? slugProblem(slug) : null;
  const slugInput = useRef<HTMLInputElement>(null);
  const focusSlug = () => setTimeout(() => slugInput.current?.focus(), 0);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    setCreateError("");
    setNotAllowed(false);
    const name = slug.trim();
    const problem = slugProblem(name);
    if (problem) {
      setCreateError(problem);
      focusSlug();
      return;
    }
    if (creating || waiting) return;
    setCreating(true);
    try {
      await api<{ slug: string }>("/api/v1/orgs", { method: "POST", body: { slug: name } });
      setSlug("");
      setTouched(false);
      await refreshTenants();
      rememberTenant(name);
      await navigate({ to: "/t/$slug/settings", params: { slug: name } });
    } catch (e) {
      const err = e as ApiError;
      if (err.code === "unauthenticated") return;
      if (err.code === "forbidden") setNotAllowed(true);
      else if (err.code === "conflict") setCreateError("That name is taken. Choose another.");
      else if (err.code === "invalid_request") setCreateError("That name is reserved or not allowed. Choose another.");
      else if (err.code === "quota_exceeded") setCreateError("You have created as many organizations as allowed for now (3 an hour, 10 in all). Try later or ask an administrator.");
      else if (err.code === "rate_limited") {
        wait(err);
        setCreateError(`Too many attempts. Try again in ${retryAfter(err)}.`);
      } else setCreateError(refusal(err));
      focusSlug();
    } finally {
      setCreating(false);
    }
  }

  return (
    <Page id="organizations" title="Organizations">
      <div className="max-w-3xl space-y-6">
        <section aria-labelledby="ns-h" className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 id="ns-h" className="text-base font-semibold text-strong">Your namespaces</h2>
            <Button size="sm" color="neutral" variant="ghost" icon="refresh-cw" label="Refresh" loading={refreshing} onClick={() => void refreshList()} />
          </div>
          {!tenants.length ? (
            <Empty icon="building-2" title="No namespaces yet"
              description="You are not a member of any organization yet. Accept an invitation, create an organization below if this instance allows it, or ask an administrator to add you." />
          ) : null}

          {visibleGroups.map((g) => (
            <div key={g.key} className="space-y-2">
              <h3 className="flex items-center gap-2 text-sm font-medium text-strong"><Icon name={g.icon} />{g.title}</h3>
              <p className="text-xs text-muted">{g.note}</p>
              <ul className="divide-y divide-line rounded-lg border border-line">
                {groups[g.key].map((t) => (
                  <li key={t.slug} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                    <span className="flex min-w-0 items-center gap-2">
                      <TextLink to={`/t/${t.slug}`} className="truncate font-medium">{t.slug}</TextLink>
                      <Badge className="border border-line">{ROLE_NAMES[t.role] ?? t.role}</Badge>
                      {g.key === "github" ? <Badge icon="github">Managed by GitHub</Badge> : null}
                    </span>
                    <ButtonLink to={`/t/${t.slug}/settings`} size="sm" color="neutral" variant="ghost" icon="settings" aria-label={`Settings of ${t.slug}`} label="Settings" />
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </section>

        <Card titleId="gh-h" title={heading("github", "Organizations on GitHub")}>
          {!githubLinked ? (
            <div className="space-y-3 text-sm">
              <p>Some organizations here take their members from GitHub. To join one, link the GitHub account that belongs to that GitHub organization; Sentinel then asks GitHub, and the organization appears here once GitHub confirms you are a member. Email invitations and email domains never add anyone to these organizations.</p>
              {security?.github_link
                ? <ButtonLink to="/account" icon="github" color="neutral" variant="outline" label="Connect GitHub to join" />
                : <p className="text-muted">This instance does not offer GitHub linking.</p>}
            </div>
          ) : (
            <div className="space-y-2 text-sm">
              <p>Your GitHub account is linked. Organizations whose membership GitHub manages appear here once GitHub confirms you belong to them. Sentinel asks at every sign-in, when GitHub reports a change, and periodically; if you just joined on GitHub, refresh this list in a minute.</p>
              <p className="text-muted">Leaving the organization on GitHub removes your access to that organization only.</p>
            </div>
          )}
        </Card>

        <Card titleId="new-org-h" title={heading("plus", "Create an organization")}>
          <form className="space-y-3" aria-label="Create an organization" noValidate onSubmit={create}>
            <p className="text-sm">You become its administrator and invite people by email. Whether you may create one is this instance's policy.</p>
            <Field label="Name" htmlFor="org-slug" hint="Lowercase letters, digits and hyphens" error={shapeProblem ?? undefined}>
              <Input id="org-slug" ref={slugInput} name="slug" value={slug} onChange={(e) => setSlug(e.target.value)} onBlur={() => setTouched(true)}
                autoComplete="off" autoCapitalize="off" spellCheck={false} maxLength={63} placeholder="my-team" className="sm:w-80" aria-invalid={!!shapeProblem || undefined} />
            </Field>
            {createError ? <Alert color="error" icon="circle-alert" title={createError} role="alert" /> : null}
            {notAllowed ? (
              <Alert color="warning" icon="lock" role="alert" title="Creating organizations is not enabled for your account."
                description={me?.super_admin ? "Platform administrators always may; check that this session is yours." : "An administrator can create one for you and invite you, or allow approved users to create their own."} />
            ) : null}
            <Button type="submit" icon="building-2" label={waiting ? `Wait ${waiting} s` : "Create organization"} loading={creating} disabled={!!waiting} />
          </form>
        </Card>
      </div>
    </Page>
  );
}
