import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { api, ApiError } from "../../../../lib/api.ts";
import { refusal, retryAfter, useRetryWait } from "../../../../lib/act.tsx";
import { refreshTenants, useSession } from "../../../../lib/session.ts";
import { useLoaded } from "../../../../lib/hooks.ts";
import { loadNamespaceSettings } from "../../../../lib/namespace.ts";
import { githubStanding } from "../../../../lib/onboarding.ts";
import { Page } from "../../../../components/Page.tsx";
import { RelTime } from "../../../../components/RelTime.tsx";
import { Alert, Badge, Button, ButtonLink, Card, Icon, TextLink } from "../../../../components/ui.tsx";

export const Route = createFileRoute("/_app/t/$slug/settings")({
  loader: async ({ params }) => ({ namespace: await loadNamespaceSettings(params.slug) }),
  head: ({ params }) => ({ meta: [{ title: `Settings · ${params.slug} · Sentinel` }] }),
  component: SettingsView,
});

const ROLE_NAMES: Record<string, string> = { reader: "Reader", operator: "Operator", admin: "Admin" };
const isoDate = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const heading = (icon: string, text: string) => <span className="flex items-center gap-2 text-base"><Icon name={icon} />{text}</span>;

function SettingsView() {
  const { slug } = Route.useParams();
  const loaded = Route.useLoaderData();
  const { me } = useSession();
  const [namespace, setNamespace] = useLoaded(loaded.namespace);
  const data = namespace.settings;
  const failure = namespace.failure;
  const refresh = async () => setNamespace(await loadNamespaceSettings(slug));

  useEffect(() => { if (failure?.code === "not_found") void refreshTenants(); }, [failure?.code]);

  const isAdmin = data?.role === "admin" || !!me?.super_admin;
  const githubManaged = data?.membership === "github";
  // Email invitations do not apply once a GitHub App is installed, even before membership is GitHub-managed.
  const invitesApply = data?.kind === "organization" && !githubManaged && !data?.github_installation;
  const where = githubStanding(data?.github_sync);

  const [rechecking, setRechecking] = useState(false);
  const [recheckNote, setRecheckNote] = useState("");
  const { waiting, start: hold } = useRetryWait();
  async function recheck() {
    if (rechecking || waiting) return;
    setRechecking(true);
    setRecheckNote("");
    try {
      await api(`/api/v1/tenants/${encodeURIComponent(slug)}/repos`);
      hold(60_000);
      await new Promise((r) => setTimeout(r, 3000));
      await refresh();
      await refreshTenants();
      setRecheckNote("Sentinel asked GitHub again if your access had not been confirmed in the last five minutes. GitHub answers in the background; this page shows the latest answer.");
    } catch (e) {
      const err = e as ApiError;
      if (err.code === "unauthenticated") return;
      if (err.code === "not_found") {
        setRecheckNote("You no longer have access to this organization.");
        await refreshTenants();
      } else if (err.code === "rate_limited") {
        hold(err);
        setRecheckNote(`Sentinel is busy. Try again in ${retryAfter(err)}.`);
      } else setRecheckNote(refusal(err));
    } finally {
      setRechecking(false);
    }
  }

  return (
    <Page id="namespace-settings" title={`Settings · ${slug}`}>
      <div className="max-w-3xl space-y-6">
        {failure ? (
          <Alert color="error" icon="circle-alert" role="alert"
            title={failure.code === "not_found" ? "Not found, or you no longer have access to it." : "Could not load the settings."}
            description={failure.code === "not_found" ? undefined : failure.words}>
            <div className="pt-1">
              {failure.code === "not_found"
                ? <ButtonLink to="/organizations" size="sm" color="neutral" variant="outline" label="Your organizations" />
                : <Button size="sm" color="neutral" variant="outline" label="Try again" onClick={() => void refresh()} />}
            </div>
          </Alert>
        ) : data ? (
          <>
            <Card titleId="about-h" title={heading(data.kind === "personal" ? "user" : githubManaged ? "github" : "building-2", "About")}>
              <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-[max-content_1fr]">
                <dt className="text-muted">Kind</dt>
                <dd>{data.kind === "personal" ? "Personal namespace" : "Organization"}</dd>
                <dt className="text-muted">Membership</dt>
                <dd className="flex flex-wrap items-center gap-2">
                  {githubManaged
                    ? <Badge icon="github">Managed by GitHub</Badge>
                    : <Badge className="border border-line">{data.kind === "personal" ? "Only you" : "Managed in Sentinel"}</Badge>}
                </dd>
                <dt className="text-muted">Your role</dt>
                <dd>{data.role ? ROLE_NAMES[data.role] : "Not a member (platform administrator)"}</dd>
                <dt className="text-muted">GitHub App</dt>
                <dd>{data.github_installation ? "Installed for this namespace" : "Not installed"}</dd>
                <dt className="text-muted">Created</dt>
                <dd><time dateTime={new Date(data.created_ms).toISOString()}>{isoDate(data.created_ms)}</time></dd>
              </dl>
            </Card>

            <Card titleId="members-h" title={heading("users", "Who belongs here")}>
              {data.kind === "personal" ? (
                <div className="space-y-2 text-sm">
                  <p>This is your personal namespace: only you belong to it, and nobody can be invited. To work with others, <TextLink to="/organizations" className="font-medium">create an organization</TextLink>.</p>
                </div>
              ) : githubManaged ? (
                <div className="space-y-4 text-sm">
                  <p>Membership is managed by GitHub. Sentinel follows who belongs to the GitHub organization: its owners are administrators here and other members operators, and each repository's access follows the person's permission on that repository on GitHub. Invitations and email domains do not add anyone; people are added and removed on GitHub.</p>
                  {data.role ? (
                    <div className="space-y-3 rounded-md border border-line p-3" role="status" aria-live="polite">
                      <h3 className="font-medium text-strong">Your access</h3>
                      {where === "confirmed" ? (
                        <p className="flex items-start gap-2"><Icon name="circle-check" className="mt-0.5 size-4 text-success" />
                          <span>GitHub confirmed your membership <RelTime ms={data.github_sync?.confirmed_ms} />.</span></p>
                      ) : where === "checking" ? (
                        <p className="flex items-start gap-2"><Icon name="loader-circle" className="mt-0.5 size-4 text-info" />
                          <span>A check with GitHub is waiting to run{data.github_sync?.confirmed_ms ? <>; it last confirmed you <RelTime ms={data.github_sync.confirmed_ms} /></> : null}.</span></p>
                      ) : where === "unknown" ? (
                        <Alert color="warning" icon="cloud-off" title="GitHub could not confirm your access recently."
                          description={`GitHub did not answer the last ${data.github_sync?.unanswered === 1 ? "check" : `${data.github_sync?.unanswered} checks`} (it may be unreachable, rate-limited, or missing a permission). Your existing access is kept for a limited grace period (one day unless the operator changed it) and nothing new is granted until GitHub answers; Sentinel keeps retrying.`} />
                      ) : (
                        <p className="flex items-start gap-2"><Icon name="circle-dashed" className="mt-0.5 size-4 text-muted" />
                          <span>GitHub has not confirmed your membership yet.</span></p>
                      )}
                      <div className="flex flex-wrap items-center gap-3">
                        <Button size="sm" color="neutral" variant="outline" icon="refresh-cw" label={waiting ? `Re-check again in ${waiting} s` : "Re-check access"}
                          loading={rechecking} disabled={!!waiting} onClick={() => void recheck()} />
                        <span className="text-xs text-muted">Sentinel also checks at every sign-in and periodically.</span>
                      </div>
                      {recheckNote ? <p className="text-xs">{recheckNote}</p> : null}
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="space-y-3 text-sm">
                  {invitesApply
                    ? <p>Membership is managed in Sentinel: people join by email invitation, when an administrator adds them, or through an email domain the operator set (below).</p>
                    : <p>Membership is managed in Sentinel by administrators. A GitHub App is installed for this organization, so email invitations and email domains do not apply to it.</p>}
                  {isAdmin ? (
                    <div className="flex flex-wrap gap-2">
                      <ButtonLink to={`/t/${slug}/admin/members`} size="sm" color="neutral" variant="outline" icon="users" label="Members" />
                      {invitesApply ? <ButtonLink to={`/t/${slug}/admin/invitations`} size="sm" color="neutral" variant="outline" icon="mail-plus" label="Invite people" /> : null}
                    </div>
                  ) : <p className="text-muted">Ask an administrator of {slug} to invite someone.</p>}
                </div>
              )}
            </Card>

            {data.auto_join ? (
              <Card titleId="domains-h" title={heading("at-sign", "Email domains that join automatically")}
                actions={<Badge icon="lock" className="border border-line">Read-only</Badge>}>
                <div className="space-y-3 text-sm">
                  {data.auto_join.domains.length ? (
                    <>
                      <ul className="flex flex-wrap gap-2" aria-label="Domains">
                        {data.auto_join.domains.map((d) => <li key={d}><Badge className="px-2 py-1 font-mono text-sm">{d}</Badge></li>)}
                      </ul>
                      {data.auto_join.applies
                        ? <p>A person whose confirmed email address is at exactly one of these domains (not a subdomain) joins this organization as a Reader when the address is confirmed or at their next sign-in. Removing a domain stops new joins; nobody who joined is removed.</p>
                        : <p>These domains are listed for this namespace but do not apply: domain joining never adds anyone to a personal namespace or to an organization with a GitHub App or GitHub-managed membership.</p>}
                    </>
                  ) : <p>No email domain joins this organization automatically.</p>}
                  <p className="text-xs text-muted">Set by the server's operator (<code>SENTINEL_AUTO_JOIN_DOMAINS</code>), not here.</p>
                </div>
              </Card>
            ) : null}
          </>
        ) : null}
      </div>
    </Page>
  );
}
