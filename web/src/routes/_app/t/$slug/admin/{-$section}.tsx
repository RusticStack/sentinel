import { createFileRoute, notFound, useRouter } from "@tanstack/react-router";
import { useOverride } from "../../../../../lib/override.ts";
import { loadNamespaceSettings } from "../../../../../lib/namespace.ts";
import { Page } from "../../../../../components/Page.tsx";
import { cx, Field, Icon, Input, PathLink } from "../../../../../components/ui.tsx";
import { Audit, loadAudit } from "../../../../../components/admin/Audit.tsx";
import { Invitations, loadInvitations } from "../../../../../components/admin/Invitations.tsx";
import { loadMembers, Members } from "../../../../../components/admin/Members.tsx";
import { loadRepoList, Repos } from "../../../../../components/admin/Repos.tsx";
import { loadSecrets, Secrets } from "../../../../../components/admin/Secrets.tsx";
import { loadServiceAccounts, ServiceAccounts } from "../../../../../components/admin/ServiceAccounts.tsx";
import { loadStorage, Storage } from "../../../../../components/admin/Storage.tsx";

const SECTIONS = [
  { id: "members", label: "Members", icon: "users" },
  { id: "invitations", label: "Invitations", icon: "mail-plus" },
  { id: "repos", label: "Repositories", icon: "folder-git-2" },
  { id: "service-accounts", label: "Service accounts", icon: "bot" },
  { id: "secrets", label: "Secrets", icon: "key-round" },
  { id: "storage", label: "Storage", icon: "hard-drive" },
  { id: "audit", label: "Audit", icon: "scroll-text" },
] as const;
type Section = (typeof SECTIONS)[number]["id"];
const isSection = (s: string): s is Section => SECTIONS.some((x) => x.id === s);
// The sections where a platform administrator's change needs a reason.
const OVERRIDDEN: Section[] = ["members", "invitations", "repos", "service-accounts"];

export const Route = createFileRoute("/_app/t/$slug/admin/{-$section}")({
  beforeLoad: ({ params }) => { if (params.section !== undefined && !isSection(params.section)) throw notFound(); },
  loader: async ({ params }) => {
    const slug = params.slug;
    const section: Section = params.section && isSection(params.section) ? params.section : "members";
    // Where membership comes from decides whether people are added here at all.
    const pending = loadNamespaceSettings(slug);
    const data = await (async () => {
      switch (section) {
        case "members": return { section, members: await loadMembers(slug) } as const;
        case "invitations": return { section, invitations: await loadInvitations(slug, (await pending).settings) } as const;
        case "repos": return { section, repos: await loadRepoList(slug) } as const;
        case "service-accounts": return { section, accounts: await loadServiceAccounts(slug) } as const;
        case "secrets": return { section, secrets: await loadSecrets(slug) } as const;
        case "storage": return { section, storage: await loadStorage(slug) } as const;
        case "audit": return { section, audit: await loadAudit(slug) } as const;
      }
    })();
    return { namespace: await pending, data };
  },
  head: ({ params }) => ({ meta: [{ title: `Tenant admin · ${params.slug} · Sentinel` }] }),
  component: TenantAdminView,
});

function TenantAdminView() {
  const { slug } = Route.useParams();
  const { namespace, data } = Route.useLoaderData();
  const router = useRouter();
  const section = data.section;
  const { needed: override, reason, setReason } = useOverride(slug);
  const settings = namespace.settings;

  const toolbar = (
    <nav aria-label="Sections" className="overflow-x-auto border-t border-line px-3">
      <ul className="flex gap-1 whitespace-nowrap">
        {SECTIONS.map((s) => {
          const current = s.id === section;
          return (
            <li key={s.id}>
              <PathLink to={`/t/${slug}/admin/${s.id}`} aria-current={current ? "page" : undefined}
                className={cx("flex items-center gap-1.5 border-b-2 px-2 py-2 text-sm", current ? "border-primary font-medium text-strong" : "border-transparent text-muted hover:text-fg")}>
                <Icon name={s.icon} className={cx("size-4", current ? "text-primary" : undefined)} />{s.label}
              </PathLink>
            </li>
          );
        })}
      </ul>
    </nav>
  );

  return (
    <Page id="tenant-admin" title={`Tenant admin · ${slug}`} toolbar={toolbar}>
      {override && OVERRIDDEN.includes(section) ? (
        <section aria-labelledby="override-h" className="space-y-3 rounded-lg border border-warning/40 bg-warning/5 p-4">
          <h2 id="override-h" className="flex items-center gap-2 text-base font-semibold text-strong"><Icon name="shield-alert" className="size-4 text-warning" />Acting as platform administrator</h2>
          <p className="text-sm">You do not administer this tenant. Changes to members, invitations, repository access and service accounts ask for a second factor and the reason below, which the audit records.</p>
          <Field label="Reason" htmlFor="override-reason" hint="1 to 100 characters">
            <Input id="override-reason" name="override-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={100} autoComplete="off" className="sm:w-96" />
          </Field>
        </section>
      ) : null}
      {data.section === "members" ? <Members key={slug} slug={slug} settings={settings} initial={data.members} />
        : data.section === "invitations" ? (
          <Invitations key={slug} slug={slug} settings={settings} settingsFailure={namespace.failure} initial={data.invitations}
            retrySettings={() => { void router.invalidate(); }} />
        )
        : data.section === "repos" ? <Repos key={slug} slug={slug} initial={data.repos} />
        : data.section === "service-accounts" ? <ServiceAccounts key={slug} slug={slug} initial={data.accounts} />
        : data.section === "secrets" ? <Secrets key={slug} slug={slug} initial={data.secrets} />
        : data.section === "storage" ? <Storage key={slug} slug={slug} initial={data.storage} />
        : <Audit key={slug} slug={slug} initial={data.audit} />}
    </Page>
  );
}
