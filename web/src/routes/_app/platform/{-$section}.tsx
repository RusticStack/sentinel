import { createFileRoute, notFound } from "@tanstack/react-router";
import { Page } from "../../../components/Page.tsx";
import { cx, Icon, PathLink } from "../../../components/ui.tsx";
import { Audit, loadPlatformAudit } from "../../../components/platform/Audit.tsx";
import { Backups, loadBackups } from "../../../components/platform/Backups.tsx";
import { loadPolicy, Policy } from "../../../components/platform/Policy.tsx";
import { loadPools, Pools } from "../../../components/platform/Pools.tsx";
import { loadRegistrations, Registrations } from "../../../components/platform/Registrations.tsx";
import { loadDeploymentStorage, Storage } from "../../../components/platform/Storage.tsx";
import { loadTenants, Tenants } from "../../../components/platform/Tenants.tsx";
import { loadWorkers, Workers } from "../../../components/platform/Workers.tsx";

// Step-up prompts come from the controller's refusals, not from this page.
const SECTIONS = [
  { id: "registrations", label: "Registrations", icon: "user-check" },
  { id: "tenants", label: "Tenants", icon: "building-2" },
  { id: "pools", label: "Pools", icon: "server" },
  { id: "workers", label: "Workers", icon: "radar" },
  { id: "storage", label: "Storage", icon: "hard-drive" },
  { id: "policy", label: "Policy", icon: "scale" },
  { id: "audit", label: "Audit", icon: "scroll-text" },
] as const;
type Section = (typeof SECTIONS)[number]["id"];
const isSection = (s: string): s is Section => SECTIONS.some((x) => x.id === s);

export const Route = createFileRoute("/_app/platform/{-$section}")({
  beforeLoad: ({ context, params }) => {
    if (!context.session.me?.super_admin) throw notFound();
    if (params.section !== undefined && !isSection(params.section)) throw notFound();
  },
  loader: async ({ params }) => {
    const section: Section = params.section && isSection(params.section) ? params.section : "registrations";
    switch (section) {
      case "registrations": return { section, registrations: await loadRegistrations() } as const;
      case "tenants": return { section, tenants: await loadTenants() } as const;
      case "pools": return { section, pools: await loadPools() } as const;
      case "workers": return { section, workers: await loadWorkers() } as const;
      case "storage": {
        const [storage, backups] = await Promise.all([loadDeploymentStorage(), loadBackups()]);
        return { section, storage, backups } as const;
      }
      case "policy": return { section, policy: await loadPolicy() } as const;
      case "audit": return { section, audit: await loadPlatformAudit() } as const;
    }
  },
  head: () => ({ meta: [{ title: "Platform · Sentinel" }] }),
  component: PlatformView,
});

function PlatformView() {
  const data = Route.useLoaderData();
  const section = data.section;

  const toolbar = (
    <nav aria-label="Sections" className="overflow-x-auto border-t border-line px-3">
      <ul className="flex gap-1 whitespace-nowrap">
        {SECTIONS.map((s) => {
          const current = s.id === section;
          return (
            <li key={s.id}>
              <PathLink to={`/platform/${s.id}`} aria-current={current ? "page" : undefined}
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
    <Page id="platform" title="Platform" toolbar={toolbar}>
      {data.section === "registrations" ? <Registrations initial={data.registrations} />
        : data.section === "tenants" ? <Tenants initial={data.tenants} />
        : data.section === "pools" ? <Pools initial={data.pools} />
        : data.section === "workers" ? <Workers initial={data.workers} />
        : data.section === "storage" ? <><Storage data={data.storage} /><Backups initial={data.backups} /></>
        : data.section === "policy" ? <Policy key={JSON.stringify(data.policy)} initial={data.policy} />
        : <Audit initial={data.audit} />}
    </Page>
  );
}
