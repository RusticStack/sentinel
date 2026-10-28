// The signed-in shell: sidebar with the namespace switcher, the tenant's views and the account menu.
import { useEffect, useState } from "react";
import { createFileRoute, Link, Outlet, useNavigate, useParams, useRouterState } from "@tanstack/react-router";
import { readCookie } from "../lib/api.ts";
import { signOut, useSession } from "../lib/session.ts";
import { shortId } from "../lib/format.ts";
import { cx, DropdownMenu, Icon, PathLink, Select, type SelectGroup } from "../components/ui.tsx";
import { MenuButtonContext, rememberTenant } from "../components/Page.tsx";

export const Route = createFileRoute("/_app")({
  // The last tenant used is a cookie, so the server renders the same choice.
  loader: async () => ({ remembered: await readCookie("sentinel-tenant") }),
  component: AppShell,
});

const ROLE_NAMES: Record<string, string> = { reader: "Reader", operator: "Operator", admin: "Admin" };

function AppShell() {
  const { me, tenants, roleIn } = useSession();
  const { remembered } = Route.useLoaderData();
  const params = useParams({ strict: false }) as { slug?: string };
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);
  const active = params.slug ?? remembered ?? null;
  const role = roleIn(active);

  useEffect(() => { if (params.slug) rememberTenant(params.slug); }, [params.slug]);
  useEffect(() => { setOpen(false); }, [pathname]);
  useEffect(() => {
    const cls = document.documentElement.classList;
    setTheme(cls.contains("dark") ? "dark" : cls.contains("light") ? "light" : matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  }, []);

  const groups: SelectGroup[] = [];
  const personal = tenants.filter((t) => t.kind === "personal");
  const github = tenants.filter((t) => t.kind !== "personal" && t.membership === "github");
  const app = tenants.filter((t) => t.kind !== "personal" && t.membership !== "github");
  if (personal.length) groups.push({ label: "Personal", items: personal.map((t) => ({ value: t.slug, label: t.slug, description: `Personal · ${ROLE_NAMES[t.role] ?? t.role}`, icon: "user" })) });
  if (app.length) groups.push({ label: "Organizations", items: app.map((t) => ({ value: t.slug, label: t.slug, description: ROLE_NAMES[t.role] ?? t.role, icon: "building-2" })) });
  if (github.length) groups.push({ label: "GitHub organizations", items: github.map((t) => ({ value: t.slug, label: t.slug, description: `GitHub-managed · ${ROLE_NAMES[t.role] ?? t.role}`, icon: "github" })) });

  const main = active && tenants.some((t) => t.slug === active) ? [
    { label: "Runs", icon: "play", to: `/t/${active}`, exact: true },
    { label: "Queue", icon: "list-ordered", to: `/t/${active}/queue` },
    { label: "Workers", icon: "server", to: `/t/${active}/workers` },
    { label: "GitHub sync", icon: "refresh-cw", to: `/t/${active}/sync` },
    { label: "Settings", icon: "settings", to: `/t/${active}/settings` },
    ...(role === "admin" || me?.super_admin ? [{ label: "Tenant admin", icon: "users", to: `/t/${active}/admin` }] : []),
  ] : [];
  const platform = [
    { label: "Organizations", icon: "building", to: "/organizations" },
    ...(me?.super_admin ? [{ label: "Platform", icon: "shield", to: "/platform" }, { label: "GitHub App", icon: "github", to: "/setup/github" }] : []),
  ];

  function switchTheme() {
    const next = theme === "dark" ? "light" : "dark";
    const cls = document.documentElement.classList;
    cls.remove("dark", "light");
    cls.add(next);
    document.cookie = `sentinel-theme=${next}; Path=/; Max-Age=${60 * 60 * 24 * 365}; SameSite=Lax${location.protocol === "https:" ? "; Secure" : ""}`;
    setTheme(next);
  }

  const navItem = (l: { label: string; icon: string; to: string; exact?: boolean }) => {
    const current = l.exact ? pathname === l.to : pathname === l.to || pathname.startsWith(l.to + "/");
    return (
      <li key={l.to}>
        <PathLink to={l.to} aria-current={current ? "page" : undefined}
          className={cx("flex items-center gap-2 rounded-md px-2 py-1.5 text-sm", current ? "bg-elevated font-medium text-strong" : "text-fg hover:bg-subtle")}>
          <Icon name={l.icon} className={cx("size-4", current ? "text-primary" : "text-muted")} />{l.label}
        </PathLink>
      </li>
    );
  };

  return (
    <div className="flex min-h-screen">
      <a href="#main" className="skip-link rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary"
        onClick={(e) => { e.preventDefault(); document.getElementById("main")?.focus(); }}>Skip to content</a>
      <aside className={cx("fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-line bg-subtle transition-transform md:sticky md:top-0 md:h-screen md:translate-x-0",
        open ? "translate-x-0" : "-translate-x-full")} aria-label="Sidebar">
        <div className="flex h-14 items-center justify-between gap-2 border-b border-line px-4">
          <Link to="/" className="flex items-center gap-2 font-semibold text-strong" aria-label="Sentinel home">
            <Icon name="radar" className="size-5 text-primary" /><span>Sentinel</span>
          </Link>
          <button type="button" className="rounded p-1 text-muted hover:bg-elevated md:hidden" aria-label="Close navigation" onClick={() => setOpen(false)}><Icon name="x" /></button>
        </div>
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-3">
          {tenants.length ? (
            <Select ariaLabel="Active namespace" value={active} placeholder="Choose a namespace" groups={groups}
              icon={personal.some((t) => t.slug === active) ? "user" : github.some((t) => t.slug === active) ? "github" : "building-2"}
              onChange={(slug) => { rememberTenant(slug); void navigate({ to: "/t/$slug", params: { slug } }); }} />
          ) : null}
          {main.length ? <nav aria-label="Tenant"><ul className="space-y-0.5">{main.map(navItem)}</ul></nav> : null}
          <nav aria-label="Platform" className="mt-auto"><ul className="space-y-0.5">{platform.map(navItem)}</ul></nav>
        </div>
        <div className="border-t border-line p-3">
          <DropdownMenu ariaLabel="Account" triggerLabel="Account menu"
            triggerClassName="flex w-full cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg hover:bg-elevated"
            trigger={<><Icon name="circle-user" /><span className="flex-1 truncate text-left">{me?.username || "Account"}</span><Icon name="chevrons-up-down" className="size-4 text-dimmed" /></>}
            sections={[
              [{ label: me?.username || shortId(me?.user), icon: "user", kind: "label" }],
              [
                { label: "Account security", icon: "shield-check", onAction: () => void navigate({ to: "/account" }) },
                { label: theme === "dark" ? "Light theme" : "Dark theme", icon: theme === "dark" ? "sun" : "moon", onAction: switchTheme },
                { label: "Sign out", icon: "log-out", onAction: () => void signOut() },
              ],
            ]} />
        </div>
      </aside>
      {open ? <div className="fixed inset-0 z-30 bg-black/40 md:hidden" aria-hidden="true" onClick={() => setOpen(false)} /> : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <MenuButtonContext.Provider value={() => setOpen(true)}>
          <Outlet />
        </MenuButtonContext.Provider>
      </div>
    </div>
  );
}
