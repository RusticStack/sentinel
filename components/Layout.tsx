import { Server } from "lucide-preact";
import type { ComponentChildren } from "preact";
import ConfirmLogout from "../islands/ConfirmLogout.tsx";
import type { SessionUser } from "../utils.ts";

export type LayoutNavId =
  | "dashboard"
  | "runners"
  | "runs"
  | "security"
  | "help";

export interface LayoutProps {
  user: SessionUser;
  /** Current path for aria-current on nav links. */
  path: string;
  /** Show Security when Vigil is configured. */
  showSecurity?: boolean;
  children: ComponentChildren;
}

function activeNav(path: string): LayoutNavId {
  if (path === "/runners" || path.startsWith("/runners/")) return "runners";
  if (path === "/runs" || path.startsWith("/runs/")) return "runs";
  if (path === "/security" || path.startsWith("/security/")) return "security";
  if (path === "/help" || path.startsWith("/help/")) return "help";
  return "dashboard";
}

function navCurrent(id: LayoutNavId, active: LayoutNavId): boolean {
  return id === active;
}

function NavLinks(props: {
  active: LayoutNavId;
  showSecurity: boolean;
  mobile?: boolean;
}) {
  const shrink = props.mobile
    ? "shell-nav-link shrink-0 px-3 py-2 text-[0.9375rem]"
    : "shell-nav-link";
  return (
    <>
      <a
        href="/"
        class={shrink}
        aria-current={navCurrent("dashboard", props.active)
          ? "page"
          : undefined}
      >
        Dashboard
      </a>
      <a
        href="/runners"
        class={shrink}
        aria-current={navCurrent("runners", props.active) ? "page" : undefined}
      >
        Runners
      </a>
      <a
        href="/runs"
        class={shrink}
        aria-current={navCurrent("runs", props.active) ? "page" : undefined}
      >
        Runs
      </a>
      {props.showSecurity && (
        <a
          href="/security"
          class={shrink}
          aria-current={navCurrent("security", props.active)
            ? "page"
            : undefined}
        >
          Security
        </a>
      )}
      <a
        href="/help"
        class={shrink}
        aria-current={navCurrent("help", props.active) ? "page" : undefined}
      >
        Help
      </a>
    </>
  );
}

/** App chrome after auth. Auth routes stay chrome-free. */
export function Layout(props: LayoutProps) {
  const active = activeNav(props.path);
  const showSecurity = Boolean(props.showSecurity);

  return (
    <div class="flex min-h-screen flex-col">
      <header
        class="glass sticky top-0 z-20 border-b border-border-subtle/70"
        data-tour="nav"
      >
        <div class="mx-auto flex h-14 max-w-6xl items-center gap-4 px-4 sm:gap-6 sm:px-6">
          <a
            href="/"
            class="flex shrink-0 items-center gap-2.5 rounded-md outline-offset-2"
          >
            <span class="flex size-7 items-center justify-center rounded-md bg-accent text-accent-ink">
              <Server class="size-3.5" strokeWidth={2.25} aria-hidden="true" />
            </span>
            <span class="font-sans text-sm font-semibold tracking-tight text-fg-strong">
              Sentinel
            </span>
          </a>

          <nav
            class="hidden items-center gap-0.5 sm:flex"
            aria-label="Primary"
          >
            <NavLinks active={active} showSecurity={showSecurity} />
          </nav>

          <div class="ml-auto flex items-center gap-3">
            <span
              class="hidden max-w-[10rem] truncate font-mono text-xs text-muted sm:inline"
              title={props.user.login}
            >
              {props.user.login}
            </span>
            <ConfirmLogout />
          </div>
        </div>

        <nav
          class="flex gap-1 overflow-x-auto border-t border-border-subtle/60 px-2 py-1 sm:hidden [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
          aria-label="Primary mobile"
        >
          <NavLinks active={active} showSecurity={showSecurity} mobile />
        </nav>
      </header>

      <main
        id="main"
        class="mx-auto flex w-full max-w-6xl flex-1 flex-col gap-5 px-4 py-6 sm:px-6 sm:py-8"
        tabIndex={-1}
      >
        {props.children}
      </main>
    </div>
  );
}
