// A view inside the signed-in shell: a top bar with the view's one level-one heading, then its main landmark (the skip-link target).
import { createContext, useContext, type ReactNode } from "react";
import { Icon } from "./ui.tsx";

export const MenuButtonContext = createContext<() => void>(() => {});

export function rememberTenant(slug: string) {
  document.cookie = `sentinel-tenant=${encodeURIComponent(slug)}; Path=/; Max-Age=${60 * 60 * 24 * 365}; SameSite=Lax${location.protocol === "https:" ? "; Secure" : ""}`;
}

export function Page({ id, title, actions, toolbar, children }: { id: string; title: ReactNode; actions?: ReactNode; toolbar?: ReactNode; children: ReactNode }) {
  const openNavigation = useContext(MenuButtonContext);
  return (
    <div id={id} className="flex min-w-0 flex-1 flex-col">
      <header className="sticky top-0 z-20 border-b border-line bg-canvas">
        <div className="flex min-h-14 flex-wrap items-center gap-2 px-4 py-2">
          <button type="button" className="rounded p-1.5 text-muted hover:bg-elevated md:hidden" aria-label="Open navigation" onClick={openNavigation}>
            <Icon name="menu" className="size-5" />
          </button>
          <h1 className="min-w-0 flex-1 truncate text-lg font-semibold text-strong">{title}</h1>
          {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        </div>
        {toolbar}
      </header>
      <main id="main" tabIndex={-1} className="min-w-0 flex-1 space-y-6 p-4 focus:outline-none sm:p-6">
        {children}
      </main>
    </div>
  );
}
