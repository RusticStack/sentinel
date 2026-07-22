import { Gauge, GitBranch, Server } from "lucide-preact";
import { Head } from "fresh/runtime";
import { page } from "fresh";
import { define } from "../utils.ts";

/**
 * Dashboard lives at `/` after auth.
 * Phase 0 has no sessions yet, so everyone is redirected to the locked login gate.
 * Phase 1 middleware will also redirect unauthenticated users; this handler stays
 * as a belt-and-suspenders check once `ctx.state.user` is set on login.
 */
export const handler = define.handlers({
  GET(ctx) {
    if (!ctx.state.user) {
      return ctx.redirect("/auth/login");
    }
    return page();
  },
});

export default define.page(function Home() {
  return (
    <div class="flex min-h-screen flex-col">
      <Head>
        <title>Sentinel</title>
      </Head>

      <header class="glass sticky top-0 z-20 border-b border-border-subtle/70">
        <div class="mx-auto flex h-14 max-w-6xl items-center gap-6 px-4 sm:px-6">
          <div class="flex shrink-0 items-center gap-2.5">
            <span class="flex size-7 items-center justify-center rounded-md bg-accent text-accent-ink">
              <Server class="size-3.5" strokeWidth={2.25} aria-hidden="true" />
            </span>
            <span class="font-sans text-sm font-semibold tracking-tight text-fg-strong">
              Sentinel
            </span>
          </div>

          <nav
            class="hidden items-center gap-0.5 sm:flex"
            aria-label="Primary"
          >
            <a href="/" class="shell-nav-link" aria-current="page">
              Dashboard
            </a>
            <span class="shell-nav-link" aria-disabled="true">
              Runners
            </span>
            <span class="shell-nav-link" aria-disabled="true">
              Runs
            </span>
          </nav>

          <div class="ml-auto">
            <a
              href="/logout"
              class="rounded-md border border-border bg-surface-2/70 px-3.5 py-1.5 font-sans text-sm font-medium text-fg transition-colors hover:border-accent-muted hover:bg-accent-soft"
            >
              Sign out
            </a>
          </div>
        </div>
      </header>

      <main
        id="main"
        class="mx-auto flex w-full max-w-6xl flex-1 flex-col gap-5 px-4 py-6 sm:px-6 sm:py-8"
      >
        <div class="fade-rise flex items-end justify-between gap-4">
          <div>
            <h1 class="font-sans text-lg font-semibold tracking-tight text-fg-strong sm:text-xl">
              Dashboard
            </h1>
            <p class="mt-0.5 text-sm text-muted">
              Overview of runners, host resources, and recent workflow runs.
            </p>
          </div>
        </div>

        <div class="fade-rise-delay grid gap-3 sm:grid-cols-3">
          <section class="glass-subtle rounded-xl p-4" aria-label="Runners">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2 text-muted">
                <Server class="size-4" aria-hidden="true" />
                <h2 class="font-sans text-sm font-medium text-fg">Runners</h2>
              </div>
            </div>
            <div class="mt-5 space-y-2.5" aria-hidden="true">
              <div class="placeholder-bar w-1/3" />
              <div class="placeholder-bar w-2/3 opacity-70" />
            </div>
          </section>

          <section class="glass-subtle rounded-xl p-4" aria-label="System">
            <div class="flex items-center gap-2 text-muted">
              <Gauge class="size-4" aria-hidden="true" />
              <h2 class="font-sans text-sm font-medium text-fg">System</h2>
            </div>
            <div class="mt-5 space-y-2.5" aria-hidden="true">
              <div class="placeholder-bar w-2/5" />
              <div class="placeholder-bar w-3/5 opacity-70" />
            </div>
          </section>

          <section class="glass-subtle rounded-xl p-4" aria-label="Runs">
            <div class="flex items-center gap-2 text-muted">
              <GitBranch class="size-4" aria-hidden="true" />
              <h2 class="font-sans text-sm font-medium text-fg">Runs</h2>
            </div>
            <div class="mt-5 space-y-2.5" aria-hidden="true">
              <div class="placeholder-bar w-1/4" />
              <div class="placeholder-bar w-1/2 opacity-70" />
            </div>
          </section>
        </div>

        <section
          class="glass fade-rise-delay flex min-h-64 flex-1 flex-col rounded-xl p-4 sm:p-5"
          aria-label="Recent activity"
        >
          <div class="flex items-center justify-between border-b border-border-subtle/80 pb-3">
            <h2 class="font-sans text-sm font-semibold text-fg-strong">
              Recent activity
            </h2>
            <span class="font-mono text-xs text-subtle">—</span>
          </div>
          <div
            class="mt-4 flex flex-1 flex-col justify-center gap-3"
            aria-hidden="true"
          >
            <div class="placeholder-bar w-full max-w-md opacity-60" />
            <div class="placeholder-bar w-full max-w-sm opacity-45" />
            <div class="placeholder-bar w-full max-w-lg opacity-35" />
            <div class="placeholder-bar w-full max-w-xs opacity-25" />
          </div>
          <p class="mt-4 text-center text-sm text-subtle">
            Runner and workflow data loads after auth (Phase 2+).
          </p>
        </section>
      </main>
    </div>
  );
});
