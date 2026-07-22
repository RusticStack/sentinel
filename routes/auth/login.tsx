import { Lock, Server } from "lucide-preact";
import { Head } from "fresh/runtime";
import { define } from "../../utils.ts";

/** Inline mark — Lucide no longer ships a GitHub icon. */
function GitHubMark() {
  return (
    <svg
      class="size-4"
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8" />
    </svg>
  );
}

/**
 * Locked auth gate — primary entry for unauthenticated users.
 * Phase 1 wires the GitHub OAuth redirect from this page / a POST handler.
 * No dashboard chrome or peek; the app feels locked until sign-in succeeds.
 */
export default define.page(function Login() {
  return (
    <div class="flex min-h-screen flex-col items-center justify-center px-4 py-10 sm:px-6">
      <Head>
        <title>Sign in · Sentinel</title>
      </Head>

      <main
        id="main"
        class="fade-rise flex w-full max-w-sm flex-col items-center"
      >
        <div class="mb-8 flex flex-col items-center gap-3 text-center">
          <span class="flex size-11 items-center justify-center rounded-xl bg-accent text-accent-ink shadow-glass-sm">
            <Server class="size-5" strokeWidth={2.25} aria-hidden="true" />
          </span>
          <div>
            <p class="font-sans text-xl font-semibold tracking-tight text-fg-strong">
              Sentinel
            </p>
            <p class="mt-1 text-sm text-muted">
              Self-hosted runner dashboard
            </p>
          </div>
        </div>

        <div class="glass w-full rounded-xl p-6 sm:p-7">
          <div class="flex items-start gap-3">
            <span class="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-accent-soft text-accent-ink">
              <Lock class="size-3.5" strokeWidth={2.25} aria-hidden="true" />
            </span>
            <div>
              <h1 class="font-sans text-base font-semibold tracking-tight text-fg-strong">
                Sign in to continue
              </h1>
              <p class="mt-1.5 text-sm leading-relaxed text-muted">
                Access is limited to members of your GitHub organization. Sign
                in to open the dashboard.
              </p>
            </div>
          </div>

          {/* Phase 1: replace disabled button with OAuth authorize redirect */}
          <button
            type="button"
            disabled
            class="mt-6 inline-flex w-full cursor-not-allowed items-center justify-center gap-2 rounded-md bg-accent/70 px-4 py-2.5 font-sans text-sm font-semibold text-accent-ink opacity-80"
            aria-describedby="oauth-phase-note"
          >
            <GitHubMark />
            Sign in with GitHub
          </button>

          <p
            id="oauth-phase-note"
            class="mt-3 text-center font-mono text-[0.7rem] leading-relaxed text-subtle"
          >
            GitHub OAuth + org check — Phase 1
          </p>
        </div>

        <p class="mt-6 max-w-xs text-center text-xs leading-relaxed text-subtle">
          After sign-in you will land on the dashboard. There is nothing to
          browse while locked.
        </p>
      </main>
    </div>
  );
});
