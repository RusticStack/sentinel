import { Lock, Server, ShieldX } from "lucide-preact";
import { Head } from "fresh/runtime";
import { page } from "fresh";
import { define } from "../../utils.ts";

export const handler = define.handlers({
  GET(ctx) {
    if (ctx.state.user) {
      return ctx.redirect("/");
    }
    return page();
  },
});

/** Clear denial for non-org members (no session). */
export default define.page(function Denied() {
  return (
    <div class="flex min-h-screen flex-col items-center justify-center px-4 py-10 sm:px-6">
      <Head>
        <title>Access denied · Sentinel</title>
      </Head>

      <main
        id="main"
        class="fade-rise flex w-full max-w-sm flex-col items-center"
      >
        <div class="mb-8 flex flex-col items-center gap-3 text-center">
          <span class="flex size-11 items-center justify-center rounded-xl bg-accent text-accent-ink shadow-glass-sm">
            <Server class="size-5" strokeWidth={2.25} aria-hidden="true" />
          </span>
          <p class="font-sans text-xl font-semibold tracking-tight text-fg-strong">
            Sentinel
          </p>
        </div>

        <div class="glass w-full rounded-xl p-6 sm:p-7">
          <div class="flex items-start gap-3">
            <span class="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-status-error/10 text-status-error">
              <ShieldX class="size-3.5" strokeWidth={2.25} aria-hidden="true" />
            </span>
            <div>
              <h1 class="font-sans text-base font-semibold tracking-tight text-fg-strong">
                Not an organization member
              </h1>
              <p class="mt-1.5 text-sm leading-relaxed text-muted">
                Your GitHub account signed in successfully, but it is not an
                active member of this organization. No session was created.
              </p>
            </div>
          </div>

          <a
            href="/auth/login"
            class="mt-6 inline-flex w-full items-center justify-center gap-2 rounded-md border border-border bg-surface-2/80 px-4 py-2.5 font-sans text-sm font-semibold text-fg transition-colors hover:border-accent-muted hover:bg-accent-soft"
          >
            <Lock class="size-3.5" strokeWidth={2.25} aria-hidden="true" />
            Back to sign in
          </a>
        </div>
      </main>
    </div>
  );
});
