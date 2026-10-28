import { createFileRoute, useRouter } from "@tanstack/react-router";
import { api } from "../../lib/api.ts";
import { rememberReturn, sameOriginPath } from "../../lib/redirect.ts";
import { NO_CONTROL, searchSchema } from "../../lib/search.ts";
import { SignInForm } from "../../components/SignInForm.tsx";
import { Alert, buttonClass, Icon, PathLink, TextLink } from "../../components/ui.tsx";
import { AuthCard, AuthTitle } from "./-card.tsx";

const NOTICES: Record<string, { title: string; description: string }> = {
  expired: { title: "Your session ended", description: "Sign in again to continue where you were." },
  "password-changed": { title: "Password changed", description: "Every session of your account was signed out. Sign in with the new password." },
  verified: { title: "Address verified", description: "Sign in with your email address and password." },
};

export const Route = createFileRoute("/_auth/login")({
  validateSearch: searchSchema({ next: [NO_CONTROL, 2048], reason: [/^(expired|password-changed|verified)$/, 32] }),
  loader: async () => ({ github: await api<{ github_sign_in?: boolean }>("/api/v1/health").then((h) => !!h?.github_sign_in, () => false) }),
  head: () => ({ meta: [{ title: "Sign in · Sentinel" }] }),
  component: Login,
});

function Login() {
  const { github } = Route.useLoaderData();
  const search = Route.useSearch();
  const router = useRouter();
  const next = sameOriginPath(search.next);
  const notice = search.reason ? NOTICES[search.reason] ?? null : null;

  return (
    <AuthCard className="max-w-sm" header={<AuthTitle>Sign in to Sentinel</AuthTitle>}
      footer={
        <div className="space-y-3">
          {github ? (
            // A full page load: GitHub sign-in is the controller's own page.
            <a href="/auth/github/start?return_to=%2F" className={buttonClass({ color: "neutral", variant: "outline", block: true })} onClick={() => rememberReturn(next)}>
              <Icon name="github" />Sign in with GitHub
            </a>
          ) : null}
          <p className="text-center text-sm">New here? <TextLink to="/register" className="font-medium">Create an account</TextLink></p>
          <p className="text-center text-xs text-muted"><PathLink to="/verify-email" className="underline">Didn't get the verification email?</PathLink></p>
        </div>
      }>
      <SignInForm onSignedIn={() => { void router.navigate({ href: next }); }}
        notice={(error) => (notice && !error ? <Alert color="info" icon="info" title={notice.title} description={notice.description} role="status" /> : null)} />
    </AuthCard>
  );
}
