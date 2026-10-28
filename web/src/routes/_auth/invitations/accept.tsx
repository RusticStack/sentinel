// The token sits in the URL fragment, which no server sees; the page reads it once and clears the address bar.
import { useEffect, useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { api, ApiError } from "../../../lib/api.ts";
import { refusal, retryAfter, useRetryWait } from "../../../lib/act.tsx";
import { fragmentToken, INVITATION_STASH, stashInvitation, unstashInvitation } from "../../../lib/onboarding.ts";
import { rememberReturn } from "../../../lib/redirect.ts";
import { refreshTenants, signOut, useSession } from "../../../lib/session.ts";
import { CheckEmail } from "../../../components/CheckEmail.tsx";
import { SignInForm } from "../../../components/SignInForm.tsx";
import { SignUpForm, type SignUpResult } from "../../../components/SignUpForm.tsx";
import { Alert, Button, ButtonLink, buttonClass, Icon } from "../../../components/ui.tsx";
import { AuthCard, AuthTitle } from "../-card.tsx";

type Phase = "reading" | "missing" | "ready" | "accepting" | "joined" | "member" | "redeemed" | "verify" | "unusable";

export const Route = createFileRoute("/_auth/invitations/accept")({
  loader: async () => ({ github: await api<{ github_sign_in?: boolean }>("/api/v1/health").then((h) => !!h?.github_sign_in, () => false) }),
  head: () => ({ meta: [{ title: "Accept an invitation · Sentinel" }] }),
  component: AcceptInvitation,
});

function unstash(): string | null {
  try {
    const raw = sessionStorage.getItem(INVITATION_STASH);
    sessionStorage.removeItem(INVITATION_STASH);
    return unstashInvitation(raw, Date.now());
  } catch {
    return null;
  }
}

function AcceptInvitation() {
  const { github } = Route.useLoaderData();
  const { me } = useSession();
  const [phase, setPhase] = useState<Phase>("reading");
  const [tenant, setTenant] = useState<string | null>(null);
  const [verification, setVerification] = useState<"email" | "operator">("email");
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [signedUp, setSignedUp] = useState<SignUpResult | null>(null);
  // The secret lives in this component's memory only and goes with it; a second run of the reading effect
  // (development's StrictMode) finds the address bar and the stash already emptied and keeps what the first read.
  const token = useRef<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const [focusAsked, setFocusAsked] = useState(0);
  const { waiting, start: wait } = useRetryWait();

  useEffect(() => {
    // Remove the stash on every visit, even when the fragment brings its own token.
    const parked = unstash();
    token.current = fragmentToken(location.hash, "invitation") ?? parked ?? token.current;
    rememberReturn(null);
    if (location.hash) history.replaceState(history.state, "", location.pathname + location.search);
    setPhase(token.current ? "ready" : "missing");
  }, []);
  useEffect(() => { if (focusAsked) heading.current?.focus(); }, [focusAsked]);

  function settle(next: Phase) {
    setPhase(next);
    if (next !== "ready") token.current = null;
    setFocusAsked((n) => n + 1);
  }

  async function accept() {
    if (!token.current || phase === "accepting" || waiting) return;
    setPhase("accepting");
    setError("");
    try {
      const done = await api<{ status: string; tenant?: string; verification?: "email" | "operator" }>("/api/v1/invitations/accept", { method: "POST", body: { token: token.current } });
      if (done.status === "joined") {
        setTenant(done.tenant ?? null);
        await refreshTenants();
        settle("joined");
      } else if (done.status === "already_member") settle("member");
      else if (done.status === "verification_sent") {
        setVerification(done.verification ?? "email");
        settle("verify");
      } else settle("redeemed");
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "unauthenticated") return;
      if (err.code === "not_found") return settle("unusable");
      setPhase("ready");
      if (err.code === "rate_limited") {
        wait(err);
        setError(`Too many attempts from here. Try again in ${retryAfter(err)}.`);
      } else setError(refusal(err));
    }
  }

  // Only a round trip that leaves the page parks the secret, in this tab, for at most ten minutes.
  function stash() {
    try {
      if (token.current) sessionStorage.setItem(INVITATION_STASH, stashInvitation(token.current, Date.now()));
    } catch { /* storage off: the person opens the link again after signing in */ }
    rememberReturn("/invitations/accept");
  }

  function switchAccount() {
    stash();
    token.current = null;
    void signOut("/invitations/accept");
  }

  function signedUpWith(result: SignUpResult) {
    setSignedUp(result);
    token.current = null;
    setFocusAsked((n) => n + 1);
  }

  const who = me?.email || me?.username || "your account";
  const title = signedUp ? "Confirm your address" : (() => {
    switch (phase) {
      case "joined": return tenant ? `You joined ${tenant}` : "Invitation accepted";
      case "member": return "You are already a member";
      case "redeemed": return "Invitation accepted";
      case "verify": return "Confirm your address to join";
      case "unusable": return "This invitation cannot be used";
      case "missing": return "Open your invitation link";
      default: return "You have been invited";
    }
  })();

  let body;
  if (phase === "reading") {
    body = <p className="text-muted" role="status">Reading the link…</p>;
  } else if (phase === "missing") {
    body = <p>This page needs the full link from your invitation email. Open the link again, or copy all of it into the address bar; it ends with <code>#token=…</code>.</p>;
  } else if ((phase === "ready" || phase === "accepting") && me) {
    body = (
      <>
        <p>You have an invitation to join an organization on Sentinel. Accept it as <strong className="break-all">{who}</strong>.</p>
        <p className="text-muted">An invitation sent to an email address can only be used by the account that holds that address, once it is confirmed.</p>
        {error ? <Alert color="error" icon="circle-alert" title={error} role="alert" /> : null}
        <div className="flex flex-wrap gap-2">
          <Button label={waiting ? `Wait ${waiting} s` : "Accept invitation"} icon="check" loading={phase === "accepting"} disabled={!!waiting} onClick={accept} />
          <Button color="neutral" variant="ghost" label="Not me — sign out" onClick={switchAccount} />
        </div>
      </>
    );
  } else if (phase === "ready" && !signedUp) {
    const tab = (value: "signin" | "signup", label: string) => (
      <Button variant={mode === value ? "solid" : "ghost"} color={mode === value ? "primary" : "neutral"} block label={label} aria-pressed={mode === value} onClick={() => setMode(value)} />
    );
    body = (
      <>
        <p>You have an invitation to join an organization on Sentinel. Sign in, or create an account with the address the invitation was sent to.</p>
        <div role="group" aria-label="How to continue" className="grid grid-cols-2 gap-1 rounded-lg bg-elevated p-1">
          {tab("signin", "I have an account")}
          {tab("signup", "I'm new here")}
        </div>
        {mode === "signin" ? <SignInForm /> : <SignUpForm invitation={token.current} onAccepted={signedUpWith} />}
        {github && mode === "signin" ? (
          // A full page load: GitHub sign-in is the controller's own page; the secret is parked for the way back.
          <a href="/auth/github/start?return_to=%2F" className={buttonClass({ color: "neutral", variant: "outline", block: true })} onClick={stash}>
            <Icon name="github" />Sign in with GitHub
          </a>
        ) : null}
      </>
    );
  } else if (signedUp) {
    body = <CheckEmail email={signedUp.email} verification={signedUp.verification} joining />;
  } else if (phase === "joined") {
    body = (
      <>
        <Alert color="success" icon="circle-check" role="status" title={tenant ? `You are now a member of ${tenant}.` : "The invitation is accepted."} />
        <ButtonLink to={tenant ? `/t/${tenant}` : "/"} label={tenant ? `Open ${tenant}` : "Continue"} block />
      </>
    );
  } else if (phase === "member") {
    body = (
      <>
        <p>Your account already belongs to this organization; the invitation was left unused.</p>
        <ButtonLink to="/organizations" label="Your organizations" block />
      </>
    );
  } else if (phase === "redeemed") {
    body = (
      <>
        <p>The invitation is accepted.</p>
        <ButtonLink to="/" label="Continue" block />
      </>
    );
  } else if (phase === "verify") {
    body = <CheckEmail verification={verification} joining />;
  } else if (phase === "unusable") {
    body = (
      <>
        <Alert color="warning" icon="mail-x" role="alert" title="Sentinel could not accept this invitation."
          description="It may have expired, already been used or been withdrawn; it may have been sent to a different email address than your account's; or the organization's membership may be managed by GitHub, where invitations do not apply." />
        <ul className="list-disc space-y-1 ps-5">
          <li>Sent to another address? Sign in with the account that holds it, or ask for an invitation to your address.</li>
          <li>Otherwise ask whoever invited you for a new invitation.</li>
        </ul>
        <ButtonLink to="/" color="neutral" variant="outline" label="Back to Sentinel" block />
      </>
    );
  } else {
    body = null;
  }

  return (
    <AuthCard className="max-w-md" header={<AuthTitle ref={heading} icon="mail-open" focusable>{title}</AuthTitle>}>
      <div className="space-y-4 text-sm">{body}</div>
    </AuthCard>
  );
}
