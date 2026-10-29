// The secret stays in the fragment so no server sees it, and is spent only on Confirm, since mail scanners open links.
import { useEffect, useRef, useState, type FormEvent } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { api, ApiError } from "../../lib/api.ts";
import { refusal, retryAfter, useRetryWait } from "../../lib/act.tsx";
import { fragmentToken, looksLikeEmail } from "../../lib/onboarding.ts";
import { loadSession, useSession } from "../../lib/session.ts";
import { CheckEmail } from "../../components/CheckEmail.tsx";
import { Alert, Button, ButtonLink, Field, Input, TextLink } from "../../components/ui.tsx";
import { AuthCard, AuthTitle } from "./-card.tsx";

type Phase = "reading" | "ready" | "confirming" | "verified" | "invalid" | "missing";

const TITLES: Record<Phase, string> = {
  reading: "Confirm your email address",
  ready: "Confirm your email address",
  confirming: "Confirming…",
  verified: "Address confirmed",
  invalid: "This link cannot be used",
  missing: "Get a new confirmation link",
};

export const Route = createFileRoute("/_auth/verify-email")({
  head: () => ({ meta: [{ title: "Confirm your email address · Sentinel" }] }),
  component: VerifyEmail,
});

function VerifyEmail() {
  const { me } = useSession();
  const [phase, setPhase] = useState<Phase>("reading");
  const [joined, setJoined] = useState(false);
  const [error, setError] = useState("");
  const token = useRef<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const [focusAsked, setFocusAsked] = useState(0);
  const { waiting, start: wait } = useRetryWait();

  // Read in the browser only, so the server render and the first browser render agree ("Reading the link…").
  // The secret lives in this component's ref, gone with it when the page is left; a second run (development's
  // StrictMode) finds the address bar already cleaned and keeps what the first read.
  useEffect(() => {
    token.current = fragmentToken(location.hash, "verification") ?? token.current;
    if (location.hash) history.replaceState(history.state, "", location.pathname + location.search);
    setPhase(token.current ? "ready" : "missing");
  }, []);
  useEffect(() => { if (focusAsked) heading.current?.focus(); }, [focusAsked]);

  function settle(next: Phase) {
    setPhase(next);
    setFocusAsked((n) => n + 1);
  }

  async function confirm() {
    if (!token.current || phase === "confirming" || waiting) return;
    setPhase("confirming");
    setError("");
    try {
      const done = await api<{ verified: boolean; joined: boolean }>("/api/v1/email/verify", { method: "POST", body: { token: token.current } });
      token.current = null;
      setJoined(done.joined);
      if (me) await loadSession(true);
      settle("verified");
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "rate_limited") {
        wait(err);
        setError(`Too many attempts from here. Try again in ${retryAfter(err)}.`);
        setPhase("ready");
        return;
      }
      token.current = null;
      if (err.code === "invalid_request") settle("invalid");
      else {
        setError(refusal(err));
        setPhase("ready");
      }
    }
  }

  const [email, setEmail] = useState(me?.email && !me.email_verified ? me.email : "");
  const [resending, setResending] = useState(false);
  const [resent, setResent] = useState<"email" | "operator" | null>(null);
  const [resendError, setResendError] = useState("");
  const resendWait = useRetryWait();

  async function resend(e: FormEvent) {
    e.preventDefault();
    if (resending || resendWait.waiting) return;
    setResendError("");
    if (!looksLikeEmail(email)) {
      setResendError("Enter the address you signed up with.");
      return;
    }
    setResending(true);
    try {
      const done = await api<{ verification: "email" | "operator" }>("/api/v1/email/resend", { method: "POST", body: { email: email.trim() } });
      setResent(done.verification);
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "rate_limited") {
        resendWait.start(err);
        setResendError(`Too many requests from here. Try again in ${retryAfter(err)}.`);
      } else {
        setResendError(err.code === "invalid_request" ? "Enter a plain email address, such as name@example.com." : refusal(err));
      }
    } finally {
      setResending(false);
    }
  }

  return (
    <AuthCard className="max-w-md" header={<AuthTitle ref={heading} focusable>{TITLES[phase]}</AuthTitle>}
      footer={<p className="text-center text-sm"><TextLink to={me ? "/" : "/login"} className="font-medium">{me ? "Back to Sentinel" : "Back to sign-in"}</TextLink></p>}>
      <div className="space-y-4">
        {phase === "reading" ? (
          <p className="text-sm text-muted" role="status">Reading the link…</p>
        ) : phase === "ready" || phase === "confirming" ? (
          <>
            <p className="text-sm">Press Confirm to prove this mailbox is yours. The link works once.</p>
            {error ? <Alert color="error" icon="circle-alert" title={error} role="alert" /> : null}
            <Button label={waiting ? `Wait ${waiting} s` : "Confirm my address"} icon="mail-check" block loading={phase === "confirming"} disabled={!!waiting} onClick={confirm} />
          </>
        ) : phase === "verified" ? (
          <>
            <Alert color="success" icon="circle-check" role="status" title="Your email address is confirmed."
              description={joined ? "The invitation it carried is accepted too: you are now a member of the organization." : undefined} />
            {me ? <ButtonLink to="/" label="Continue" block /> : (
              <>
                <p className="text-sm">You can now sign in with this address. If this instance reviews new accounts, an administrator approves yours first.</p>
                <ButtonLink to="/login" search={{ reason: "verified" }} label="Sign in" block />
              </>
            )}
          </>
        ) : (
          <>
            {phase === "invalid" ? (
              <Alert color="warning" icon="link-2-off" role="alert" title="The link is invalid or has expired."
                description="A link works once and for 24 hours, and a newer link replaces an older one. Ask for a new link below." />
            ) : (
              <p className="text-sm">The link you opened is incomplete, or you came here directly. Enter your address and, if it is waiting for confirmation, a new link is sent.</p>
            )}
            {resent ? <CheckEmail email={email} verification={resent} /> : (
              <form className="space-y-3" aria-label="Send a new confirmation link" noValidate onSubmit={resend}>
                <Field label="Email address" htmlFor="resend-email">
                  <Input id="resend-email" name="email" value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="email" autoCapitalize="off" spellCheck={false} required />
                </Field>
                {resendError ? <Alert color="error" icon="circle-alert" title={resendError} role="alert" /> : null}
                <Button type="submit" label={resendWait.waiting ? `Wait ${resendWait.waiting} s` : "Send a new link"} block loading={resending} disabled={!!resendWait.waiting} />
              </form>
            )}
          </>
        )}
      </div>
    </AuthCard>
  );
}
