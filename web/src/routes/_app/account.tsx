// Secrets (seed, codes, passwords) stay in this page's memory, are cleared once used and never reach storage or a URL.
import { useState, type FormEvent } from "react";
import { createFileRoute, useRouter } from "@tanstack/react-router";
import { api, ApiError } from "../../lib/api.ts";
import { refusal, retryAfter, StepUpDeclined, useRetryWait, withStepUp } from "../../lib/act.tsx";
import { byteLength, looksLikeEmail } from "../../lib/onboarding.ts";
import { toast } from "../../lib/overlay.tsx";
import { rememberReturn } from "../../lib/redirect.ts";
import { ended, loadSession, useSession } from "../../lib/session.ts";
import type { Security } from "../../lib/types";
import { Page } from "../../components/Page.tsx";
import { showOnce } from "../../components/ShowOnceDialog.tsx";
import { TotpEnroll } from "../../components/TotpEnroll.tsx";
import { Alert, Badge, Button, Card, cx, Field, Icon, Input } from "../../components/ui.tsx";

export const Route = createFileRoute("/_app/account")({
  loader: async () => {
    try {
      return { security: await api<Security>("/api/v1/me/security"), error: null };
    } catch (e) {
      return { security: null, error: (e as Error).message || "The request failed." };
    }
  },
  head: () => ({ meta: [{ title: "Account security · Sentinel" }] }),
  component: Account,
});

const isoDate = (ms: number) => new Date(ms).toISOString().slice(0, 10);

function Heading({ icon, children }: { icon: string; children: string }) {
  return <span className="inline-flex items-center gap-2 text-base"><Icon name={icon} />{children}</span>;
}

function Account() {
  const { security, error: loadError } = Route.useLoaderData();
  const router = useRouter();
  const { me } = useSession();
  const refresh = () => router.invalidate();
  const github = security?.identities.find((i) => i.provider === "github") ?? null;

  const [reissuing, setReissuing] = useState(false);
  async function reissue() {
    if (reissuing) return;
    setReissuing(true);
    try {
      const fresh = await withStepUp(() => api<{ recovery_codes: string[] }>("/api/v1/mfa/recovery-codes", { method: "POST", body: {} }), me);
      await showOnce({
        title: "Your new recovery codes",
        description: "The earlier codes no longer work.",
        secrets: fresh.recovery_codes,
        filename: "sentinel-recovery-codes.txt",
      });
      await refresh();
    } catch (e) {
      if (e instanceof StepUpDeclined) return;
      const err = e as ApiError;
      if (err.code === "unauthenticated") return;
      toast({ title: `Recovery codes: ${err.code === "not_found" ? "no authenticator is set up" : refusal(err)}.`, color: "error", icon: "circle-alert", duration: 8000 });
    } finally {
      setReissuing(false);
    }
  }

  const [current, setCurrent] = useState("");
  const [fresh, setFresh] = useState("");
  const [again, setAgain] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [changing, setChanging] = useState(false);
  function clearPasswords() {
    setCurrent("");
    setFresh("");
    setAgain("");
  }

  async function changePassword(e: FormEvent) {
    e.preventDefault();
    if (changing) return;
    setPasswordError("");
    const n = byteLength(fresh);
    if (n < 12 || n > 256) {
      setPasswordError("The new password must be 12 to 256 bytes long.");
      return;
    }
    if (fresh !== again) {
      setPasswordError("The new password and its repetition differ.");
      return;
    }
    setChanging(true);
    const body = { current, new: fresh };
    try {
      await withStepUp(() => api("/api/v1/password", { method: "POST", body }), me);
      clearPasswords();
      await ended("password-changed");
    } catch (x) {
      if (x instanceof StepUpDeclined) return;
      const err = x as ApiError;
      if (err.code === "unauthenticated") return clearPasswords();
      setCurrent("");
      setPasswordError(err.code === "forbidden" ? "The current password was not accepted. Five wrong attempts end this session."
        : err.code === "invalid_request" ? "The new password must be 12 to 256 bytes long."
          : err.code === "rate_limited" ? `Too many attempts. Try again in ${retryAfter(err)}.`
            : refusal(err));
    } finally {
      body.current = "";
      body.new = "";
      setChanging(false);
    }
  }

  // Every answer reads the same whether or not another account holds the address.
  const [newEmail, setNewEmail] = useState("");
  const [emailNote, setEmailNote] = useState<"sent-email" | "sent-operator" | null>(null);
  const [emailError, setEmailError] = useState("");
  const [savingEmail, setSavingEmail] = useState(false);
  const [resendingEmail, setResendingEmail] = useState(false);
  const emailWait = useRetryWait();

  async function changeEmail(e: FormEvent) {
    e.preventDefault();
    if (savingEmail || emailWait.waiting) return;
    setEmailError("");
    setEmailNote(null);
    if (!looksLikeEmail(newEmail)) {
      setEmailError("Enter an email address such as name@example.com.");
      return;
    }
    setSavingEmail(true);
    try {
      const done = await withStepUp(() => api<{ verification: "email" | "operator" }>("/api/v1/me/email", { method: "POST", body: { email: newEmail.trim() } }), me);
      setEmailNote(done.verification === "email" ? "sent-email" : "sent-operator");
      setNewEmail("");
      await loadSession(true);
    } catch (x) {
      if (x instanceof StepUpDeclined) return;
      const err = x as ApiError;
      if (err.code === "unauthenticated") return;
      if (err.code === "rate_limited") emailWait.start(err);
      setEmailError(err.code === "invalid_request" ? "Enter a plain email address, such as name@example.com." : refusal(err));
    } finally {
      setSavingEmail(false);
    }
  }

  async function resendEmail() {
    if (resendingEmail || emailWait.waiting) return;
    setResendingEmail(true);
    setEmailError("");
    try {
      const done = await api<{ verification: "email" | "operator" }>("/api/v1/me/email/resend", { method: "POST", body: {} });
      setEmailNote(done.verification === "email" ? "sent-email" : "sent-operator");
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "unauthenticated") return;
      if (err.code === "rate_limited") emailWait.start(err);
      setEmailError(err.code === "conflict" ? "No address is waiting for confirmation." : err.code === "rate_limited" ? `You asked for several links already. Try again in ${retryAfter(err)}.` : refusal(err));
    } finally {
      setResendingEmail(false);
    }
  }

  const [linking, setLinking] = useState(false);
  async function linkGitHub() {
    if (linking) return;
    setLinking(true);
    try {
      const started = await withStepUp(() => api<{ authorize_url: string }>("/api/v1/identities/github/link", { method: "POST", body: {} }), me);
      if (!/^https:\/\//.test(started.authorize_url)) throw new ApiError(0, { code: "invalid_response", message: "the controller gave an unexpected address" });
      // The controller ends the round trip on `/`, which continues back here.
      rememberReturn("/account");
      window.location.assign(started.authorize_url);
    } catch (x) {
      setLinking(false);
      if (x instanceof StepUpDeclined) return;
      const err = x as ApiError;
      if (err.code === "unauthenticated") return;
      toast({ title: `Link GitHub: ${refusal(err)}.`, color: "error", icon: "circle-alert", duration: 8000 });
    }
  }

  const remaining = security?.mfa.recovery_codes_remaining ?? 0;

  return (
    <Page id="account" title="Account security">
      <div className="max-w-3xl space-y-6">
        {me ? <p className="text-sm text-muted">Your user id is <code id="my-user-id" className="select-all font-mono text-strong">{me.user}</code>. An organization&apos;s administrator needs it to add you.</p> : null}
        {loadError || !security ? (
          <Alert color="error" icon="circle-alert" title="Could not load your account's security settings." description={loadError} role="alert">
            <Button size="sm" color="neutral" variant="outline" label="Try again" className="mt-1" onClick={() => { void refresh(); }} />
          </Alert>
        ) : (
          <>
            <Card titleId="mfa-h" title={<Heading icon="smartphone">Authenticator app</Heading>}
              actions={security.mfa.enrolled ? <Badge color="success" icon="shield-check">On</Badge> : <Badge color="neutral">Off</Badge>}>
              {security.mfa.enrolled ? (
                <div className="space-y-4">
                  <p className="text-sm">Codes from your authenticator app confirm sensitive changes: issuing service credentials, administration, your password.</p>
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-line p-3">
                    <div>
                      <h3 className="text-sm font-medium text-strong">Recovery codes</h3>
                      <p className={cx("text-sm", remaining <= 3 ? "text-warning" : "text-muted")}>
                        {remaining} of 10 left{remaining === 0 ? " — replace them now" : remaining <= 3 ? " — consider replacing them" : ""}.
                      </p>
                    </div>
                    <Button color="neutral" variant="outline" icon="refresh-cw" label="Replace recovery codes" loading={reissuing} onClick={reissue} />
                  </div>
                  <p className="text-xs text-muted">Lost the device and every code? An operator can remove the authenticator on the controller host (<code>sentinel admin mfa disable</code>); that also signs out every session.</p>
                </div>
              ) : (
                <TotpEnroll hasPassword={security.password} pending={security.mfa.pending} username={me?.username} onDone={() => { void refresh(); }} onCancel={() => { void refresh(); }} />
              )}
            </Card>

            <Card titleId="email-h" title={<Heading icon="mail">Email address</Heading>}
              actions={me?.email && me.email_verified ? <Badge color="success" icon="badge-check">Confirmed</Badge> : me?.email ? <Badge color="warning">Not confirmed</Badge> : null}>
              <div className="space-y-4 text-sm">
                {me?.email ? <p className="break-all"><span className="text-muted">Address:</span> {me.email}</p>
                  : <p className="text-muted">No email address. Adding one lets you sign in with it and accept invitations sent to it.</p>}
                {me?.email && !me.email_verified ? (
                  <div className="flex flex-wrap items-center gap-3">
                    <span>Open the link sent to this address to confirm it; until then it cannot sign in.</span>
                    <Button size="sm" color="neutral" variant="outline" icon="send" label={emailWait.waiting ? `Wait ${emailWait.waiting} s` : "Send the link again"}
                      loading={resendingEmail} disabled={!!emailWait.waiting} onClick={resendEmail} />
                  </div>
                ) : null}
                <form className="flex flex-wrap items-end gap-3" aria-label="Change your email address" noValidate onSubmit={changeEmail}>
                  <Field label={me?.email ? "New address" : "Address"} htmlFor="new-email" className="w-72 max-w-full">
                    <Input id="new-email" name="new-email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} type="email" autoComplete="email" autoCapitalize="off" spellCheck={false} />
                  </Field>
                  <Button type="submit" label={me?.email ? "Change address" : "Add address"} loading={savingEmail} disabled={!!emailWait.waiting} />
                </form>
                <p className="text-xs text-muted">A new address takes effect once you open the link sent to it; your current confirmed address keeps working until then.</p>
                <div aria-live="polite" className="space-y-2">
                  {emailNote === "sent-email" ? <Alert color="success" icon="mail-check" title="If that address can be used, a confirmation link is on its way." description="It works once, for 24 hours." />
                    : emailNote === "sent-operator" ? <Alert color="info" icon="user-cog" title="This instance does not send email." description="Ask your administrator for the confirmation link (sentinel admin account email-link)." />
                      : null}
                  {emailError ? <Alert color="error" icon="circle-alert" title={emailError} role="alert" /> : null}
                </div>
              </div>
            </Card>

            <Card titleId="password-h" title={<Heading icon="key-round">Password</Heading>}>
              {security.password ? (
                <form className="space-y-4" aria-label="Change your password" onSubmit={changePassword}>
                  <input type="text" name="username" autoComplete="username" value={me?.username ?? ""} className="sr" tabIndex={-1} aria-hidden="true" readOnly />
                  <Field label="Current password" htmlFor="pw-current" className="w-full sm:w-80">
                    <Input id="pw-current" name="current" value={current} onChange={(e) => setCurrent(e.target.value)} type="password" autoComplete="current-password" required />
                  </Field>
                  <Field label="New password" htmlFor="pw-new" hint="12 to 256 bytes" className="w-full sm:w-80">
                    <Input id="pw-new" name="new" value={fresh} onChange={(e) => setFresh(e.target.value)} type="password" autoComplete="new-password" minLength={12} required />
                  </Field>
                  <Field label="New password again" htmlFor="pw-again" className="w-full sm:w-80">
                    <Input id="pw-again" name="again" value={again} onChange={(e) => setAgain(e.target.value)} type="password" autoComplete="new-password" minLength={12} required />
                  </Field>
                  {passwordError ? <Alert color="error" icon="circle-alert" title={passwordError} role="alert" /> : null}
                  <p className="text-xs text-muted">Changing it signs out every session and app of your account, this one included{security.mfa.enrolled ? ", and asks for a code from your authenticator first" : ""}.</p>
                  <Button type="submit" label="Change password" loading={changing} />
                </form>
              ) : (
                <p className="text-sm text-muted">Your account has no local password: you sign in with GitHub.</p>
              )}
            </Card>

            <Card titleId="identities-h" title={<Heading icon="link">Linked identities</Heading>}>
              <div className="space-y-4">
                {security.identities.length ? (
                  <ul className="divide-y divide-line">
                    {security.identities.map((i) => (
                      <li key={i.provider} className="flex items-center justify-between gap-2 py-2 text-sm">
                        <span className="flex items-center gap-2 font-medium capitalize text-strong"><Icon name={i.provider === "github" ? "github" : "link"} />{i.provider}</span>
                        <span className="text-muted">linked <time dateTime={new Date(i.linked_ms).toISOString()}>{isoDate(i.linked_ms)}</time></span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-muted">No external account is linked.</p>
                )}
                {security.github_link && !github ? (
                  <div className="space-y-2">
                    <p className="text-sm">Link your GitHub account to sign in with it and to join organizations whose membership GitHub manages. You confirm it's you first, then approve on GitHub and come back here.</p>
                    <Button icon="github" color="neutral" variant="outline" label="Link a GitHub account" loading={linking} onClick={linkGitHub} />
                  </div>
                ) : null}
              </div>
            </Card>
          </>
        )}
      </div>
    </Page>
  );
}
