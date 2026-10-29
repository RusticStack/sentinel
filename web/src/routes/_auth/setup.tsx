// Gated by the one-time setup token, so the first visitor to reach the port gets nothing.
// Answers are kept in session storage; the setup token and passwords stay in memory and are asked again on resume.
// Everything is sent in one request; the controller creates it all in one commit.
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { api, ApiError, setCsrfToken } from "../../lib/api.ts";
import { refusal, retryAfter, useRetryWait } from "../../lib/act.tsx";
import {
  baseUrlProblem, DRAFT_KEY, emptyDraft, isSetupToken, looksLikeEmail, parseDraft, passwordAdvice, serializeDraft, slugProblem,
  type RegistrationChoice, type TenantCreationChoice, type WizardDraft,
} from "../../lib/onboarding.ts";
import { loadSession, useSession } from "../../lib/session.ts";
import { markSetupClosed } from "../../lib/setup.ts";
import { PasswordAdvice } from "../../components/PasswordAdvice.tsx";
import { TotpEnroll } from "../../components/TotpEnroll.tsx";
import { Alert, Button, ButtonLink, cx, Field, Icon, Input, TextLink } from "../../components/ui.tsx";
import { AuthCard } from "./-card.tsx";

export const Route = createFileRoute("/_auth/setup")({
  head: () => ({ meta: [{ title: "Set up Sentinel" }] }),
  component: Setup,
});

const STEPS = ["Setup token", "Administrator", "Who can join", "Instance", "Email", "Namespaces", "Review"] as const;
const LAST_DRAFT_STEP = STEPS.length - 1;
const SECURE = STEPS.length;
const DONE = STEPS.length + 1;

const REGISTRATIONS: { value: RegistrationChoice; label: string; description: string }[] = [
  { value: "invite-only", label: "By invitation only", description: "Nobody can sign up on their own. You (or an organization's administrators) invite people by email; an invitation is their approval. Recommended." },
  { value: "approval-required", label: "Anyone may ask; you approve", description: "Anyone who reaches this instance can sign up, and their account waits until a platform administrator approves it." },
  { value: "closed", label: "Closed", description: "No new accounts at all, invited or not. Good while you finish preparing; you can open it later." },
];
const CREATIONS: { value: TenantCreationChoice; label: string; description: string }[] = [
  { value: "super-admin-only", label: "Only platform administrators", description: "You create organizations and add people to them." },
  { value: "approved-users", label: "Any approved account", description: "Every admitted person may create up to 10 organizations of their own and administer them." },
];

const MAIL_LINES = [
  "SENTINEL_RESEND_API_KEY_FILE=/etc/sentinel/resend-key",
  "SENTINEL_EMAIL_FROM=Sentinel <sentinel@example.com>",
] as const;
const lineName = (line: string) => line.slice(0, line.indexOf("="));

const FAILURE_WORDS: Record<string, string> = {
  not_configured: "The controller has no Resend key and sender yet, so nothing was sent",
  invalid_settings: "That address cannot receive a test message; check it and try again",
  transient: "Resend could not be reached or asked to wait; try again in a moment",
  permanent: "Resend refused the message; check the key and that the sender's domain is verified in Resend",
};

const ORIGIN_REFUSED = "The controller refused this page's address. Open Sentinel at the address the controller is configured with (its public_url), or set public_url to the address you are using and restart the controller.";

type MailResult = { kind: "sent" } | { kind: "failed"; failure: string; reason: string } | { kind: "error"; message: string };

function loadDraft(): string | null {
  try { return sessionStorage.getItem(DRAFT_KEY); } catch { return null; }
}
function forgetDraft() {
  try { sessionStorage.removeItem(DRAFT_KEY); } catch { /* ignore */ }
}

/** Native radios as cards: one fieldset and legend per choice. */
function Choices<T extends string>({ name, legend, items, value, onChange }: { name: string; legend: string; items: { value: T; label: string; description: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <fieldset className="space-y-2">
      <legend className="mb-2 text-sm font-medium text-strong">{legend}</legend>
      {items.map((item) => (
        <label key={item.value} htmlFor={`${name}-${item.value}`}
          className="flex cursor-pointer items-start gap-3 rounded-md border border-line p-3 text-sm has-checked:border-primary has-checked:bg-primary/5">
          <input id={`${name}-${item.value}`} type="radio" name={name} value={item.value} checked={value === item.value} onChange={() => onChange(item.value)}
            className="mt-1 accent-[var(--s-primary)]" />
          <span><span className="font-medium text-strong">{item.label}</span><span className="block text-muted">{item.description}</span></span>
        </label>
      ))}
    </fieldset>
  );
}

function Setup() {
  const session = useSession();
  const [draft, setDraft] = useState<WizardDraft>(emptyDraft);
  const [step, setStep] = useState(0);
  const [resumeAt, setResumeAt] = useState(0);
  const [resumed, setResumed] = useState(false);
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [mailTo, setMailTo] = useState("");
  const [completed, setCompleted] = useState<{ organization: string | null; personal: string | null } | null>(null);
  const [stepError, setStepError] = useState("");
  const [gone, setGone] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  // Persistence starts with the person's first change, so restoring a draft cannot save step 0 over it.
  const dirty = useRef(false);
  const done = useRef(false);

  useEffect(() => {
    const stored = parseDraft(loadDraft(), LAST_DRAFT_STEP);
    if (!stored.baseUrl) stored.baseUrl = location.origin;
    setDraft(stored);
    if (stored.step > 0) {
      setResumeAt(stored.step);
      setResumed(true);
    }
    setStep(0);
  }, []);

  useEffect(() => {
    if (!dirty.current || done.current) return;
    try { sessionStorage.setItem(DRAFT_KEY, serializeDraft({ ...draft, step: Math.min(step, LAST_DRAFT_STEP) })); } catch { /* storage off: no resume */ }
  }, [draft, step]);

  // Each step's heading takes focus as it opens (not on the first render: the token field has it then).
  const opened = useRef(false);
  useEffect(() => {
    if (!opened.current) { opened.current = true; return; }
    heading.current?.focus();
  }, [step, gone]);

  const edit = <K extends keyof WizardDraft>(key: K, value: WizardDraft[K]) => {
    dirty.current = true;
    setDraft((d) => ({ ...d, [key]: value }));
  };
  const moveTo = (at: number) => {
    dirty.current = true;
    setStep(at);
  };

  function problem(at: number): string | null {
    switch (at) {
      case 0:
        return isSetupToken(token) ? null : "The setup token is 64 characters of 0–9 and a–f. Copy it whole from the file or the log line.";
      case 1: {
        if (!looksLikeEmail(draft.email)) return "Enter the administrator's email address, such as you@example.com.";
        const advice = passwordAdvice(password);
        if (!advice.acceptable) return advice.hints[0] ?? "Choose a longer password.";
        if (password !== again) return "The password and its repetition differ.";
        if (draft.displayName.length > 128) return "Use at most 128 characters for the name.";
        return null;
      }
      case 3:
        if (!draft.instanceName.trim()) return "Give the instance a name.";
        if (draft.instanceName.trim().length > 64) return "Use at most 64 characters for the instance name.";
        return baseUrlProblem(draft.baseUrl);
      case 5: {
        for (const [label, value] of [["Personal namespace", draft.personalNamespace], ["Organization", draft.organization]] as const) {
          const p = value ? slugProblem(value) : null;
          if (p) return `${label}: ${p}`;
        }
        if (draft.personalNamespace && draft.personalNamespace === draft.organization) return "The personal namespace and the organization need different names.";
        return null;
      }
      default:
        return null;
    }
  }

  function next() {
    const p = problem(step);
    setStepError(p ?? "");
    if (p) return;
    const target = step + 1;
    if (resumeAt > target) {
      if (step === 0 && !password) { moveTo(1); return; }
      moveTo(resumeAt);
      setResumeAt(0);
      return;
    }
    moveTo(target);
  }
  function back() {
    setStepError("");
    if (step > 0) moveTo(step - 1);
  }
  function goTo(at: number) {
    setStepError("");
    setResumeAt(0);
    moveTo(!isSetupToken(token) ? 0 : at > 1 && !password ? 1 : at);
  }

  const regLabel = REGISTRATIONS.find((r) => r.value === draft.registration)?.label ?? draft.registration;
  const creationLabel = CREATIONS.find((c) => c.value === draft.tenantCreation)?.label ?? draft.tenantCreation;

  // --- email ---
  const [mailConfigured, setMailConfigured] = useState<boolean | null>(null);
  const [copyStatus, setCopyStatus] = useState("");
  const [mailResult, setMailResult] = useState<MailResult | null>(null);
  const [testing, setTesting] = useState(false);
  const mailWait = useRetryWait();

  // Whether the controller delivers mail is read each time the step opens.
  useEffect(() => {
    if (step !== 4) return;
    setMailTo((to) => to || draft.email);
    let live = true;
    api<{ open: boolean; mail_configured?: boolean }>("/api/v1/setup").then((status) => {
      if (!live) return;
      if (status.open === false) setupGone();
      else setMailConfigured(status.mail_configured === true);
    }, () => { /* unknown: the test form stays offered */ });
    return () => { live = false; };
  }, [step]);

  async function copyLine(line: string) {
    try {
      await navigator.clipboard.writeText(line);
      setCopyStatus(`Copied the ${lineName(line)} line to the clipboard.`);
    } catch {
      setCopyStatus("The browser refused the clipboard; select the line and copy it instead.");
    }
  }

  async function testMail() {
    if (testing || mailWait.waiting) return;
    setMailResult(null);
    const to = (mailTo || draft.email).trim();
    if (!looksLikeEmail(to)) {
      setMailResult({ kind: "error", message: "Enter the address the test message should go to, such as you@example.com." });
      return;
    }
    setTesting(true);
    try {
      const answer = await api<{ sent: boolean; failure?: string; reason?: string }>("/api/v1/setup/mail-test", { method: "POST", body: { token: token.trim(), to } });
      if (answer.sent) {
        setMailResult({ kind: "sent" });
        setMailConfigured(true);
      } else {
        const failure = answer.failure ?? "transient";
        if (failure === "not_configured") setMailConfigured(false);
        setMailResult({ kind: "failed", failure, reason: answer.reason ?? "" });
      }
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "forbidden" && err.message === "setup token refused") {
        tokenRefused();
        return;
      }
      if (err.code === "not_found") return setupGone();
      if (err.code === "rate_limited") mailWait.start(err);
      setMailResult({ kind: "error", message: err.code === "rate_limited" ? `Another test is running or too many were sent. Try again in ${retryAfter(err)}.` : err.code === "forbidden" ? ORIGIN_REFUSED : refusal(err) });
    } finally {
      setTesting(false);
    }
  }

  const emailSummary = mailResult?.kind === "sent" ? "Configured; test message sent"
    : mailConfigured === false ? "Not configured; links are printed by sentinel admin"
      : mailConfigured ? "Configured; not tested"
        : "Not tested (optional)";

  // --- finishing ---
  const [finishing, setFinishing] = useState(false);
  const [finishError, setFinishError] = useState("");
  const finishWait = useRetryWait();

  function tokenRefused() {
    setToken("");
    moveTo(0);
    setStepError("The setup token was not accepted. It may be mistyped, older than an hour, replaced by a restart, or locked for five minutes after repeated wrong tries. Read the current one on the host.");
  }
  function setupGone() {
    done.current = true;
    setGone(true);
    forgetDraft();
    markSetupClosed();
  }

  async function finish() {
    if (finishing || finishWait.waiting) return;
    for (const at of [0, 1, 3, 5]) {
      const p = problem(at);
      if (p) { goTo(at); setStepError(p); return; }
    }
    setFinishing(true);
    setFinishError("");
    const body: Record<string, unknown> = {
      token: token.trim(),
      email: draft.email.trim(),
      password,
      registration: draft.registration,
      tenant_creation: draft.tenantCreation,
      instance_name: draft.instanceName.trim(),
    };
    if (draft.displayName.trim()) body.display_name = draft.displayName.trim();
    if (draft.baseUrl.trim()) body.base_url = draft.baseUrl.trim().replace(/\/+$/, "");
    if (draft.personalNamespace) body.personal_namespace = draft.personalNamespace;
    if (draft.organization) body.organization = draft.organization;
    try {
      const created = await api<{ csrf: string; organization: string | null; personal_namespace: string | null }>("/api/v1/setup", { method: "POST", body });
      setCsrfToken(created.csrf);
      done.current = true;
      setToken("");
      setAgain("");
      setCompleted({ organization: created.organization ?? null, personal: created.personal_namespace ?? null });
      forgetDraft();
      markSetupClosed();
      await loadSession(true);
      setStep(SECURE);
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "forbidden" && err.message === "setup token refused") tokenRefused();
      else if (err.code === "forbidden") setFinishError(ORIGIN_REFUSED);
      else if (err.code === "not_found") setupGone();
      else if (err.code === "conflict") setFinishError("That address or one of the names is already taken. Change the administrator's address or the namespace names and try again.");
      else if (err.code === "invalid_request") setFinishError(`The controller refused a field (${err.message}). Check the answers above.`);
      else if (err.code === "rate_limited") {
        finishWait.start(err);
        setFinishError(`Too many attempts. Try again in ${retryAfter(err)}.`);
      } else setFinishError(refusal(err));
    } finally {
      body.password = undefined;
      setFinishing(false);
    }
  }

  // The password typed in step 2 is sent once more, to set up the authenticator, and then dropped.
  function leaveSecure() {
    setPassword("");
    setStep(DONE);
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (step === LAST_DRAFT_STEP) void finish();
    else next();
  }

  const title = gone ? "Setup is already complete" : step === SECURE ? "Protect your account" : step === DONE ? "Sentinel is ready" : STEPS[step] ?? "Set up Sentinel";
  const firstNamespace = completed?.organization ?? completed?.personal ?? null;

  const header = (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Icon name="radar" className="size-6 text-primary" />
        <span className="text-sm font-medium text-muted">Set up Sentinel</span>
      </div>
      {step <= LAST_DRAFT_STEP && !gone ? (
        <nav aria-label="Setup steps">
          <ol className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
            {STEPS.map((name, i) => (
              <li key={name} aria-current={i === step ? "step" : undefined}
                className={cx("flex items-center gap-1", i === step ? "font-semibold text-strong" : i < step ? "text-fg" : "text-muted")}>
                <Icon name={i < step ? "circle-check" : "circle"} className={cx("size-3.5", i < step && "text-success")} />
                <span>{i + 1}. {name}</span>
              </li>
            ))}
          </ol>
        </nav>
      ) : null}
      <h1 ref={heading} tabIndex={-1} className="text-lg font-semibold text-strong focus:outline-none">{title}</h1>
    </div>
  );

  let content: ReactNode;
  if (gone) {
    content = (
      <>
        <p className="text-sm">Someone finished setting up this instance (from another browser or on the host) before this wizard did. Nothing from this wizard was saved.</p>
        <ButtonLink to="/login" label="Go to sign-in" block />
      </>
    );
  } else if (step <= LAST_DRAFT_STEP) {
    const reviewRows = [
      { at: 1, label: "Administrator", value: draft.displayName ? `${draft.displayName} <${draft.email}>` : draft.email },
      { at: 2, label: "Who can create an account", value: regLabel },
      { at: 2, label: "Who can create organizations", value: creationLabel },
      { at: 3, label: "Instance", value: draft.baseUrl ? `${draft.instanceName} — ${draft.baseUrl}` : draft.instanceName },
      { at: 4, label: "Email", value: emailSummary },
      { at: 5, label: "Personal namespace", value: draft.personalNamespace || "None" },
      { at: 5, label: "First organization", value: draft.organization || "None" },
    ];
    content = (
      <form className="space-y-5" noValidate aria-label={STEPS[step]} onSubmit={submit}>
        {step === 0 ? (
          <>
            {resumed ? <Alert color="info" icon="history" role="status" title="Picking up where you left off."
              description="Your answers were kept in this tab. For safety the setup token and passwords were not: enter them again." /> : null}
            <p className="text-sm">This proves you run the server. When the controller starts without an administrator, it writes a one-time setup token to a file only its service user can read and prints it once in its log:</p>
            <ul className="list-disc space-y-1 ps-5 text-sm">
              <li>the file <code>setup-token</code> in the controller's data directory, or</li>
              <li>the <code>setup_required</code> line in the controller's log.</li>
            </ul>
            <p className="text-sm text-muted">It works for one hour; restarting the controller makes a new one. Five wrong tries lock setup for five minutes.</p>
            <Field label="Setup token" htmlFor="setup-token" required>
              <Input id="setup-token" name="setup-token" value={token} onChange={(e) => setToken(e.target.value)} type="password" autoComplete="off" autoCapitalize="off" spellCheck={false}
                maxLength={80} required autoFocus className="font-mono" />
            </Field>
          </>
        ) : step === 1 ? (
          <>
            <p className="text-sm">This account administers the whole instance. Its address is trusted as confirmed, so it can sign in right away.</p>
            <Field label="Email address" htmlFor="admin-email" required>
              <Input id="admin-email" name="email" value={draft.email} onChange={(e) => edit("email", e.target.value)} type="email" autoComplete="email" autoCapitalize="off" spellCheck={false} required autoFocus />
            </Field>
            <Field label="Your name" htmlFor="admin-name" hint="Optional">
              <Input id="admin-name" name="display_name" value={draft.displayName} onChange={(e) => edit("displayName", e.target.value)} autoComplete="name" maxLength={128} />
            </Field>
            <input type="text" name="username" autoComplete="username" value={draft.email} className="sr" tabIndex={-1} aria-hidden="true" readOnly />
            <Field label="Password" htmlFor="admin-password" required>
              <Input id="admin-password" name="password" value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="new-password" minLength={12} maxLength={256}
                required aria-describedby="admin-advice" />
            </Field>
            <PasswordAdvice id="admin-advice" password={password} context={[draft.email, draft.displayName, draft.instanceName]} />
            <Field label="Password again" htmlFor="admin-again" required>
              <Input id="admin-again" name="again" value={again} onChange={(e) => setAgain(e.target.value)} type="password" autoComplete="new-password" required />
            </Field>
          </>
        ) : step === 2 ? (
          <>
            <Choices name="registration" legend="Who can create an account" items={REGISTRATIONS} value={draft.registration} onChange={(v) => edit("registration", v)} />
            <Choices name="tenant-creation" legend="Who can create organizations" items={CREATIONS} value={draft.tenantCreation} onChange={(v) => edit("tenantCreation", v)} />
            <p className="text-xs text-muted">Both can be changed later under Platform → Policy. Whatever you choose, people only ever see the organizations they belong to.</p>
          </>
        ) : step === 3 ? (
          <>
            <Field label="Instance name" htmlFor="instance-name" required hint="Up to 64 characters">
              <Input id="instance-name" name="instance_name" value={draft.instanceName} onChange={(e) => edit("instanceName", e.target.value)} maxLength={64} required autoFocus />
            </Field>
            <Field label="Address people use" htmlFor="instance-url" hint="Optional" help="The address of this web interface, as people type it.">
              <Input id="instance-url" name="base_url" value={draft.baseUrl} onChange={(e) => edit("baseUrl", e.target.value)} type="url" inputMode="url" autoCapitalize="off" spellCheck={false}
                maxLength={255} placeholder="https://ci.example.com" />
            </Field>
            <p className="text-xs text-muted">Links in emails and GitHub keep using the controller's configured <code>public_url</code>; keep the two the same.</p>
          </>
        ) : step === 4 ? (
          <>
            <p className="text-sm">Optional. Sentinel can email confirmation links and invitations through Resend. Without it, nobody is locked out: you hand links over yourself.</p>
            {mailConfigured === false ? (
              <>
                <Alert color="info" icon="mail-x" title="Email is not configured on the controller."
                  description="Nothing is sent until the controller has a Resend API key and a sender. Until then, verification and invitation links are printed by sentinel admin on the host." />
                <p className="text-sm">To turn email on, put the Resend API key in the file <code>/etc/sentinel/resend-key</code>, readable only by the controller's service user (owner-only), add these two lines to the controller's environment and restart it. The key never goes in a variable or in this page.</p>
                <ul className="space-y-2" aria-label="Environment lines for the controller">
                  {MAIL_LINES.map((line) => (
                    <li key={line} className="flex items-center gap-2">
                      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded bg-elevated px-2 py-1.5 text-xs text-strong">{line}</code>
                      <Button size="xs" color="neutral" variant="outline" icon="copy" aria-label={`Copy the ${lineName(line)} line`} onClick={() => { void copyLine(line); }} />
                    </li>
                  ))}
                </ul>
                <p className="text-xs text-muted" role="status">{copyStatus}</p>
                <p className="text-xs text-muted">Use a sender on a domain verified in Resend. Restarting the controller makes a new setup token.</p>
              </>
            ) : (
              <>
                {mailConfigured ? <p className="text-sm">The controller has a Resend key and sender. Send a test message to check that they work.</p> : null}
                <div className="flex flex-wrap items-end gap-3">
                  <Field label="Send test to" htmlFor="mail-to" className="w-64 max-w-full">
                    <Input id="mail-to" name="mail-to" value={mailTo} onChange={(e) => setMailTo(e.target.value)} type="email" placeholder={draft.email || "you@example.com"} autoCapitalize="off" spellCheck={false} />
                  </Field>
                  <Button color="neutral" variant="outline" icon="send" label={mailWait.waiting ? `Wait ${mailWait.waiting} s` : "Send test message"} loading={testing} disabled={!!mailWait.waiting}
                    onClick={() => { void testMail(); }} />
                </div>
              </>
            )}
            <div aria-live="polite">
              {mailResult?.kind === "sent" ? <Alert color="success" icon="mail-check" title="Test message sent." description="Check that it arrived (and not in spam)." />
                : mailResult?.kind === "failed" ? <Alert color="warning" icon="mail-warning" title={`${FAILURE_WORDS[mailResult.failure] ?? "The test failed"}.`}
                  description={mailResult.reason ? `${mailResult.failure === "transient" || mailResult.failure === "permanent" ? "Resend said" : "The controller said"}: ${mailResult.reason}` : undefined} />
                  : mailResult?.kind === "error" ? <Alert color="error" icon="circle-alert" title={mailResult.message} />
                    : null}
            </div>
            <p className="text-xs text-muted">A failed test does not stop setup: you can finish now and configure email later.</p>
          </>
        ) : step === 5 ? (
          <>
            <p className="text-sm">Optional. Names are 2 to 63 lowercase letters, digits and hyphens, and are part of addresses (<code>/t/name</code>).</p>
            <Field label="Your personal namespace" htmlFor="ns-personal" hint="Optional" help="A space only you belong to." className="w-full sm:w-80">
              <Input id="ns-personal" name="personal" value={draft.personalNamespace} onChange={(e) => edit("personalNamespace", e.target.value)} autoComplete="off" autoCapitalize="off" spellCheck={false}
                maxLength={63} placeholder="your-name" />
            </Field>
            <Field label="First organization" htmlFor="ns-org" hint="Optional" help="You administer it and can invite people to it by email." className="w-full sm:w-80">
              <Input id="ns-org" name="organization" value={draft.organization} onChange={(e) => edit("organization", e.target.value)} autoComplete="off" autoCapitalize="off" spellCheck={false}
                maxLength={63} placeholder="my-team" />
            </Field>
          </>
        ) : (
          <>
            <p className="text-sm">Nothing is created until you finish. Then everything below is created at once.</p>
            <dl className="divide-y divide-line rounded-lg border border-line text-sm">
              {reviewRows.map((row) => (
                <div key={row.label} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                  <dt className="text-muted">{row.label}</dt>
                  <dd className="flex min-w-0 items-center gap-2"><span className="break-all text-strong">{row.value}</span>
                    <Button size="xs" color="neutral" variant="link" label="Change" aria-label={`Change ${row.label.toLowerCase()}`} onClick={() => goTo(row.at)} />
                  </dd>
                </div>
              ))}
            </dl>
            {finishError ? <Alert color="error" icon="circle-alert" title={finishError} role="alert" /> : null}
          </>
        )}

        {stepError ? <Alert color="error" icon="circle-alert" title={stepError} role="alert" /> : null}

        <div className="flex flex-wrap justify-between gap-2 pt-1">
          {step > 0 ? <Button color="neutral" variant="ghost" icon="arrow-left" label="Back" onClick={back} /> : <span />}
          {step < LAST_DRAFT_STEP
            ? <Button type="submit" trailingIcon="arrow-right" label={step === 4 || step === 5 ? "Next (optional step)" : "Next"} />
            : <Button type="submit" icon="check" label={finishWait.waiting ? `Wait ${finishWait.waiting} s` : "Finish setup"} loading={finishing} disabled={!!finishWait.waiting} />}
        </div>
      </form>
    );
  } else if (step === SECURE) {
    content = (
      <>
        <Alert color="success" icon="circle-check" role="status" title="Setup is complete and you are signed in." />
        <TotpEnroll hasPassword password={password} username={draft.email} onDone={leaveSecure}
          intro={<p className="text-sm">Your account can change everything on this instance. An authenticator app adds a code that changes every 30 seconds, asked for before sensitive changes, so a stolen session or password alone is not enough. Recommended; you can also do it later from Account security.</p>}
          actions={<Button color="neutral" variant="ghost" label="Skip for now" onClick={leaveSecure} />} />
      </>
    );
  } else {
    const nextStep = (icon: string, tone: string, children: ReactNode) => (
      <li className="flex items-start gap-2"><Icon name={icon} className={cx("mt-0.5 shrink-0", tone)} /><span>{children}</span></li>
    );
    content = (
      <>
        <p className="text-sm">Here is what to do next:</p>
        <ul className="space-y-2 text-sm">
          {completed?.organization
            ? nextStep("mail-plus", "text-primary", <><TextLink to={`/t/${completed.organization}/admin/invitations`} className="font-medium">Invite people to {completed.organization}</TextLink> by email.</>)
            : nextStep("building-2", "text-primary", <><TextLink to="/organizations" className="font-medium">Create an organization</TextLink> and invite people to it.</>)}
          {nextStep("server", "text-primary", <>Connect a worker and set up worker pools under <TextLink to="/platform/pools" className="font-medium">Platform → Pools</TextLink>.</>)}
          {nextStep("scale", "text-primary", <>Review who can join under <TextLink to="/platform/policy" className="font-medium">Platform → Policy</TextLink>.</>)}
          {!session.me?.mfa ? nextStep("shield-check", "text-warning", <>Set up an authenticator under <TextLink to="/account" className="font-medium">Account security</TextLink>.</>) : null}
        </ul>
        <ButtonLink to={firstNamespace ? `/t/${firstNamespace}` : "/"} label="Open Sentinel" block />
      </>
    );
  }

  return (
    <AuthCard className="max-w-2xl" header={header} bodyClassName="space-y-5">
      {content}
    </AuthCard>
  );
}
