// Every outcome reads the same whether the address is new or already has an account.
import { useRef, useState, type FormEvent } from "react";
import { api, ApiError } from "../lib/api.ts";
import { refusal, retryAfter, useRetryWait } from "../lib/act.tsx";
import { looksLikeEmail, passwordAdvice } from "../lib/onboarding.ts";
import { PasswordAdvice } from "./PasswordAdvice.tsx";
import { Alert, Button, Field, Input } from "./ui.tsx";

export interface SignUpResult { email: string; verification: "email" | "operator" }

export function SignUpForm({ invitation, onAccepted }: { invitation?: string | null; onAccepted: (result: SignUpResult) => void }) {
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState("");
  const [policy, setPolicy] = useState<"closed" | "invitation" | "unusable" | null>(null);
  const [busy, setBusy] = useState(false);
  const { waiting, start: wait } = useRetryWait();
  const emailInput = useRef<HTMLInputElement>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy || waiting) return;
    setError("");
    setPolicy(null);
    if (!looksLikeEmail(email)) {
      setError("Enter an email address such as name@example.com.");
      setTimeout(() => emailInput.current?.focus(), 0);
      return;
    }
    const advice = passwordAdvice(password);
    if (!advice.acceptable) {
      setError(advice.hints[0] ?? "Choose a longer password.");
      return;
    }
    if (password !== again) {
      setError("The password and its repetition differ.");
      return;
    }
    setBusy(true);
    const body: Record<string, string> = { email: email.trim(), password };
    if (displayName.trim()) body.display_name = displayName.trim();
    if (invitation) body.invitation = invitation;
    setPassword("");
    setAgain("");
    try {
      const done = await api<{ status: string; verification: "email" | "operator" }>("/api/v1/register", { method: "POST", body });
      onAccepted({ email: body.email!, verification: done.verification });
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "rate_limited") {
        wait(err);
        setError(`Too many sign-up attempts from here. Try again in ${retryAfter(err)}.`);
      } else if (err.code === "forbidden" && err.message.includes("closed")) {
        setPolicy("closed");
      } else if (err.code === "forbidden" && err.message.includes("needs an invitation")) {
        setPolicy("invitation");
      } else if (err.code === "forbidden" && err.message.includes("invitation")) {
        setPolicy("unusable");
      } else if (err.code === "forbidden") {
        setError("Sign-up was refused for this address. Open Sentinel at the address it is configured with.");
      } else if (err.code === "invalid_request") {
        setError("Check the email address and the password (12 to 256 characters).");
      } else {
        setError(refusal(err));
      }
    } finally {
      body.password = "";
      setBusy(false);
    }
  }

  return (
    <form className="space-y-4" aria-label="Create an account" noValidate onSubmit={submit}>
      <Field label="Email address" htmlFor="su-email" required>
        <Input id="su-email" name="email" ref={emailInput} value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="email" autoCapitalize="off" spellCheck={false} required autoFocus />
      </Field>
      <Field label="Your name" htmlFor="su-name" hint="Optional">
        <Input id="su-name" name="display_name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" maxLength={128} />
      </Field>
      {/* For password managers: the new password belongs to this address. */}
      <input type="text" name="username" autoComplete="username" value={email} className="sr" tabIndex={-1} aria-hidden="true" readOnly />
      <Field label="Password" htmlFor="su-password" required>
        <Input id="su-password" name="password" value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="new-password" minLength={12} maxLength={256} required aria-describedby="su-advice" />
      </Field>
      <PasswordAdvice id="su-advice" password={password} context={[email, displayName]} />
      <Field label="Password again" htmlFor="su-again" required>
        <Input id="su-again" name="again" value={again} onChange={(e) => setAgain(e.target.value)} type="password" autoComplete="new-password" required />
      </Field>
      {error ? <Alert color="error" icon="circle-alert" title={error} role="alert" />
        : policy === "closed" ? <Alert color="warning" icon="lock" role="alert" title="Sign-up is closed on this instance."
          description="The administrator is not accepting new accounts. If you already have one, sign in." />
          : policy === "invitation" ? <Alert color="warning" icon="mail" role="alert" title="Sign-up needs an invitation."
            description="Ask an administrator to invite you by email, then open the link in the invitation." />
            : policy === "unusable" ? <Alert color="warning" icon="mail-x" role="alert" title="This invitation cannot be used."
              description="It may have expired, been used or been withdrawn. Ask whoever invited you for a new one." />
              : null}
      <Button type="submit" label={waiting ? `Wait ${waiting} s` : "Create account"} block loading={busy} disabled={!!waiting} />
    </form>
  );
}
