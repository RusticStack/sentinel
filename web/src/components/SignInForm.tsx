// A refusal never says whether the account exists; the password is cleared after every try.
import { useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, ApiError, setCsrfToken } from "../lib/api.ts";
import { refusal, retryAfter, useRetryWait } from "../lib/act.tsx";
import { loadSession } from "../lib/session.ts";
import { Alert, Button, Field, Input, TextLink } from "./ui.tsx";

export function SignInForm({ onSignedIn, notice }: { onSignedIn?: () => void; notice?: (error: string) => ReactNode }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const passwordInput = useRef<HTMLInputElement>(null);
  const { waiting, start: wait } = useRetryWait();

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy || waiting) return;
    setBusy(true);
    setError("");
    try {
      const me = await api<{ csrf: string }>("/api/v1/login", { method: "POST", body: { username: username.trim(), password } });
      setCsrfToken(me.csrf);
      setPassword("");
      await loadSession(true);
      onSignedIn?.();
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "rate_limited") wait(err);
      setError(err.code === "unauthenticated"
        ? "Sign-in refused. Check the email address or username and the password. An email address signs in only once it is verified; after repeated failures sign-in pauses for a while."
        : err.code === "rate_limited" ? `Too many sign-in attempts. Try again in ${retryAfter(err)}.`
          : err.code === "forbidden" ? "Sign-in was refused for this address. Open Sentinel at the address it is configured with."
            : refusal(err));
      setPassword("");
      setTimeout(() => passwordInput.current?.focus(), 0);
    } finally {
      setBusy(false);
    }
  }

  // The password lives only in this component's state, which goes with it when it unmounts.
  return (
    <form className="space-y-4" aria-label="Sign in" onSubmit={submit}>
      {notice?.(error)}
      <Field label="Email or username" htmlFor="username">
        <Input id="username" name="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="off" spellCheck={false} required autoFocus />
      </Field>
      <Field label="Password" htmlFor="password" hint={<TextLink to="/forgot-password" className="text-xs">Forgot your password?</TextLink>}>
        <Input id="password" name="password" ref={passwordInput} value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="current-password" required />
      </Field>
      {error ? <Alert color="error" icon="circle-alert" title={error} role="alert" /> : null}
      <Button type="submit" label={waiting ? `Wait ${waiting} s` : "Sign in"} block loading={busy} disabled={!!waiting} />
    </form>
  );
}
