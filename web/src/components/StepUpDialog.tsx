// "Confirm it's you" (docs/web-ui.md, Step-up): the proof is cleared from the field after every try.
import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "../lib/api.ts";
import { refusal, retryAfter, useRetryWait } from "../lib/act.tsx";
import { Alert, Button, ButtonLink, DialogModal, Field, Input } from "./ui.tsx";

type Method = "totp" | "recovery" | "password";
const FIELDS = {
  totp: { label: "Code from the app", type: "text", autoComplete: "one-time-code", inputMode: "numeric" as const, maxLength: 7, hint: "6 digits" },
  recovery: { label: "Recovery code", type: "text", autoComplete: "off", inputMode: "text" as const, maxLength: 64, hint: undefined },
  password: { label: "Your password", type: "password", autoComplete: "current-password", inputMode: "text" as const, maxLength: 1024, hint: undefined },
};

export function StepUpDialog({ mfa, password, onClose }: { mfa: boolean; password: boolean; onClose: (confirmed: boolean) => void }) {
  const [method, setMethod] = useState<Method>(mfa ? "totp" : "password");
  const impossible = !mfa && !password;
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const { waiting, start: wait } = useRetryWait();
  const input = useRef<HTMLInputElement>(null);
  const field = FIELDS[method];

  useEffect(() => { setCode(""); setError(""); input.current?.focus(); }, [method]);
  useEffect(() => () => setCode(""), []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy || waiting) return;
    // The controller tolerates retyped recovery codes, so only their ends are trimmed.
    const proof = method === "totp" ? code.replace(/\s+/g, "") : method === "recovery" ? code.trim() : code;
    setCode("");
    if (!proof) { setError(method === "password" ? "Enter your password." : "Enter a code."); return; }
    setBusy(true);
    setError("");
    try {
      await api("/api/v1/step-up", { method: "POST", body: { method, code: proof } });
      onClose(true);
    } catch (err) {
      const x = err as ApiError;
      if (x.code === "unauthenticated") { onClose(false); return; }
      if (x.code === "rate_limited") { wait(x); setError(`Too many attempts. Try again in ${retryAfter(x)}.`); }
      else if (x.code === "forbidden" && x.details?.step_up) {
        setError(method === "totp" ? "That code was not accepted. Wait for the next one and check the device's clock."
          : method === "recovery" ? "That recovery code was not accepted, or it was already used." : "That password was not accepted.");
      } else setError(refusal(x));
      setTimeout(() => input.current?.focus(), 0);
    } finally {
      setBusy(false);
    }
  }

  return (
    <DialogModal isOpen onClose={() => onClose(false)} title="Confirm it's you"
      description={impossible ? "This change needs a second factor." : "This change needs a recent second factor. It stays confirmed for a few minutes."}
      footer={<>
        <Button color="neutral" variant="ghost" label="Cancel" onClick={() => onClose(false)} />
        {!impossible ? <Button type="submit" form="step-up" label={waiting ? `Wait ${waiting} s` : "Confirm"} loading={busy} disabled={!!waiting} /> : null}
      </>}>
      {impossible ? (
        <div className="space-y-3 text-sm">
          <p>Your account signs in with GitHub and has no password, so it proves it is you with an authenticator app. Set one up first, then try again.</p>
          <ButtonLink to="/account" icon="shield-check" label="Set up an authenticator" onClick={() => onClose(false)} />
        </div>
      ) : (
        <form id="step-up" className="space-y-4" noValidate onSubmit={submit}>
          {mfa ? (
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium text-strong">Confirm with</legend>
              {([["totp", "Authenticator app", "The six-digit code it shows now"], ["recovery", "Recovery code", "One of the codes saved at enrollment; each works once"]] as const).map(([v, l, d]) => (
                <label key={v} className="flex items-start gap-2 text-sm">
                  <input type="radio" name="stepup-method" value={v} checked={method === v} onChange={() => setMethod(v)} className="mt-1 accent-[var(--s-primary)]" />
                  <span><span className="font-medium text-strong">{l}</span><span className="block text-muted">{d}</span></span>
                </label>
              ))}
            </fieldset>
          ) : null}
          <Field label={field.label} htmlFor="stepup-code" hint={field.hint}>
            <Input id="stepup-code" ref={input} value={code} onChange={(e) => setCode(e.target.value)} type={field.type} autoComplete={field.autoComplete}
              inputMode={field.inputMode} maxLength={field.maxLength} autoCapitalize="off" spellCheck={false} required autoFocus aria-invalid={!!error || undefined} />
          </Field>
          {error ? <Alert color="error" title={error} role="alert" /> : null}
          <p className="text-xs text-muted">
            Wrong attempts are counted: five in a row end this session{mfa ? ", and ten wrong codes lock the authenticator for 15 minutes" : ""}.
          </p>
        </form>
      )}
    </DialogModal>
  );
}
