// The seed lives only in this component's state and is dropped on cancel, confirmation and unmount. Its QR code is
// one SVG path drawn here (lib/qr.ts): no library or service sees it.
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, ApiError } from "../lib/api.ts";
import { refusal, retryAfter, useRetryWait } from "../lib/act.tsx";
import { toast } from "../lib/overlay.tsx";
import { encodeQr, qrPath, totpSecret } from "../lib/qr.ts";
import { setSession, signOut, useSession } from "../lib/session.ts";
import { showOnce } from "./ShowOnceDialog.tsx";
import { Alert, Button, buttonClass, Field, Icon, Input } from "./ui.tsx";

export function TotpEnroll({ hasPassword, pending, username, password, intro, actions, onStarted, onDone, onCancel }: {
  hasPassword: boolean;
  pending?: boolean;
  username?: string | null;
  /** A password just typed elsewhere (the setup wizard), sent once instead of asking again. */
  password?: string | null;
  intro?: ReactNode;
  actions?: ReactNode;
  onStarted?: () => void;
  onDone?: () => void;
  onCancel?: () => void;
}) {
  const session = useSession();
  const [enrollPassword, setEnrollPassword] = useState("");
  const [enrollError, setEnrollError] = useState("");
  const [reauthenticate, setReauthenticate] = useState(false);
  const [enrolling, setEnrolling] = useState(false);
  const [uri, setUri] = useState<string | null>(null);
  const [confirmCode, setConfirmCode] = useState("");
  const [confirmError, setConfirmError] = useState("");
  const [confirming, setConfirming] = useState(false);
  const qr = useMemo(() => (uri ? encodeQr(uri) : null), [uri]);
  const qrBox = qr ? qr.size + 8 : 0;
  const secret = uri ? totpSecret(uri) : null;
  const codeInput = useRef<HTMLInputElement>(null);
  const { waiting, start: wait } = useRetryWait();

  useEffect(() => { if (uri) codeInput.current?.focus(); }, [uri]);

  async function startEnroll(e: FormEvent) {
    e.preventDefault();
    if (enrolling || waiting) return;
    setEnrolling(true);
    setEnrollError("");
    setReauthenticate(false);
    const given = password ?? enrollPassword;
    const body = hasPassword ? { password: given } : {};
    setEnrollPassword("");
    try {
      const started = await api<{ provisioning_uri: string }>("/api/v1/mfa/enroll", { method: "POST", body });
      setUri(started.provisioning_uri);
      setConfirmCode("");
      setConfirmError("");
      onStarted?.();
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "unauthenticated") return;
      if (err.code === "forbidden" && err.details?.reauthenticate) {
        setReauthenticate(true);
        setEnrollError("Setting up an authenticator needs a recent sign-in. Sign in again, then come back here.");
      } else if (err.code === "forbidden" && err.message === "enrollment refused") {
        setEnrollError("That password was not accepted. Five wrong attempts end this session.");
      } else if (err.code === "conflict") {
        setEnrollError("An authenticator is already set up.");
        onDone?.();
      } else if (err.code === "rate_limited") {
        wait(err);
        setEnrollError(`Too many attempts. Try again in ${retryAfter(err)}.`);
      } else {
        setEnrollError(err.code === "forbidden" ? err.message : refusal(err));
      }
    } finally {
      setEnrolling(false);
    }
  }

  function cancelEnroll() {
    setUri(null);
    setConfirmCode("");
    setConfirmError("");
    onCancel?.();
  }

  async function confirmEnroll(e: FormEvent) {
    e.preventDefault();
    if (confirming) return;
    const code = confirmCode.replace(/\s+/g, "");
    setConfirmCode("");
    if (!/^\d{6}$/.test(code)) {
      setConfirmError("Enter the six-digit code the app shows now.");
      return;
    }
    setConfirming(true);
    setConfirmError("");
    try {
      const done = await api<{ recovery_codes: string[] }>("/api/v1/mfa/enroll/confirm", { method: "POST", body: { code } });
      setUri(null);
      if (session.me) setSession({ me: { ...session.me, mfa: true, stepped_up: true }, tenants: session.tenants });
      await showOnce({
        title: "Save your recovery codes",
        description: "Each code confirms it's you once if the authenticator is not at hand.",
        secrets: done.recovery_codes,
        filename: "sentinel-recovery-codes.txt",
        note: "Keep them apart from the device that runs the authenticator.",
      });
      toast({ title: "Authenticator set up", color: "success", icon: "check" });
      onDone?.();
    } catch (x) {
      const err = x as ApiError;
      if (err.code === "unauthenticated") return;
      setConfirmError(err.code === "forbidden" ? "That code was not accepted. Check the device's clock and use the current code; five wrong codes end this session."
        : err.code === "not_found" ? "No setup is in progress any more. Start again."
          : refusal(err));
      if (err.code === "not_found") setUri(null);
      setTimeout(() => codeInput.current?.focus(), 0);
    } finally {
      setConfirming(false);
    }
  }

  if (uri) {
    return (
      <div className="space-y-4">
        <ol className="list-decimal space-y-1 ps-5 text-sm">
          <li>Scan the code with an authenticator app, or enter the key by hand.</li>
          <li>Type the six-digit code the app then shows.</li>
        </ol>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
          {qr ? (
            <svg viewBox={`0 0 ${qrBox} ${qrBox}`} className="size-48 shrink-0 rounded-md bg-white" shapeRendering="crispEdges" role="img"
              aria-label="QR code for your authenticator app; the same key is written beside it">
              <path d={qrPath(qr)} fill="#000" />
            </svg>
          ) : null}
          <div className="min-w-0 space-y-2">
            <p className="text-sm text-muted">Key (time-based, 6 digits, 30 seconds)</p>
            <p id="totp-key" className="select-all break-all rounded-md border border-line bg-elevated px-3 py-2 font-mono text-sm text-strong">{secret ?? "—"}</p>
            <a href={uri} className={buttonClass({ color: "neutral", variant: "link", size: "sm" }, "px-0")}>
              <Icon name="external-link" />Open in an authenticator app on this device
            </a>
          </div>
        </div>
        <form className="flex flex-wrap items-end gap-3" aria-label="Confirm the authenticator" onSubmit={confirmEnroll}>
          <Field label="Code from the app" htmlFor="totp-confirm" hint="6 digits" className="w-40">
            <Input id="totp-confirm" name="totp" ref={codeInput} value={confirmCode} onChange={(e) => setConfirmCode(e.target.value)} autoComplete="one-time-code"
              inputMode="numeric" maxLength={7} required aria-invalid={!!confirmError || undefined} />
          </Field>
          <Button type="submit" label="Confirm" loading={confirming} />
          <Button color="neutral" variant="ghost" label="Cancel" onClick={cancelEnroll} />
        </form>
        {confirmError ? <Alert color="error" icon="circle-alert" title={confirmError} role="alert" /> : null}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {intro ?? <p className="text-sm">An authenticator app on your phone gives a code that changes every 30 seconds. Sentinel asks for it before sensitive changes, so a stolen session alone cannot make them.</p>}
      {pending ? <Alert color="info" icon="info" title="A setup was started and not finished." description="Start again for a new key; the earlier one stops working." /> : null}
      <form className="flex flex-wrap items-end gap-3" aria-label="Set up an authenticator" onSubmit={startEnroll}>
        {hasPassword && password == null ? (
          <>
            {/* For password managers: which account this password belongs to. */}
            <input type="text" name="username" autoComplete="username" value={username ?? ""} className="sr" tabIndex={-1} aria-hidden="true" readOnly />
            <Field label="Your password" htmlFor="enroll-password" className="w-64 max-w-full">
              <Input id="enroll-password" name="enroll-password" value={enrollPassword} onChange={(e) => setEnrollPassword(e.target.value)} type="password" autoComplete="current-password" required
                aria-invalid={(!!enrollError && !reauthenticate) || undefined} />
            </Field>
          </>
        ) : null}
        <Button type="submit" icon="qr-code" label={waiting ? `Wait ${waiting} s` : pending ? "Start again" : "Set up"} loading={enrolling} disabled={!!waiting} />
        {actions}
      </form>
      {!hasPassword ? <p className="text-xs text-muted">Your account signs in with GitHub, so setting up needs a sign-in within the last few minutes.</p> : null}
      {enrollError ? (
        <Alert color="error" icon="circle-alert" title={enrollError} role="alert">
          {reauthenticate ? <Button size="sm" color="error" variant="soft" icon="log-in" label="Sign in again" className="mt-1" onClick={() => { void signOut("/account"); }} /> : null}
        </Alert>
      ) : null}
    </div>
  );
}
