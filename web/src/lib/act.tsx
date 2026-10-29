// Actions: one helper runs a mutation, asks for step-up when the controller says so, and says the outcome.
import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "./api.ts";
import { openOverlay, toast } from "./overlay.tsx";
import { markSteppedUp, refreshTenants } from "./session.ts";
import type { Me, Security } from "./types";
import { StepUpDialog } from "../components/StepUpDialog.tsx";

export class StepUpDeclined extends Error {
  constructor() { super("step-up declined"); }
}

export const needsStepUp = (e: unknown): e is ApiError => e instanceof ApiError && e.code === "forbidden" && !!e.details.step_up;

/** Runs `call`; when it is refused for want of a recent second factor, asks for one and retries once. */
export async function withStepUp<T>(call: () => Promise<T>, me: Me | null): Promise<T> {
  try {
    return await call();
  } catch (e) {
    if (!needsStepUp(e)) throw e;
    const security = await api<Security>("/api/v1/me/security");
    const confirmed = await openOverlay<boolean>((close) => <StepUpDialog mfa={!!me?.mfa} password={security.password} onClose={close} />);
    if (!confirmed) throw new StepUpDeclined();
    markSteppedUp();
    return await call();
  }
}

export async function act<T>(me: Me | null, label: string, call: () => Promise<T>, successToast = true): Promise<T | undefined> {
  try {
    const result = await withStepUp(call, me);
    if (successToast) toast({ title: `${label}: done`, color: "success", icon: "check" });
    return result;
  } catch (e) {
    if (e instanceof StepUpDeclined) return undefined;
    const err = e as ApiError;
    // The API helper already sent the person to sign-in; no toast here.
    if (err.code === "unauthenticated") return undefined;
    toast({ title: `${label}: ${refusal(err)}.`, color: "error", icon: "circle-alert", duration: 8000 });
    if (err.code === "not_found" || err.code === "forbidden") await refreshTenants();
    return undefined;
  }
}

export function refusal(err: ApiError): string {
  switch (err.code) {
    case "not_found": return "not found, or you no longer have access to it";
    case "forbidden":
      if (err.details?.scope) return `your credential lacks the ${err.details.scope} scope`;
      if (err.details?.step_up) return "this needs a recent second factor, and it was not confirmed";
      return "you are not permitted to do that";
    case "conflict": return `not allowed now (${err.message})`;
    case "rate_limited": return `too many requests; try again in ${retryAfter(err)}`;
    case "network": return "the server could not be reached";
    default: return err.message;
  }
}

export function retryAfter(err: ApiError): string {
  const s = Math.max(1, Math.ceil(Number(err.details?.retry_after_ms ?? 1000) / 1000));
  return s === 1 ? "a second" : `${s} seconds`;
}

/** Seconds left of a rate-limit wait, counted down in the page. */
export function useRetryWait() {
  const [until, setUntil] = useState(0);
  const [now, setNow] = useState(0);
  const timer = useRef<ReturnType<typeof setInterval> | undefined>(undefined);
  useEffect(() => () => clearInterval(timer.current), []);
  const waiting = Math.max(0, Math.ceil((until - now) / 1000));
  function start(source: ApiError | number) {
    const ms = typeof source === "number" ? source : Number(source.details?.retry_after_ms ?? 2000);
    const t = Date.now();
    setNow(t);
    setUntil(t + Math.max(1000, ms));
    clearInterval(timer.current);
    timer.current = setInterval(() => {
      const n = Date.now();
      setNow(n);
      if (n >= t + Math.max(1000, ms)) clearInterval(timer.current);
    }, 1000);
  }
  return { waiting, start };
}
