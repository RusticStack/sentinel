/// Run a mutation the way every button does: a toast for the outcome, a
/// step-up dialog (then one retry) when the controller asks for a second
/// factor, and on a refusal a re-read of the caller's tenants, since a
/// role or membership may have changed under the open page. A session that
/// ended is taken to sign-in by `useApi`.
export function useAct() {
  const toast = useToast();
  const session = useSession();
  const withStepUp = useStepUp();

  return async function act<T>(label: string, call: () => Promise<T>): Promise<T | undefined> {
    try {
      const result = await withStepUp(call);
      toast.add({ title: `${label}: done`, color: "success", icon: "i-lucide-check" });
      return result;
    } catch (e) {
      if (e instanceof StepUpDeclined) return undefined;
      const err = e as ApiError;
      if (err.code === "unauthenticated") return undefined;
      toast.add({ title: `${label}: ${refusal(err)}.`, color: "error", icon: "i-lucide-circle-alert", duration: 8000 });
      if (err.code === "not_found" || err.code === "forbidden") await session.refreshTenants();
      return undefined;
    }
  };
}

/// A refusal in words, for a toast or an inline message.
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

/// `details.retry_after_ms` as "N seconds" (at least one).
export function retryAfter(err: ApiError): string {
  const s = Math.max(1, Math.ceil(Number(err.details?.retry_after_ms ?? 1000) / 1000));
  return s === 1 ? "a second" : `${s} seconds`;
}
