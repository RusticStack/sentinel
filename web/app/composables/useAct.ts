import StepUpModal from "~/components/StepUpModal.vue";

/// Run a mutation the way every button does: a toast for the outcome, a
/// step-up dialog (then one retry) when the controller asks for a second
/// factor, and on a refusal a re-read of the caller's tenants, since a
/// role or membership may have changed under the open page.
export function useAct() {
  const toast = useToast();
  const overlay = useOverlay();
  const session = useSession();
  const stepUp = overlay.create(StepUpModal, { destroyOnClose: true });

  return async function act<T>(label: string, call: () => Promise<T>): Promise<T | undefined> {
    try {
      let result: T;
      try {
        result = await call();
      } catch (e) {
        if (e instanceof ApiError && e.code === "forbidden" && e.details.step_up) {
          const confirmed = await stepUp.open({ mfa: !!session.me.value?.mfa });
          if (!confirmed) return undefined;
          if (session.me.value) session.me.value.stepped_up = true;
          result = await call();
        } else throw e;
      }
      toast.add({ title: `${label}: done`, color: "success", icon: "i-lucide-check" });
      return result;
    } catch (e) {
      const err = e as ApiError;
      const why = err.code === "not_found" ? "not found, or you no longer have access to it"
        : err.code === "forbidden" ? (err.details?.scope ? `your credential lacks the ${err.details.scope} scope` : "you are not permitted to do that")
          : err.code === "conflict" ? `not allowed now (${err.message})` : err.message;
      toast.add({ title: `${label}: ${why}.`, color: "error", icon: "i-lucide-circle-alert", duration: 8000 });
      if (err.code === "unauthenticated") await session.ended();
      else if (err.code === "not_found" || err.code === "forbidden") await session.refreshTenants();
      return undefined;
    }
  };
}
