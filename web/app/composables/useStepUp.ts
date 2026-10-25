import type { Security } from "~~/shared/types/api";
import StepUpModal from "~/components/StepUpModal.vue";

export class StepUpDeclined extends Error {
  constructor() { super("step-up declined"); }
}

export const needsStepUp = (e: unknown): e is ApiError => e instanceof ApiError && e.code === "forbidden" && !!e.details.step_up;

export function useStepUp() {
  const api = useApi();
  const overlay = useOverlay();
  const session = useSession();

  return async function withStepUp<T>(call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (e) {
      if (!needsStepUp(e)) throw e;
      const me = session.me.value;
      const security = await api<Security>("/api/v1/me/security");
      // One overlay per prompt: one created with `destroyOnClose` is gone
      // after it closes and cannot be opened again.
      const confirmed = await overlay.create(StepUpModal, { destroyOnClose: true }).open({ mfa: !!me?.mfa, password: security.password });
      if (!confirmed) throw new StepUpDeclined();
      if (session.me.value) session.me.value.stepped_up = true;
      return await call();
    }
  };
}
