import StepUpModal from "~/components/StepUpModal.vue";

/// The person closed "Confirm it's you" without confirming: the action was
/// not made, and nothing needs saying.
export class StepUpDeclined extends Error {
  constructor() { super("step-up declined"); }
}

/// Whether a refusal asks for a recent second factor (A06): issuing service
/// credentials, platform-administrator overrides, reissuing recovery codes,
/// linking an identity, a password change with a factor enrolled.
export const needsStepUp = (e: unknown): e is ApiError => e instanceof ApiError && e.code === "forbidden" && !!e.details.step_up;

/// Run `call`; when the controller asks for a step-up, ask the person with
/// the "Confirm it's you" dialog and run it once more. Anything else the
/// call throws is the caller's to say; a dismissed dialog is
/// `StepUpDeclined`.
export function useStepUp() {
  const overlay = useOverlay();
  const session = useSession();
  const dialog = overlay.create(StepUpModal, { destroyOnClose: true });

  return async function withStepUp<T>(call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (e) {
      if (!needsStepUp(e)) throw e;
      const me = session.me.value;
      const confirmed = await dialog.open({ mfa: !!me?.mfa, password: !!me?.username });
      if (!confirmed) throw new StepUpDeclined();
      if (session.me.value) session.me.value.stepped_up = true;
      return await call();
    }
  };
}
