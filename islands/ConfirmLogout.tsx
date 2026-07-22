import { useEffect, useRef } from "preact/hooks";

/**
 * Logout confirm via native `<dialog showModal()>` (Esc closes, focus trap,
 * focus restored to trigger). Cancel is autofocused.
 */
export default function ConfirmLogout() {
  const dialogRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    const onCancel = () => {
      // Browser already closes on Esc; keep focus on trigger afterward.
      queueMicrotask(() => {
        document.getElementById("sentinel-logout-trigger")?.focus();
      });
    };
    const onClose = () => {
      document.getElementById("sentinel-logout-trigger")?.focus();
    };
    dialog.addEventListener("cancel", onCancel);
    dialog.addEventListener("close", onClose);
    return () => {
      dialog.removeEventListener("cancel", onCancel);
      dialog.removeEventListener("close", onClose);
    };
  }, []);

  const open = (e: Event) => {
    e.preventDefault();
    const dialog = dialogRef.current;
    if (!dialog) return;
    dialog.showModal();
    // Prefer Cancel (safe action); avoid autoFocus on a closed dialog at paint.
    queueMicrotask(() => {
      dialog.querySelector<HTMLElement>('button[value="cancel"]')?.focus();
    });
  };

  return (
    <>
      <button
        type="button"
        id="sentinel-logout-trigger"
        class="rounded-md border border-border bg-surface-2/70 px-3.5 py-2 font-sans text-sm font-medium text-fg transition-colors hover:border-accent-muted hover:bg-accent-soft sm:py-1.5"
        onClick={open}
        aria-haspopup="dialog"
      >
        Logout
      </button>

      <dialog
        ref={dialogRef}
        class="sentinel-dialog glass max-w-sm rounded-xl p-0 text-fg shadow-glass"
        aria-labelledby="sentinel-logout-title"
        aria-describedby="sentinel-logout-desc"
      >
        <form method="dialog" class="p-5 sm:p-6">
          <h2
            id="sentinel-logout-title"
            class="font-sans text-base font-semibold tracking-tight text-fg-strong"
          >
            Sign out?
          </h2>
          <p
            id="sentinel-logout-desc"
            class="mt-2 text-sm leading-relaxed text-muted"
          >
            This ends your Sentinel session on this browser. You will need to
            sign in again with GitHub.
          </p>
          <div class="mt-5 flex flex-wrap justify-end gap-2">
            <button
              type="submit"
              value="cancel"
              class="rounded-md border border-transparent px-3.5 py-2.5 font-sans text-sm font-semibold text-muted hover:bg-surface-2/50 hover:text-fg sm:py-2"
            >
              Cancel
            </button>
            <a
              href="/logout"
              class="inline-flex min-h-10 items-center justify-center rounded-md bg-accent px-3.5 py-2.5 font-sans text-sm font-semibold text-accent-ink hover:bg-accent-hover sm:min-h-0 sm:py-2"
            >
              Sign out
            </a>
          </div>
        </form>
      </dialog>
    </>
  );
}
