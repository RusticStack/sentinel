// Imperative dialogs and toasts: `openOverlay` resolves when the dialog closes; each dialog is unmounted on close so
// the values it held (a proof, a shown-once secret) do not outlive it.
import { useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { cx, Icon, type Color } from "../components/ui.tsx";

type Entry = { id: number; render: () => ReactNode };
let overlays: Entry[] = [];
let next = 1;
const overlayListeners = new Set<() => void>();
const emitOverlays = () => { for (const l of overlayListeners) l(); };

export function openOverlay<T>(render: (close: (value: T) => void) => ReactNode): Promise<T> {
  return new Promise<T>((resolve) => {
    const id = next++;
    let done = false;
    const close = (value: T) => {
      if (done) return;
      done = true;
      overlays = overlays.filter((o) => o.id !== id);
      emitOverlays();
      resolve(value);
    };
    overlays = [...overlays, { id, render: () => render(close) }];
    emitOverlays();
  });
}

const EMPTY_LIST: Entry[] = [];
export function OverlayHost() {
  const list = useSyncExternalStore((l) => { overlayListeners.add(l); return () => overlayListeners.delete(l); }, () => overlays, () => EMPTY_LIST);
  return <>{list.map((o) => <OverlaySlot key={o.id} entry={o} />)}</>;
}
function OverlaySlot({ entry }: { entry: Entry }) { return <>{entry.render()}</>; }

// --- toasts ---
export interface Toast { id: number; title: string; color?: Color; icon?: string; duration?: number }
let toasts: Toast[] = [];
const toastListeners = new Set<() => void>();
const emitToasts = () => { for (const l of toastListeners) l(); };

export function toast(t: Omit<Toast, "id">) {
  const id = next++;
  toasts = [...toasts.slice(-4), { id, ...t }];
  emitToasts();
  setTimeout(() => dismiss(id), t.duration ?? 5000);
}
function dismiss(id: number) { toasts = toasts.filter((t) => t.id !== id); emitToasts(); }

const TONE: Record<Color, string> = {
  primary: "text-primary", neutral: "text-muted", success: "text-success", info: "text-info", warning: "text-warning", error: "text-error",
};

export function Toaster() {
  const list = useSyncExternalStore((l) => { toastListeners.add(l); return () => toastListeners.delete(l); }, () => toasts, () => toasts);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  // One polite region for outcomes and one assertive region for refusals, present from the first render.
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2">
      <div role="status" aria-live="polite" className="contents">
        {mounted && list.filter((t) => t.color !== "error").map((t) => <ToastCard key={t.id} t={t} />)}
      </div>
      <div role="alert" aria-live="assertive" className="contents">
        {mounted && list.filter((t) => t.color === "error").map((t) => <ToastCard key={t.id} t={t} />)}
      </div>
    </div>
  );
}
function ToastCard({ t }: { t: Toast }) {
  return (
    <div className="pointer-events-auto flex items-start gap-2 rounded-md border border-line bg-canvas p-3 text-sm text-fg shadow-lg">
      <Icon name={t.icon ?? "info"} className={cx("mt-0.5 size-4", TONE[t.color ?? "neutral"])} />
      <p className="flex-1">{t.title}</p>
      <button type="button" aria-label="Dismiss" className="text-muted hover:text-fg" onClick={() => dismiss(t.id)}><Icon name="x" /></button>
    </div>
  );
}
