// One polite live region for the whole interface (the log viewer's search and jump announcements).
import { useSyncExternalStore } from "react";

let text = "";
const listeners = new Set<() => void>();

export function announce(next: string) {
  // Cleared first so the same words are announced again.
  text = "";
  for (const l of listeners) l();
  requestAnimationFrame(() => { text = next; for (const l of listeners) l(); });
}

export function Announcer() {
  const value = useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l); }, () => text, () => "");
  return <div role="status" aria-live="polite" className="sr">{value}</div>;
}
