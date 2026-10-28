// A platform administrator acting in a tenant they do not administer gives a reason, sent as `reason` with
// changes to members, invitations, repository access and service accounts (docs/web-ui.md, Step-up). The reason is
// kept per tenant for the browser session; the server render always starts empty.
import { useSyncExternalStore } from "react";
import { toast } from "./overlay.tsx";
import { useSession } from "./session.ts";

const reasons = new Map<string, string>();
const listeners = new Set<() => void>();
const subscribe = (l: () => void) => { listeners.add(l); return () => { listeners.delete(l); }; };
function store(slug: string, value: string) {
  reasons.set(slug, value);
  for (const l of listeners) l();
}

export function useOverride(slug: string) {
  const { me, roleIn } = useSession();
  const needed = !!me?.super_admin && roleIn(slug) !== "admin";
  const reason = useSyncExternalStore(subscribe, () => reasons.get(slug) ?? "", () => "");
  const current = () => (reasons.get(slug) ?? "").trim();

  /** False (and says why) while a needed reason is empty: the change is not sent. */
  function ready(): boolean {
    if (!needed || current()) return true;
    toast({ title: "Give a reason for acting as platform administrator first.", color: "warning", icon: "circle-alert" });
    document.getElementById("override-reason")?.focus();
    return false;
  }
  function withReason<T extends object>(body: T): T & { reason?: string } {
    return needed ? { ...body, reason: current() } : body;
  }
  return { needed, reason, setReason: (value: string) => store(slug, value), ready, withReason };
}
