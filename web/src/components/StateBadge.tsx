import { stateLook, words } from "../lib/format.ts";
import { Badge } from "./ui.tsx";

export function StateBadge({ state, label }: { state: string | null | undefined; label?: string }) {
  const look = stateLook(state || "unknown");
  return <Badge color={look.color} icon={look.icon.replace(/^i-lucide-/, "")}>{label ?? words(state || "unknown")}</Badge>;
}
