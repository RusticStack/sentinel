// Server and first browser render must match, so the time shows as UTC clock time until mounted.
import { fmtAgo } from "../lib/format.ts";
import { useNow } from "./ui.tsx";

export function RelTime({ ms }: { ms: number | null | undefined }) {
  const now = useNow();
  if (!ms) return <span className="text-muted">—</span>;
  const iso = new Date(ms).toISOString();
  return <time dateTime={iso} title={iso} className="whitespace-nowrap">{now === null ? `${iso.slice(11, 19)} UTC` : fmtAgo(ms, now)}</time>;
}
