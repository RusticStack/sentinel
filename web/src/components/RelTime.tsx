// Server and first browser render must match, so the time shows as UTC clock time until mounted.
import { fmtAgo, fmtUntil } from "../lib/format.ts";
import { useNow } from "./ui.tsx";

export function RelTime({ ms }: { ms: number | null | undefined }) {
  const now = useNow();
  if (!ms) return <span className="text-muted">—</span>;
  const iso = new Date(ms).toISOString();
  return <time dateTime={iso} title={iso} className="whitespace-nowrap">{now === null ? `${iso.slice(11, 19)} UTC` : fmtAgo(ms, now)}</time>;
}

/** A deadline ahead of now: the retention an artifact is kept to. The first browser render is a UTC clock time, as
 * RelTime's is, so the server and the browser agree; once mounted it reads "in 23 h" (or "due now" past it). */
export function Until({ ms }: { ms: number | null | undefined }) {
  const now = useNow();
  if (!ms) return <span className="text-muted">—</span>;
  const iso = new Date(ms).toISOString();
  return <time dateTime={iso} title={iso} className="whitespace-nowrap">{now === null ? `${iso.slice(0, 10)}` : fmtUntil(ms, now)}</time>;
}
