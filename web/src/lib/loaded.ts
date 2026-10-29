// A section's first read as the loader leaves it: the value, or the refusal in words. A failed read used to become
// `null`, which every view drew as an empty table, so an outage looked like "no members" or "no pools".
import { useLoaded } from "./hooks.ts";
import { ApiError } from "./api.ts";
import { refusal } from "./act.tsx";

export interface Load<T> { value: T | null; failure: string | null }

/** Reads once; a refusal becomes its words (never the payload), anything else "the server could not be reached". */
export async function attempt<T>(read: () => Promise<T>): Promise<Load<T>> {
  try {
    return { value: await read(), failure: null };
  } catch (e) {
    return { value: null, failure: refusal(e instanceof ApiError ? e : new ApiError(0, null)) };
  }
}

const UNANSWERED = "the controller did not answer";

/**
 * The loaded value with a setter for later reads, where `null` means a read failed. `failure` is set only while
 * there is no value, so a failed refresh keeps showing what was loaded before.
 */
export function useLoad<T>(initial: Load<T>): { data: T | null; setData: (next: T | null) => void; failure: string | null } {
  const [load, setLoad] = useLoaded<Load<T>>(initial);
  return {
    data: load.value,
    setData: (next) => setLoad({ value: next, failure: next === null ? UNANSWERED : null }),
    failure: load.value === null ? load.failure ?? UNANSWERED : null,
  };
}
