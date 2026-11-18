// A manual run records the Sentinel account that started it; a webhook run records none, because the provider's sender
// is text its author chose and is never shown as a person. The controller names the account only while it is still a
// member of the tenant, so a missing name falls back to the account's short id.
import type { Run } from "./types";
import { shortId } from "./format.ts";

/** The line naming who started a run, or null when no Sentinel account did. */
export function startedBy(run: Pick<Run, "actor">): string | null {
  if (!run.actor) return null;
  return `Started by ${run.actor.display_name || shortId(run.actor.user_id)}`;
}
