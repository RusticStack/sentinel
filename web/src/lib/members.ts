// Adding a member: the controller resolves a username only among a tenant's existing members; a person who is not
// one yet is added by user id (docs/api.md, members). This reads the form's text the same way, before any request,
// so the refusal can say what to do instead of "not found, or you no longer have access".
export const USER_ID = /^usr_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Whether the members read holds every member: a read that failed (null) or has a further page does not. */
export const listComplete = (page: { next: string | null } | null): boolean => page !== null && !page.next;

export type MemberTarget =
  | { path: string; unlisted?: boolean }
  | { problem: string };

/**
 * `listed` is the members the page holds, and `complete` says that is every member (no further page). A username is
 * resolved to its member's id; an unknown name is refused outright only when the list is complete, otherwise it goes
 * to the controller, which knows the members beyond the first page (`unlisted`).
 */
export function memberTarget(input: string, listed: readonly { user: string; username: string | null }[], complete: boolean): MemberTarget {
  const who = input.trim();
  if (!who) return { problem: "Enter a user id (usr_…) or a member's username." };
  if (USER_ID.test(who)) return { path: who };
  const known = listed.find((m) => m.username === who);
  if (known) return { path: known.user };
  if (!complete) return { path: who, unlisted: true };
  return { problem: "Only a user id (usr_…) adds someone who is not a member yet. Ask them for it (it is on their account page), or invite them by email." };
}
