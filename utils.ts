import { createDefine } from "fresh";

/** Session user set by auth middleware. Absent = locked / unauthenticated. */
export type SessionUser = {
  id: number;
  login: string;
  avatarUrl?: string;
  name?: string | null;
};

// Shared request state for middleware, layouts, and routes.
export type State = {
  user?: SessionUser;
};

export const define = createDefine<State>();
