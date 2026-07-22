import { createDefine } from "fresh";

/** Session user set by Phase 1 auth middleware. Absent = locked / unauthenticated. */
export type SessionUser = {
  login: string;
};

// Shared request state for middleware, layouts, and routes.
export type State = {
  user?: SessionUser;
};

export const define = createDefine<State>();
