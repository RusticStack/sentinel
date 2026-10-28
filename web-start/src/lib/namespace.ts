// A namespace's settings, or the refusal in words: the settings and tenant administration views show either.
import type { NamespaceSettings } from "./types";
import { api, ApiError } from "./api.ts";
import { refusal } from "./act.tsx";

export interface NamespaceLoad { settings: NamespaceSettings | null; failure: { code: string; words: string } | null }

export async function loadNamespaceSettings(slug: string): Promise<NamespaceLoad> {
  try {
    return { settings: await api<NamespaceSettings>(`/api/v1/tenants/${encodeURIComponent(slug)}/settings`), failure: null };
  } catch (e) {
    const err = e instanceof ApiError ? e : new ApiError(0, null);
    return { settings: null, failure: { code: err.code, words: refusal(err) } };
  }
}
