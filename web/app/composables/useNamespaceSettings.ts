import type { NamespaceSettings } from "~~/shared/types/api";

/// A namespace's settings (`GET /tenants/{slug}/settings`), shared by the
/// settings page and tenant administration under one key. A refusal is kept
/// as data — its code and the words for it — rather than thrown, so a page
/// can say "not found" or "try again" without a crash page.
export function useNamespaceSettings(slug: string) {
  const api = useApi();
  const result = useAsyncData(`namespace-settings-${slug}`, async () => {
    try {
      return { settings: await api<NamespaceSettings>(`/api/v1/tenants/${slug}/settings`), failure: null };
    } catch (e) {
      const err = e as ApiError;
      return { settings: null, failure: { code: err.code, words: refusal(err) } };
    }
  });
  return result;
}
