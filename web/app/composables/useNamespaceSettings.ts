import type { NamespaceSettings } from "~~/shared/types/api";

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
