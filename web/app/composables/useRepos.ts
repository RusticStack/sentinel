export function useRepos(slug: MaybeRefOrGetter<string>) {
  const api = useApi();
  return useAsyncData(
    () => `repos-${toValue(slug)}`,
    async () => {
      const list = await api<{ repos: { id: string; name: string }[] }>(`/api/v1/tenants/${toValue(slug)}/repos`);
      list.repos.sort((a, b) => a.name.localeCompare(b.name));
      return list;
    },
  );
}
