/// A tenant's repositories the caller may read, by name (a stable order;
/// the first is the default wherever one is needed). One cached request per
/// tenant, shared by every view that lists them.
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
