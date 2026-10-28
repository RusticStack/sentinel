import { api } from "./api.ts";

export interface RepoList { repos: { id: string; name: string }[] }

export async function loadRepos(slug: string): Promise<RepoList> {
  const list = await api<RepoList>(`/api/v1/tenants/${encodeURIComponent(slug)}/repos`);
  list.repos.sort((a, b) => a.name.localeCompare(b.name));
  return list;
}
