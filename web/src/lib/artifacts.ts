// An artifact's files as the run page browses them: a tree built once from the manifest, the path search over it, and
// the request paths the page uses. Pure, so the tree and the search are unit-tested without a browser
// (`web/test/artifacts.test.mjs`); the page only renders what these return.

export interface ArtifactRow {
  id: string;
  job: string;
  job_name: string;
  attempt: string;
  name: string;
  state: string;
  manifest_version: number | null;
  entries: number;
  bytes: number;
  class: string;
  charged_bytes: number;
  retain_until_ms: number;
  pinned_ms: number | null;
  created_ms: number;
}

/** One manifest entry. `preview` is the controller's own verdict on what may be shown inline. */
export interface Entry {
  path: string;
  digest: string;
  len: number;
  mode: number;
  preview: "text" | "image" | null;
}

export interface Manifest {
  version: number;
  digest: string;
  payload_len: number;
  entries: Entry[];
}

/** One artifact's row plus, when captured, its manifest and the tenant its objects are read by. */
export interface ArtifactDetail extends ArtifactRow {
  tenant: string;
  manifest?: Manifest;
}

/** A directory or a file in the tree. Directories carry their children, sorted; files carry what a row shows. */
export interface Tree {
  name: string;
  path: string;
  dir: boolean;
  len: number;
  digest: string;
  preview: Entry["preview"];
  children: Tree[];
}

export function fileName(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

/** The directory part of a path ("" at the top level). */
export function dirName(path: string): string {
  const cut = path.lastIndexOf("/");
  return cut < 0 ? "" : path.slice(0, cut);
}

/**
 * The manifest's entries as one tree, in one pass: a map from directory path to its node, so each entry costs its own
 * segments and nothing is rescanned. Children sort by name with directories first, which is what the page shows.
 */
export function tree(entries: Entry[]): Tree[] {
  const root: Tree = { name: "", path: "", dir: true, len: 0, digest: "", preview: null, children: [] };
  if (!entries.length) return root.children;
  const dirs = new Map<string, Tree>([["", root]]);
  const dir = (path: string) => ({ name: fileName(path), path, dir: true, len: 0, digest: "", preview: null, children: [] as Tree[] });
  for (const entry of entries) {
    const cut = entry.path.lastIndexOf("/");
    let parent = root;
    if (cut > 0) {
      // Each ancestor is created once and remembered by its full path, so a deep entry costs its own segments only.
      let at = -1;
      for (;;) {
        at = entry.path.indexOf("/", at + 1);
        if (at < 0 || at >= cut) break;
        const path = entry.path.slice(0, at);
        let node = dirs.get(path);
        if (!node) {
          node = dir(path);
          dirs.set(path, node);
          parent.children.push(node);
        }
        parent = node;
      }
      const path = entry.path.slice(0, cut);
      let node = dirs.get(path);
      if (!node) {
        node = dir(path);
        dirs.set(path, node);
        parent.children.push(node);
      }
      parent = node;
    }
    parent.children.push({ name: fileName(entry.path), path: entry.path, dir: false, len: entry.len, digest: entry.digest, preview: entry.preview, children: [] });
  }
  const sort = (nodes: Tree[]) => {
    nodes.sort((a, b) => (a.dir === b.dir ? (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) : a.dir ? -1 : 1));
    for (const node of nodes) if (node.dir) sort(node.children);
  };
  sort(root.children);
  return root.children;
}

/** The entries whose path holds `query`, case-insensitively; all of them for an empty query. */
export function filter(entries: Entry[], query: string): Entry[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return entries;
  return entries.filter((entry) => entry.path.toLowerCase().includes(needle));
}

/** One entry's preview: bounded by the controller, and always an attachment rather than a document. */
export function previewUrl(run: string, artifact: string, path: string): string {
  return `/api/v1/runs/${run}/artifacts/${artifact}/preview?path=${encodeURIComponent(path)}`;
}

/** One entry's bytes, through the object route the manifest's digests name. */
export function entryUrl(tenant: string, digest: string): string {
  return `/api/v1/tenants/${tenant}/objects/${digest}`;
}

/** The whole artifact as one archive, generated from the manifest as it streams. */
export function archiveUrl(run: string, artifact: string, format: "tar" | "zip"): string {
  return `/api/v1/runs/${run}/artifacts/${artifact}/archive?format=${format}`;
}
