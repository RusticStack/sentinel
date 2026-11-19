// One artifact's files, for the run page: the manifest as a tree with each file's size and digest, a search over the
// paths, and the inline preview the controller allows — text cut at 1 MiB and images, both served as attachments, so
// nothing a job wrote is ever a document in this origin. Everything else downloads.
import { useEffect, useState } from "react";
import { archiveUrl, dirName, entryUrl, fileName, filter, previewUrl, tree, type ArtifactDetail, type Entry, type Tree } from "../../lib/artifacts.ts";
import { fmtBytes } from "../../lib/format.ts";
import { Icon, Input, cx } from "../ui.tsx";

const DIGEST_SHOWN = 12;

interface Preview {
  path: string;
  text?: string;
  image?: string;
  truncated?: boolean;
  error?: string;
}

function Row({ node, selected, onChoose, tenant }: {
  node: Tree; selected: string | null; onChoose: (node: Tree) => void; tenant: string;
}) {
  if (node.dir) {
    return (
      <li>
        <p className="flex items-center gap-1.5 py-0.5 text-sm text-muted">
          <Icon name="folder-git-2" className="size-3.5" />
          <span className="font-medium text-strong">{node.name}</span>
          <span className="text-xs">{node.children.length} {node.children.length === 1 ? "entry" : "entries"}</span>
        </p>
        <ul className="ml-3 space-y-0.5 border-l border-line pl-3">
          {node.children.map((child) => (
            <Row key={child.path} node={child} selected={selected} onChoose={onChoose} tenant={tenant} />
          ))}
        </ul>
      </li>
    );
  }
  const choosable = node.preview !== null;
  return (
    <li className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
      <button type="button" data-path={node.path} aria-pressed={selected === node.path}
        onClick={() => onChoose(node)} disabled={!choosable}
        aria-label={choosable ? `Preview ${node.path}` : `${node.path} has no preview`}
        className={cx("inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5 text-left",
          choosable ? "text-primary hover:bg-elevated cursor-pointer" : "text-muted disabled:cursor-default",
          selected === node.path && "bg-elevated text-strong")}>
        <Icon name={node.preview === "image" ? "archive" : "scroll-text"} className="size-3.5" />
        <span className="break-all">{node.name}</span>
      </button>
      <span className="font-mono text-xs text-muted">{fmtBytes(node.len)}</span>
      <code title={node.digest} className="font-mono text-xs text-muted">{node.digest.slice(DIGEST_SHOWN)}</code>
      <a href={entryUrl(tenant, node.digest)} download={node.name} aria-label={`Download ${node.path}`}
        className="text-xs text-primary underline underline-offset-2">Download</a>
    </li>
  );
}

export function ArtifactBrowser({ run, detail }: { run: string; detail: ArtifactDetail }) {
  const entries = detail.manifest?.entries ?? [];
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Entry | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const shown = filter(entries, query);
  const nodes = tree(shown);

  useEffect(() => {
    setPreview(null);
    if (!selected || !selected.preview) return;
    const url = previewUrl(run, detail.id, selected.path);
    if (selected.preview === "image") {
      setPreview({ path: selected.path, image: url });
      return;
    }
    const controller = new AbortController();
    let alive = true;
    (async () => {
      try {
        const response = await fetch(url, { credentials: "same-origin", signal: controller.signal });
        if (!response.ok) throw new Error(String(response.status));
        const bytes = await response.arrayBuffer();
        if (!alive) return;
        setPreview({
          path: selected.path,
          text: new TextDecoder().decode(bytes),
          truncated: response.headers.get("x-sentinel-truncated") === "true",
        });
      } catch (e) {
        if (alive && (e as Error)?.name !== "AbortError") {
          setPreview({ path: selected.path, error: "The controller could not read this file for a preview." });
        }
      }
    })();
    return () => { alive = false; controller.abort(); };
  }, [selected, run, detail.id]);

  const choose = (node: Tree) => {
    const entry = entries.find((e) => e.path === node.path) ?? null;
    setSelected(entry && entry.path === selected?.path ? null : entry);
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="w-full max-w-sm">
          <label htmlFor="artifact-search" className="text-sm font-medium text-strong">Search paths</label>
          <Input id="artifact-search" type="search" autoComplete="off" placeholder="reports/, .log, build" value={query}
            onChange={(e) => setQuery(e.target.value)} className="mt-1" />
        </div>
        <p className="text-xs text-muted" role="status">
          {shown.length} of {entries.length} {entries.length === 1 ? "entry" : "entries"}
          {entries.length ? ` · ${fmtBytes(detail.manifest?.payload_len ?? 0)}` : null}
        </p>
        <p className="flex items-center gap-3 text-sm">
          <a href={archiveUrl(run, detail.id, "tar")} className="inline-flex items-center gap-1 text-primary underline underline-offset-2">
            <Icon name="download" className="size-3.5" />Download .tar
          </a>
          <a href={archiveUrl(run, detail.id, "zip")} className="inline-flex items-center gap-1 text-primary underline underline-offset-2">
            <Icon name="download" className="size-3.5" />Download .zip
          </a>
        </p>
      </div>

      {shown.length === 0 ? (
        <p className="text-sm text-muted">{entries.length ? "No path holds that text." : "This artifact has no files."}</p>
      ) : (
        <ul aria-label="Files" className="max-h-96 space-y-0.5 overflow-auto rounded-md border border-line p-3">
          {nodes.map((node) => (
            <Row key={node.path} node={node} selected={selected?.path ?? null} onChoose={choose} tenant={detail.tenant} />
          ))}
        </ul>
      )}

      {selected && preview ? (
        <section id="artifact-preview" aria-labelledby="artifact-preview-h" className="space-y-2">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 id="artifact-preview-h" className="text-sm font-semibold text-strong">{selected.path}</h3>
            <p className="text-xs text-muted">
              {fmtBytes(selected.len)} · <code className="font-mono">{selected.digest.slice(0, DIGEST_SHOWN)}</code>
              {dirName(selected.path) ? ` in ${dirName(selected.path)}` : null}
            </p>
          </div>
          {preview.error ? (
            <p role="alert" className="text-sm text-error">{preview.error}</p>
          ) : preview.image ? (
            <img src={preview.image} alt={`Preview of ${fileName(selected.path)}`} className="max-h-96 rounded-md border border-line bg-canvas" />
          ) : (
            <>
              {preview.truncated ? (
                <p className="text-xs text-warning" id="artifact-preview-truncated">Showing the first 1 MiB; download the file for all of it.</p>
              ) : null}
              <pre className="max-h-96 overflow-auto rounded-md border border-line bg-subtle p-3 font-mono text-xs text-strong" tabIndex={0}>{preview.text}</pre>
            </>
          )}
          <p className="text-xs text-muted">Previews are a job's own output, served as a download rather than as a page: nothing here runs in Sentinel.</p>
        </section>
      ) : null}
    </div>
  );
}
