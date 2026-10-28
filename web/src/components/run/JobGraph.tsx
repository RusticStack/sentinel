import { useNavigate } from "@tanstack/react-router";
import type { Explanation, JobStatus } from "../../lib/types";
import { stateLook, words } from "../../lib/format.ts";

const W = 176, H = 42, GX = 56, GY = 14, PAD = 12;
const TONE: Record<string, string> = { success: "text-success", error: "text-error", warning: "text-warning", info: "text-info", primary: "text-primary", neutral: "text-muted" };

export function JobGraph({ explain, jobs, run }: { explain: Explanation; jobs: JobStatus[]; run: string }) {
  const navigate = useNavigate();
  const level = new Map<string, number>();
  for (const job of explain.jobs) level.set(job.name, job.needs.length ? 1 + Math.max(...job.needs.map((n) => level.get(n) ?? 0)) : 0);
  const columns: string[][] = [];
  for (const job of explain.jobs) (columns[level.get(job.name)!] ||= []).push(job.name);
  const pos = new Map<string, [number, number]>();
  columns.forEach((col, x) => col.forEach((name, y) => pos.set(name, [PAD + x * (W + GX), PAD + y * (H + GY)])));
  const width = PAD * 2 + columns.length * (W + GX) - GX;
  const height = PAD * 2 + Math.max(1, ...columns.map((c) => c.length)) * (H + GY) - GY;
  const edges = explain.jobs.flatMap((job) => job.needs.map((need) => {
    const [x1, y1] = pos.get(need)!, [x2, y2] = pos.get(job.name)!;
    const ax = x1 + W, ay = y1 + H / 2, bx = x2, by = y2 + H / 2;
    return `M${ax},${ay} C${ax + GX / 2},${ay} ${bx - GX / 2},${by} ${bx},${by}`;
  }));
  const byName = new Map(jobs.map((j) => [j.name, j]));
  const label = `Job graph: ${explain.jobs.map((j) => `${j.name}${j.needs.length ? " after " + j.needs.join(" and ") : ""}`).join("; ")}`;
  return (
    <div className="dag overflow-x-auto rounded-lg border border-line bg-subtle">
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="group" aria-label={label}>
        {edges.map((d, i) => <path key={i} className="edge" d={d} />)}
        {explain.jobs.map((job) => {
          const status = byName.get(job.name);
          const state = status?.state ?? "pending";
          const [x, y] = pos.get(job.name)!;
          const node = (
            <g className={`node ${TONE[stateLook(state).color]}`} transform={`translate(${x},${y})`}>
              <rect width={W} height={H} rx="8" />
              <text x="10" y="17">{job.name.length > 22 ? job.name.slice(0, 21) + "…" : job.name}</text>
              <text x="10" y="33" className="state">{words(state)}</text>
            </g>
          );
          if (!status?.attempt) return <g key={job.name}>{node}</g>;
          const href = `/runs/${run}/logs/${status.attempt}`;
          return (
            <a key={job.name} href={href} aria-label={`${job.name}: ${words(state)}, open log`}
              onClick={(e) => { e.preventDefault(); void navigate({ href }); }}>{node}</a>
          );
        })}
      </svg>
    </div>
  );
}
