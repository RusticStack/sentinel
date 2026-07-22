import type { ComponentChildren } from "preact";
import type { OrgRunner } from "../lib/github.ts";
import type { ServiceStatus } from "../lib/system.ts";
import { StatusBadge, type StatusTone } from "./StatusBadge.tsx";

export type RunnerWithService = OrgRunner & {
  service?: ServiceStatus;
};

export function runnerStatusTone(
  runner: Pick<OrgRunner, "status" | "busy">,
): StatusTone {
  if (runner.status !== "online") return "offline";
  if (runner.busy) return "busy";
  return "idle";
}

export function runnerStatusLabel(
  runner: Pick<OrgRunner, "status" | "busy">,
): string {
  if (runner.status !== "online") return runner.status || "offline";
  if (runner.busy) return "busy";
  return "idle";
}

function formatServiceMemory(bytes: number | null | undefined): string | null {
  if (bytes == null || !Number.isFinite(bytes) || bytes < 0) return null;
  const mb = bytes / (1024 * 1024);
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${Math.round(mb)} MB`;
}

export interface RunnerCardProps {
  runner: RunnerWithService;
  href?: string;
  /** Highlight when deep-linked from the dashboard. */
  highlighted?: boolean;
  footer?: ComponentChildren;
}

/** Glass runner summary: GitHub status + local systemd when available. */
export function RunnerCard(props: RunnerCardProps) {
  const { runner } = props;
  const tone = runnerStatusTone(runner);
  const label = runnerStatusLabel(runner);
  const service = runner.service;
  const mem = formatServiceMemory(service?.memoryCurrentBytes);
  const labels = runner.labels.map((l) => l.name).filter(Boolean);

  const body = (
    <>
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <p class="truncate font-sans text-sm font-semibold text-fg-strong">
            {runner.name}
          </p>
          <p class="mt-0.5 font-mono text-[0.7rem] text-subtle">
            {runner.os}
            {runner.ephemeral ? " · ephemeral" : ""}
          </p>
        </div>
        <StatusBadge tone={tone}>{label}</StatusBadge>
      </div>

      {labels.length > 0 && (
        <ul class="mt-3 flex flex-wrap gap-1.5" aria-label="Labels">
          {labels.slice(0, 6).map((name) => (
            <li
              key={name}
              class="rounded-md bg-surface-3/80 px-1.5 py-0.5 font-mono text-[0.65rem] text-muted"
            >
              {name}
            </li>
          ))}
          {labels.length > 6 && (
            <li class="rounded-md px-1.5 py-0.5 font-mono text-[0.65rem] text-subtle">
              +{labels.length - 6}
            </li>
          )}
        </ul>
      )}

      <dl class="mt-3 grid gap-1.5 font-mono text-[0.7rem] text-muted">
        {service && (
          <>
            <div class="flex justify-between gap-2">
              <dt>Service</dt>
              <dd class="text-fg">
                {service.available
                  ? `${service.activeState ?? "-"}${
                    service.subState ? ` / ${service.subState}` : ""
                  }`
                  : "unavailable"}
              </dd>
            </div>
            {service.mainPid != null && (
              <div class="flex justify-between gap-2">
                <dt>PID</dt>
                <dd class="text-fg">{service.mainPid}</dd>
              </div>
            )}
            {mem && (
              <div class="flex justify-between gap-2">
                <dt>Memory</dt>
                <dd class="text-fg">{mem}</dd>
              </div>
            )}
          </>
        )}
      </dl>

      {props.footer}
    </>
  );

  const shellClass = `glass-subtle block rounded-xl p-4 transition-colors ${
    props.highlighted
      ? "ring-2 ring-accent/70 ring-offset-2 ring-offset-surface-0"
      : ""
  } ${props.href ? "hover:border-accent-muted/60 hover:bg-accent-soft/30" : ""}`
    .trim();

  if (props.href) {
    return (
      <a href={props.href} class={shellClass}>
        {body}
      </a>
    );
  }

  return <div class={shellClass}>{body}</div>;
}
