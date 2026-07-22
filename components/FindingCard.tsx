import type { ComponentChildren } from "preact";
import { StatusBadge } from "./StatusBadge.tsx";
import { formatRelativeTime, severityTone } from "../lib/format.ts";

export type FindingCardProps = {
  findingId: string;
  severity: string | null;
  status: string;
  description: string | null;
  timestamp: string | null;
  dataSource?: string;
  /** Defaults to the Sentinel finding page. */
  href?: string;
  /** Compact strip row vs full card. */
  compact?: boolean;
  class?: string;
  trailing?: ComponentChildren;
};

export function FindingCard(props: FindingCardProps) {
  const href = props.href ??
    `/security/finding/${encodeURIComponent(props.findingId)}`;
  const severity = props.severity ?? "unknown";
  const compact = props.compact ?? false;

  const body = (
    <>
      <div class="flex min-w-0 flex-1 flex-col gap-1">
        <div class="flex flex-wrap items-center gap-2">
          <StatusBadge tone={severityTone(props.severity)}>
            {severity}
          </StatusBadge>
          <span class="font-mono text-[0.7rem] uppercase tracking-wide text-subtle">
            {props.status}
          </span>
          {props.dataSource && (
            <span class="font-mono text-[0.7rem] text-subtle">
              {props.dataSource}
            </span>
          )}
        </div>
        <p
          class={`font-sans text-sm text-fg-strong ${
            compact ? "line-clamp-1" : "line-clamp-2"
          }`}
        >
          {props.description?.trim() || "No description"}
        </p>
        <p class="font-mono text-xs text-subtle">
          <span class="text-muted">{props.findingId}</span>
          {props.timestamp
            ? (
              <>
                {" · "}
                {formatRelativeTime(props.timestamp)}
              </>
            )
            : null}
        </p>
      </div>
      {props.trailing}
    </>
  );

  const classes =
    `flex items-start gap-3 rounded-lg border border-border-subtle/80 bg-surface-2/40 px-3 py-2.5 transition-colors hover:border-accent-muted hover:bg-accent-soft/40 ${
      props.class ?? ""
    }`.trim();

  return (
    <a href={href} class={classes}>
      {body}
    </a>
  );
}
