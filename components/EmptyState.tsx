import type { ComponentChildren } from "preact";

export interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: ComponentChildren;
  action?: ComponentChildren;
  /** Softer copy for expected empty lists vs. hard failures. */
  tone?: "neutral" | "error" | "warning";
  class?: string;
}

const toneBorder: Record<NonNullable<EmptyStateProps["tone"]>, string> = {
  neutral: "border-border-subtle/80",
  error: "border-status-error/25 bg-status-error/5",
  warning: "border-status-warning/25 bg-status-warning/5",
};

export function EmptyState(props: EmptyStateProps) {
  const tone = props.tone ?? "neutral";
  return (
    <div
      class={`flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed px-4 py-10 text-center ${
        toneBorder[tone]
      } ${props.class ?? ""}`.trim()}
      role={tone === "error" ? "alert" : undefined}
    >
      {props.icon && (
        <div class="flex size-10 items-center justify-center rounded-lg bg-surface-3/80 text-muted">
          {props.icon}
        </div>
      )}
      <div class="max-w-sm">
        <p class="font-sans text-sm font-semibold text-fg-strong">
          {props.title}
        </p>
        {props.description && (
          <p class="mt-1.5 text-sm leading-relaxed text-muted">
            {props.description}
          </p>
        )}
      </div>
      {props.action && <div class="mt-1">{props.action}</div>}
    </div>
  );
}
