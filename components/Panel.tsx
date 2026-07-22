import type { ComponentChildren } from "preact";

export interface PanelProps {
  title?: string;
  subtitle?: string;
  actions?: ComponentChildren;
  children: ComponentChildren;
  class?: string;
  /** Stronger glass for primary panels; subtle for nested metric groups. */
  tone?: "default" | "subtle";
  /** Accessible name when title is omitted. */
  "aria-label"?: string;
  /** Product-tour hook (Driver.js). */
  "data-tour"?: string;
}

export function Panel(props: PanelProps) {
  const glass = props.tone === "subtle" ? "glass-subtle" : "glass";
  return (
    <section
      class={`${glass} rounded-xl p-4 sm:p-5 ${props.class ?? ""}`.trim()}
      aria-label={props["aria-label"] ?? props.title}
      data-tour={props["data-tour"]}
    >
      {(props.title || props.actions) && (
        <div class="mb-4 flex flex-wrap items-end justify-between gap-3 border-b border-border-subtle/80 pb-3">
          <div class="min-w-0">
            {props.title && (
              <h2 class="font-sans text-sm font-semibold tracking-tight text-fg-strong">
                {props.title}
              </h2>
            )}
            {props.subtitle && (
              <p class="mt-0.5 text-sm text-muted">{props.subtitle}</p>
            )}
          </div>
          {props.actions && (
            <div class="flex shrink-0 items-center gap-2">{props.actions}</div>
          )}
        </div>
      )}
      {props.children}
    </section>
  );
}
