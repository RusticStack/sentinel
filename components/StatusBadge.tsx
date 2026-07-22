import type { ComponentChildren } from "preact";

export type StatusTone =
  | "online"
  | "idle"
  | "busy"
  | "offline"
  | "error"
  | "success"
  | "warning"
  | "info";

/**
 * Soft tinted chips for runner / workflow states on the light glass UI.
 * Color plus a visible label — never color alone. Not for shell “live”
 * chrome; the app does not show Live/Offline connection theater.
 */
const toneClass: Record<StatusTone, string> = {
  online: "bg-status-online/12 text-status-online",
  idle: "bg-status-idle/12 text-status-idle",
  busy: "bg-status-busy/12 text-status-busy",
  offline: "bg-status-offline/15 text-status-offline",
  error: "bg-status-error/12 text-status-error",
  success: "bg-status-success/12 text-status-success",
  warning: "bg-status-warning/12 text-status-warning",
  info: "bg-status-info/12 text-status-info",
};

export interface StatusBadgeProps {
  tone: StatusTone;
  children: ComponentChildren;
}

/** Accessible status chip for entity states (runners, jobs), not shell health. */
export function StatusBadge(props: StatusBadgeProps) {
  return (
    <span
      class={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-mono text-[0.7rem] font-medium tracking-wide uppercase ${
        toneClass[props.tone]
      }`}
    >
      <span
        class="size-1.5 shrink-0 rounded-full bg-current opacity-90"
        aria-hidden="true"
      />
      {props.children}
    </span>
  );
}
