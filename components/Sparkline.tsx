export type SparklineProps = {
  values: number[];
  width?: number;
  height?: number;
  class?: string;
  /** Accessible name; omit when decorative and parent labels the metric. */
  label?: string;
};

/** Tiny inline SVG trend line (no chart library). Needs ≥2 finite values. */
export function Sparkline(props: SparklineProps) {
  const w = props.width ?? 72;
  const h = props.height ?? 20;
  const values = props.values.filter((v) => Number.isFinite(v));
  if (values.length < 2) return null;

  let min = Math.min(...values);
  let max = Math.max(...values);
  if (min === max) {
    min -= 1;
    max += 1;
  }

  const pad = 1.5;
  const span = max - min;
  const points = values.map((v, i) => {
    const x = pad + (i / (values.length - 1)) * (w - pad * 2);
    const y = pad + (1 - (v - min) / span) * (h - pad * 2);
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(" ");

  return (
    <svg
      width={w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      class={`sparkline ${props.class ?? ""}`.trim()}
      role={props.label ? "img" : "presentation"}
      aria-label={props.label}
      aria-hidden={props.label ? undefined : true}
    >
      <polyline
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        points={points}
      />
    </svg>
  );
}
