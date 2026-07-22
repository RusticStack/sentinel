import type { ComponentChildren } from "preact";

export type DataTableColumn = {
  key: string;
  header: string;
  /** Align numeric / mono columns to the end. */
  align?: "start" | "end";
  class?: string;
  /**
   * Hide this column below the breakpoint (secondary data on small screens).
   * Cell + header share the same visibility class.
   */
  hideBelow?: "sm" | "md" | "lg";
};

export type DataTableRow = {
  key: string;
  cells: Record<string, ComponentChildren>;
  href?: string;
};

export interface DataTableProps {
  columns: DataTableColumn[];
  rows: DataTableRow[];
  caption?: string;
  class?: string;
  /** Compact density for dashboard previews. */
  dense?: boolean;
}

function hideClass(hideBelow?: DataTableColumn["hideBelow"]): string {
  if (hideBelow === "sm") return "col-hide-sm";
  if (hideBelow === "md") return "col-hide-md";
  if (hideBelow === "lg") return "col-hide-lg";
  return "";
}

/** Server-rendered table: no client sorting; filters stay on the URL. */
export function DataTable(props: DataTableProps) {
  const cellPad = props.dense ? "px-2.5 py-2" : "px-3 py-2.5";
  const hasHidden = props.columns.some((c) => c.hideBelow);
  // Narrower min-width when secondary columns collapse on small screens.
  const minWidth = hasHidden ? "min-w-0 sm:min-w-[36rem]" : "min-w-[36rem]";
  const regionLabel = props.caption
    ? `${props.caption} (scroll horizontally for more columns)`
    : "Data table (scroll horizontally for more columns)";

  return (
    <div
      class={`table-scroll ${props.class ?? ""}`.trim()}
      role="region"
      aria-label={regionLabel}
      tabIndex={0}
    >
      <table class={`w-full ${minWidth} border-collapse text-left text-sm`}>
        {props.caption && <caption class="sr-only">{props.caption}</caption>}
        <thead>
          <tr class="border-b border-border-subtle/90">
            {props.columns.map((col) => (
              <th
                scope="col"
                class={`${cellPad} font-sans text-xs font-semibold tracking-wide text-muted uppercase ${
                  col.align === "end" ? "text-end" : "text-start"
                } ${hideClass(col.hideBelow)} ${col.class ?? ""}`.trim()}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {props.rows.map((row) => {
            if (row.href) {
              return (
                <tr
                  key={row.key}
                  class="border-b border-border-subtle/60 transition-colors last:border-0 hover:bg-accent-soft/40"
                >
                  {props.columns.map((col, i) => (
                    <td
                      class={`${cellPad} align-middle text-fg ${
                        col.align === "end" ? "text-end" : "text-start"
                      } ${hideClass(col.hideBelow)} ${col.class ?? ""}`.trim()}
                    >
                      {i === 0
                        ? (
                          <a
                            href={row.href}
                            class="font-medium text-fg-strong underline-offset-2 hover:underline focus-visible:underline"
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {row.cells[col.key]}
                            <span class="sr-only">(opens on GitHub)</span>
                          </a>
                        )
                        : row.cells[col.key]}
                    </td>
                  ))}
                </tr>
              );
            }

            return (
              <tr
                key={row.key}
                class="border-b border-border-subtle/60 last:border-0 hover:bg-surface-2/40"
              >
                {props.columns.map((col) => (
                  <td
                    class={`${cellPad} align-middle text-fg ${
                      col.align === "end" ? "text-end" : "text-start"
                    } ${hideClass(col.hideBelow)} ${col.class ?? ""}`.trim()}
                  >
                    {row.cells[col.key]}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
