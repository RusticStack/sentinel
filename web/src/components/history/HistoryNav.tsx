// The History views of one tenant: durations, the flaky tests of a repository, and log search across recent runs (a
// comparison is opened from the durations).
import { PathLink, cx } from "../ui.tsx";

export function HistoryNav({ slug, repo, current }: { slug: string; repo: string | null; current: "durations" | "flakes" | "search" | "compare" }) {
  const items = [
    { key: "durations", label: "Durations", to: `/t/${slug}/history` },
    { key: "flakes", label: "Flaky tests", to: `/t/${slug}/history/flakes` },
    { key: "search", label: "Log search", to: `/t/${slug}/history/search` },
  ] as const;
  return (
    <nav aria-label="History views" className="flex flex-wrap gap-1">
      {items.map((i) => {
        const here = i.key === current || (current === "compare" && i.key === "durations");
        return (
          <PathLink key={i.key} to={i.to} search={repo ? { repo } : undefined} aria-current={here ? "page" : undefined}
            className={cx("rounded-md px-3 py-1.5 text-sm", here ? "bg-elevated font-medium text-strong" : "text-fg hover:bg-subtle")}>
            {i.label}
          </PathLink>
        );
      })}
    </nav>
  );
}
