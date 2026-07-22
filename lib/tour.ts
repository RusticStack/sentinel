/**
 * Product tour selectors + localStorage keys (shared by island + help page).
 * Storage is client-only; SSR never reads these keys.
 */

export const TOUR_SEEN_KEY = "sentinel.tour.seen";
export const TOUR_BANNER_DISMISSED_KEY = "sentinel.tour.bannerDismissed";

/** Query flag to force-start the dashboard tour (`/?tour=1`). */
export const TOUR_QUERY = "tour";

export type TourStepDef = {
  /** Matches `[data-tour="…"]` on the dashboard. */
  region: string;
  title: string;
  description: string;
  side?: "top" | "right" | "bottom" | "left";
};

export const TOUR_STEPS: TourStepDef[] = [
  {
    region: "nav",
    title: "Navigation",
    description:
      "Jump between Dashboard, Runners, Runs, and Help. Security appears when Vigil is configured.",
    side: "bottom",
  },
  {
    region: "system",
    title: "Host resources",
    description:
      "Memory, disk, and load on the Sentinel host. Values refresh quietly in the background.",
    side: "bottom",
  },
  {
    region: "runners",
    title: "Runners",
    description:
      "Self-hosted GitHub Actions runners for your org, plus local systemd state when available.",
    side: "top",
  },
  {
    region: "runs",
    title: "Workflow runs",
    description:
      "Recent Actions runs across org repositories. Open a row to view it on GitHub.",
    side: "top",
  },
  {
    region: "security",
    title: "Security",
    description:
      "Optional Vigil SOC summary: findings, cases, and agents when VIGIL_URL is set.",
    side: "top",
  },
];

export function tourElementSelector(region: string): string {
  return `[data-tour="${region}"]`;
}
