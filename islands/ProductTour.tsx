import { useEffect, useRef, useState } from "preact/hooks";
import { type Driver, driver } from "driver.js";
import "driver.js/dist/driver.css";
import { Button } from "../components/Button.tsx";
import {
  TOUR_BANNER_DISMISSED_KEY,
  TOUR_QUERY,
  TOUR_SEEN_KEY,
  TOUR_STEPS,
  tourElementSelector,
} from "../lib/tour.ts";

export type ProductTourProps = {
  /** When true, show the first-run guidance strip (dashboard only). */
  showBanner?: boolean;
};

function prefersReducedMotion(): boolean {
  if (typeof globalThis.matchMedia !== "function") return false;
  return globalThis.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function readFlag(key: string): boolean {
  try {
    return globalThis.localStorage?.getItem(key) === "1";
  } catch {
    return false;
  }
}

function writeFlag(key: string, value: boolean): void {
  try {
    if (value) globalThis.localStorage?.setItem(key, "1");
    else globalThis.localStorage?.removeItem(key);
  } catch {
    // Private mode / blocked storage: tour still works for this session.
  }
}

function buildDriver(): Driver {
  const steps = TOUR_STEPS
    .filter((step) =>
      document.querySelector(tourElementSelector(step.region)) != null
    )
    .map((step) => ({
      element: tourElementSelector(step.region),
      popover: {
        title: step.title,
        description: step.description,
        side: step.side ?? "bottom",
        align: "start" as const,
      },
    }));

  // Fallback centered intro when no regions mounted yet.
  const driveSteps = steps.length > 0 ? steps : [{
    popover: {
      title: "Dashboard tour",
      description:
        "Open the Dashboard to walk through runners, host resources, and workflow runs.",
    },
  }];

  return driver({
    showProgress: true,
    progressText: "{{current}} / {{total}}",
    nextBtnText: "Next",
    prevBtnText: "Back",
    doneBtnText: "Done",
    animate: !prefersReducedMotion(),
    overlayColor: "rgb(16 22 14)",
    overlayOpacity: 0.45,
    stagePadding: 8,
    stageRadius: 12,
    popoverClass: "sentinel-driver",
    allowKeyboardControl: true,
    allowClose: true,
    smoothScroll: !prefersReducedMotion(),
    skipMissingElement: true,
    steps: driveSteps,
    onDestroyed: () => {
      writeFlag(TOUR_SEEN_KEY, true);
      writeFlag(TOUR_BANNER_DISMISSED_KEY, true);
      // Return focus to a sensible control after Esc / Done.
      const replay = document.querySelector<HTMLElement>(
        "[data-tour-replay]",
      );
      const bannerBtn = document.querySelector<HTMLElement>(
        "[data-tour-start]",
      );
      (replay ?? bannerBtn)?.focus();
    },
    onPopoverRender: (popover) => {
      // Improve a11y: treat popover as a dialog; Driver.js lacks a full focus trap.
      const root = popover.wrapper;
      root.setAttribute("role", "dialog");
      root.setAttribute("aria-modal", "true");
      if (popover.title) {
        popover.title.id ||= "sentinel-driver-title";
        root.setAttribute("aria-labelledby", popover.title.id);
      }
      if (popover.description) {
        popover.description.id ||= "sentinel-driver-desc";
        root.setAttribute("aria-describedby", popover.description.id);
      }
      // Prefer focusing the primary action for keyboard users.
      queueMicrotask(() => {
        popover.nextButton?.focus();
      });
    },
  });
}

/**
 * Client-only Driver.js tour + optional first-run banner.
 * Mount on authenticated pages that expose `data-tour` regions (dashboard).
 */
export default function ProductTour(props: ProductTourProps) {
  const showBannerProp = props.showBanner ?? true;
  const driverRef = useRef<Driver | null>(null);
  const [bannerVisible, setBannerVisible] = useState(false);

  const destroyTour = () => {
    driverRef.current?.destroy();
    driverRef.current = null;
  };

  const startTour = () => {
    destroyTour();
    const d = buildDriver();
    driverRef.current = d;
    d.drive();
    writeFlag(TOUR_BANNER_DISMISSED_KEY, true);
    setBannerVisible(false);
  };

  const dismissBanner = () => {
    writeFlag(TOUR_BANNER_DISMISSED_KEY, true);
    setBannerVisible(false);
  };

  useEffect(() => {
    const params = new URLSearchParams(globalThis.location.search);
    const forceTour = params.get(TOUR_QUERY) === "1";
    const seen = readFlag(TOUR_SEEN_KEY);
    const bannerDismissed = readFlag(TOUR_BANNER_DISMISSED_KEY);

    if (forceTour) {
      // Clean the query so refresh does not re-loop the tour.
      params.delete(TOUR_QUERY);
      const next = params.toString();
      const url = `${globalThis.location.pathname}${
        next ? `?${next}` : ""
      }${globalThis.location.hash}`;
      globalThis.history.replaceState({}, "", url);
      // Defer until layout paint so data-tour nodes exist.
      const t = globalThis.setTimeout(() => startTour(), 80);
      return () => {
        globalThis.clearTimeout(t);
        destroyTour();
      };
    }

    if (showBannerProp && !seen && !bannerDismissed) {
      setBannerVisible(true);
    }

    return () => destroyTour();
    // Mount-once: first-run + ?tour=1 only.
  }, []);

  if (!bannerVisible) return null;

  return (
    <aside
      class="glass fade-rise flex flex-wrap items-center justify-between gap-3 rounded-xl px-4 py-3"
      aria-label="Getting started"
    >
      <div class="min-w-0">
        <p class="font-sans text-sm font-semibold text-fg-strong">
          New here? Take a short tour
        </p>
        <p class="mt-0.5 text-sm text-muted">
          Walk through runners, host resources, and workflow runs. You can
          replay it anytime from Help.
        </p>
      </div>
      <div class="flex shrink-0 flex-wrap gap-2">
        <Button
          type="button"
          variant="primary"
          class="!py-1.5"
          data-tour-start
          onClick={startTour}
        >
          Start tour
        </Button>
        <Button
          type="button"
          variant="ghost"
          class="!py-1.5"
          onClick={dismissBanner}
        >
          Dismiss
        </Button>
      </div>
    </aside>
  );
}
