import { assertEquals } from "@std/assert";
import {
  TOUR_BANNER_DISMISSED_KEY,
  TOUR_QUERY,
  TOUR_SEEN_KEY,
  TOUR_STEPS,
  tourElementSelector,
} from "./tour.ts";

Deno.test("tour steps cover core dashboard regions", () => {
  const regions = TOUR_STEPS.map((s) => s.region);
  assertEquals(regions.includes("nav"), true);
  assertEquals(regions.includes("system"), true);
  assertEquals(regions.includes("runners"), true);
  assertEquals(regions.includes("runs"), true);
  assertEquals(regions.includes("security"), true);
});

Deno.test("tourElementSelector builds data-tour hooks", () => {
  assertEquals(tourElementSelector("runners"), '[data-tour="runners"]');
});

Deno.test("tour storage keys are stable client-only identifiers", () => {
  assertEquals(TOUR_SEEN_KEY, "sentinel.tour.seen");
  assertEquals(TOUR_BANNER_DISMISSED_KEY, "sentinel.tour.bannerDismissed");
  assertEquals(TOUR_QUERY, "tour");
});
