import { recordMetricSample } from "../../lib/metric_history.ts";
import { getSystemMetrics } from "../../lib/system.ts";
import { define } from "../../utils.ts";

/**
 * GET /api/system: host CPU/RAM/disk/load/uptime (+ optional history).
 * Auth-gated by middleware (401 JSON if unauthenticated).
 */
export const handler = define.handlers({
  async GET(ctx) {
    if (!ctx.state.user) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const metrics = await getSystemMetrics();
    let history;
    try {
      history = await recordMetricSample(metrics);
    } catch {
      history = undefined;
    }
    return Response.json({ ...metrics, history });
  },
});
