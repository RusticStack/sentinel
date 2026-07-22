import { define } from "../../utils.ts";
import { isVigilConfigured, loadSecuritySnapshot } from "../../lib/vigil.ts";

/**
 * GET /api/security: Vigil SOC summary for SecurityFeed / poll fallback.
 * When VIGIL_URL is unset: `{ enabled: false }` (200) so core CI stays unaffected.
 */
export const handler = define.handlers({
  async GET(ctx) {
    if (!ctx.state.user) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    if (!isVigilConfigured()) {
      return Response.json({ enabled: false });
    }

    const snap = await loadSecuritySnapshot(12);
    return Response.json(snap ?? { enabled: false });
  },
});
