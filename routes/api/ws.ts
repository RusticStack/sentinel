import { define } from "../../utils.ts";
import { buildRealtimeSnapshot } from "../../lib/realtime_push.ts";
import { REALTIME_INTERVAL_MS } from "../../lib/realtime.ts";

/**
 * GET /api/ws: auth-gated WebSocket push of system + runners + runs
 * (+ Vigil summary when VIGIL_URL is set).
 * Unauthenticated clients receive JSON 401 from middleware (or here).
 */
export const handler = define.handlers({
  GET(ctx) {
    if (!ctx.state.user) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    let pushTimer: ReturnType<typeof setInterval> | undefined;

    const clearPush = () => {
      if (pushTimer != null) {
        clearInterval(pushTimer);
        pushTimer = undefined;
      }
    };

    return ctx.upgrade({
      open(socket) {
        const push = async () => {
          if (socket.readyState !== WebSocket.OPEN) return;
          try {
            const snapshot = await buildRealtimeSnapshot();
            socket.send(JSON.stringify(snapshot));
          } catch (err) {
            const message = err instanceof Error
              ? err.message
              : "Failed to build snapshot";
            if (socket.readyState === WebSocket.OPEN) {
              socket.send(JSON.stringify({
                type: "snapshot",
                ts: Date.now(),
                system: null,
                runners: null,
                runs: null,
                vigil: null,
                errors: {
                  system: message,
                  runners: message,
                  runs: message,
                },
              }));
            }
          }
        };

        void push();
        pushTimer = setInterval(() => {
          void push();
        }, REALTIME_INTERVAL_MS);
      },
      close() {
        clearPush();
      },
      error() {
        clearPush();
      },
    }, { idleTimeout: 120 });
  },
});
