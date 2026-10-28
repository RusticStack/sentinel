// Live updates as server-sent events (docs/web-ui.md, "Live updates"). The event names, ids and payloads are
// the ones the Nuxt interface sent, so the browser code and Last-Event-ID resumption are unchanged.
import { ATTEMPT_ID, RUN_ID, sleep, upstream } from "./upstream.ts";

const encoder = new TextEncoder();

function eventStream(request: Request, body: (push: (e: { event?: string; id?: string; data?: string; comment?: boolean }) => void, signal: AbortSignal) => Promise<void>): Response {
  const controller = new AbortController();
  request.signal.addEventListener("abort", () => controller.abort(), { once: true });
  const stream = new ReadableStream<Uint8Array>({
    start(sink) {
      const push = (e: { event?: string; id?: string; data?: string; comment?: boolean }) => {
        if (controller.signal.aborted) return;
        let text = "";
        if (e.comment) text = ":\n\n";
        else {
          if (e.id) text += `id: ${e.id}\n`;
          if (e.event) text += `event: ${e.event}\n`;
          for (const line of (e.data ?? "").split("\n")) text += `data: ${line}\n`;
          text += "\n";
        }
        try { sink.enqueue(encoder.encode(text)); } catch { controller.abort(); }
      };
      body(push, controller.signal).catch(() => {}).finally(() => { try { sink.close(); } catch { /* closed */ } });
    },
    cancel() { controller.abort(); },
  });
  return new Response(stream, {
    headers: { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive", "x-accel-buffering": "no" },
  });
}

const bad = (text: string) => new Response(text, { status: 400, headers: { "content-type": "text/plain; charset=utf-8" } });

// Pushes a run event only when the version changes, so the browser keeps one idle stream instead of polling.
export function runStream(request: Request, id: string): Response {
  if (!RUN_ID.test(id)) return bad("malformed run id");
  return eventStream(request, async (push, signal) => {
    let version: string | null = null;
    let backoff = 500;
    let state = "live";
    const status = (next: string) => { if (next !== state) { state = next; push({ event: "status", data: next }); } };
    while (!signal.aborted) {
      let answer;
      try {
        answer = await upstream(request, `/api/v1/runs/${id}/wait?timeout_ms=25000${version ? `&since=${version}` : ""}`, signal);
      } catch {
        if (signal.aborted) break;
        status("reconnecting");
        await sleep(backoff, signal);
        backoff = Math.min(backoff * 2, 15000);
        continue;
      }
      if (answer.status === 429 || answer.status >= 500) {
        status(answer.status === 429 ? "busy" : "reconnecting");
        const wait = Math.max(answer.body?.details?.retry_after_ms ?? 0, backoff);
        await sleep(wait * (0.8 + Math.random() * 0.4), signal);
        backoff = Math.min(backoff * 2, 15000);
        continue;
      }
      if (answer.status !== 200) {
        push({ event: "refused", data: JSON.stringify(answer.body ?? { code: "http_" + answer.status }) });
        break;
      }
      backoff = 500;
      status("live");
      if (answer.body.changed || version === null) push({ event: "run", data: JSON.stringify(answer.body.run) });
      else push({ comment: true });
      version = answer.body.version;
      if (answer.body.finished) {
        push({ event: "finished", data: "{}" });
        break;
      }
    }
  });
}

// Event ids are `step:seq`, so Last-Event-ID resumes exactly after the last frame received.
export function logStream(request: Request, attempt: string, query: URLSearchParams): Response {
  if (!ATTEMPT_ID.test(attempt)) return bad("malformed attempt id");
  let step = Number(query.get("step") ?? 0);
  let after = Number(query.get("after") ?? 0);
  const last = request.headers.get("last-event-id");
  if (last && /^\d+:\d+$/.test(last)) [step, after] = last.split(":").map(Number) as [number, number];
  if (!Number.isSafeInteger(step) || step < 0 || !Number.isSafeInteger(after) || after < 0) return bad("malformed position");
  return eventStream(request, async (push, signal) => {
    let backoff = 500;
    let state = "live";
    const status = (next: string) => { if (next !== state) { state = next; push({ event: "status", data: next }); } };
    while (!signal.aborted) {
      let page;
      try {
        page = await upstream(request, `/api/v1/attempts/${attempt}/logs?step=${step}&after=${after}&limit=500&wait=1`, signal);
      } catch {
        if (signal.aborted) break;
        status("reconnecting");
        await sleep(backoff, signal);
        backoff = Math.min(backoff * 2, 15000);
        continue;
      }
      if (page.status === 429 || page.status >= 500) {
        status(page.status === 429 ? "busy" : "reconnecting");
        const wait = Math.max(page.body?.details?.retry_after_ms ?? 0, backoff);
        await sleep(wait * (0.8 + Math.random() * 0.4), signal);
        backoff = Math.min(backoff * 2, 15000);
        continue;
      }
      if (page.status !== 200) {
        push({ event: "refused", data: JSON.stringify(page.body ?? { code: "http_" + page.status }) });
        break;
      }
      backoff = 500;
      status("live");
      const frames = page.body.frames as { seq: number }[];
      if (frames.length) after = Math.max(after, frames[frames.length - 1]!.seq);
      const next = page.body.next_after;
      if (next !== null && next !== undefined) after = Math.max(after, next);
      if (frames.length) push({ id: `${step}:${after}`, event: "frames", data: JSON.stringify({ step, frames, gaps: page.body.gaps }) });
      if (page.body.complete && (next === null || next === undefined)) {
        // The step is read to its end; later steps may still hold frames.
        if (!page.body.step_done && !frames.length) {
          push({ event: "complete", data: JSON.stringify({ gaps: page.body.gaps }) });
          break;
        }
      }
      if (page.body.step_done && (next === null || next === undefined)) {
        push({ id: `${step + 1}:${after}`, event: "step_done", data: JSON.stringify({ step }) });
        step += 1;
      }
    }
  });
}
