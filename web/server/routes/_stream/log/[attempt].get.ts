// Event ids are `step:seq`, so Last-Event-ID resumes exactly after the last frame received.
export default defineEventHandler(async (event) => {
  const attempt = getRouterParam(event, "attempt") || "";
  if (!ATTEMPT_ID.test(attempt)) throw createError({ statusCode: 400, statusMessage: "malformed attempt id" });
  const query = getQuery(event);
  let step = Number(query.step ?? 0);
  let after = Number(query.after ?? 0);
  const last = getRequestHeader(event, "last-event-id");
  if (last && /^\d+:\d+$/.test(last)) {
    const [s, a] = last.split(":").map(Number);
    step = s!;
    after = a!;
  }
  if (!Number.isSafeInteger(step) || step < 0 || !Number.isSafeInteger(after) || after < 0) {
    throw createError({ statusCode: 400, statusMessage: "malformed position" });
  }
  const stream = createEventStream(event);
  const controller = new AbortController();
  stream.onClosed(() => controller.abort());
  const signal = controller.signal;

  (async () => {
    let backoff = 500;
    let state = "live";
    const status = async (next: string) => {
      if (next === state) return;
      state = next;
      await stream.push({ event: "status", data: next });
    };
    while (!signal.aborted) {
      let page;
      try {
        page = await upstream(event, `/api/v1/attempts/${attempt}/logs?step=${step}&after=${after}&limit=500&wait=1`, signal);
      } catch {
        if (signal.aborted) break;
        await status("reconnecting");
        await sleep(backoff, signal);
        backoff = Math.min(backoff * 2, 15000);
        continue;
      }
      if (page.status === 429 || page.status >= 500) {
        await status(page.status === 429 ? "busy" : "reconnecting");
        const wait = Math.max(page.body?.details?.retry_after_ms ?? 0, backoff);
        await sleep(wait * (0.8 + Math.random() * 0.4), signal);
        backoff = Math.min(backoff * 2, 15000);
        continue;
      }
      if (page.status !== 200) {
        await stream.push({ event: "refused", data: JSON.stringify(page.body ?? { code: "http_" + page.status }) });
        break;
      }
      backoff = 500;
      await status("live");
      const frames = page.body.frames as { seq: number }[];
      if (frames.length) {
        after = Math.max(after, frames[frames.length - 1]!.seq);
      }
      if (page.body.next_after !== null && page.body.next_after !== undefined) after = Math.max(after, page.body.next_after);
      if (frames.length) {
        await stream.push({ id: `${step}:${after}`, event: "frames", data: JSON.stringify({ step, frames, gaps: page.body.gaps }) });
      }
      if (page.body.complete && (page.body.next_after === null || page.body.next_after === undefined)) {
        // The step is read to its end; later steps may still hold frames.
        if (!page.body.step_done && !frames.length) {
          await stream.push({ event: "complete", data: JSON.stringify({ gaps: page.body.gaps }) });
          break;
        }
      }
      if (page.body.step_done && (page.body.next_after === null || page.body.next_after === undefined)) {
        await stream.push({ id: `${step + 1}:${after}`, event: "step_done", data: JSON.stringify({ step }) });
        step += 1;
      }
    }
    await stream.close();
  })().catch(() => stream.close());

  return stream.send();
});
