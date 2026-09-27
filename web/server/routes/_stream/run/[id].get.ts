// Live run updates for the browser as server-sent events. This process
// holds the controller's long poll (`GET /runs/{id}/wait`) on the
// browser's behalf and pushes a `run` event each time the run's version
// changes; the browser keeps one idle stream open instead of polling.
//
// Events: `run` (the run document), `status` ({busy|reconnecting|live}),
// `refused` (the controller's error: the session ended or access was
// removed; the stream then ends), `finished` (every job is terminal).
export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, "id") || "";
  if (!RUN_ID.test(id)) throw createError({ statusCode: 400, statusMessage: "malformed run id" });
  const stream = createEventStream(event);
  const controller = new AbortController();
  stream.onClosed(() => controller.abort());
  const signal = controller.signal;

  (async () => {
    let version: string | null = null;
    let backoff = 500;
    let state = "live";
    const status = async (next: string) => {
      if (next === state) return;
      state = next;
      await stream.push({ event: "status", data: next });
    };
    while (!signal.aborted) {
      let answer;
      try {
        answer = await upstream(event, `/api/v1/runs/${id}/wait?timeout_ms=25000${version ? `&since=${version}` : ""}`, signal);
      } catch {
        if (signal.aborted) break;
        await status("reconnecting");
        await sleep(backoff, signal);
        backoff = Math.min(backoff * 2, 15000);
        continue;
      }
      if (answer.status === 429 || answer.status >= 500) {
        await status(answer.status === 429 ? "busy" : "reconnecting");
        const wait = Math.max(answer.body?.details?.retry_after_ms ?? 0, backoff);
        await sleep(wait * (0.8 + Math.random() * 0.4), signal);
        backoff = Math.min(backoff * 2, 15000);
        continue;
      }
      if (answer.status !== 200) {
        await stream.push({ event: "refused", data: JSON.stringify(answer.body ?? { code: "http_" + answer.status }) });
        break;
      }
      backoff = 500;
      await status("live");
      if (answer.body.changed || version === null) await stream.push({ event: "run", data: JSON.stringify(answer.body.run) });
      else await stream.push(":");
      version = answer.body.version;
      if (answer.body.finished) {
        await stream.push({ event: "finished", data: "{}" });
        break;
      }
    }
    await stream.close();
  })().catch(() => stream.close());

  return stream.send();
});
