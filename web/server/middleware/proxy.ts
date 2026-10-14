// Everything the controller serves itself passes through to it unchanged,
// cookies and redirects included, so the browser sees one origin. Request
// bodies are streamed under a hard cap, never buffered whole.
export default defineEventHandler(async (event) => {
  const verdict = classifyProxyPath(event.path, event.method);
  if (verdict.kind === "pass") return;
  if (verdict.kind === "reject") throw createError({ statusCode: 400, statusMessage: "Bad Request" });

  const options: { method: string; redirect: "manual"; body?: ReadableStream<Uint8Array>; duplex?: "half" } = {
    method: event.method,
    redirect: "manual",
  };
  const exceeded = { value: false };
  if (BODY_METHODS.has(event.method)) {
    const declared = Number(getRequestHeader(event, "content-length"));
    if (declared > verdict.limit) throw createError({ statusCode: 413, statusMessage: "Payload Too Large" });
    const source = getRequestWebStream(event);
    if (source) {
      options.body = capBody(source, verdict.limit, exceeded);
      options.duplex = "half";
    }
  }
  try {
    return await sendProxy(event, sentinelApi(event) + event.path, {
      headers: upstreamHeaders(event),
      fetchOptions: options,
    });
  } catch {
    // An aborted or oversized upload fails the whole request; it is never
    // relayed as a shorter body. Nothing of the error is echoed.
    if (exceeded.value) throw createError({ statusCode: 413, statusMessage: "Payload Too Large" });
    throw createError({ statusCode: 502, statusMessage: "Bad Gateway" });
  }
});
