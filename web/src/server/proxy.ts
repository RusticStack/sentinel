// The controller's own routes, passed through with their cookies, redirects and bodies (docs/web-ui.md, "One origin").
import { BODY_METHODS, type ProxyVerdict } from "./guard.ts";
import { capBody, sentinelApi, upstreamHeaders } from "./upstream.ts";

const status = (code: number, text: string) => new Response(text, { status: code, headers: { "content-type": "text/plain; charset=utf-8" } });

// Node's fetch decodes a compressed body, so the encoding and length it came with no longer apply.
const DROP = ["content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"];

export async function proxy(request: Request, path: string, verdict: Extract<ProxyVerdict, { kind: "proxy" }>): Promise<Response> {
  const init: RequestInit & { duplex?: "half" } = { method: request.method, redirect: "manual", headers: upstreamHeaders(request) };
  const exceeded = { value: false };
  if (BODY_METHODS.has(request.method)) {
    const declared = Number(request.headers.get("content-length"));
    if (declared > verdict.limit) return status(413, "Payload Too Large");
    if (request.body) {
      init.body = capBody(request.body, verdict.limit, exceeded);
      init.duplex = "half";
    }
  }
  let answer: Response;
  try {
    answer = await fetch(sentinelApi() + path, init);
  } catch {
    // Never relay a truncated body: an aborted or oversized upload must fail whole.
    return exceeded.value ? status(413, "Payload Too Large") : status(502, "Bad Gateway");
  }
  const headers = new Headers(answer.headers);
  if (answer.headers.has("content-encoding")) for (const name of DROP) headers.delete(name);
  else for (const name of DROP.slice(2)) headers.delete(name);
  return new Response(answer.body, { status: answer.status, statusText: answer.statusText, headers });
}
