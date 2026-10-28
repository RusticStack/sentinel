// Server render only: reads go straight to the controller with the browser's own credentials. The server render
// never mutates, so it never needs the CSRF secret.
import { getRequest } from "@tanstack/react-start/server";
import { forwarded, sentinelApi } from "../server/upstream.ts";
import { ApiError, type ApiOptions } from "./api.ts";

export async function serverApi(path: string, opts: ApiOptions): Promise<unknown> {
  if ((opts.method || "GET") !== "GET") throw new Error("the server render only reads");
  const request = getRequest();
  let response: Response;
  try {
    response = await fetch(sentinelApi() + path, { headers: { ...forwarded(request), ...opts.headers }, signal: opts.signal });
  } catch {
    throw new ApiError(0, null);
  }
  const text = await response.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  if (!response.ok) throw new ApiError(response.status, body);
  return body;
}

export function requestCookie(name: string): string | null {
  const header = getRequest().headers.get("cookie") || "";
  const m = new RegExp(`(?:^|; )${name}=([^;]*)`).exec(header);
  if (!m) return null;
  try { return decodeURIComponent(m[1]!); } catch { return null; }
}
