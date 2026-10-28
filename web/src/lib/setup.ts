import { api } from "./api.ts";

// Setup never reopens, so once closed the browser remembers it for the page's life.
let closed = false;

export async function setupOpen(): Promise<boolean> {
  if (closed && typeof window !== "undefined") return false;
  try {
    const open = (await api<{ open: boolean }>("/api/v1/setup")).open === true;
    if (!open && typeof window !== "undefined") closed = true;
    return open;
  } catch {
    // Unreachable counts as closed: sign-in then shows its own error, not a setup wizard.
    return false;
  }
}

export function markSetupClosed() { if (typeof window !== "undefined") closed = true; }
