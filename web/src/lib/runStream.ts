// The run page follows its run through one EventSource; EventSource reconnects by itself, so there is no manual retry.
import { useEffect, useState } from "react";
import type { Run } from "./types";
import { ended, refreshTenants } from "./session.ts";
import { toast } from "./overlay.tsx";

export type StreamStatus = "live" | "busy" | "reconnecting" | "lost" | "finished" | "refused";

export function useRunStream(id: string, initial: Run, onRun: (run: Run) => void) {
  const [status, setStatus] = useState<StreamStatus>("live");
  const [refused, setRefused] = useState<string | null>(null);
  useEffect(() => {
    setRefused(null);
    if (initial.jobs.every((j) => j.terminal)) { setStatus("finished"); return; }
    setStatus("live");
    let current: StreamStatus = "live";
    const set = (s: StreamStatus) => { current = s; setStatus(s); };
    const source = new EventSource(`/_stream/run/${id}`);
    source.addEventListener("run", (e) => { onRun(JSON.parse((e as MessageEvent).data)); set("live"); });
    source.addEventListener("status", (e) => {
      const next = (e as MessageEvent).data as StreamStatus;
      if (current === "busy" && next === "live") toast({ title: "Updates resumed", color: "info", icon: "radio" });
      set(next);
    });
    source.addEventListener("finished", () => { set("finished"); source.close(); });
    source.addEventListener("refused", (e) => {
      source.close();
      const body = JSON.parse((e as MessageEvent).data || "{}");
      set("refused");
      setRefused(body.code === "unauthenticated" ? "Your session ended." : "You no longer have access to this run.");
      if (body.code === "unauthenticated") void ended();
      else void refreshTenants();
    });
    source.onerror = () => { if (source.readyState !== EventSource.CLOSED) set("lost"); };
    source.onopen = () => { if (current === "lost") set("live"); };
    return () => source.close();
    // The stream is per run; a new run id opens a new one.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);
  return { status, refused };
}
