import type { Run } from "~~/shared/types/api";

/// Keep `run` current from this server's run stream while the page is
/// open: a `run` event per change, `status` when the controller is busy or
/// unreachable, `refused` when access is gone (the page then says so and
/// the tenant list is re-read). EventSource reconnects by itself.
export function useRunStream(id: string, run: Ref<Run | null | undefined>) {
  const status = ref<"live" | "busy" | "reconnecting" | "lost" | "finished" | "refused">("live");
  const refused = ref<string | null>(null);
  const session = useSession();
  const toast = useToast();
  let source: EventSource | null = null;

  onMounted(() => {
    if (!run.value || run.value.jobs.every((j) => j.terminal)) { status.value = "finished"; return; }
    source = new EventSource(`/_stream/run/${id}`);
    source.addEventListener("run", (e) => { run.value = JSON.parse((e as MessageEvent).data); status.value = "live"; });
    source.addEventListener("status", (e) => {
      const next = (e as MessageEvent).data as "live" | "busy" | "reconnecting";
      if (status.value === "busy" && next === "live") toast.add({ title: "Updates resumed", color: "info", icon: "i-lucide-radio" });
      status.value = next;
    });
    source.addEventListener("finished", () => { status.value = "finished"; source?.close(); });
    source.addEventListener("refused", async (e) => {
      source?.close();
      const body = JSON.parse((e as MessageEvent).data || "{}");
      status.value = "refused";
      refused.value = body.code === "unauthenticated" ? "Your session ended." : "You no longer have access to this run.";
      if (body.code === "unauthenticated") await session.ended();
      else await session.refreshTenants();
    });
    source.onerror = () => { if (source?.readyState !== EventSource.CLOSED) status.value = "lost"; };
    source.onopen = () => { if (status.value === "lost") status.value = "live"; };
  });
  onBeforeUnmount(() => source?.close());
  return { status, refused };
}
