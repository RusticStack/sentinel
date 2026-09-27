<script setup lang="ts">
import type { LogPage, StepRecord } from "~~/shared/types/api";

// The log viewer mounted in the page (browser only: it measures and
// scrolls the DOM). Deep links (`?step=&seq=&q=`) open at their line.
const props = defineProps<{
  attempt: string;
  run: string;
  steps: { index: number; id: string }[];
  outcomes: StepRecord[] | null;
  complete: boolean;
}>();
const emit = defineEmits<{ refused: [string] }>();
const host = ref<HTMLElement | null>(null);
const route = useRoute();
const router = useRouter();
const api = useApi();
const announcer = useState("announce", () => "");
let viewer: LogViewer | null = null;

function jumpTo(query: Record<string, any>) {
  if (viewer && query.seq !== undefined) viewer.jump(Number(query.step || 0), Number(query.seq), typeof query.q === "string" ? query.q : null);
}

onMounted(() => {
  viewer = new LogViewer(host.value!, {
    attempt: props.attempt,
    run: props.run,
    steps: props.steps,
    outcomes: props.outcomes,
    complete: props.complete,
    page: (q) => api<LogPage>(`/api/v1/attempts/${props.attempt}/logs?${q}`),
    search: (q) => api(`/api/v1/attempts/${props.attempt}/logs/search?${q}`),
    announce: (text) => { announcer.value = ""; requestAnimationFrame(() => (announcer.value = text)); },
    refused: (body) => emit("refused", body?.code === "unauthenticated" ? "Your session ended." : "You no longer have access to this log."),
    linked: (step, seq, q) => router.replace({ query: { step, seq, ...(q ? { q } : {}) } }),
  });
  if (route.query.seq !== undefined) jumpTo(route.query);
  else if (!props.complete) viewer.followLive();
  else viewer.schedule();
});
watch(() => route.query, (q) => jumpTo(q));
onBeforeUnmount(() => viewer?.destroy());
</script>

<template>
  <div ref="host" class="log" />
</template>
