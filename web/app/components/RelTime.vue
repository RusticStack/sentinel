<script setup lang="ts">
// A time as relative text, with the absolute time for the curious. The
// server and the first browser render show the same UTC clock time (the
// two clocks differ); once mounted it turns relative and ticks every 15 s.
const props = defineProps<{ ms: number | null | undefined }>();
const now = ref<number | null>(null);
let timer: ReturnType<typeof setInterval> | undefined;
onMounted(() => { now.value = Date.now(); timer = setInterval(() => (now.value = Date.now()), 15000); });
const text = computed(() => {
  if (!props.ms) return "—";
  if (now.value === null) return `${new Date(props.ms).toISOString().slice(11, 19)} UTC`;
  return fmtAgo(props.ms, now.value);
});
onBeforeUnmount(() => clearInterval(timer));
const iso = computed(() => (props.ms ? new Date(props.ms).toISOString() : undefined));
</script>

<template>
  <time v-if="ms" :datetime="iso" :title="iso" class="whitespace-nowrap">{{ text }}</time>
  <span v-else class="text-muted">—</span>
</template>
