export function useRetryWait() {
  const until = ref(0);
  const now = ref(0);
  let ticker: ReturnType<typeof setInterval> | undefined;
  const waiting = computed(() => Math.max(0, Math.ceil((until.value - now.value) / 1000)));

  function start(source: ApiError | number) {
    const ms = typeof source === "number" ? source : Number(source.details?.retry_after_ms ?? 2000);
    now.value = Date.now();
    until.value = now.value + Math.max(1000, ms);
    clearInterval(ticker);
    ticker = setInterval(() => {
      now.value = Date.now();
      if (now.value >= until.value) clearInterval(ticker);
    }, 1000);
  }

  onBeforeUnmount(() => clearInterval(ticker));
  return { waiting, start };
}
