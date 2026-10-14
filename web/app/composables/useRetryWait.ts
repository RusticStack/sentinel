/// A countdown for a `rate_limited` answer: `start(err)` (or a number of
/// milliseconds) begins it, `waiting` is the whole seconds left (0 when the
/// person may try again), and the timer stops itself and on unmount. A form
/// disables its submit button while `waiting` is non-zero and says why.
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
