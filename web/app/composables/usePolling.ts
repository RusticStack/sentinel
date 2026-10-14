export function usePolling(refresh: () => Promise<unknown>, ms: number) {
  let timer: ReturnType<typeof setInterval> | undefined;
  onMounted(() => {
    timer = setInterval(() => { if (document.visibilityState === "visible") refresh().catch(() => {}); }, ms);
  });
  onBeforeUnmount(() => clearInterval(timer));
}
