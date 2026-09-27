/// Refresh `refresh` every `ms` while the page is open and the tab visible.
export function usePolling(refresh: () => Promise<unknown>, ms: number) {
  let timer: ReturnType<typeof setInterval> | undefined;
  onMounted(() => {
    timer = setInterval(() => { if (document.visibilityState === "visible") refresh().catch(() => {}); }, ms);
  });
  onBeforeUnmount(() => clearInterval(timer));
}
