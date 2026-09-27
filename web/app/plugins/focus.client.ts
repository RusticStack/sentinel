// After a client-side navigation, move focus to the new view's heading so
// a screen reader starts reading there, and name the tab after it. A link
// from the old single-page interface (`/#/runs/<id>`, what GitHub check
// runs point at) goes to the run.
export default defineNuxtPlugin((nuxtApp) => {
  const router = useRouter();
  const legacy = location.hash.match(/^#\/runs\/(run_[0-9a-f-]{36})$/);
  if (legacy) router.replace(`/runs/${legacy[1]}`);
  let first = true;
  nuxtApp.hook("page:finish", () => {
    if (first) { first = false; return; }
    requestAnimationFrame(() => {
      const heading = document.querySelector<HTMLElement>("main h1, [data-slot=title]");
      if (!heading) return;
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    });
  });
});
