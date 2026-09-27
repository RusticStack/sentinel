// Every page but sign-in needs a session. The first render happens on the
// server with the browser's cookie, so a signed-out visitor is sent to
// sign-in before any page is drawn.
export default defineNuxtRouteMiddleware(async (to) => {
  const session = useSession();
  const me = await session.load();
  if (to.path === "/login") {
    if (me) return navigateTo(typeof to.query.next === "string" && to.query.next.startsWith("/") ? to.query.next : "/");
    return;
  }
  if (!me) return navigateTo({ path: "/login", query: to.fullPath === "/" ? {} : { next: to.fullPath } });
  const slug = to.params.slug;
  if (typeof slug === "string") useState("tenant").value = slug;
});
