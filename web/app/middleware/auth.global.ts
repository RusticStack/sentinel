// The first render runs on the server with the browser's cookie, so a signed-out visitor is redirected before any page draws.

const PUBLIC = new Set(["/login", "/register", "/verify-email", "/forgot-password", "/setup", "/invitations/accept"]);
const SIGNED_OUT_ONLY = new Set(["/login", "/register"]);

export default defineNuxtRouteMiddleware(async (to) => {
  const session = useSession();
  const me = await session.load();
  if (to.path === "/login" || to.path === "/setup") {
    const open = await useSetupStatus().isOpen();
    if (to.path === "/setup") return open ? undefined : navigateTo(me ? "/" : "/login", { replace: true });
    if (open && !me) return navigateTo("/setup", { replace: true });
  }
  if (SIGNED_OUT_ONLY.has(to.path) && me) return navigateTo(sameOriginPath(to.query.next));
  if (PUBLIC.has(to.path)) return;
  if (!me) return navigateTo({ path: "/login", query: to.fullPath === "/" ? {} : { next: to.fullPath } });
  const slug = to.params.slug;
  if (typeof slug === "string") useState("tenant").value = slug;
});
