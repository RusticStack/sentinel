// Leftovers of a round trip that left the interface. Once a page has loaded
// in full, a pending return has served: `/` follows it on the server, so
// whatever page drew is where the round trip led (the server-side render
// may not get to clear the cookie when it redirects). An invitation secret
// parked for GitHub sign-in is dropped once past its ten minutes, wherever
// the tab is; the accept page removes it on its own as soon as it reads it.
export default defineNuxtPlugin((nuxtApp) => {
  nuxtApp.hook("app:mounted", () => {
    if (new RegExp(`(?:^|; )${RETURN_COOKIE}=`).test(document.cookie)) rememberReturn(null);
    try {
      const raw = sessionStorage.getItem(INVITATION_STASH);
      if (raw !== null && unstashInvitation(raw, Date.now()) === null) sessionStorage.removeItem(INVITATION_STASH);
    } catch { /* storage off: nothing was parked */ }
  });
});
