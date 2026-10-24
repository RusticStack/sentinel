// The server-side render may not get to clear the return cookie when it redirects, so it is cleared here.
export default defineNuxtPlugin((nuxtApp) => {
  nuxtApp.hook("app:mounted", () => {
    if (new RegExp(`(?:^|; )${RETURN_COOKIE}=`).test(document.cookie)) rememberReturn(null);
    try {
      const raw = sessionStorage.getItem(INVITATION_STASH);
      if (raw !== null && unstashInvitation(raw, Date.now()) === null) sessionStorage.removeItem(INVITATION_STASH);
    } catch { /* storage off: nothing was parked */ }
  });
});
