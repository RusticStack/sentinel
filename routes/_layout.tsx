import { Layout } from "../components/Layout.tsx";
import { optionalEnv } from "../lib/env.ts";
import { define } from "../utils.ts";

/**
 * Root layout: dashboard chrome when authenticated.
 * Auth routes keep the locked-gate aesthetic (no nav peek).
 */
export default define.layout(function RootLayout(ctx) {
  const path = ctx.url.pathname;
  const isAuthRoute = path === "/auth" || path.startsWith("/auth/");
  const user = ctx.state.user;

  if (!user || isAuthRoute) {
    return <ctx.Component />;
  }

  return (
    <Layout
      user={user}
      path={path}
      showSecurity={Boolean(optionalEnv("VIGIL_URL"))}
    >
      <ctx.Component />
    </Layout>
  );
});
