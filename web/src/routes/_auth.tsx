// The signed-out pages (sign-in, sign-up, email links, setup): one centred column.
import { createFileRoute, Outlet } from "@tanstack/react-router";

export const Route = createFileRoute("/_auth")({
  component: () => (
    <main id="main" className="flex min-h-screen items-center justify-center bg-subtle p-4">
      <Outlet />
    </main>
  ),
});
