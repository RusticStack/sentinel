import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/_auth/verify-email")({
  component: () => <h1>Confirm your email address</h1>,
});
