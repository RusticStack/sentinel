import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/_auth/forgot-password")({
  component: () => <h1>Forgot your password?</h1>,
});
