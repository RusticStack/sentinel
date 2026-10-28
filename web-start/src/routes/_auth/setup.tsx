import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/_auth/setup")({
  component: () => <h1>Set up Sentinel</h1>,
});
