import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/_auth/invitations/accept")({
  component: () => <h1>Invitation</h1>,
});
