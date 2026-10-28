import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/t/$slug/admin/{-$section}")({
  component: () => <Page id="todo" title="Tenant administration"><p>Not moved yet.</p></Page>,
});
