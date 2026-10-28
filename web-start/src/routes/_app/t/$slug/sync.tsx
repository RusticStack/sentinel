import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/t/$slug/sync")({
  component: () => <Page id="todo" title="GitHub sync"><p>Not moved yet.</p></Page>,
});
