import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/t/$slug/")({
  component: () => <Page id="todo" title="Runs"><p>Not moved yet.</p></Page>,
});
