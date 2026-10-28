import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/runs/$id/")({
  component: () => <Page id="todo" title="Run"><p>Not moved yet.</p></Page>,
});
