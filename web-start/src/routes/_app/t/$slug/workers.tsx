import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/t/$slug/workers")({
  component: () => <Page id="todo" title="Workers"><p>Not moved yet.</p></Page>,
});
