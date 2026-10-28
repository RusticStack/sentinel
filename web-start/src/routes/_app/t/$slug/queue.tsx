import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/t/$slug/queue")({
  component: () => <Page id="todo" title="Queue"><p>Not moved yet.</p></Page>,
});
