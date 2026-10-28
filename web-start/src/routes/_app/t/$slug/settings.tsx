import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/t/$slug/settings")({
  component: () => <Page id="todo" title="Settings"><p>Not moved yet.</p></Page>,
});
