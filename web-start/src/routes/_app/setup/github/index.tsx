import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/setup/github/")({
  component: () => <Page id="todo" title="GitHub App"><p>Not moved yet.</p></Page>,
});
