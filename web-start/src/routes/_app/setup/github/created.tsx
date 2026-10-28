import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/setup/github/created")({
  component: () => <Page id="todo" title="GitHub App created"><p>Not moved yet.</p></Page>,
});
