import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../../components/Page.tsx";

export const Route = createFileRoute("/_app/setup/github/installed")({
  component: () => <Page id="todo" title="GitHub App installed"><p>Not moved yet.</p></Page>,
});
