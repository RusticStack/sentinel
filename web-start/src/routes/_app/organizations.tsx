import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../components/Page.tsx";

export const Route = createFileRoute("/_app/organizations")({
  component: () => <Page id="todo" title="Organizations"><p>Not moved yet.</p></Page>,
});
