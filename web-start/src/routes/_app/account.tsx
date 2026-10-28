import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../components/Page.tsx";

export const Route = createFileRoute("/_app/account")({
  component: () => <Page id="todo" title="Account security"><p>Not moved yet.</p></Page>,
});
