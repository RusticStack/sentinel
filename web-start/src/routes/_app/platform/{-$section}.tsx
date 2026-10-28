import { createFileRoute } from "@tanstack/react-router";
import { Page } from "../../../components/Page.tsx";

export const Route = createFileRoute("/_app/platform/{-$section}")({
  component: () => <Page id="todo" title="Platform"><p>Not moved yet.</p></Page>,
});
