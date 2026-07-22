import { App, staticFiles, trailingSlashes } from "fresh";
import { type State } from "./utils.ts";

export const app = new App<State>({ trustProxy: true });

app.use(staticFiles());
app.use(trailingSlashes("never"));

app.fsRoutes();
