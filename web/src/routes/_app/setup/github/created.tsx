// GitHub returns here after creating the App, with a one-hour code that anyone holding it could exchange for the
// App's credentials. The page takes it out of the address bar at once and hands it to the controller, which
// exchanges it and keeps the credentials; this page never sees them.
import { useEffect, useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { api, ApiError } from "../../../../lib/api.ts";
import { refusal } from "../../../../lib/act.tsx";
import { CODE, STATE, type GithubAppFacts } from "../../../../lib/githubApp.ts";
import { Page } from "../../../../components/Page.tsx";
import { Alert, ButtonLink } from "../../../../components/ui.tsx";

export const Route = createFileRoute("/_app/setup/github/created")({
  head: () => ({ meta: [{ title: "GitHub App created · Sentinel" }] }),
  component: Created,
});

type Outcome = { kind: "working" } | { kind: "done"; app: GithubAppFacts; install: string } | { kind: "refused"; text: string };

function Created() {
  const [outcome, setOutcome] = useState<Outcome>({ kind: "working" });
  const once = useRef(false);
  useEffect(() => {
    if (once.current) return;
    once.current = true;
    const params = new URLSearchParams(location.search);
    const code = params.get("code") ?? "", state = params.get("state") ?? "";
    history.replaceState(history.state, "", location.pathname);
    if (!CODE.test(code) || !STATE.test(state)) { setOutcome({ kind: "refused", text: "This address does not carry a usable answer from GitHub." }); return; }
    api<{ app: GithubAppFacts; install_url: string }>("/api/v1/github/app/conversion", { method: "POST", body: { code, state } }).then(
      (r) => setOutcome({ kind: "done", app: r.app, install: r.install_url }),
      (e) => {
        const err = e as ApiError;
        setOutcome({ kind: "refused", text: err.code === "not_found" || err.code === "forbidden"
          ? "The setup could not be finished: it was started by another session, it expired, or it was already used. Start again from the GitHub App page; if GitHub created an App anyway, delete it on GitHub first."
          : `The setup could not be finished: ${refusal(err)}.` });
      },
    );
  }, []);
  return (
    <Page id="github-created" title="GitHub App created">
      {outcome.kind === "working" ? <p role="status" className="text-sm text-muted">Finishing the setup with GitHub…</p>
        : outcome.kind === "refused" ? <Alert color="error" role="alert" title={outcome.text}><ButtonLink to="/setup/github" size="sm" variant="outline" color="neutral" label="Back to the GitHub App" /></Alert>
        : (
          <div className="space-y-4">
            <Alert color="success" role="status" title={`${outcome.app.name} is ready`} description="The controller stored its credentials. Install it on the GitHub organization or account whose repositories Sentinel should build." />
            {outcome.install.startsWith("https://") ? <a className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary" href={outcome.install}>Install the App on GitHub</a> : null}
          </div>
        )}
    </Page>
  );
}
