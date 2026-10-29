// GitHub returns here after the App is installed; the controller checks the installation belongs to the App and
// binds it to the namespace the setup was started for.
import { useEffect, useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { api, ApiError } from "../../../../lib/api.ts";
import { refusal } from "../../../../lib/act.tsx";
import { refreshTenants } from "../../../../lib/session.ts";
import { INSTALL_REFUSAL, INSTALLATION, SETUP_ACTION, STATE } from "../../../../lib/githubApp.ts";
import { Page } from "../../../../components/Page.tsx";
import { Alert, ButtonLink } from "../../../../components/ui.tsx";

export const Route = createFileRoute("/_app/setup/github/installed")({
  head: () => ({ meta: [{ title: "GitHub App installed · Sentinel" }] }),
  component: Installed,
});

type Outcome = { kind: "working" } | { kind: "done"; tenant: string; account: string } | { kind: "refused"; text: string } | { kind: "requested" };

function Installed() {
  const [outcome, setOutcome] = useState<Outcome>({ kind: "working" });
  const once = useRef(false);
  useEffect(() => {
    if (once.current) return;
    once.current = true;
    const p = new URLSearchParams(location.search);
    const id = p.get("installation_id") ?? "", action = p.get("setup_action") ?? "", state = p.get("state") ?? "";
    history.replaceState(history.state, "", location.pathname);
    // A member without rights on GitHub can only request the installation; an owner approves it there.
    if (action === "request") { setOutcome({ kind: "requested" }); return; }
    if (!INSTALLATION.test(id) || !SETUP_ACTION.test(action) || !STATE.test(state)) {
      setOutcome({ kind: "refused", text: "This address does not carry a usable answer from GitHub. Start the installation from your namespace again." });
      return;
    }
    api<{ tenant: string; account: string }>("/api/v1/github/app/installation", { method: "POST", body: { installation_id: Number(id), setup_action: action, state } }).then(
      (r) => { setOutcome({ kind: "done", tenant: r.tenant, account: r.account }); void refreshTenants(); },
      (e) => {
        const err = e as ApiError;
        const why = INSTALL_REFUSAL[String(err.details?.reason ?? "")];
        setOutcome({ kind: "refused", text: why ? `The installation could not be connected. ${why}` : err.code === "conflict"
          ? (err.details?.reason === "not_configured" ? "This deployment has no GitHub App configured." : "That installation is already connected to another namespace.")
          : err.code === "not_found"
            ? "The installation could not be connected: it was started by another session or namespace, it expired, or it was already used."
            : `The installation could not be connected: ${refusal(err)}.` });
      },
    );
  }, []);
  return (
    <Page id="github-installed" title="GitHub App installed">
      {outcome.kind === "working" ? <p role="status" className="text-sm text-muted">Connecting the installation…</p>
        : outcome.kind === "requested" ? <Alert color="info" role="status" title="Installation requested" description="An owner of the GitHub organization has to approve it on GitHub. Once approved, GitHub tells Sentinel." />
        : outcome.kind === "refused" ? <Alert color="error" role="alert" title={outcome.text}><ButtonLink to="/setup/github" size="sm" variant="outline" color="neutral" label="Back to the GitHub App" /></Alert>
        : (
          <Alert color="success" role="status" title={`Connected ${outcome.account} to ${outcome.tenant}`} description="Its repositories can now be bound in the namespace's administration.">
            <ButtonLink to={`/t/${outcome.tenant}/settings`} size="sm" label="Open the namespace settings" />
          </Alert>
        )}
    </Page>
  );
}
