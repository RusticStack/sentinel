// One-click GitHub App setup (U17): a platform administrator creates the deployment's App from a manifest the
// controller builds; tenant administrators then install it on their GitHub organization or account.
import { useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { api, ApiError } from "../../../../lib/api.ts";
import { act } from "../../../../lib/act.tsx";
import { useSession } from "../../../../lib/session.ts";
import { CREATE_REFUSAL, REACHABILITY, type GithubAppStatus, type ManifestStart } from "../../../../lib/githubApp.ts";
import { Page } from "../../../../components/Page.tsx";
import { Alert, Badge, Button, Card, Checkbox, Field, Input } from "../../../../components/ui.tsx";

export const Route = createFileRoute("/_app/setup/github/")({
  loader: async () => {
    try {
      return { status: await api<GithubAppStatus>("/api/v1/github/app"), refusal: null as string | null };
    } catch (e) {
      const err = e as ApiError;
      return { status: null, refusal: err.status === 403 ? "forbidden" : err.status === 404 ? "unavailable" : err.message };
    }
  },
  head: () => ({ meta: [{ title: "GitHub App · Sentinel" }] }),
  component: GithubAppView,
});

const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

function GithubAppView() {
  const { status, refusal } = Route.useLoaderData();
  const { me, tenants } = useSession();
  const [kind, setKind] = useState<"user" | "organization">("organization");
  const [login, setLogin] = useState("");
  const [problem, setProblem] = useState("");
  const [busy, setBusy] = useState(false);
  const [shared, setShared] = useState(false);
  const [manifest, setManifest] = useState<ManifestStart | null>(null);
  const form = useRef<HTMLFormElement>(null);
  const admin = tenants.filter((t) => t.role === "admin");

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (kind === "organization" && !LOGIN.test(login.trim())) {
      setProblem("Enter the organization's GitHub login: letters, digits and single hyphens, up to 39 characters.");
      return;
    }
    setProblem("");
    setBusy(true);
    const owner = kind === "user" ? { kind } : { kind, login: login.trim() };
    const started = await act(me, "Create the GitHub App", () => api<ManifestStart>("/api/v1/github/app/manifest", { method: "POST", body: { owner, public: shared } }), false);
    setBusy(false);
    if (!started) return;
    // The manifest is posted to GitHub by a form, as GitHub's manifest flow requires; the page policy allows only github.com as a form target here.
    setManifest(started);
    requestAnimationFrame(() => form.current?.submit());
  }

  async function install(slug: string) {
    const answer = await act(me, `Install on ${slug}`, () => api<{ install_url: string }>(`/api/v1/tenants/${encodeURIComponent(slug)}/github/installation-url`, { method: "POST", body: {} }), false);
    if (answer?.install_url?.startsWith("https://")) window.location.assign(answer.install_url);
  }

  return (
    <Page id="github-app" title="GitHub App">
      {refusal === "forbidden" ? (
        <Alert color="warning" role="status" title="Only a platform administrator can see the deployment's GitHub App."
          description="Ask your administrator. Tenant administrators can install an App that exists from their namespace's settings." />
      ) : refusal ? (
        <Alert color="error" role="alert" title="The GitHub App status could not be read" description={refusal === "unavailable" ? "This controller does not offer the one-click setup yet." : refusal} />
      ) : status ? <>
        {status.configured && status.app ? (
          <Card title="The deployment's App" titleId="app-h">
            <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-sm">
              <dt className="text-muted">App</dt><dd><a className="text-primary underline" href={status.app.html_url} rel="noreferrer">{status.app.name}</a> <code className="text-xs">({status.app.slug})</code></dd>
              <dt className="text-muted">Owner</dt><dd>{status.app.owner}</dd>
              <dt className="text-muted">Configured by</dt><dd>{status.source === "files" ? <Badge>configuration files on the controller host</Badge> : <Badge color="success">one-click setup</Badge>}</dd>
              <dt className="text-muted">Webhook</dt><dd><code className="break-all text-xs">{status.webhook_url ?? "—"}</code></dd>
            </dl>
          </Card>
        ) : null}

        {!status.webhook_reachable ? (
          <Alert color="warning" role="status" title="GitHub cannot deliver events to this controller"
            description={<>
              <p>{status.reason ? REACHABILITY[status.reason] : "The controller's public address cannot receive GitHub webhooks."}</p>
              <p className="mt-1">The App can still be created, with its webhook registered inactive. Check runs can still be published, because publishing is a request from the controller to GitHub, but pushes and pull requests will not start runs until GitHub can reach <code>{status.webhook_url ?? "the webhook address"}</code> over HTTPS. Put the controller behind a public HTTPS address (the reverse proxy in front of sentinel-web), or start runs with the CLI or polling intake.</p>
            </>} />
        ) : null}

        {!status.configured ? (
          status.can_create ? (
            <Card title="Create the App" titleId="create-h" description="Sentinel builds the App's manifest (name, webhook address, the permissions and events it uses) and GitHub creates it on the account you choose. You confirm on GitHub; nothing is typed into a configuration file.">
              <form className="space-y-4" onSubmit={create} noValidate>
                <fieldset className="space-y-2">
                  <legend className="text-sm font-medium text-strong">Create it on</legend>
                  <label className="flex items-start gap-2 text-sm">
                    <input type="radio" name="gh-owner" value="organization" checked={kind === "organization"} onChange={() => setKind("organization")} className="mt-1 accent-[var(--s-primary)]" />
                    <span><span className="font-medium text-strong">A GitHub organization</span><span className="block text-muted">You must be an owner of it on GitHub.</span></span>
                  </label>
                  <label className="flex items-start gap-2 text-sm">
                    <input type="radio" name="gh-owner" value="user" checked={kind === "user"} onChange={() => setKind("user")} className="mt-1 accent-[var(--s-primary)]" />
                    <span><span className="font-medium text-strong">My personal GitHub account</span><span className="block text-muted">The account signed in to github.com in this browser.</span></span>
                  </label>
                </fieldset>
                {kind === "organization" ? (
                  <Field label="Organization login" htmlFor="gh-org" error={problem || undefined}>
                    <Input id="gh-org" value={login} onChange={(e) => setLogin(e.target.value)} autoCapitalize="off" spellCheck={false} placeholder="my-org" className="max-w-xs" />
                  </Field>
                ) : null}
                <Checkbox id="gh-public" checked={shared} onChange={setShared} label="Let other GitHub accounts install it"
                  description="Needed when more than one GitHub organization or account will connect to this deployment. Otherwise only the account that owns the App can install it." />
                <Button type="submit" icon="github" label="Create on GitHub" loading={busy} />
              </form>
              {manifest ? (
                <form ref={form} method="post" action={manifest.action_url} className="sr" aria-hidden="true">
                  <input type="hidden" name="manifest" value={manifest.manifest} />
                </form>
              ) : null}
            </Card>
          ) : (
            <Alert color={status.create_refusal && status.create_refusal !== "forbidden" ? "warning" : "info"} role="status" title="This deployment has no GitHub App yet"
              description={status.create_refusal ? CREATE_REFUSAL[status.create_refusal] : "A platform administrator creates it here."} />
          )
        ) : null}

        {status.configured ? (
          <Card title="Install on your namespaces" titleId="install-h" description="Installing the App on a GitHub organization or account connects its repositories to the matching Sentinel namespace. Only that namespace's administrators can do it.">
            {admin.length ? (
              <ul className="space-y-2">
                {admin.map((t) => (
                  <li key={t.slug} className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm text-strong">{t.slug}</span>
                    <Button size="sm" color="neutral" variant="outline" icon="github" label={`Install on ${t.slug}`} onClick={() => install(t.slug)} />
                  </li>
                ))}
              </ul>
            ) : <p className="text-sm text-muted">You administer no namespace.</p>}
          </Card>
        ) : null}
      </> : null}
    </Page>
  );
}
