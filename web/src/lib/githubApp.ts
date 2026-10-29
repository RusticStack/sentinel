// The controller's GitHub App setup contract (docs/github-app.md). sentinel-web only relays: the manifest code is
// exchanged, and every App credential stored, by the controller; none of them ever reaches this process or the browser.
export interface GithubAppFacts { id: number; slug: string; name: string; html_url: string; owner: string }

export type Unreachable = "no_public_url" | "not_https" | "private_address" | "tailnet_only" | "single_label_host";

export interface GithubAppStatus {
  configured: boolean;
  source: "files" | "manifest" | null;
  app: GithubAppFacts | null;
  public_url: string | null;
  webhook_url: string | null;
  webhook_reachable: boolean;
  reason: Unreachable | null;
  can_create: boolean;
  /** Platform administrators only: why creating is refused now. */
  create_refusal?: CreateRefusal | null;
  install_url: string | null;
}

export type CreateRefusal = "files" | "configured" | "no_public_url" | "public_url_has_path" | "no_master_key" | "forbidden";

export const CREATE_REFUSAL: Record<CreateRefusal, string> = {
  files: "This controller is configured by GitHub App files on its host, which take precedence; remove them to use one-click setup.",
  configured: "This deployment already has its GitHub App.",
  no_public_url: "The controller has no public address (public_url), so there is no webhook or return address to give GitHub. Set it and restart the controller.",
  public_url_has_path: "The controller's public address has a path; GitHub's return addresses need the bare origin. Set public_url to the origin and restart the controller.",
  no_master_key: "The controller has no master key to seal the App's private key and secrets with. Create master.key on the controller host (docs/sealed-storage.md), then restart it.",
  forbidden: "Only a platform administrator can create the deployment's GitHub App.",
};

export const INSTALL_REFUSAL: Record<string, string> = {
  foreign_installation: "GitHub says that installation does not belong to this deployment's App.",
  cross_account: "The App was installed on a GitHub account that is not this namespace's.",
  not_org_owner: "Only an owner of the GitHub organization can connect it to a namespace.",
  link_github: "Link your GitHub account on the Account security page first, so Sentinel can see it is yours.",
  tenant_mismatch: "The installation belongs to a different namespace than the one it was started from.",
};

export interface ManifestStart { action_url: string; manifest: string; state: string; expires_ms: number }

export const REACHABILITY: Record<Unreachable, string> = {
  no_public_url: "The controller has no public address configured, so there is no webhook address to give GitHub.",
  not_https: "The controller's public address is not HTTPS. GitHub delivers webhooks only to an HTTPS address it can reach.",
  private_address: "The controller's public address is a private, loopback or link-local address that GitHub cannot reach from the internet.",
  tailnet_only: "The controller's public address is only reachable inside your Tailcat network; GitHub is outside it.",
  single_label_host: "The controller's public address is a single-label host name that does not resolve on the internet.",
};

export const CODE = /^[A-Za-z0-9_-]{1,128}$/;
export const STATE = /^[A-Za-z0-9_-]{16,128}$/;
export const INSTALLATION = /^[1-9][0-9]{0,15}$/;
export const SETUP_ACTION = /^(install|update|request)$/;
