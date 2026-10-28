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
  install_url: string | null;
}

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
