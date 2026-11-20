// The provider policy, as code: which provider a request may be sent to, and what it must
// carry when it is. The controller decides the same thing at admission
// (`sentinel_store::ai::admit`) and this is the second half of that decision, because
// `zero_retention` is a property of the request sent, not of the provider row.
//
// Two rules are enforced structurally rather than checked before use:
//
// - A `local_only` tenant is only ever given the `local` provider, and the `local` endpoint
//   is refused at construction unless it stays inside the operator's own network. A public
//   address therefore cannot be built for such a tenant at all.
// - OpenRouter always carries `provider.zdr: true`, and `data_collection: deny` under
//   `zero_retention`. Nothing else in the package can construct an OpenRouter request.

/** The four providers a deployment may allow, in the order the controller lists them. */
export type ProviderName = "local" | "openrouter" | "anthropic" | "openai";

export const PROVIDERS: readonly ProviderName[] = ["local", "openrouter", "anthropic", "openai"];

export function parseProvider(text: string): ProviderName | null {
  return (PROVIDERS as readonly string[]).includes(text) ? (text as ProviderName) : null;
}

/** What a tenant's opt-in commits to on the provider's side (`docs/ai.md`). */
export type DataPolicy = "local_only" | "zero_retention" | "provider_terms";

export function parseDataPolicy(text: string): DataPolicy | null {
  return text === "local_only" || text === "zero_retention" || text === "provider_terms" ? text : null;
}

/** What a request is admitted as: the provider, the model, and the switches it must carry. */
export interface Admission {
  readonly provider: ProviderName;
  readonly model: string;
  readonly policy: DataPolicy;
  /** OpenRouter's zero-data-retention switch. On for every request, whatever the policy. */
  readonly zdr: boolean;
  /** OpenRouter's `data_collection: deny`. On under `zero_retention`, which is what it promises. */
  readonly denyCollection: boolean;
}

/** Why a request may not be made. Every one of these ends it as `unavailable`. */
export type Refusal =
  | { readonly reason: "provider"; readonly provider: string }
  | { readonly reason: "policy"; readonly provider: ProviderName; readonly policy: DataPolicy }
  | { readonly reason: "model" };

/** Whether `policy` may use `provider` at all. */
export function allows(policy: DataPolicy, provider: ProviderName): boolean {
  switch (policy) {
    case "local_only":
      return provider === "local";
    case "zero_retention":
      // The local endpoint keeps nothing because it is ours; OpenRouter keeps nothing because
      // every request says so. The direct APIs have no per-request retention switch, so a
      // request to them could not be held to this policy and is refused rather than made.
      return provider === "local" || provider === "openrouter";
    case "provider_terms":
      return true;
  }
}

/** The admission for one request, or the reason there is none. */
export function admit(policy: DataPolicy, provider: string, model: string): Admission | Refusal {
  const known = parseProvider(provider);
  if (known === null) {
    return { reason: "provider", provider };
  }
  if (!allows(policy, known)) {
    return { reason: "policy", provider: known, policy };
  }
  const trimmed = model.trim();
  if (trimmed.length === 0 || trimmed.length > 128 || /[\u0000-\u001f\u007f]/.test(trimmed)) {
    return { reason: "model" };
  }
  return {
    provider: known,
    model: trimmed,
    policy,
    zdr: known === "openrouter",
    denyCollection: known === "openrouter" && policy === "zero_retention",
  };
}

const LOOPBACK = /^(localhost|127(\.\d{1,3}){3}|::1|\[::1\])$/;
const PRIVATE_V4 = [
  /^10(\.\d{1,3}){3}$/,
  /^192\.168(\.\d{1,3}){2}$/,
  /^172\.(1[6-9]|2\d|3[01])(\.\d{1,3}){2}$/,
  /^169\.254(\.\d{1,3}){2}$/,
];
const PRIVATE_V6 = /^(fc|fd|fe8|fe9|fea|feb)[0-9a-f]{0,2}:([0-9a-f]{0,4}:)*[0-9a-f]{0,4}$/;

/**
 * Whether `endpoint` stays inside the operator's own network: loopback, an address in a
 * private range, or a single-label host name (which only the operator's own resolver can
 * resolve). A public name or address is not local, and a `local_only` tenant never gets one.
 */
export function staysLocal(endpoint: string): boolean {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return false;
  }
  const host = url.hostname.replace(/\.$/, "");
  if (host.length === 0) {
    return false;
  }
  if (LOOPBACK.test(host)) {
    return true;
  }
  if (PRIVATE_V4.some((range) => range.test(host))) {
    return true;
  }
  if (host.includes(":") && PRIVATE_V6.test(host.replace(/^\[|\]$/g, ""))) {
    return true;
  }
  // A name with no dot is resolved by the operator's own resolver: never a public FQDN.
  return !host.includes(".") && !host.includes(":");
}

/** The read-only half of Sentinel's scope set: what a delegated token may hold. */
export const READ_SCOPES: readonly string[] = [
  "runs:read",
  "logs:read",
  "artifacts:read",
  "cache:read",
  "secrets:metadata",
];

/** Whether every scope in `scopes` is read-only. A delegation that is not is refused. */
export function isReadOnly(scopes: readonly string[]): boolean {
  return scopes.every((scope) => READ_SCOPES.includes(scope));
}

/** The delegated scopes a requester's scopes leave: their scopes intersected with read-only. */
export function readOnly(scopes: readonly string[]): string[] {
  return READ_SCOPES.filter((scope) => scopes.includes(scope));
}
