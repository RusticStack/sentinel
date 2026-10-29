# API credentials

Implemented in `sentinel-auth::token` (text form), `sentinel-store::tokens` (issuance, validation, revocation) and `sentinel admin token`, with append-only metadata migration **6**.

`sntl_` credentials are the long-lived bearer form for the CLI and tooling, provisioned host-locally; [OAuth](oauth.md) is the other. They are deliberately not a development mode: a credential produces the same `Principal` a browser session does, and every tenant, repository and administrative decision is still the live check in [authorization](authorization.md). There is no unauthenticated endpoint, no local-request exemption, and nothing that constructs full authority because a caller looked trusted.

## What a credential is

A 256-bit opaque secret from the OS CSPRNG, presented as `sntl_` followed by 64 lower-case hex characters and stored only as its BLAKE3 digest. The same secret primitive as a [session](local-authentication.md); the prefix exists so secret scanners and log filters can recognize one, and so a session cookie value can never be presented as a bearer token by accident. `Authorization: Bearer <credential>` is the transport; the scheme is matched case-insensitively, the credential is not.

The secret is shown exactly once, at issuance. A lost credential is replaced, never recovered — the deployment does not hold anything that could show it again.

Every credential carries, fixed at issuance:

- **An account.** A credential never has an identity of its own; it acts as a human or a service principal.
- **A scope**, at least one bit of `read`, `run`, `secrets`, `tenant-admin`, `platform-admin`. An empty or undefined bit pattern is refused rather than defaulted.
- **Optional narrowing** to one tenant, and optionally one repository of that tenant. The database refuses a repository that the named tenant does not own, so the narrowing filter cannot be aimed across an ownership boundary.
- **A mandatory expiry**, 1 second to 90 days, defaulting to 30 days. There is no representation for "never expires" to opt into by mistake.

Only use and revocation may change afterwards. Scope, owner, expiry and identity are immutable by trigger: widening a credential means issuing a new one, and a revoked row cannot be un-revoked by a raw `UPDATE`.

## Authority

The stored scope is a **ceiling, not a grant**. Validation is one primary-key probe joined to the account, and everything that could have changed since issuance is a predicate of that same statement: revocation, expiry, the account's active flag, and a service principal's home tenant. Platform administration is then dropped unless the account still holds it, so demoting a super admin takes effect on its next request without hunting down its credentials.

What comes back is a `Principal`, and it is authorized exactly like a session's: membership and repository grants are live queries. Removing the membership behind a credential ends its access immediately, without touching the credential.

**There is no HTTP route that issues a `sntl_` credential.** The only operator surface is the host-local `sentinel admin token issue` below, which provisions through `tokens::provision` for any account within what that account may hold. The store also has `tokens::issue`, which applies the authorization layer to an issuer. No route or command calls it, so the table describes what it enforces, not an API you can reach:

| Issuer (`tokens::issue`) | May issue for |
|---|---|
| Platform admin | Any account |
| Tenant admin | A service principal of that tenant |
| Any account | Itself, never wider than the scope it is already acting under |

Over the API a bearer-style credential for a service principal is an OAuth **service grant** instead ([OAuth](oauth.md#service-account-grants)): `POST /tenants/{slug}/service-accounts/{usr}/grants`, which needs a browser session that has stepped up within the policy window ([step-up](step-up.md#issuing-credentials)); a bearer or OAuth token cannot issue one.

Delegation only narrows: a request for more than the caller holds is refused before identity is considered, so an over-wide request fails the same way for every caller. Platform scope additionally requires the target account to be a super admin, enforced by the API and by a database trigger; a service principal can never carry it, and its credential is confined to its home tenant.

Revocation is immediate and final, available to the credential's owner, a platform admin or a host-local operator. Suspending an account revokes its credentials along with its sessions, in the same transaction. Nobody can revoke, list or confirm the existence of another account's credential: those attempts return the same "not found" as a guessed identifier.

## Host-local provisioning

```sh
sentinel admin token issue --data-dir <PATH> --user root --name "laptop cli" \
    --scope read,run --tenant acme --repo app --expires-in 7d > credential
sentinel admin token list --data-dir <PATH> --user root
sentinel admin token revoke --data-dir <PATH> --id tok_...
```

The secret is the only thing written to stdout, so a redirect captures exactly the credential and nothing else; the identifier, scope and expiry an operator reads go to stderr. `--user` accepts a local username or a `usr_` identifier, `--tenant`/`--repo` take operator-facing names, and every refusal — unknown scope name, lifetime beyond the maximum, unknown account, tenant or repository, `--repo` without `--tenant`, malformed or unknown `tok_` identifier — exits 2 with a plain message. `token list` prints metadata only; no command can print an existing secret.

Authority is the operating system's, as with [bootstrap and recovery](local-authentication.md): the command opens the controller's database directly, so only a user who already has that access can provision a credential. Host-local name resolution lives in `sentinel-store::lookup`, a trusted internal beside `auth::provisioning`; it answers "which row is this name" and performs no authorization. The rule is not "no route calls it" — routes do, for example `lookup::repo_by_name` after `auth::member_tenant_by_slug` in the same transaction, or `lookup::tenant_by_slug` followed by `auth::require_repo` in the same snapshot — but that **nothing a route answers may depend on a lookup alone**: it is the first half of a decision whose second half gives a denied row the same `not_found` as an absent one, and a route whose answer would differ ("exists but not yours") resolves through `auth::member_tenant_by_slug` or `auth::narrowing_by_name`, which check live membership in the resolving statement. Naming a person in a tenant uses `auth::resolve_member`, which resolves a sign-in name only among that tenant's members.

## Verification

`crates/sentinel-store/tests/tokens.rs` covers issuance, validation, narrowing, expiry, revocation and the immutability triggers; `sentinel-auth` unit tests cover the prefixed text form and `Authorization` header parsing. Validation is a primary-key probe guarded by a query-plan test that rejects table scans and temporary sort trees; `last_used_ms` is operator visibility, not authentication, and is written at most once a minute per credential. The cost of validating and issuing a credential is timed by [`bench/auth-cost.sh`](../bench/auth-cost.sh) ([benchmarking](benchmarking.md#auth-and-credential-cost)); no record from it is committed yet.
