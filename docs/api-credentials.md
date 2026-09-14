# API credentials (A03)

Implemented in `sentinel-auth::token` (text form), `sentinel-store::tokens` (issuance, validation, revocation) and `sentinel admin token`, with append-only metadata migration **6**.

This is how the CLI and the first API slice authenticate before browser OAuth (A09) exists. It is deliberately not a development mode: a credential produces the same `Principal` a browser session does, and every tenant, repository and administrative decision is still the live check in [authorization](authorization.md). There is no unauthenticated endpoint, no local-request exemption, and nothing that constructs full authority because a caller looked trusted.

## What a credential is

A 256-bit opaque secret from the OS CSPRNG, presented as `sntl_` followed by 64 lower-case hex characters and stored only as its BLAKE3 digest. The same secret primitive as an [A02 session](local-authentication.md); the prefix exists so secret scanners and log filters can recognize one, and so a session cookie value can never be presented as a bearer token by accident. `Authorization: Bearer <credential>` is the transport; the scheme is matched case-insensitively, the credential is not.

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

Issuance goes through the same layer:

| Issuer | May issue for |
|---|---|
| Host-local operator (`sentinel admin`) | Any account, within what that account may hold |
| Platform admin | Any account |
| Tenant admin | A service principal of that tenant |
| Any account | Itself, never wider than the scope it is already acting under |

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

Authority is the operating system's, as with [bootstrap and recovery](local-authentication.md): the command opens the controller's database directly, so only a user who already has that access can provision a credential. Host-local name resolution lives in `sentinel-store::lookup`, a trusted internal beside `auth::provisioning`; it answers "which row is this name" and performs no authorization, and no route may expose it.

## Cost

Measured on `DOOMBRINGER` (i7-13700KF, Ubuntu 24.04 WSL2, ext4), release build, database at `synchronous=FULL`:

| Operation | Mean |
|---|---|
| Credential validation | 1.3 µs |
| Rejection of an unknown credential | 1.0 µs |
| Issuance (durable commit) | 1.5 ms |

Validation is what every API request pays, and it is a 32-byte primary-key probe plus one key join, guarded by a query-plan test that rejects table scans and temporary sort trees. Unlike a password, a presented credential needs no key derivation: it is already high-entropy, so there is nothing to slow down and no timing signal worth equalizing. `last_used_ms` is operator visibility, not authentication, and is written at most once a minute per credential.

WSL2 is a development reference, not a production qualification.

## Verification

`crates/sentinel-store/tests/tokens.rs` uses two organizations, a tenant admin, a tenant-bound service principal and an unrelated account. It covers a host-local credential authorizing through A01 (and losing access the moment its membership is removed), the digest-only store, expiry and its bounds, refusal of empty and undefined scopes, a repository scope aimed at another tenant, platform scope requiring a super admin and being dropped on demotion, self-issue narrowing, a tenant admin issuing only for its own service principal, revocation by owner and by suspension, raw-SQL un-revoke and widening refused, another account unable to revoke or list, metadata-only listing with recorded use, audited issuance and revocation, and bounded purging. `sentinel-auth` unit tests cover the prefixed text form, rejection of a bare session-style value and `Authorization` header parsing. The `sentinel admin token` surface was exercised end to end on Linux.

See [TODO.md](../TODO.md) for commands and results, and [OAuth and secrets](auth-and-secrets.md) for the OAuth flows that will supersede host-local provisioning for humans.
