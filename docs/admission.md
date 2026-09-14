# Registration and admission (A05)

Implemented in `sentinel-store::registration` and `sentinel admin policy|invite|account`, with append-only metadata migration **8**.

Four decisions are kept apart, because conflating them is how a CI system ends up granting compute to whoever clicked "install":

| Decision | Who makes it |
|---|---|
| An account exists | The deployment's registration policy, plus an invitation if one is required |
| The account is admitted | An invitation, or a platform admin approving a pending application |
| A namespace exists | A super admin, or — under policy — an approved account creating its own personal namespace |
| A forge installation belongs to a tenant | A platform admin, or — under policy — an admin of *that* tenant |

Authenticating is none of them. [Local login](local-authentication.md) and [GitHub sign-in](github-sign-in.md) establish who you are; this document is about whether that gets you anything.

## Registration policy

One row, super-admin controlled, audited, read inside the transaction that decides an application — so a policy change that commits while an application is in flight is the one that applies.

- **`invite-only`** (the default): an unspent, unexpired invitation is required. The invitation *is* the approval, so the account is active immediately.
- **`approval-required`**: anyone may apply. Without an invitation the account is created **pending** and waits for a decision.
- **`closed`**: no new accounts, invitation or not. Outstanding invitations do not survive closing — closed means closed, and they expire on their own. Everybody already admitted keeps signing in normally: closing registration is not a lockout of the people you already have.

Two further settings: `tenant_creation` (`super-admin-only` by default, or `approved-users`) and `installation_binding` (`tenant-admins` by default, or `super-admin-only`).

```sh
sentinel admin policy show --data-dir <PATH>
sentinel admin policy set --data-dir <PATH> --registration approval-required
```

## Pending, approved, rejected

`users.status` is pending (0), approved (1) or rejected (2), and a database trigger enforces that only an approved account can be `active`. That matters more than it sounds: `active` is the predicate every authorization query in [authorization](authorization.md) already joins on, so a pending account holds no session, no tenant data and no worker access **by construction**, not because each query remembered to ask.

A pending account may *hold* the credential it registered with — otherwise approving it would leave it with no way to sign in — but holding is not using: every authentication path still requires an active account. A rejected account keeps its username and identity claimed, so a rejected applicant cannot simply reapply, and its sessions and API credentials are revoked in the same transaction as the rejection.

```sh
sentinel admin account pending --data-dir <PATH>
sentinel admin account approve --data-dir <PATH> --user alice
sentinel admin account reject  --data-dir <PATH> --user alice
```

## Invitations

A 256-bit secret stored only as its digest, presented exactly once and delivered out of band — there is no mandatory mail server, and no way to show the link again. An invitation may bind, all optional:

- **A tenant and a role**, granted as membership on acceptance. Both or neither.
- **A verified identity** (`provider:subject`), so only the person holding that GitHub account can redeem it. A local applicant cannot redeem an identity-bound invitation, and neither can a different GitHub account.
- **An expiry**, 1 second to 30 days, 7 by default. There is no open-ended invitation.

Redemption is one-use and happens in the same transaction as the account it creates, so a lost race creates nothing. The terms are immutable, and a spent or revoked invitation never becomes unspent. A platform admin may invite to any tenant or to none; a tenant admin may invite only into the tenant they administer, and cannot mint a deployment-wide invitation.

```sh
sentinel admin invite create --data-dir <PATH> --tenant acme --role operator --expires-in 7d > invite
sentinel admin invite list --data-dir <PATH>
sentinel admin invite revoke --data-dir <PATH> --id inv_...
```

The secret is the only thing on stdout, as with [API credentials](api-credentials.md); the identifier and expiry go to stderr.

## Who is deciding

Platform administration has two legitimate sources, and the audit trail tells them apart. `Authority::Credential { principal, stepped_up }` is an authenticated caller, checked live, carrying whether its session recently proved a second factor. `Authority::HostLocal` is an operator on the controller's own host, whose authority is the database file itself — the same authority that admits the first administrator. The host-local variant exists so `sentinel admin` does not have to fabricate a `Principal` for somebody who never authenticated, and every host-local decision is recorded as such.

## Installations

Seeing an installation is not trusting it. `record_installation` is trusted intake for webhook handling (G01–G02) and is idempotent, because deliveries repeat; the row it writes is **known, unbound and inactive**, resolving to no tenant. Installing the App on GitHub cannot create a tenant or allocate compute.

`bind_installation` is the decision that makes it usable, and requires administration of *that* tenant (or platform administration) plus the deployment's binding policy. An installation already bound elsewhere must be explicitly unbound first, so a repository's owner never changes underneath running work. Unbinding returns it to the known-but-inactive state rather than deleting it.

## Verification

`crates/sentinel-store/tests/registration.rs` covers the default invite-only policy refusing an uninvited application without creating an account; an invitation admitting exactly once, with replay, unknown and revoked secrets refused; expiry, revocation and lifetime bounds; tenant/role/identity binding, including a local applicant and a different GitHub account both refused; a pending account that cannot log in and cannot be issued a session even by the trusted path; approval making it work and a second approval failing; rejection revoking live sessions, refusing re-registration and resisting a raw `UPDATE` to reactivate; closing registration refusing invited and uninvited applicants alike while local login and GitHub sign-in keep working for existing accounts; policy, approval and rejection requiring platform scope rather than an ordinary session; a tenant admin inviting only into their own tenant; namespace creation refused under the default policy and allowed under `approved-users`, with one personal namespace per account and none for a tenant-scoped credential; installations remaining inactive until bound, idempotent re-delivery, rebinding requiring an unbind, and binding refused for a non-admin of that tenant or under the stricter policy; and audited decisions with bounded purging of spent invitations.

The `sentinel admin policy|invite|account` surface was exercised end to end on Linux, including every refusal path and the host-local audit marking.

See [TODO.md](../TODO.md) for commands and results. Policy changes require a recent [step-up](step-up.md); tenant suspension and role revocation are A07.
