# Tenant suspension, revocation and pool grants

Implemented in `sentinel-store::tenancy`, the audited membership and grant mutations in `sentinel-store::auth`, and `sentinel admin tenant|pool` (migration **11**).

Revoking authority also has to settle the work and connections that already hold it. Both happen in one transaction.

## Suspending a tenant

`tenancy::suspend` requires platform administration with a recent [step-up](step-up.md) — it ends service for every member at once — and in one transaction:

| Effect | How |
|---|---|
| Intake stops | `tenants.active = 0`, the flag every authorization predicate in [authorization](authorization.md) already joins on. Repository queries, namespace resolution, tenant administration and pool access all fail from the next statement. |
| Credentials revoked | Every API credential and OAuth grant scoped to the tenant, which includes every one of its service accounts' (a service credential is confined to its home tenant). Deployment-wide human credentials survive: a person may belong to other tenants, and nothing they hold reaches this one. |
| Invitations revoked | Unspent invitations into the tenant. |
| Jobs canceled | Every live run and job gets the durable `cancel_requested` flag. Jobs nobody owns yet (blocked, queued) are moved to `Canceled` through the state machine, so the run aggregates honestly. Jobs a worker owns keep their state; the worker reads the flag, stops, and reports its own terminal outcome — never faked from the controller. |
| Subscriptions re-authorize | The tenant's authorization epoch moves (below). |

Sessions are **not** revoked — they are deployment-wide, not tenant-scoped. Retained evidence — runs, logs, artifacts — is untouched: suspension is a stop, not a deletion, and [retention](retention.md) decides the rest. `Suspension` reports the counts, and the audit row carries them.

`tenancy::create_organization` is the audited, host-local way the first namespace of a deployment comes to exist before any route does. `tenancy::reactivate` lifts the flag and moves the epoch. Nothing revoked comes back on its own: credentials are reissued, canceled jobs are rerun.

## The authorization epoch

Every query re-checks membership and grants, but a long-lived subscription — a log stream, an event cursor — cannot re-run its predicate per frame. `tenants.authz_epoch` is a monotonic counter that moves in the same transaction as **any** change to who may act in the tenant: suspension and reactivation, membership set or removed, repository grant changed, pool granted or revoked. A subscription records the epoch it was authorized at and re-authorizes when `tenancy::epoch` no longer returns it. A trigger refuses to move it backwards. The API's long-lived streams (`routes.rs`) poll it; nothing is cached.

## Membership and grant revocation

`auth::set_membership`, `auth::remove_membership` and `auth::set_repo_grant` are audited and move the epoch. A role downgrade takes effect on the next query. Removing a membership cascades its repository grants **and revokes the member's credentials scoped to that tenant** in the same transaction and records a removal tombstone (`membership_removals`) so [domain auto-join](admission.md#domain-auto-join) cannot re-add the person, because nothing they could reach remains; the member's credentials scoped to other tenants are untouched. Invitations the member minted as a tenant admin need no revocation: redemption re-checks the inviter's live authority ([admission](admission.md#invitations)), so removal, a downgrade below tenant admin, or suspension of the account voids them at once.

## GitHub-backed membership

An organization tenant bound to a GitHub **organization** installation can be converted so that its members and their repository access are derived from GitHub for the person's linked numeric account id ([GitHub sign-in](github-sign-in.md#github-backed-organizations)). Conversion is an explicit, audited act (`PUT /tenants/{slug}/membership-source`, or host-local `sentinel admin source github-backing`); upgrading changes no tenant. Everyone still has a personal namespace, and a person sees only the tenants they are a member of: a tenant the person is not (or no longer) a member of is the same uniform `NotFound` as one that does not exist, so GitHub membership is never an oracle for slugs. Removal on GitHub deletes the membership and everything hanging on it exactly as [`remove_membership`](#membership-and-grant-revocation) does, and moves the tenant's epoch so live streams re-authorize; unlinking GitHub ends every derived membership of the person in the same transaction and touches no app-managed one. Releasing the tenant's last organization installation returns it to app-managed membership and keeps the derived access as locally managed.

## Organization names and GitHub organizations

A namespace name is first come, first served, so a self-service organization could claim the name of a GitHub organization before its owner installs the App. `organizations::create_self_service` therefore refuses (`conflict`, the answer for a taken name) any name equal, case-insensitively, to the login of an account the GitHub App is installed on, bound to a tenant or not, unless the creator is a platform administrator ([admission](admission.md#self-service-organizations)). The way to take such a name is the installation: the owner installs the App, a tenant administrator binds the installation to a tenant of any name, and the operator may name the tenant after the organization first. Tests: `crates/sentinel-store/tests/setup.rs`.

## Pool grants

Worker pools are capacity, and capacity is the platform's to allocate. A pool is either **dedicated** to one tenant — no grant needed, and the database refuses to grant it to anybody else — or **shared**, platform-managed, admitting only tenants with an explicit grant. Approval of one tenant never makes its code trusted on another's machines: ownership and the grants table are the only two ways in.

`tenancy::require_pool_access` is one statement — tenant active, pool active, and owner-or-granted — and the scheduler asks it per placement. A suspended tenant loses even its own dedicated pool. Withdrawing a grant stops new placement at once; work already leased on the pool's workers finishes or is canceled by its own tenant's policy. Worker enrollment into a pool is in [worker link](worker-link.md).

```sh
sentinel admin pool create  --data-dir <PATH> --name shared-linux
sentinel admin pool create  --data-dir <PATH> --name acme-builders --tenant acme
sentinel admin pool grant   --data-dir <PATH> --pool shared-linux --tenant acme
sentinel admin pool revoke  --data-dir <PATH> --pool shared-linux --tenant acme
sentinel admin pool list    --data-dir <PATH> --tenant acme
sentinel admin tenant create     --data-dir <PATH> --slug acme
sentinel admin tenant suspend    --data-dir <PATH> --tenant acme
sentinel admin tenant reactivate --data-dir <PATH> --tenant acme
```

## Cost

Suspension is an administrative action, not a hot path: it walks the tenant's live jobs once (indexed by tenant, bounded by the state-code range) and applies one state-machine transition per unowned job. The per-placement check `require_pool_access` is a single indexed statement, and `epoch` is one primary-key read.

## Verification

`crates/sentinel-store/tests/tenancy.rs`: a plain session cannot suspend and a stepped-up admin can; suspension revokes the tenant-scoped human and service credentials but not a deployment-wide one, spends the tenant's invitation, cancels the queued and blocked jobs through the state machine while the leased job keeps its state with the cancel flag set, moves the epoch, leaves the run on record and the other tenant reachable, audits the counts, refuses a second suspension, and reactivation restores intake without restoring anything revoked; a role downgrade, a grant and a removal each move the epoch and are audited, removal kills the tenant-scoped credential and not another tenant's, and the epoch cannot be rewound by raw SQL; pool names are bounded, a dedicated pool admits only its owner and takes no grant (API and raw SQL), a shared pool admits exactly the granted tenant, listing needs membership, an outsider cannot grant, revocation is immediate and not repeatable, and a suspended tenant loses its own pool.
