# Tenant suspension, revocation and pool grants (A07)

Implemented in `sentinel-store::tenancy`, the audited membership and grant mutations in `sentinel-store::auth`, and `sentinel admin tenant|pool`, with append-only metadata migration **11**.

Revoking authority is only half a decision; the other half is what happens to the work and the connections that already hold it. This module makes both halves one transaction.

## Suspending a tenant

`tenancy::suspend` requires platform administration with a recent [step-up](step-up.md) — it ends service for every member at once — and in one transaction:

| Effect | How |
|---|---|
| Intake stops | `tenants.active = 0`, the flag every authorization predicate in [authorization](authorization.md) already joins on. Repository queries, namespace resolution, tenant administration and pool access all fail from the next statement. |
| Credentials revoked | Every API credential scoped to the tenant, which includes every one of its service accounts' (a service credential is confined to its home tenant by A03). Deployment-wide human credentials survive: a person may belong to other tenants, and nothing they hold reaches this one. |
| Invitations revoked | Unspent invitations into the tenant. |
| Jobs canceled | Every live job gets the durable `cancel_requested` flag. Jobs nobody owns yet (blocked, queued) are moved to `Canceled` through the state machine, so the run aggregates honestly. Jobs a worker owns keep their state; the worker reads the flag, stops, and reports its own terminal outcome — never faked from the controller. |
| Subscriptions re-authorize | The tenant's authorization epoch moves (below). |

Sessions are **not** revoked — they are deployment-wide, not tenant-scoped. Retained evidence — runs, logs, artifacts — is untouched: suspension is a stop, not a deletion, and retention policy (Part 13) decides the rest. `Suspension` reports the counts, and the audit row carries them.

`tenancy::create_organization` is the audited, host-local way the first namespace of a deployment comes to exist before any route does. `tenancy::reactivate` lifts the flag and moves the epoch. Nothing revoked comes back on its own: credentials are reissued, canceled jobs are rerun.

## The authorization epoch

Every query re-checks membership and grants, but a long-lived subscription — a log stream, an event cursor — cannot re-run its predicate per frame. `tenants.authz_epoch` is a monotonic counter that moves in the same transaction as **any** change to who may act in the tenant: suspension and reactivation, membership set or removed, repository grant changed, pool granted or revoked. A subscription records the epoch it was authorized at and re-authorizes when `tenancy::epoch` no longer returns it. A trigger refuses to move it backwards. W05/W08 streams consume this; nothing here is cached.

## Membership and grant revocation

`auth::set_membership`, `auth::remove_membership` and `auth::set_repo_grant` (A01) are now audited and move the epoch. A role downgrade takes effect on the next query. Removing a membership cascades its repository grants (unchanged) **and revokes the member's credentials scoped to that tenant** in the same transaction, because nothing they could reach remains; the member's credentials scoped to other tenants are untouched.

## Pool grants

Worker pools are capacity, and capacity is the platform's to allocate. A pool is either **dedicated** to one tenant — no grant needed, and the database refuses to grant it to anybody else — or **shared**, platform-managed, admitting only tenants with an explicit grant. Approval of one tenant never makes its code trusted on another's machines: ownership and the grants table are the only two ways in.

`tenancy::require_pool_access` is one statement — tenant active, pool active, and owner-or-granted — and the scheduler (W02) asks it per placement. A suspended tenant loses even its own dedicated pool. Withdrawing a grant stops new placement at once; work already leased on the pool's workers finishes or is canceled by its own tenant's policy. Worker enrollment into a pool is W01.

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

`crates/sentinel-store/tests/tenancy.rs`: a plain session cannot suspend and a stepped-up admin can; suspension revokes the tenant-scoped human and service credentials but not a deployment-wide one, spends the tenant's invitation, cancels the queued and blocked jobs through the state machine while the leased job keeps its state with the cancel flag set, moves the epoch, leaves the run on record and the other tenant reachable, audits the counts, refuses a second suspension, and reactivation restores intake without restoring anything revoked; a role downgrade, a grant and a removal each move the epoch and are audited, removal kills the tenant-scoped credential and not another tenant's, and the epoch cannot be rewound by raw SQL; pool names are bounded, a dedicated pool admits only its owner and takes no grant (API and raw SQL), a shared pool admits exactly the granted tenant, listing needs membership, an outsider cannot grant, revocation is immediate and not repeatable, and a suspended tenant loses its own pool. The `sentinel admin tenant|pool` surface was exercised end to end on Linux.

See [TODO.md](../TODO.md) for commands and results.
