# Identity and authorization (A01)

Implemented in `sentinel-core::auth` and `sentinel-store::auth`, with append-only metadata migration **4**. This is the durable authorization layer for A02/A03 and the first API slice. A02 implements [local authentication](local-authentication.md) on top of it: host-local bootstrap, password credentials and opaque sessions that produce the `Principal` this layer authorizes. A03 adds [API credentials](api-credentials.md), the second source of that same `Principal`, and A04 adds [GitHub sign-in](github-sign-in.md), which produces an ordinary session once a verified provider identity resolves to an admitted account. HTTP routes arrive with W08; there is no unauthenticated development endpoint.

## Durable identities and namespaces

- `UserId` is a typed inline UUID v4 (`usr_<uuid>`), distinct from tenant/repo IDs. The `users` table stores human and service principals; `kind` is immutable. Display names are bounded metadata, not unique login identities.
- Human users are global to the deployment. Service principals have an immutable home tenant, cannot be super admins, cannot have external sign-in identities and cannot acquire tenant-admin memberships. Their credentials carry explicit expiry and scopes ([A03](api-credentials.md)); a stored account alone authenticates nobody.
- External identity keys are `(configured provider key, immutable verified provider subject)`. They are unique across the deployment, linked to one human and never silently reassigned. Provider subject is not an email/login/display name. Separate providers can have the same subject text. This module stores verified links; [A04](github-sign-in.md) verifies provider proof and requires an authenticated session as linking intent.
- Organization and personal namespaces share a unique canonical slug space: 1–63 lowercase ASCII letters/digits/hyphens, alphanumeric at both ends. Validation borrows the input; it never silently lowercases a conflicting name.
- Personal namespaces bind one human owner, at most one personal namespace per owner, and create the required tenant-admin membership in the same transaction. The owner membership cannot be removed or downgraded. Organization creation grants no implicit memberships. Namespace identity/ownership is immutable in A01.
- Migration preserves existing v3 organization tenants and their data without creating users or granting access. Previously admitted legacy slugs are preserved, not silently renamed; new namespace creation uses canonical validation.

## Authority model

Effective repository authority is the intersection of:

1. **Authenticated principal and credential/client scope** (`Principal`).
2. **Live active account and active owning tenant**. Only an approved account is active, so a pending or rejected one ([admission](admission.md)) fails this step without any query having to ask about status.
3. **Live membership role**, looked up from the actual repository's owner.
4. **Explicit repository grant**, except for a human tenant admin's own tenant.

`Principal` contains an ID and a permissions/tenant/repo upper bound. It has no deserializer and contains no caller-asserted role. It is constructed only by trusted authentication code after validating the credential. Passing a request's `user_id` or tenant into this constructor is not authentication. Future OAuth/token scopes must narrow it; never construct `ALL` just because a token belongs to an admin.

| Role | Repository access | Administration |
|---|---|---|
| Super admin | **No ambient repository access.** Needs ordinary membership/grants for data queries. | Explicit `PLATFORM_ADMIN` scope allows platform administration; tenant administration additionally needs `TENANT_ADMIN` scope. |
| Human tenant admin | Read/run/secret-write for repos in their own active tenant, capped by credential scopes. | Own memberships, repository bindings/grants and service principals; no platform role changes. |
| Operator | Only explicitly granted repos/actions; may receive read and run permissions. | None. |
| Reader | Only explicitly granted read access; cannot run even if a stale/oversized grant contains the run bit. | None. |
| Service account | Only its home tenant, live non-admin membership and explicit repo/actions, capped by credential scopes. | None, including when its supplied scope contains admin bits. |

Repository permission bits are `READ` (1), `RUN` (2), `WRITE_SECRETS` (4). Admin scope bits are `TENANT_ADMIN` (8) and `PLATFORM_ADMIN` (16); they cannot be stored in repository grants. These are internal database bit positions, not the final OAuth scope vocabulary. `READ` will map to run/log/artifact evidence reads and `RUN` to dispatch/rerun/cancel; fine-grained OAuth scopes must also be checked by the eventual operation adapter.

Secret-write delegation is independent: an operator's run grant never grants it implicitly. An explicit secret-write grant may be given to a reader or operator; no role has a plaintext secret read-back operation. The secret APIs/storage remain S01 and later.

## Queries and mutations

`get_repo`, `list_repos`, `require_repo` and `get_run_spec` share one static SQL authorization predicate. They join repository ownership to current users, tenants, memberships and grants. Supplied tenant/repo scopes are only narrowing filters. Neither a guessed ID nor a different CLI-selected tenant can grant access.

- Single-repo and spec reads return `NotFound` for both denied and absent resources.
- Lists filter unauthorized rows in SQL, before pagination; they expose neither cross-tenant totals nor skipped-row metadata. Pages are 1–100 rows, ordered by binary repo ID with an exclusive keyset boundary. `after` is a filter, not a credential or independently trusted cursor.
- Spec reads join run -> repo and spec ownership in the same SQLite read statement. They do not check access on one connection and retrieve the blob on another.
- `auth::create_run` authorizes `RUN` and derives the tenant from the repo inside the same writer transaction that inserts the run/spec/jobs. The caller supplies a trusted compiled/resolved spec; source-token and image-resolution authority remain later execution/intake work.
- Namespace resolution checks live membership or explicit platform administration. Repo-scoped credentials cannot use it to enumerate tenant metadata.
- Administrative mutations take a `Transaction`, recheck current authority, and write within that transaction. A queued request does not retain a positive permission result from an earlier read.
- Downgrading a role takes effect on the next query. Removing membership cascades deletion of its repo grants; re-adding membership does not resurrect authority. Setting a grant to `NONE` removes it. Account/tenant active flags are checked live. A07 will add audited suspension workflows and subscription/token/job cancellation propagation.

`jobs`, `runs`, the writer's closure/raw interfaces and `auth::provisioning` are **trusted controller internals**, not public client APIs. The worker state-machine `Actor` is unrelated to a human authorization principal. W08 must call authorized operations (and extend them for status/rerun/cancel) rather than expose raw tenant-scoped helpers. A02 owns first-admin admission and password/session authentication, and adds `local_auth` with the same rules (trusted host-local entry points, authority rechecked inside the writing transaction); A03 adds `tokens` and the trusted `lookup` host-local name resolver; A04 adds `sign_in`, whose `complete` issues a session only for an already-verified provider subject; A05 adds `registration`, where `record_installation` is trusted intake and every other entry point takes an explicit `Authority`. No route may directly expose `provisioning::insert_human(super_admin)`.

## Storage defenses and upgrade

Migration 4 adds users, immutable external identity links, memberships, repo grants, namespace type/owner and active flags. Grants have composite foreign keys to both owning repo and membership. Service-account shape and membership ceilings have database checks/triggers as well as API validation.

The [Parts 01–02 audit](parts-01-02-audit.md) found that old parent foreign keys did not enforce equal tenant IDs. Migration 4 adds ownership triggers for existing runs/jobs/attempts/specs/idempotency references and forbids changing a repo/run/job's owning tenant. This preserves old tables/blobs and fails inconsistent upgrades atomically instead of assigning an arbitrary owner. Unknown newer database versions are rejected. Normal controller updates still use the existing fenced transition contracts.

## Cost and bounds

- User IDs, roles, scopes and permission checks are inline values; no per-request role graph, string permission parsing or external membership request.
- Repository access uses cached static statements and primary-key joins. `require_repo` returns a 16-byte tenant ID without allocating repository metadata. Spec reads use one statement/snapshot.
- Listing uses the `(tenant_id, id)` repository index and keyset range. A query-plan test verifies point and page lookups use index searches and avoid table scans and temporary sort trees. Returned strings/vectors are allocated only for actual results.
- Administrative changes use short existing single-writer transactions; there is no separate authorization service/cache, lock hierarchy or new crate/dependency.
- No authorization latency claim is made from unit tests. The store's outstanding reader/writer lifetime bounds are explicitly tracked in the audit before server integration.

## Verification

The authorization suite uses two organizations and a personal namespace with overlapping human roles and a tenant-bound bot. It tests wrong-tenant/repo scope, missing IDs, platform/tenant privilege separation, reader ceilings, explicit secrets delegation, unauthorized lists, keyset pages, role/grant/membership revocation, immutable identity links, inactive accounts/tenants, transaction rollback, revocation before queued mutations, authorized dispatch/spec reads, raw-SQL constraint attacks, v3 migration/rollback, future-version rejection and reopen durability. The query-plan test guards indexed authorization access.

See [TODO.md](../TODO.md) for commands and actual verification results. Session expiry/recovery, invitations and running-stream revocation are A02–A08 verification, not claims made by these storage tests.
