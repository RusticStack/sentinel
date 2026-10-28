# Identity and authorization

Implemented in `sentinel-core::auth` and `sentinel-store::auth` (metadata migration **4**). It is the durable authorization layer behind every API route. [Local authentication](local-authentication.md) (host-local bootstrap, password credentials, opaque sessions) and [API credentials](api-credentials.md) produce the `Principal` this layer authorizes, and [GitHub sign-in](github-sign-in.md) produces an ordinary session once a verified provider identity resolves to an admitted account. There is no unauthenticated development endpoint.

## Durable identities and namespaces

- `UserId` is a typed inline UUID v4 (`usr_<uuid>`), distinct from tenant/repo IDs. The `users` table stores human and service principals; `kind` is immutable. Display names are bounded metadata, not unique login identities.
- Human users are global to the deployment. Service principals have an immutable home tenant, cannot be super admins, cannot have external sign-in identities and cannot acquire tenant-admin memberships. Their credentials carry explicit expiry and scopes ([API credentials](api-credentials.md)); a stored account alone authenticates nobody.
- External identity keys are `(configured provider key, immutable verified provider subject)`. They are unique across the deployment, linked to one human and never silently reassigned. Provider subject is not an email/login/display name. Separate providers can have the same subject text. This module stores verified links; [GitHub sign-in](github-sign-in.md) verifies provider proof and requires an authenticated session as linking intent.
- Organization and personal namespaces share a unique canonical slug space: 1–63 lowercase ASCII letters/digits/hyphens, alphanumeric at both ends. Validation borrows the input; it never silently lowercases a conflicting name.
- Personal namespaces bind one human owner, at most one personal namespace per owner, and create the required tenant-admin membership in the same transaction. The owner membership cannot be removed or downgraded. Organization creation grants no implicit memberships. Namespace identity and ownership are immutable.
- Migration preserves existing v3 organization tenants and their data without creating users or granting access. Previously admitted legacy slugs are preserved, not silently renamed; new namespace creation uses canonical validation.

## Authority model

Effective repository authority is the intersection of:

1. **Authenticated principal and credential/client scope** (`Principal`).
2. **Live active account and active owning tenant**. Only an approved account is active, so a pending or rejected one ([admission](admission.md)) fails this step without any query having to ask about status.
3. **Live membership role**, looked up from the actual repository's owner.
4. **Explicit repository grant**, except for a human tenant admin's own tenant.

`Principal` contains an ID and a permissions/tenant/repo upper bound. It has no deserializer and contains no caller-asserted role. It is constructed only by trusted authentication code after validating the credential. Passing a request's `user_id` or tenant into this constructor is not authentication. OAuth and token scopes only narrow it; never construct `ALL` just because a token belongs to an admin.

| Role | Repository access | Administration |
|---|---|---|
| Super admin | **No ambient repository access.** Needs ordinary membership/grants for data queries. | Explicit `PLATFORM_ADMIN` scope allows platform administration; tenant administration additionally needs `TENANT_ADMIN` scope. Changing a tenant's memberships, repository grants or service credentials without being an administrator of that tenant needs fresh [step-up](step-up.md#platform-scope-is-not-data-access) and an audited reason, so the reach cannot quietly become data access. |
| Human tenant admin (GitHub-backed tenant: an organization owner) | Read/run/secret-write for repos in their own active tenant, capped by credential scopes. | Own memberships, repository bindings/grants and service principals; no platform role changes. |
| Operator | Only explicitly granted repos/actions; may receive read and run permissions. | None. |
| Reader | Only explicitly granted read access; cannot run even if a stale/oversized grant contains the run bit. | None. |
| Service account | Only its home tenant, live non-admin membership and explicit repo/actions, capped by credential scopes. | None, including when its supplied scope contains admin bits. |

Repository permission bits are `READ` (1), `RUN` (2), `WRITE_SECRETS` (4). Admin scope bits are `TENANT_ADMIN` (8) and `PLATFORM_ADMIN` (16); they cannot be stored in repository grants. These are internal database bit positions, not the OAuth scope vocabulary; fine-grained OAuth scopes are checked in addition. Permission and scope bit positions and the OAuth scope wire names are persisted, so renumbering silently changes every stored grant; an undefined bit is refused when a row is read, so a corrupt or newer row cannot widen authority. A scope is only a ceiling on `Permissions`, a repository operator does not implicitly gain `WRITE_SECRETS` or administration, and the audience is stored as an integer in `oauth_*.resource`.

Secret-write delegation is independent: an operator's run grant never grants it implicitly. An explicit secret-write grant may be given to a reader or operator; no role has a plaintext secret read-back operation.

A `run` grant (or an MCP `runs:write` token) can submit a pipeline of its own, so it never reaches secrets: a manually dispatched run is refused every secret and the API refuses a manual pipeline that declares one ([secrets](secrets.md#who-may-cause-a-delivery)). Only runs built from the repository's own pipeline at a bound revision, from a delivery authenticated at intake (a verified webhook signature or the hook secret; never a polled event), receive them.

## Queries and mutations

`get_repo`, `list_repos`, `require_repo` and `get_run_spec` share one static SQL authorization predicate. They join repository ownership to current users, tenants, memberships and grants. Supplied tenant/repo scopes are only narrowing filters. Neither a guessed ID nor a different CLI-selected tenant can grant access.

- Single-repo and spec reads return `NotFound` for both denied and absent resources, and so does resolving a tenant slug for a client (`auth::member_tenant_by_slug`): a tenant the caller has no live relationship with, a suspended one and a missing one are the same answer, so listing `GET /tenants/{slug}/repos` cannot enumerate namespaces.
- Lists filter unauthorized rows in SQL, before pagination; they expose neither cross-tenant totals nor skipped-row metadata. Pages are 1–100 rows, ordered by binary repo ID with an exclusive keyset boundary. `after` is a filter, not a credential or independently trusted cursor.
- Spec reads join run -> repo and spec ownership in the same SQLite read statement. They do not check access on one connection and retrieve the blob on another.
- `auth::create_run` authorizes `RUN` and derives the tenant from the repo inside the same writer transaction that inserts the run/spec/jobs. The caller supplies a trusted compiled/resolved spec.
- Namespace resolution checks live membership or explicit platform administration. Repo-scoped credentials cannot use it to enumerate tenant metadata.
- Administrative mutations take a `Transaction`, recheck current authority, and write within that transaction. A queued request does not retain a positive permission result from an earlier read. Where a change also needs step-up, a browser session's stamp is re-read from its row in that same transaction (`Authority::require_fresh`), not trusted from the request.
- `auth::require_tenant_admin` treats a platform administrator as an administrator of every tenant for administration only. The client-route forms (`set_membership_as`, `set_repo_grant_as`, service-account creation, `allow_repo`, `issue_service_grant`) take an `Authority` and, for a platform administrator who is not a member-administrator of the tenant, require fresh step-up and a reason, recorded as a `platform-override` audit row. The `Principal`-only `set_membership`/`set_repo_grant` carry no step-up policy and exist for trusted provisioning and fixtures; no route calls them.
- A person is named in a tenant by a `usr_…` id or by the local sign-in name of an existing member (`auth::resolve_member`); a name is never resolved outside the tenant.
- Downgrading a role takes effect on the next query. Removing membership cascades deletion of its repo grants and revokes the member's credentials scoped to that tenant; re-adding membership does not resurrect authority. Setting a grant to `NONE` removes it. Account/tenant active flags are checked live. Every membership and grant change is audited and moves the tenant's authorization epoch; suspension and its propagation to credentials, invitations, jobs and subscriptions are in [tenancy](tenancy.md).

`jobs`, `runs`, the writer's closure/raw interfaces and `auth::provisioning` are **trusted controller internals**, not public client APIs. The worker state-machine `Actor` is unrelated to a human authorization principal. Routes call authorized operations rather than raw tenant-scoped helpers. The other store modules follow the same rules:

- `local_auth`: first-admin admission and password/session authentication; trusted host-local entry points, authority rechecked inside the writing transaction.
- `tokens` and `lookup`: `lookup` is a trusted name resolver and is unauthorized. A route may use it only as the first half of a decision whose second half answers `NotFound` for a denied row exactly as for an absent one; a route whose answer would otherwise differ resolves names through `auth::member_tenant_by_slug` or `auth::narrowing_by_name`, which check live membership in the resolving statement.
- `sign_in`: `complete` issues a session only for an already-verified provider subject.
- `registration`: `record_installation` is trusted intake; every other entry point takes an explicit `Authority`.
- [`mfa`](step-up.md): `Authority` carries a step-up freshness bit, so changes to who can authenticate require a recent second factor as well as live platform administration.

No route may directly expose `provisioning::insert_human(super_admin)`.

## GitHub-backed tenants

A tenant with `membership_source = 1` takes its people from GitHub ([GitHub sign-in](github-sign-in.md#github-backed-organizations)); the authority model above is unchanged. Derived rows are ordinary `memberships` and `repo_grants` rows carrying `synced_ms` (the time GitHub last confirmed them), so the repository predicate never reads it and no request waits for GitHub: an organization owner is a tenant administrator, any other active member is an operator, and a repository grant is the permission GitHub reports for the person's linked numeric account id, never above it (`admin` read/run/secrets, `maintain` and `write` read/run, `triage` and `read` read). Manual adds, role changes, removals, invitations and grants for human accounts of such a tenant are refused with `forbidden` (`github_members::require_app_managed`); service accounts stay managed here. A removal on GitHub (a signed `member_removed`, or a later check that no longer finds the person) deletes the membership, its grants, the tenant-scoped API credentials and OAuth grants and moves the authorization epoch in one transaction. Answers that prove nothing (rate limit, server error, missing App permission, a reply about another account) keep what exists until a configurable grace period is over and grant nothing new.

## Storage defenses and upgrade

Migration 4 adds users, immutable external identity links, memberships, repo grants, namespace type/owner and active flags. Grants have composite foreign keys to both owning repo and membership. Service-account shape and membership ceilings have database checks/triggers as well as API validation.

Earlier parent foreign keys did not enforce equal tenant IDs (Parts 01–02 audit). Migration 4 adds ownership triggers for existing runs/jobs/attempts/specs/idempotency references and forbids changing a repo/run/job's owning tenant. This preserves old tables/blobs and fails inconsistent upgrades atomically instead of assigning an arbitrary owner. Unknown newer database versions are rejected. Normal controller updates still use the existing fenced transition contracts.

## Cost and bounds

- User IDs, roles, scopes and permission checks are inline values; no per-request role graph, string permission parsing or external membership request.
- Repository access uses cached static statements and primary-key joins. `require_repo` returns a 16-byte tenant ID without allocating repository metadata. Spec reads use one statement/snapshot.
- Listing uses the `(tenant_id, id)` repository index and keyset range. A query-plan test verifies point and page lookups use index searches and avoid table scans and temporary sort trees. Returned strings/vectors are allocated only for actual results.
- Administrative changes use short existing single-writer transactions; there is no separate authorization service/cache, lock hierarchy or new crate/dependency.
- Present and absent repositories take the same path: `require_repo` runs one cached statement keyed on the repository ID and returns `NotFound` for a missing row and a forbidden one alike, with the same status and body. It is not constant-work: `repo_authorization_runs_the_same_keyed_probe_for_present_and_absent_objects` counts SQLite VM instructions and measures that two absent IDs cost exactly the same, while an existing repository the caller may not see costs about a dozen instructions more (41 against 28 on the verification host) because the keyed row is found and then filtered by membership. The difference is bounded (the test allows 32), involves no scan or sort, and is nanoseconds; no timing-equality claim is made, and isolation rests on identical answers, not on equal time.
- No authorization latency claim is made from unit tests.

## Verification

The authorization suite uses two organizations and a personal namespace with overlapping human roles and a tenant-bound bot. It tests wrong-tenant/repo scope, missing IDs, platform/tenant privilege separation, reader ceilings, explicit secrets delegation, unauthorized lists, keyset pages, role/grant/membership revocation, immutable identity links, inactive accounts/tenants, transaction rollback, revocation before queued mutations, authorized dispatch/spec reads, raw-SQL constraint attacks, v3 migration/rollback, future-version rejection and reopen durability. The query-plan test guards indexed authorization access.

`crates/sentinel-store/tests/cross_tenant.rs` exercises authorization, invitations and suspension together: two organizations and a personal namespace with overlapping memberships and a tenant-bound service account, guessed and foreign identifiers, foreign and forged cursors, an invitation raced by eight applicants, pending accounts and unbound installations, one tenant's suspension leaving the others and shared people working, last-admin recovery through lockout, and reopen.

The product model's isolation is exercised on three levels, none of which asserts timing: `crates/sentinel-store/tests/tenancy_isolation.rs` builds an owner (a personal namespace and the domain-created organization `alpha`), a colleague (the organization `beta` and a personal namespace), a second domain-joined reader and a GitHub-backed organization admitting only GitHub-confirmed people, and checks resolution, repositories, runs, secrets, pools and workers, cursors, administration, invitations beside domain joins, a domain rule dropped during verifications, GitHub departure and last-administrator recovery; `crates/sentinel-api/tests/tenant_isolation.rs` sends every route that names a tenant, repository, run, job, attempt, artifact, object, upload, member, worker or pool from one camp against the other's real identifiers and against guessed ones, and requires the same status and body, that nothing changed, and that the platform administrator reads no tenant's data; `crates/sentinel/tests/tenant_isolation.rs` does the same through the CLI (exit 4 with the same document).
