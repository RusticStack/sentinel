# Onboarding and tenancy remediation

The state of the onboarding and tenancy work after its final verification pass, one section per work package, as recorded by each package's implementer and reviewer. It continues [audit remediation](audit-remediation.md) and uses the same words: **fixed** (changed on the branch; whether it ran is under verification), **deferred** (not changed, with the reason), **review note** (a reviewer's remaining concern, not fixed unless said so) and **pending** (needs a run that has not happened). Anything a package lists under neither deferred nor review notes was fixed by its branch.

## Release candidate: Resend-only email and the wizard's mail test

Branch `release-candidate` (from `fix/resend-ui`: the audit remediation, the onboarding and tenancy work, Resend-only email and the wizard update), checked 2026-10-14.

What changed since the onboarding pass: mail is delivered only through the Resend HTTP API. The SMTP transport and its `[mail]` keys and `SENTINEL_SMTP_*` variables are removed; the controller reads a Resend key from an owner-only file (`SENTINEL_RESEND_API_KEY_FILE`) and a sender (`SENTINEL_EMAIL_FROM`), `GET /api/v1/setup` gains `mail_configured` (false once setup is closed), and `POST /api/v1/setup/smtp-test` is replaced by `POST /api/v1/setup/mail-test {token, to}`. The wizard's email step sends that test and, when mail is not configured, shows the two environment lines. The contract is in [compatibility](compatibility.md), [API](api.md), [configuration](configuration.md) and [web interface](web-ui.md).

| Check | Where | Result |
|---|---|---|
| `cargo fmt-check` | workstation | passed (before and after the fixes) |
| `cargo lint` | workstation | passed (before and after the fixes) |
| `pnpm -C web typecheck` | workstation | exit 0, zero `error TS` lines (the same Vue language tools `vue-router/volar` plugin-resolution warning) before and after the fixes |
| `cargo lint-linux` | verification VPS, `nice -n 19 ionice -c3`, `CARGO_BUILD_JOBS=6`, the separate clone `/srv/sentinel-af` shipped as git bundles, nothing pushed, every `crates/**/*.rs` touched first so the workspace crates rebuild | first pass on the unfixed branch failed (one lint error, below); clean on the final tree |
| `cargo test-cli` | same | unfixed branch: 1,586 run, 1,585 passed, 1 failed, 21 skipped. Final tree: **1,586 passed, 21 skipped** (0 failed) in 116 s |
| `cargo test-linux` | same | unfixed branch: 1,632 run, 1,630 passed, 2 failed, 21 skipped. Final tree: **1,632 passed, 21 skipped** (0 failed) in 121 s |
| `pnpm -C web test:unit` | same, pnpm 12.3.4 and Node 22.22.1 from `/srv/sentinel-runs` (user-local, nothing global) | 22 of 22 passed |
| `pnpm -C web build` | same | passed (Nuxt 4 / Nitro build completes in about a minute; the stall seen on the workstation did not occur) |
| Web browser test | same, `SENTINEL_BROWSER=/opt/chrome-headless-shell/as-root` | final tree: **229 of 229 checks** (the test passes). Before the CSP fixes: 227 of 229, the two `no script errors` checks |

Unlike the previous pass, the final `test-cli` and `test-linux` runs are clean full runs of the final tree, started after the sources were touched, and the web unit, build and browser runs are of the same tree. Host load at the start was low (CPU pressure `some avg10` about 1 to 2); an earlier probe saw a load average of 135 from other services' Nuxt builds, and no result here comes from that period except the first, failing, lint run.

### Fixed in this pass

| Finding | Cause | Fix |
|---|---|---|
| `cargo lint-linux`: `clippy::type_complexity` on `start_mail` (Linux-only, so the workstation could not show it) | The return type was a nested `Result<(Option<Box<Lane>>, Option<Arc<Resend>>), Error>` | A named `MailStart` type |
| `sentinel-api::tenant_isolation setup_and_registration_say_the_same_thing_to_everyone` | The test pinned the closed setup answer to `{"open": false}`; the Resend work added `mail_configured` (always present, false once closed), as the documented contract says | The test expects `{"open": false, "mail_configured": false}`: still exactly those two keys, so nothing else about the instance may appear |
| `sentinel::service::tests::a_bad_email_setting_is_refused_without_echoing_it` (server build only) | The assertion "the refusal does not contain the bad sender" is false for `@example.com`: the fixed refusal sentence itself shows `addr@example.com` | The test asserts the refusal is exactly one of the two fixed sentences, which is the no-echo property without the substring accident |
| Browser checks `no script errors so far` and `no uncaught script errors` (open since `audit-fixes-final`): `Applying inline style violates ... style-src` | Found with a throw-away instrumented copy of the browser driver (hooks on style-element creation and the `securitypolicyviolation` event, on the VPS only, not committed): three libraries add `<style>` elements in the browser. (1) `@nuxt/icon` in its default CSS mode appends one for each icon first drawn after load (its hash was in the policy only for icons the server rendered). (2) `@nuxtjs/color-mode` with `disableTransition: true`, which Nuxt UI sets, appends `*{transition:none!important}` whenever the colour mode is applied. (3) vaul-vue (bundled by Nuxt UI) appends its constant 5 KB drawer stylesheet when its module loads (seen on `/t/acme` and run pages) | (1) `icon.mode: "svg"`: inline `<svg>`, no style element. (2) `colorMode.disableTransition: false`. (3) A fresh random nonce per response, in `style-src` only, in the `csp-nonce` meta tag that vaul-vue reads (`server/plugins/csp.ts`); scripts get no nonce. `style-src` still has no `unsafe-inline`. Documented in [web interface](web-ui.md) |

### Flaky tests

None of them failed in the two clean full runs of the final tree. In isolation on the VPS, five runs each, all passed: `sentinel-link::tailcat back_off_resets_after_a_healthy_helper_and_never_delays_a_new_list` (7.5 s each), `sentinel-store::bounds a_stalled_write_is_reported_as_ambiguous_not_as_failed` (11.4 s) and `sentinel-store::local_auth credential_free_floods_cannot_grow_the_audit_trail_without_bound` (6 s). The browser test's `role changes during open sessions` passed in all five browser runs of this pass (it timed out once in three runs on the onboarding tree, under heavier host load). No race was reproduced, so nothing was changed in code or tests; all four are timing-bound by design and stay on the watch list for a contended host. Nothing was weakened or deleted.

### Still pending

- The GitHub App, step-up and revoke items listed under the packages below, which need real services or HTTP clients this environment does not have.
- A real Resend delivery: the tests use a fake endpoint; no key was available, so `POST /setup/mail-test` and the outbox have not sent a message through `api.resend.com`.

## Onboarding pass verification

Branch `onboarding-final` (from `onboarding-c`), checked 2026-10-14.

| Check | Where | Result |
|---|---|---|
| `cargo fmt-check` | workstation | passed |
| `cargo lint` | workstation | passed (re-run after the last fix) |
| `pnpm -C web typecheck` | workstation | exit 0 (the Vue language tools print the same `vue-router/volar/sfc-route-blocks` plugin-resolution warning; no type error) |
| `cargo lint-linux` | verification VPS, `nice -n 19 ionice -c3`, `CARGO_BUILD_JOBS=6`, a separate clone (`/srv/sentinel-af`) shipped as a git bundle, nothing pushed | first pass failed (below); passed after the fix and again on the final tree |
| `cargo test-cli` | same | first pass on the unfixed tree: 1,579 run, 1,559 passed, 20 failed, 21 skipped (causes below) |
| `cargo test-linux` | same | first pass on the unfixed tree: 1,625 run, 1,604 passed, 21 failed, 21 skipped; run under heavy load (load average 28 and CPU pressure `some avg10` 58 at its start, from other services on the host) |
| Re-runs after the fixes | same, `--all-features`, only the affected binaries | 135 tests (the fixed suites plus the three load-sensitive binaries) with one failure, then 187 tests (all of `sentinel-link`, `sentinel-mail` and the fixed suites) all passed, 9 skipped; the link test that failed was also run five times alone, five passes |
| `pnpm -C web test:unit` | same | 22 of 22 passed (`guards`, `onboarding`, `qr`) |
| `pnpm -C web build` | same | passed |
| Web browser test | same, `SENTINEL_BROWSER=/opt/chrome-headless-shell/as-root` | 227 of 229 checks passed on the final tree; the two failures are the Content-Security-Policy checks below, which fail the same way on `audit-fixes-final`, before any onboarding change (156 of 158 there) |

There was no single clean full run of `test-cli` and `test-linux` after the fixes. The first full passes found the failures below; after them only the binaries they touched, and the binaries that flaked under load, were re-run (the instruction was to re-run only the affected ones). `test-linux` is the superset of `test-cli` plus the role features, and the re-runs used its flags.

### The VPS pnpm and Node problem

`docs/development.md` had `pnpm` 10 on the VPS pending an update. It was solved without touching the host's global tools: `npm i -g --prefix /srv/sentinel-runs/pnpm12 pnpm@12.3.4` (the version `web/package.json` pins) and `npm i --prefix /srv/sentinel-runs/node22 node@22.22.1`, both put first on `PATH` for the run. The second was needed for a reason not recorded before: Ubuntu's `nodejs` 22.22.1 is built without TypeScript support (`process.config.variables.node_use_amaro` is `false`), so `node --test web/test/*.test.mjs` cannot import the `.ts` helpers; the npm-distributed binary has it. The same Node runs the browser test's scripts.

### Failures the first VPS pass found

Compile and lint (Linux-only, which the workstation could not show):

- `sentinel` `service.rs`: `start_mail(&config, ...)` where `config` is already a `&Config` (`clippy::needless_borrow`, denied). Fixed.

Test failures (20 in `test-cli`, 21 in `test-linux`), with the cause of each. Each was confirmed by reading the code; no assertion was weakened or removed.

| Test | Cause | Fix |
|---|---|---|
| `sentinel-mail` mail transport test | The test built its config on a port the client refuses | Removed with the mail transport it covered, which is now Resend only |
| `sentinel-store::email_identity` (3 tests) | `recent_audit(conn, 200)`; the limit is 100 | The helper asks for 100 |
| `sentinel::tenant_isolation` (2 tests) | `--json` was placed after the subcommand, but it belongs to `sentinel api`, before it | The helper moves a trailing `--json` in front of the subcommand |
| `sentinel-api::tenant_isolation` (the camp setup, so nearly every test in the suite) | The camps' bearer tokens asked for `P::ALL`, which includes platform scope; the store refuses that for an account that is not a super admin. The two narrowed grants had the same flaw | Camp and narrowed tokens ask for repository plus tenant-admin permissions |
| `sentinel-api::tenant_isolation nothing_the_other_camp_tried_changed_anything` | Read `version` and `active` at the top of the secret document; the route nests them under `secret`. This is the unverified field name the implementer listed, and the old assertion would have passed vacuously with a wrong name | The test reads the nested fields |
| `sentinel-api::tenant_isolation an_invitation_link_presented_by_two_people_at_once_joins_exactly_one` | Sent the raw secret text; the route parses the `sntl_` form, so both presenters got `not_found` | The test sends `token::format` of the secret |
| `sentinel-api::web a_caller_lists_its_own_tenants...` | The tenant list now carries `kind` and `membership`; the test expected only `slug` and `role` | The expected documents carry all four fields |
| `sentinel-checks::reconcile a_renamed_or_dropped_repository_loses_its_binding` | Waited for the binding to be revoked, then read the notice list at once; the notice is pushed after the store write | It waits for the notice too |
| `sentinel-api::account` (two enrollment tests, both runs) | The helper searched all 1,000,000 codes for the first that any of the three accepted steps took, which can be the previous step's; the search takes 12 to 15 s in a debug build on a loaded host, long enough for that code to lapse | The helper takes only the current step's code |
| `sentinel-link::link queued_work_reaches_a_connected_worker...` | Waited for exactly three log acknowledgements, but the worker may acknowledge frames 1 and 2 together; failed 2 of 3 runs even on a quiet host | It counts one more than the acknowledgements seen before the resend |
| `sentinel-api::web_browser` sign-up check | The shared fixture leaves the deployment on approval-required (`web.rs` asserts that), so the sign-up page was accepted and no invitation message appeared | The browser test sets invitation-only, the default its comment names, after building the fixture; Pat's application stays pending |

Three more failed only in the loaded `test-linux` run and passed in every re-run: `sentinel-link::tailcat back_off_resets_after_a_healthy_helper_and_never_delays_a_new_list`, `sentinel-store::bounds a_stalled_write_is_reported_as_ambiguous_not_as_failed` and `sentinel-store::local_auth credential_free_floods_cannot_grow_the_audit_trail_without_bound` (46 s that run). They are timing-bound; no change was made, and a host that is not contended should be used for any baseline.

### Open after this pass

- **The web interface logs Content-Security-Policy violations.** Both browser checks `no script errors so far` and `no uncaught script errors` fail with `Applying inline style violates ... style-src 'self' 'sha256-...'`: something at run time adds a `<style>` that `web/server/plugins/csp.ts` did not hash. It is not new: the same two checks fail on `audit-fixes-final`. The source was not found; no onboarding page contains a `<style>` or `useHead` style. Deferred. **Fixed in the release candidate** (icons, colour-mode and drawer style elements; see above).
- **A timing flake in the browser test.** In one of three browser runs on the onboarding tree `role changes during open sessions` timed out waiting for a run page right after the busy-controller spell; the other two passed it. Not changed.
- The VPS `pnpm` and Node setup above lives under `/srv/sentinel-runs`, not in the host's global tools; `docs/development.md` still describes the global install as pending.

## email-identity (`fix/email-identity-r2`)

Fixed: everything not listed below.

Deferred:

- `POST /me/email/resend` still returns 429 when the allowance is spent and 409 when nothing is pending. Both depend only on the caller's own pending state, and the 429 comes from the minted count, which counts only mints. The pending address being verified elsewhere yields 409 rather than 202, a one-bit leak that was not in the review. Closing it needs a per-account attempt counter and a schema change, so it is left for the integrator.

Pending verification:

- The compile and run of `crates/sentinel-api/tests/email.rs` and `crates/sentinel-store/tests/email_identity.rs`: **done**. Both ran in `test-linux`; `email.rs` passed, `email_identity.rs` failed three tests on a test helper (page limit, above) and passes after it.
- The platform-override test covers only a bearer credential, which never holds step-up; the stepped-up session success path with a reason is not exercised over HTTP. Still pending.
- The revoke route reads an optional JSON body on `DELETE`; not exercised against real HTTP clients that send an empty `DELETE`. Still pending.

Review notes:

- (med) `POST /tenants/{slug}/invitations` (`routes/email.rs:386-430` with `registration.rs:265-269`) has no platform-override control. `member_tenant_by_slug` resolves any tenant for a super admin who is not a member and `invite_to` then passes on `require_platform` alone, so a platform administrator can invite an address they control into any tenant as admin with no step-up, no reason and no platform-override audit row, against `docs/step-up.md` (`Authority::require_tenant_access_change`). Revoking invitations skips the same check. Fix: route creation through `require_tenant_access_change`, or require step-up and a reason for a non-member admin, and add a test.
- (med) `POST /me/email` is an enumeration oracle (`email.rs:473-496` `request_canonical`, `registration.rs` `accept_invitation`, `routes/email.rs` `set_email`), although `docs/api.md` and the comments promise the same reply either way. An address verified by another account returns `Suppressed`, a 202 forever; an unclaimed address mints a link each time, so the sixth request in an hour is `Throttled`, a 429; the per-recipient outbox ceiling (5 an hour) also yields 429. `Accepted::Throttled` versus `Unusable` in `POST /invitations/accept` leaks the same way. Fix: count attempts against the account allowance even when suppressed, or return 202 for every outcome except the account's own limit.
- (low) Accounts registered by email that never verify are never purged (`register_with`, the `email.rs` purge). Under open registration they accumulate, limited only by the Signup budget (2/s deployment-wide). Consider purging unverified, never-signed-in email accounts after the token horizon.
- (low) Anyone can queue up to 5 messages an hour to any address by registering or calling `/email/resend`, which also exhausts the recipient allowance (`email.rs:455-496`). The victim's own verification or invitation mail is then silently throttled, and the mail text invites a pre-hijack click on a claim the attacker created. Inherent to the design; the denial should be documented.
- (low) `live_user` checks only `status != 2`, not `active = 1`, so a suspended account holding a verification token can verify and be granted membership through a token-carried invitation; the accept route does check `active` (`email.rs` `confirm`, `registration.rs` `redeem_verified`).
- (low) `sentinel admin ... invite_email` (`admin.rs:1058-1093`): with `--email` and a configured lane the secret is not printed, so an abandoned message leaves the one-time secret unrecoverable and the operator must create a new invitation. Acceptable but undocumented. `admin.rs` and `service.rs` are Linux and server-feature only and were not compiled by the reviewer; `cargo lint-linux` has now compiled them.

## github-org-membership (`fix/github-org-membership-r2`)

Fixed: everything not listed below.

Deferred:

- Repeated `user_login` and `org_membership` calls on each 5-minute retry were a consequence of the token scope failure. With a working token the walk completes and the pair is not retried, so no separate change was made.

Pending verification:

- Compile and run the `sentinel-github` and `sentinel-checks` members tests: **done**, in `test-linux` (they passed; the one `sentinel-checks::reconcile` failure was a test race, above).
- Confirm against a real GitHub App that a token minted with `members:read` plus `metadata:read` can read `/repos/{o}/{r}/collaborators/{login}/permission`. Still pending: the tests use the stub.

Review notes:

- (med) `membership_token` and `repo_role` (`sentinel-github/src/app.rs`, about lines 330-345 and 440-480 of the diff) with `sentinel-checks/src/members.rs` `ask()`: the token was minted with `{"members":"read"}` only, but `repo_role` calls the collaborator permission endpoint, which needs repository Metadata read. With the narrowed token GitHub will probably answer 403 or 404, which `repo_role` maps to `Unknown`; every non-owner member's walk then stops at the first repository, `observed.complete` stays false, and the pair retries forever on the 5-minute backoff, deriving no repository grant (GitHub-backed plain members get Operator with zero repositories). Each retry repeats `user_login` and `org_membership`. The implementer lists this as unverified and the design hinges on it: request the repository permission the endpoint needs, or prove the endpoint works with the members-only token.
- (low) A repository that keeps answering `Unknown` (a 404 or 403 on a renamed or deleted repository whose binding is not yet revoked) halts the walk; the cursor stays at the last settled repository and later passes never revisit earlier ones, so after the grace period `settle_grants` sweeps their grants. One bad repository blocks those after it and eventually removes access to those before it. The `Absent` branch of `ask()` is dead code, because `repo_role` never returns `Absent`. A per-repository 404 should mean "no access" or be skipped, with a bounded attempt count.
- (low) The 60 s on-demand gap fence reads `checked_ms` of an existing queue row (`sentinel-store/src/github_members.rs` `enqueue_user`, and the `sign_in`/`local_auth` callers). A non-member candidate row is deleted by `drop_row` on `Absent`, so the next sign-in inserts a fresh row with `checked_ms = 0` and the fence never applies: a user with a linked GitHub account can make each sign-in schedule up to 256 tenants x 2 GitHub calls against other organizations' installation budgets, limited only by the sign-in throttle. Keep a negative-result timestamp, or leave the row parked until the gap passes.
- (low) While a membership stays stale (a GitHub outage leaves `synced_ms` old for up to the grace period), every `GET /tenants/{slug}/repos` by that member opens a writer transaction (`sentinel-api/src/routes.rs`, `touch` and `enqueue_user`). The comment says "rate limited in the store", but only the row update is gated. Gate it with an in-memory per-(tenant, user) timestamp, or have `touch()` also check `checked_ms`.
- (low) If `target()` returns `None` because the organization installation row is gone or no longer bound, other than through `unbind_installation` or the suspended path, the lane drops the queue row ("target gone"); derived members then keep access indefinitely with no check and no grace expiry, because `seed()` re-adds the row and the lane drops it again (`github_members.rs` `target()` and `apply`). Confirm every path that clears `installations.tenant_id` or deletes the row calls `installation_released`, or expire derived rows when `target` is `None`.

## onboarding-backend (`fix/onboarding-backend`)

Fixed: everything not listed below.

Deferred:

- `SENTINEL_AUTO_JOIN_DOMAINS` parsing is not in this branch. `sentinel_api::Options::auto_join` is the hook and `service.rs` passes the default (empty), so the settings route's `auto_join.applies` is false everywhere until the auto-join branch supplies the rules. (The `domain-auto-join` branch below does supply them.)
- The wizard's mail test made a real outbound connection to a host and port the token holder chose (SSRF). Resolved: the test now sends only to the fixed Resend host.
- The emailed `/verify-email` and `/invitations/accept` pages and the web wizard UI were not part of this backend task (the `onboarding-ui` branch adds them).
- Migration number 52 was the next free one on this base; the integrator renumbers if another branch also takes it.
- `sentinel-api` now depends on `sentinel-mail`, so `Cargo.lock` gained one edge and no new external crate.

Pending verification:

- Compile `crates/sentinel/src/service.rs` (`announce_setup`, `write_owner_only`, `retire_setup_file`, the `Maintenance::start` signature, the `start_with` call) with `cargo lint-linux` on the VPS: **done**. It found one needless borrow in the neighbouring `start_mail` call (fixed above) and passes.
- `cargo test -p sentinel-store --test setup` and `cargo test -p sentinel-api --test setup`: **done**, in the suites; both passed, including the throttling and org-budget assertions that were feared to need adjusting.
- The upgrade and schema tests that enumerate migrations and the `READABLE_BY` entry `(52, 51)`: **done**, in the suites; passed.
- Confirm on the VPS that the token file is mode 0600 and that a restart with setup still open issues a new token and voids the old one. Still pending: no test or manual check of the running controller was made in this pass.

Review notes:

- (low) `sentinel-store/src/setup.rs:42`: the `TOKEN_TTL_MS` doc comment says `admin setup-token` issues a new token. No such command exists; only a controller restart issues one, as `admission.md` and `development.md` say. Fix the comment.
- (low, resolved) the earlier mail test connected to any host and port the token holder gave. The test now goes only to the fixed Resend host and its `reason` carries only a status and an error name.
- (low) `routes/setup.rs` `status` (about line 85) and `oauth/mod.rs` `Budget::Setup`: `GET /setup` runs an uncached store read per request while setup is open with no admission budget, and five wrong well-formed tokens from anyone lock setup for 5 minutes, which a client can keep up. Neither is a privilege issue; `admin bootstrap` is the documented escape, so worth a doc note.
- (low) `sentinel-store/src/organizations.rs` `create_self_service`: self-service organizations can take slugs matching the login of a GitHub organization not yet bound to a tenant, which allows squatting. Moving `approved-users` deployments from personal-only to also allowing organizations widens what existing deployments grant; the compatibility entry documents the widening but not the squatting. Check it against installation binding.
- (low) `sentinel/src/service.rs` `announce_setup` (about line 2125): the setup token is logged at warn level to the console and any log collector, by design and documented; it is dead after an hour or once setup closes. The Linux-only code now compiles and lints on the VPS.

## domain-auto-join (`fix/domain-auto-join`)

Fixed: everything not listed below.

Deferred:

- Run the new tests and `cargo lint-linux` on the VPS: **done** (above).
- Compile-check `crates/sentinel/src/service.rs` on Linux with the server feature: **done**.
- Migration number 52 and audit event 74 may need renumbering by the integrator if another branch took them (see the same note under `onboarding-backend`).
- A member an administrator removes rejoins at the next sign-in while the domain is listed (documented); there is no per-user opt-out record.
- No web UI for the setting; it is set by environment variable only.

Pending verification:

- `cargo nextest` for the `sentinel-store` tests `auto_join`, `upgrade`, `email_identity`, `registration` and `local_auth`: **done**, in the suites; they pass (`email_identity` after the test helper fix, `local_auth` after a timing-bound test passed on re-run).
- `cargo lint-linux` including the `service.rs` changes: **done**, passes.
- That the test fixture's `Authority::HostLocal` passes `registration::set_policy` and `create_personal_namespace` under the default policy: **done**; the `auto_join` tests pass.

Review notes:

- (low) `sentinel-store/src/auto_join.rs:355` and `docs/admission.md:724`: a member an administrator removes rejoins at the next sign-in while the domain is listed, because there is no per-user opt-out record. Documented, and it follows from the operator's setting deciding membership. Consider a follow-up if admin removal is meant to stick.
- (low) `sentinel/src/service.rs:981`: a non-Unicode `SENTINEL_AUTO_JOIN_DOMAINS` value is silently treated as unset, because `unwrap_or_default` swallows `VarError::NotUnicode`. The operator gets no startup warning. A fixed warning with no content would match the "warn on malformed" brief.
- (low) `sentinel-store/src/local_auth.rs:797`: `auto_join::apply` runs inside every `issue_session` transaction, so an unexpected error from it (for example a namespace-insert failure) would fail the sign-in. Policy refusals do not error and the organization lookup and insert share one writer transaction, so it looks unreachable, but it is a sign-in availability coupling.
- (low) `sentinel/src/service.rs:2065`: the Linux-only controller wiring (Config field, Role matching, `record_auto_join`) is now compiled and linted on the VPS and passes.

## tenancy-isolation-tests (`fix/tenancy-isolation-tests`)

Fixed: everything not listed below. The three new suites ran for the first time in this pass and had the test-side defects in the table above (camp permissions, `--json` position, secret field names, invitation token text); with them fixed they pass.

Deferred:

- **Intra-tenant leak, not fixed.** `GET /queue` requires only tenant membership (`require_tenant_member`), not a repository grant. A reader or operator without a grant on a repository, or a member of a GitHub-backed organization without GitHub access to it, still sees that repository's waiting jobs: run id, repository id, age, scheduling reason, and a `total` that counts hidden repositories. Admins are the only members with implicit access to every repository, so these two cases see more than they should. A fix would filter the page and total by readable repositories in `dispatch::list_queue`, a hot path with performance budgets, and changes the documented contract (`docs/api.md`, `docs/web-ui.md`). It needs an owner decision and a `docs/compatibility.md` entry.
- No cross-tenant leak was found in the route code read for the API tests. Every slug route resolves through membership or ends in `NotFound`, and `GET /workers`, `GET /queue`, uploads and objects fall back to `NotFound` for non-members.
- The CLI suite covers `api` commands only. Interactive sign-up, verification-email delivery and the setup-token race over HTTP are not newly covered, because existing store tests (`setup.rs`, `email_identity.rs`, `auto_join.rs`) and API tests (`setup.rs`, `email.rs`) already cover them.

Pending verification:

- The three new suites (`sentinel-store --test tenancy_isolation`, `sentinel-api --test tenant_isolation`, `sentinel --test tenant_isolation`): **done**; the store suite passed first time, the other two after the fixes above.
- The assumptions listed as likely failure points: the JSON field names were wrong in one place (the nested secret document, fixed); `?cursor=` text, the invitation-accept race (202/404 for the address-bound token, 200/404 for the link token), identical 403/404 on the platform routes, and the GitHub-backed store test's read grant all held. The sweep's "a refusal never repeats an identifier the request did not carry" assertion found nothing.

Review notes:

- (low) `crates/sentinel-api/tests/tenant_isolation.rs:848,871`: the "nothing changed" checks read `cancel_requested` and `received` with `unwrap_or(false)` and `unwrap_or(0)`, so a wrong field name would pass without checking anything. The secret check had exactly that flaw in a stricter form and is fixed; the two others still use the defaults. Assert that the field exists and has the expected type.
- (low) `docs/authorization.md:79`: the paragraph says "the store does the same keyed probe either way", a timing-equivalence claim nobody verified and the suites do not assert. Soften it or point to the code that makes it true.
- (low) The suite does not cover the HTTP-level setup-token, verification and auto-join races the brief asked for; only pre-existing store and API tests do. A coverage gap, not a defect.
- (low) `GET /queue` needs only tenant membership (the deferred item above). It needs a tracked follow-up and a `docs/compatibility.md` entry when fixed.

## onboarding-ui (`fix/onboarding-ui-r2`)

Fixed: everything not listed below.

Deferred: none recorded by the package.

Pending verification:

- `node --test web/test/*.test.mjs` on the VPS: **done**, 22 of 22 (see the Node note above).
- `web/test/ui.mjs` scenario "organizations and invitations" through `crates/sentinel-api/tests/web_browser.rs`: **done**; the new invitation round-trip and expiry checks passed, including "a GitHub sign-in started from an invitation comes back to the invitation, not the first tenant" and "an expired parked invitation secret is removed on the next load". The sign-up check needed the fixture policy fix above.
- That Nuxt's server-side `useCookie` deletion reaches the redirect response from `index.vue`: the browser checks "the return marker is cleared once it has served" and "without a pending return `/` opens a tenant again" passed.
- `pnpm -C web build`: **done**, passes.

Review notes:

- (med) `web/app/pages/invitations/accept.vue:87-95,159` (depends on `web/app/pages/index.vue:6-14`): the GitHub sign-in round trip from the invitation page usually failed without telling anyone, because the server-side render of `index.vue` redirected to the first tenant before the client read `sentinel-return`, and the secret stayed in `sessionStorage` past its ten minutes. The branch's later commits (`a GitHub sign-in started from an invitation comes back to it`, the pending-return fallthrough and the round-trip browser checks) address this and the browser test now passes it; the review note is kept because the package's own record has not been re-read against those commits.
- (low) `web/app/pages/setup.vue:52-63`: resuming survives only one refresh. On mount `Object.assign(draft, stored)` fires the deep watcher and `save()` writes step 0 over the stored step, so a second refresh before passing the token step loses the position and shows no "picking up where you left off" notice, against `docs/web-ui.md#first-run-setup`. Keep `resumeAt` in the stored step until the person passes it.
- (low, superseded) the wizard's copy-paste environment lines must each stand on their own line without a trailing comment (systemd `EnvironmentFile` and `docker --env-file` do not strip one); the Email step now shows the Resend lines ([web interface](web-ui.md#first-run-setup)).
- (low) `web/app/pages/forgot-password.vue:22`: the page tells the administrator to run `sentinel admin recover --username <NAME>`, but an account that signed up by email has a generated username (`registration.rs:1010`) the person does not know, and `recover` does not take an email address. The page should say the administrator must find the username first.
- (low) `web/app/components/admin/Invitations.vue:96-105`: if `GET /tenants/{slug}/settings` fails (`settings` is null) the tab shows only its heading, with no form, explanation or retry, so a failed load looks like an empty feature. The brief requires an error state with a retry.
- (low) `crates/sentinel-api/tests/setup.rs:365-369`: the new `github_sync` response field is tested only for its absence on an app-created organization. No API test checks it is present and correct on a GitHub-backed organization, or that `check_due` switches between a due row and a settled future row (`routes/setup.rs:440-455`).
