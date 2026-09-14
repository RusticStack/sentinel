# Part 03 audit: identity, admission and step-up (A01–A06)

Audited 2026-09-14 after `e1218fd`, by re-reading every trust-boundary module in `sentinel-store` (`auth`, `local_auth`, `tokens`, `sign_in`, `registration`, `mfa`), migrations 4–9, `sentinel-auth`, `sentinel-github` and the host-local `sentinel admin` surface, and by writing a failing test for each gap before fixing it. Findings are grouped by what an attacker would need to hold.

## Fixed in this audit (commit `feat: close Part 03 audit findings`)

| # | Finding | Why it mattered | Fix |
|---|---|---|---|
| 1 | **Step-up had no failure limit.** A six-digit TOTP has three valid values per window; a stolen cookie could guess indefinitely, and the password proof bypassed the login lockout entirely. | The second factor was weaker than the first. | Migration 10 adds `sessions.step_up_failures`. Five consecutive failed proofs revoke the session and audit `SessionRevoked` with detail `step-up failures`; a successful proof resets the counter. Tested for password and TOTP proofs. |
| 2 | **`sign_in::link` needed only a session.** A hijacked session could attach the attacker's GitHub account, granting persistent access that survives a password change. | Linking changes who can authenticate as the account — A06's own rule. | `link` takes `Policy` and requires `Session::require_step_up`. Tested. |
| 3 | **`provision_credential` took a bare `Principal`.** Giving an account a password is an authentication change that needed no step-up. | Same rule as #2. | Takes `Authority` and calls `require_privileged`. Tested. |
| 4 | **Two host-local commands still fabricated a `Principal`** (`token list`, `identity list`), the pattern A05 removed elsewhere. | Audit rows for those reads could not say who acted. | `tokens::list`, `tokens::revoke`, `sign_in::identities` and `sign_in::unlink` take `Authority`. |
| 5 | **Suspension racing a GitHub sign-in** surfaced as an SQL constraint error from the session trigger. | Not a security hole, but a route would have reported an internal error rather than `NoAccount`. | `sign_in::complete` maps the trigger refusal to `Outcome::NoAccount`. |

## Verified sound, and worth stating

- **One liveness predicate.** Every authorization query joins `users.active = 1`; migration 8 makes `active` imply `status = approved` by trigger. Pending, rejected and suspended accounts therefore fail *every* path — session, credential, GitHub sign-in, repository query — without any statement having to know about status. Confirmed by the A05 and A06 suites (`issue_session` refused for a pending account even through the trusted path).
- **Secrets are digests everywhere except the TOTP seed**, which is sealed under a key outside the database with per-account associated data. A stolen `metadata.sqlite` yields no cookie, credential, invitation, recovery code or seed. Confirmed by tests that search the raw tables for the plaintext.
- **Verification never runs inside the writer.** Argon2 (login, password change, step-up by password, registration) and the writer's recheck of the exact record verified are the same pattern in every module.
- **Bearer credentials can never step up.** `Authority::credential` is always `stepped_up: false`, so an API token — even one carrying `platform-admin` — cannot change the policy, the super-admin set, suspension, passwords or identity links. Only a session with a recent proof, or the host-local operator, can. Tested. This is deliberate and now documented in [step-up](step-up.md).
- **Host-local authority is the strongest and needs no step-up**, and every host-local action is recorded as such. The database file is the root of trust for bootstrap, recovery, key creation, lost-device removal and logout-all; there is no network path to any of them.
- **Immutability by trigger** for sessions, credentials, invitations, installations, sign-in state, identity links, audit rows and the bootstrap latch; revoked, spent and consumed rows cannot be revived by raw SQL. Each has a test that tries.
- **Bounded everything a remote party controls**: usernames, display names, invitation and credential lifetimes, page sizes, audit detail, GitHub responses (headers, body, redirects, timeout), callback queries, and purge batches.

## Accepted deviations, recorded rather than fixed

- **Audit timestamps use the wall clock**, not the operation's `now`. Operations take `now` for determinism in tests; audit rows are provenance and record when the row was written. In production both are the same clock. Not changed, because it would touch every entry point for no security gain.
- **`approve`/`reject` need platform administration but not step-up.** They admit or refuse *new* accounts under a policy that itself needed step-up to set; treating every approval as privileged would push administrators toward long step-up windows. Recorded as a policy choice.
- **A GitHub-only super admin must enroll TOTP before any privileged change**, because the password proof requires a local credential. Enrollment itself needs only a session, so there is no lockout: sign in, enroll, step up. Documented in [step-up](step-up.md).
- **`Registration::Closed` refuses outstanding invitations.** Closed means closed; invitations expire on their own. Documented in [admission](admission.md); a one-line change if the deployment wants invitations to survive closing.
- **Sessions issued before migration 9 have no `ses_` name** and cannot be revoked individually — only by logout-all. They expire within seven days regardless.

## Still open in Part 03

- **A07** — tenant suspension, membership/role revocation, pool grants, running-stream and job cancellation propagation. `tenants.active` is already honoured by every predicate, but nothing yet flips it or propagates it.
- **A08** — the cross-tenant sweep with two organizations, a personal namespace, overlapping memberships, invitation races, guessed IDs, cross-tenant cursors and downloads, and last-admin recovery. Parts of this exist across the per-task suites; the consolidated sweep is not written.
- **No HTTP routes exist (W08).** Every contract above is verified at the library boundary and, for GitHub, against a loopback provider. The cookie, CSRF, state and bearer policies are the bytes the routes must use; they are not yet used by a route.
- **Rate limiting of `login` is per-account lockout only.** Password spraying across many usernames is audited (`LoginRejected` with no subject) but not throttled; that needs a request-level limiter in the server, not the store.

See [TODO.md](../TODO.md) for the commands and results behind each claim.
