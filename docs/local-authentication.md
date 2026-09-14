# Local authentication (A02)

Implemented in `sentinel-auth` (password hashing, opaque secrets, cookie/CSRF policy), `sentinel-store::local_auth` (bootstrap, credentials, sessions, audit) and the host-local `sentinel admin` command, with append-only metadata migration **5**.

This is authentication only. Admission is [A01's authorization layer](authorization.md): a validated session produces a `Principal`, and every repository, tenant and platform decision is still a live membership/grant check. GitHub sign-in is A04, registration and invitations are A05, MFA and step-up are A06.

## First-admin bootstrap

`sentinel admin bootstrap --data-dir <PATH> --username <NAME>` opens the controller's `metadata.sqlite` directly and creates one super admin with a local password. Its authority is the operating system's: only a user who can already open that file can run it. There is no network route to it, the server process does not expose it, and "first visitor wins" is not implemented anywhere.

- The password is read from standard input as raw bytes, minus one trailing newline. It never appears in argv, the process list, shell history, diagnostics or an error message. A terminal stdin is refused with the redirect form instead.
- Bootstrap refuses once the single-row `bootstrap` latch exists **or** any active super admin exists, so restoring a backup or provisioning an admin another way also closes it. The check is repeated inside the writing transaction; the user, its credential and the latch are one commit.
- `sentinel admin status --data-dir <PATH>` reports bootstrap availability, active super admins, live sessions and the last ten audit records. It refuses to create a database, so a mistyped path says so rather than answering about a new empty one.

## Passwords

Argon2id through the maintained RustCrypto `argon2` crate at OWASP's 19 MiB / t=2 / p=1 profile. Sentinel implements no cryptography: the crate owns the KDF and the constant-time comparison, and the stored PHC string owns the parameters.

- Records are per-account salted (16 bytes of OS entropy). Parameters come from the record on verification, so accounts written under older parameters still verify; `needs_rehash` rewrites them after a successful login, outside the writer transaction.
- Passwords are 12–256 bytes and may not be only spacing. That is an admission rule, not a composition rule: no character-class requirements, no silent truncation, no normalization of the bytes supplied.
- One lane (`p=1`) deliberately: a login must not take a whole core of parallel work away from job scheduling. Verification never runs inside a database transaction.
- An unknown or malformed username still pays for a verification against an unreachable placeholder record, so account existence is not revealed by response or by time. Every attempt is audited, with no subject for an unknown name.
- Ten consecutive failures lock an account for fifteen minutes. The failure is counted only against the exact record that was tested, so a concurrent password change is not miscounted. The lockout is a window, not a state an attacker can make permanent; host-local recovery clears it immediately.

## Sessions

Opaque 256-bit secrets from the OS CSPRNG, stored only as their BLAKE3 digest. A stolen database snapshot yields no usable cookie, and validation is one 32-byte primary-key probe.

- Two deadlines, both absolute instants recorded at issuance: idle (8 h) and absolute (7 days). Expiry, revocation and the account's live `kind`/`active` state are predicates of the single validation statement, so a suspended account's cookie stops working immediately without waiting for a sweep.
- Sliding the idle deadline is a write, so it happens only after `refresh_after_ms` (5 min) of the window is spent, and never past the absolute deadline. A session pinned to its absolute deadline is never refreshed again.
- Login issues a new session; it does not reuse one. Logout revokes one session, logout-all revokes every live session of the account, and a password change, super-admin demotion or suspension revokes them in the same transaction as the change. The database refuses to un-revoke a session, to move its absolute deadline or to change its user, CSRF secret or creation time.
- `purge_expired` deletes revoked and expired rows in bounded batches; it is maintenance, not the expiry mechanism.
- A session's `Principal` carries repository bits plus `TENANT_ADMIN`, and `PLATFORM_ADMIN` only for an actual super admin. It is not a capability: `auth` still verifies membership and grants per tenant, per query. A06 adds step-up before privileged policy changes use the platform bit.

## Cookies and CSRF

- `__Host-sentinel_session`, with `Path=/; Secure; HttpOnly; SameSite=Strict` and no `Domain`, so a sibling hostname can neither set nor read it.
- `SameSite=Strict` rather than `Lax`: Sentinel has no cross-site entry flow that must arrive authenticated, and top-level GET navigation mutates nothing.
- State-changing requests must echo the session's own CSRF secret in the `x-sentinel-csrf` header — a header cross-site form posts cannot set. The secret is per session, compared by digest in constant time; another session's secret, and the session cookie itself, are both rejected.
- Cookie parsing refuses a duplicated or malformed cookie rather than taking the first match: two cookies of that name mean something is injecting them.
- No HTTP server exists yet (W08, Part 12). These are the exact bytes and the exact decision the eventual handlers must use, written and tested once instead of per route.

## Recovery and the last super admin

`sentinel admin recover --data-dir <PATH> --username <NAME>` resets a local password, clears the lockout and revokes the account's sessions, so an operator locked out — or stranded by a GitHub outage — is never permanently shut out. Every use is recorded as host-local in the audit table.

`auth_audit` is append-only: updates and deletes are refused by trigger, as are updates and deletes of the bootstrap latch. Records carry the event, actor, subject, host-local flag and at most 128 bytes of bounded detail (a login name) — never a password, hash, digest or cookie value.

The deployment must keep one reachable super admin. `set_super_admin` and `set_active` require `PLATFORM_ADMIN` scope and audit the change, and database triggers refuse any update or delete that would empty the active super-admin set — including a raw controller statement or a repair script. Demotion and suspension revoke the account's sessions in the same transaction.

## Cost

Measured on `DOOMBRINGER` (i7-13700KF, Ubuntu 24.04 WSL2, ext4), release build, database at `synchronous=FULL`:

| Operation | Mean |
|---|---|
| Session validation (`authenticate`) | 1.3 µs |
| Accepted login (Argon2id + durable commit) | 13.8 ms |
| Rejected login | 14.5 ms |
| Unknown username | 15.3 ms |

Verification dominates by design, and the three login outcomes cost the same order of magnitude, which is the point of the placeholder record. Session validation is what every authenticated request pays: one primary-key probe and one key join, guarded by a query-plan test that rejects table scans and temporary sort trees. Sliding an idle deadline is the only write a read-only request can trigger, and only after five minutes.

WSL2 is a development reference, not a production qualification.

## Verification

`crates/sentinel-store/tests/local_auth.rs` covers bootstrap admitting exactly one admin and then refusing itself (latch and pre-existing admin alike), password acceptance and rejection, unknown and wrongly-cased usernames, forged cookies, the database holding no usable cookie value, idle and absolute expiry with refresh bounded by the absolute deadline, logout and logout-all, refusal to un-revoke by raw SQL, lockout and its expiry, host-local recovery resetting and revoking, password change requiring the current password and rotating sessions, last-super-admin protection through the API and through raw `UPDATE`/`DELETE`, suspension invalidating live cookies at once, credentials refused for service principals, administration requiring explicit platform scope rather than a session alone, append-only audit carrying no credential material, and bounded purging. `sentinel-auth` unit tests cover hashing, rehash detection, input bounds, secret round-tripping and rejection, cookie attributes, ambiguous cookie headers and CSRF binding.

See [TODO.md](../TODO.md) for commands and results.
