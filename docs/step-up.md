# Second factors, step-up and session administration (A06)

Implemented in `sentinel-auth::mfa` and `sentinel-auth::sealed`, `sentinel-store::mfa`, the `Authority` type in `sentinel-store::auth`, and `sentinel admin key|mfa|session`, with append-only metadata migrations **9**, **10** (per-session failure limit) and **31** (per-account second-factor lockout).

A session proves who you are. **Step-up** proves you are still there, just now, with something more than a cookie — before a change that alters who can authenticate at all. It is freshness, not authority: `Authority::require_privileged` demands both a recent stamp and a live platform-admin check, in the same transaction as the change.

## What requires step-up

| Change | Entry point |
|---|---|
| Registration / tenant-creation / installation-binding policy | `registration::set_policy` |
| Granting or revoking super admin | `local_auth::set_super_admin` |
| Suspending or reactivating an account | `local_auth::set_active` |
| Rejecting an account that was already approved (permanent: a rejected account can be neither approved nor reactivated) | `registration::reject` |
| Suspending or reactivating a tenant | `tenancy::suspend`, `tenancy::reactivate` |
| Linking an external identity to an account | `sign_in::link` |
| Provisioning a local password for an existing account | `local_auth::provision_credential` |
| Removing your own second factor, reissuing recovery codes | `mfa::disable`, `mfa::reissue_recovery_codes` |

Routine administration — approving applications, rejecting a *pending* application, inviting, revoking credentials, binding installations — needs platform (or tenant) administration but not step-up. Rejecting reads the account's status in the same transaction: pending is platform administration, approved needs step-up as `set_active` does, so an unstepped credential cannot permanently do what it cannot do reversibly. `Authority::HostLocal` needs no step-up either: holding the database file is already stronger than any proof a session can offer, and every host-local action is audited as such.

A session that lacks a fresh stamp gets `Error::StepUpRequired`, distinct from `Forbidden`, so a client can prompt for a code rather than report a denial. **A bearer credential can never step up**: `Authority::credential` is always unstepped, so an API token — even one carrying `platform-admin` — cannot make any of these changes. Only a session with a recent proof, or the host-local operator, can.

Five consecutive failed proofs **revoke the session** (migration 10, `MAX_STEP_UP_FAILURES`): a six-digit code has three valid values per window, and a cookie holder who keeps guessing is not the person it was issued to. A successful proof resets the counter.

The per-session limit alone does not hold anyone who knows the password: they sign in again and keep guessing. So wrong TOTP and recovery-code proofs are also counted **per account**, across every session (migration 32, `mfa_totp.failures`/`locked_until_ms`, counted in the same write as the session counter). Ten consecutive failures (`MAX_FACTOR_FAILURES`) lock the second factor for fifteen minutes (`FACTOR_LOCKOUT_MS`): every proof is refused — a correct code included, and a recovery code is not spent — and every session of the account is revoked in the same transaction, audited as `SessionRevoked` with detail `second factor locked`. The window is not extended by tries during it; once it ends the count restarts at the next failure, as the login lockout does. A successful proof resets the count, and host-local password recovery (`sentinel admin recover`) clears both. That bounds online guessing to ten codes per fifteen minutes per account, whatever the number of sign-ins. Linking an external identity (`sign_in::link`) and provisioning a password (`provision_credential`) are authentication changes and require step-up too. The stamp lasts `Policy::step_up_ms` (10 minutes), only ever moves forward, cannot be written onto a revoked session, and is judged against the clock — a stamp in the future is not fresh.

## Proofs

- **TOTP** (RFC 6238: SHA-1, 6 digits, 30 seconds, one step of drift) through the maintained `totp-rs` crate; Sentinel's unit tests check its reference vectors. RFC 6238 leaves one-use to the implementer, so `mfa_totp.last_step` records the last accepted step and a trigger refuses to move it backwards: a code seen over a shoulder is worthless within its own window.
- **Recovery codes**: ten 50-bit codes in a look-alike-free alphabet, stored as BLAKE3 digests, each spent once (a trigger refuses to un-spend). Retyping without the separator or in upper case still works. Reissuing a set replaces the old one entirely.
- **Password**, accepted **only when no second factor is enrolled**. Otherwise the weaker proof would stand in for the stronger, which is the opposite of stepping up.

A wrong proof returns `false` and an audited `StepUpFailed`, not an error: the caller renders one response either way. A GitHub-only account has no password to offer, so a GitHub-only super admin must enroll TOTP before any privileged change; enrollment itself needs only a session, so there is no lockout.

## The seed is sealed

A TOTP seed is the one credential that must be recoverable to be useful, so it is the one value not stored as a digest. It is sealed with XChaCha20-Poly1305 (RustCrypto) under a 32-byte key that lives **outside the database** — `master.key`, created owner-only by `sentinel admin key create`, which refuses to overwrite. The associated data binds each ciphertext to its account, so a row copied onto another account cannot be opened. A stolen `metadata.sqlite` yields no seed and no ability to mint codes; losing the key loses every sealed value, which is the operator's trade to make and the command says so.

Enrollment is two steps: `begin_enrollment` writes an unconfirmed seed and returns the `otpauth://` URI once; `confirm_enrollment` requires a code from the app, issues the recovery codes once, and stamps the session. Until confirmed, nothing about authentication changes — an abandoned enrollment cannot lock anybody out. A confirmed factor cannot be quietly re-enrolled by a live session; replacing it means `disable` under step-up, which also revokes every session of the account so no stepped-up window outlives the factor.

There is no host-local *enrollment* — it needs the person and their device — but there is host-local removal, for a lost device with spent codes, audited as host-local.

## Session administration

Sessions now carry a public `ses_` identifier (migration 9; sessions issued before it are unnamed, still work, and are reached by logout-all). `local_auth::sessions` lists an account's sessions as metadata — created, deadlines, step-up time, revoked — with no digest and no cookie value anywhere in the record. `revoke_session` revokes one by name; the account itself or a platform admin may do either, and anybody else gets the same `NotFound` as a guessed identifier. `revoke_all_host_local` is the operator's logout-all.

```sh
sentinel admin key create   --data-dir <PATH>
sentinel admin mfa status   --data-dir <PATH> --user root
sentinel admin mfa disable  --data-dir <PATH> --user root
sentinel admin session list       --data-dir <PATH> --user root
sentinel admin session revoke     --data-dir <PATH> --user root --id ses_...
sentinel admin session logout-all --data-dir <PATH> --user root
```

## Verification

`sentinel-auth` unit tests: RFC 6238 reference vectors, one-step drift with the matched step reported, malformed codes refused before HMAC work, provisioning URI shape and seed redaction, recovery codes distinct and retype-tolerant, sealed values opening only under their key and context, damaged/truncated/unknown-version ciphertexts refused, key file created once at the right size.

`crates/sentinel-store/tests/mfa.rs`: a platform-admin session refused every privileged change until it steps up, the password serving as proof only before enrollment, freshness expiring on schedule and host-local needing none; enrollment confirmed by a code with the seed stored only sealed and no recovery code present in the database; a TOTP code accepted once with replay and raw rewind refused and the password no longer accepted; recovery codes one-use, retype-tolerant, reissue needing step-up and killing the old set; removal needing step-up and ending every session, with host-local removal audited; sessions listed and revoked by name with no secret in the output and outsiders refused; and the stamp neither forgeable, rewindable, placeable on a revoked session, nor fresh when in the future; wrong codes accumulating across fresh sign-ins until the account's factor locks and every session is revoked (`step_up_failures_accumulate_across_sessions`), the lock refusing a correct code and sparing recovery codes until it ends (`an_account_lockout_refuses_even_a_correct_code_until_it_expires`), and host-local recovery clearing it (`host_local_recovery_clears_the_step_up_lockout`). `crates/sentinel-store/tests/registration.rs` covers rejecting an approved account needing step-up (`rejecting_an_approved_account_needs_step_up`). Every earlier suite was updated to pass an `Authority` and still passes. The `sentinel admin key|mfa|session` surface was exercised end to end on Linux.

See [TODO.md](../TODO.md) for commands and results, and [admission](admission.md) for the decisions this gates.
