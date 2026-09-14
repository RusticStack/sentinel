# Second factors, step-up and session administration (A06)

Implemented in `sentinel-auth::mfa` and `sentinel-auth::sealed`, `sentinel-store::mfa`, the `Authority` type in `sentinel-store::auth`, and `sentinel admin key|mfa|session`, with append-only metadata migration **9**.

A session proves who you are. **Step-up** proves you are still there, just now, with something more than a cookie — before a change that alters who can authenticate at all. It is freshness, not authority: `Authority::require_privileged` demands both a recent stamp and a live platform-admin check, in the same transaction as the change.

## What requires step-up

| Change | Entry point |
|---|---|
| Registration / tenant-creation / installation-binding policy | `registration::set_policy` |
| Granting or revoking super admin | `local_auth::set_super_admin` |
| Suspending or reactivating an account | `local_auth::set_active` |
| Removing your own second factor, reissuing recovery codes | `mfa::disable`, `mfa::reissue_recovery_codes` |

Routine administration — approving applications, inviting, revoking credentials, binding installations — needs platform (or tenant) administration but not step-up. `Authority::HostLocal` needs no step-up either: holding the database file is already stronger than any proof a session can offer, and every host-local action is audited as such.

A session that lacks a fresh stamp gets `Error::StepUpRequired`, distinct from `Forbidden`, so a client can prompt for a code rather than report a denial. The stamp lasts `Policy::step_up_ms` (10 minutes), only ever moves forward, cannot be written onto a revoked session, and is judged against the clock — a stamp in the future is not fresh.

## Proofs

- **TOTP** (RFC 6238: SHA-1, 6 digits, 30 seconds, one step of drift) through the maintained `totp-rs` crate; Sentinel's unit tests check its reference vectors. RFC 6238 leaves one-use to the implementer, so `mfa_totp.last_step` records the last accepted step and a trigger refuses to move it backwards: a code seen over a shoulder is worthless within its own window.
- **Recovery codes**: ten 50-bit codes in a look-alike-free alphabet, stored as BLAKE3 digests, each spent once (a trigger refuses to un-spend). Retyping without the separator or in upper case still works. Reissuing a set replaces the old one entirely.
- **Password**, accepted **only when no second factor is enrolled**. Otherwise the weaker proof would stand in for the stronger, which is the opposite of stepping up.

A wrong proof returns `false` and an audited `StepUpFailed`, not an error: the caller renders one response either way.

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

`crates/sentinel-store/tests/mfa.rs`: a platform-admin session refused every privileged change until it steps up, the password serving as proof only before enrollment, freshness expiring on schedule and host-local needing none; enrollment confirmed by a code with the seed stored only sealed and no recovery code present in the database; a TOTP code accepted once with replay and raw rewind refused and the password no longer accepted; recovery codes one-use, retype-tolerant, reissue needing step-up and killing the old set; removal needing step-up and ending every session, with host-local removal audited; sessions listed and revoked by name with no secret in the output and outsiders refused; and the stamp neither forgeable, rewindable, placeable on a revoked session, nor fresh when in the future. Every earlier suite was updated to pass an `Authority` and still passes. The `sentinel admin key|mfa|session` surface was exercised end to end on Linux.

See [TODO.md](../TODO.md) for commands and results, and [admission](admission.md) for the decisions this gates.
