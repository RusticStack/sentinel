# Worker enrollment, identity and sessions (W01)

Implemented in `sentinel-link` (identity, pinned TLS, framing, hello/heartbeat), `sentinel-store::workers` (enrollment, identity, liveness, revocation) and `sentinel admin worker`, with append-only metadata migration **13**.

## Identity is a key you hold

There is no certificate authority. A worker generates its own self-signed TLS certificate (`Identity::generate`: ECDSA P-256 via `rcgen`); the **fingerprint** — BLAKE3 of the certificate DER — is its identity. The controller stores only that fingerprint; the private key never leaves the machine it was made on, is saved owner-only, and regenerating it means becoming a different worker.

The trust runs both ways and both ways are pinned:

- The controller demands a client certificate and, at the TLS layer, accepts any well-formed one whose holder proves possession in the handshake. *Which* fingerprints are live workers is decided afterwards by the store — `workers::authenticate` — with the certificate in hand.
- The worker accepts exactly one server fingerprint, the one it was handed with its enrollment. A wrong controller never reaches the hello, and the enrollment is never presented to it.

No root store is consulted on either side, so a compromised public CA cannot insert itself, and a rotated controller certificate is an explicit re-enrollment rather than a silent change of trust. TLS 1.3 only.

## Enrollment is one-time, expiring and pool-bound

`sentinel admin worker enroll --pool builders` issues a secret (an hour by default, a day at most), stored only as a digest, and prints it once on stdout. The operator delivers it to the machine out of band. On its **first** session the worker presents the secret with its hello; `workers::enroll` redeems it exactly once, binding the presented fingerprint and the worker-generated `wrk_` identifier to **the pool the enrollment was issued for**. A worker never chooses or changes its pool: moving one means revoking and enrolling again.

Refusals are typed and audited: an unknown, spent, expired or revoked secret; a pool that is not active; a reused identifier or fingerprint (`Conflict`, leaving the enrollment unspent for the real machine). Pool access for *placement* is A07's `require_pool_access`, checked per tenant at dispatch (W02); enrollment decides which pool's capacity a machine is.

## Sessions

A session is one TLS connection, framed as big-endian `u32` length + postcard message, capped at `MAX_CONTROL_MESSAGE_BYTES` before any allocation. The first exchange is `Hello` → `Welcome` or `Reject`:

- `Hello` carries C03's `negotiate::Hello` (protocol range, capabilities, arch), the worker's identifier and name, and optionally the enrollment secret.
- The controller runs `negotiate::negotiate` (highest common version, required capabilities), then asks its `Admission` policy: a known fingerprint is welcomed; an unknown one with a valid enrollment is enrolled and welcomed; anything else is a typed `Rejection` the worker must not retry unchanged.
- `Welcome` returns the negotiated set and the heartbeat interval.

After that only heartbeats flow here. The worker sends `Ping(seq)` every `HEARTBEAT_INTERVAL` (5 s); the controller answers `Pong(seq)`, reports the beat to admission, and the store records `last_seen` at most once per `SEEN_RECORD_INTERVAL_MS` (60 s) — a beat every few seconds costs the writer one row per minute. Either side that hears nothing for `HEARTBEAT_DEADLINE` (15 s, two missed beats: one delayed packet must not tear down a session carrying live work) reports `Lost`. A second hello, an out-of-sequence pong or an oversized frame is a protocol violation that ends the session.

`workers::revoke` refuses the fingerprint at its next authentication; the running session is closed by W06's lease reconciliation, and the identity can never enroll again. Offers, leases and logs are W02–W05; this is who is on the other end and whether they are still there.

```sh
sentinel admin worker enroll --data-dir <PATH> --pool builders --expires-in 1h > enrollment
sentinel admin worker list   --data-dir <PATH> --pool builders
sentinel admin worker revoke --data-dir <PATH> --id wrk_...
```

## What is not here yet

The `sentinel server` and `sentinel worker` processes do not yet open this link: the listener, the worker's reconnect loop and the enrollment/identity configuration land with W02's dispatch loop, which is what the session exists to carry. The library is exercised against real TLS sockets on loopback, not against a running controller.

## Verification

`crates/sentinel-store/tests/workers.rs`: enrollment needs platform administration, an active pool and a bounded lifetime; a spent, expired or revoked enrollment is refused and cannot be un-spent by raw SQL; a reused identifier or fingerprint conflicts while the fresh enrollment stays usable; a worker authenticates by fingerprint only, liveness moves forward at the bounded cadence and never backwards, pool and fingerprint are immutable by trigger, listing is gated on the platform or an admitted tenant's membership, revocation is final and not repeatable.

`crates/sentinel-link/tests/link.rs`, over real TLS on loopback with the store as admission: an unknown certificate without an enrollment is `NotEnrolled`; with one it is welcomed with the negotiated protocol, beats are recorded, the enrollment is then spent for an impostor, the enrolled identity reconnects with no enrollment at all, and after revocation the same certificate is `NotEnrolled` and cannot re-enroll under its identity; a wrong server fingerprint fails in the handshake before the hello and leaves the enrollment unspent; an unsupported protocol version and an expired enrollment are typed refusals; every server-side session ends in a clean refusal or goodbye. `sentinel-link` unit tests cover PEM round-trip with a stable fingerprint and base64 correctness. The `sentinel admin worker` surface was exercised end to end on Linux.

See [TODO.md](../TODO.md) for commands and results, [tenancy](tenancy.md) for pools and grants, and [protocol contracts](protocol.md) for negotiation and size limits.
