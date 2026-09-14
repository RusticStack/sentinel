# Worker link: enrollment, sessions and dispatch (W01–W02)

Implemented in `sentinel-link` (identity, pinned TLS, full-duplex framing, hello/heartbeat, the `controller` dispatch loop and the `worker` reconnect loop), `sentinel-store::workers` (enrollment, identity, liveness, revocation), `sentinel-store::dispatch` (ready queue, reservations, fenced offers and leases) and `sentinel admin worker`, with append-only metadata migrations **13** and **14**. The `sentinel server` and `sentinel worker` processes open the link as described in [configuration](configuration.md).

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

The session is full duplex on one TLS connection: the rustls state sits behind a mutex held only while bytes move between it and a buffer, never across a socket call, so one thread reads the socket while any thread — the dispatcher — writes. An offer therefore reaches a worker the moment it is placed, not at its next beat.

The worker sends `Ping { seq, held }` every `HEARTBEAT_INTERVAL` (5 s), where `held` names the attempts it still holds (at most `MAX_LIST_ITEMS`, 64). The controller answers `Pong { seq, lease_until_ms, stop }`: the leases of every held attempt it recognises are renewed to `now + DEFAULT_LEASE_MS` (30 s, never backwards), and `stop` lists what the worker must end at once because the controller no longer counts it as held — lapsed, finished elsewhere, or never its. Liveness is recorded at most once per `SEEN_RECORD_INTERVAL_MS` (60 s), and a beat with nothing to renew and liveness fresh costs no write at all. Either side that hears nothing for `HEARTBEAT_DEADLINE` (15 s, two missed beats: one delayed packet must not tear down a session carrying live work) reports `Lost`. A second hello, an out-of-sequence pong, an oversized frame or a held list over the bound is a protocol violation that ends the session.

`workers::revoke` refuses the fingerprint at its next authentication; its held attempts expire with their leases ([cancellation](cancellation.md)), and the identity can never enroll again.

## Dispatch (W02)

**The ready queue is the database.** A job is queued when its row says so (`jobs_ready`, the partial index on `(priority, created_seq) WHERE state_code = 1`); nothing in memory has to be rebuilt after a restart. Its resource needs (`cpu_millis`, `memory_bytes`) are copied from the compiled spec at run creation so placement never decodes a spec blob.

**A reservation is an attempt.** `dispatch::place` finds, in one indexed statement, the oldest ready job of the best priority that the worker's pool may serve — A07's `require_pool_access` rule inline: tenant active, pool active, tenant its owner or explicitly granted — whose image is resolved and which fits the worker's free capacity (its reported capacity less the sum of the attempts it holds, one statement over `attempts_held_by_worker`). It then calls `jobs::lease`: the `Leased` transition under the next fence and the attempt row, carrying the reservation, commit together or not at all. There is no separate reservation table to forget. A larger job at the head of the queue is passed over for a smaller one behind it; keeping it from starving is Q02.

**Offers are fenced and acknowledged.** The controller pushes `Offer { attempt, tenant, run, job, fence, lease_until, resources, image }` through the session. The worker answers `Ack` or `Decline` with the fence; the link dedups by attempt within a session, so a repeated offer of an accepted attempt is re-acknowledged and never re-executed. `dispatch::acknowledge` is compare-and-set on worker and fence — a repeat is idempotent, a stale one is `Conflict`. A decline, or no acknowledgement within `OFFER_ACK_MS` (5 s, found by the dispatcher's sweep over `attempts_pending_ack`), lapses the offer: the reservation is released and the job goes back to the queue through the new core edge `OfferLapsed` (`leased → queued`, fence unchanged), so a late acknowledgement or report from that attempt is stale by construction and the next lease strictly advances the fence. A declined job is not re-placed on the spot but at the next reconciliation, which bounds a worker that keeps refusing to one offer per interval.

**Wake, don't poll.** The dispatcher thread sleeps on a condition variable. Anything that changes the answer to "is there work for a connected worker?" wakes it: a worker arriving, `Controller::wake()` after an enqueue or completion, a decline. Each pass sweeps unacknowledged offers, then fills every connected worker until nothing fits, one writer transaction per placement. `RECONCILE_INTERVAL` (2 s) is the safety net for a missed wake, not the clock; heartbeats never drive dispatch. Verified: a job enqueued while a worker is connected reaches it in well under half the reconciliation interval.

**Completion frees capacity and decides dependents in one transaction.** `dispatch::finish` applies the worker's report through the state machine under its fence; when the job reaches terminal, the reservation is released and every blocked job of the run whose dependencies have all finished is queued (`DependenciesSatisfied`) or ruled out (`Skip`, when a dependency did not succeed — transitively). The spec is read once, and only when the run still has a blocked job.

**Every queued job has a reason.** `dispatch::wait_reason` answers `Dependency`, `Policy` (image unresolved, cancel requested), `NoMatchingWorker { cpu_short, memory_short }` (no enrolled worker of a pool the tenant may use could ever fit it), `WorkerOffline` (such workers exist but none is connected), or `Capacity` (a connected worker fits it once its current work releases).

**Reports and specs.** After acknowledging, a worker asks for the run spec (`NeedSpec` → `Source` (protocol 2 only, bound sources) + `Context` + `Spec` chunks of `SPEC_CHUNK_BYTES`, reassembled up to `MAX_SPEC_BYTES`; `NoSpec` when the attempt is not its, when a bound source cannot be authorized for it, or when the worker cannot receive a credential) and then reports each phase with `Report { attempt, fence, event }`. The controller runs every report through `dispatch::report`: the attempt must be held by that worker under that fence, then the state machine decides; a stale or foreign report changes nothing and is counted in `stale_reports`. A terminal report releases the reservation, decides dependents and wakes the dispatcher. The `Executor` trait the worker implements is in [executor](executor.md). Log frames (`Log`/`LogEnd`, answered with `LogAck`/`LogRefused`) follow the same held-by-this-worker rule and are acknowledged only once durable; see [logs](logs.md). `Abandon { attempt, fence }` is how a restarted worker hands back an attempt it found in its leftovers; see [reconciliation](reconciliation.md).

**Worker side.** `worker::run` connects, presents the enrollment on its first hello only (spent once welcomed, whatever happens afterwards), serves the session, and on loss reconnects with back-off doubling from 1 s to 30 s with ±25 % jitter, reset after a session that lasted 30 s. A typed rejection is final: the loop returns rather than retrying an unchanged hello. The `Executor` trait is what W03 implements: take an offer or not, stop an attempt, report what is held, learn the renewed deadline. `Handle::stop` closes the socket from the process's thread, so shutdown never waits for a beat.

## Processes

`sentinel server` opens `<data_dir>/metadata.sqlite`, loads or generates `<data_dir>/controller.crt|.key`, listens on `listen` (default `127.0.0.1:7443`) and logs `link_listening` with the fingerprint workers must pin. `sentinel worker` with `controller` and `controller_fingerprint` configured loads or generates `<data_dir>/worker.crt|.key` and `<data_dir>/worker.id`, reads `enrollment_file` if present (removed once spent), measures its capacity (every core; total memory less a host reserve of one eighth clamped to 512 MiB–2 GiB; both overridable), and runs the loop above. With rootless Podman available the worker runs offers through the [executor](executor.md); without it every offer is declined (`executor_unavailable`, `offer_declined`), so jobs stay queued rather than sitting leased on a machine that cannot start them. Shutdown closes sessions and stops the dispatcher within 2 s, then drains the store within 5 s; a stalled store is reported and exits 1 ([storage](storage.md#bounds-and-failure-behavior)).

```sh
sentinel admin worker enroll --data-dir <PATH> --pool builders --expires-in 1h > enrollment
sentinel admin worker list   --data-dir <PATH> --pool builders
sentinel admin worker revoke --data-dir <PATH> --id wrk_...
```

```sh
sentinel admin worker enroll --data-dir <PATH> --pool builders --expires-in 1h > enrollment
sentinel admin worker list   --data-dir <PATH> --pool builders
sentinel admin worker revoke --data-dir <PATH> --id wrk_...
```

## What is not here yet

Lease expiry, cancellation and timeouts are in [cancellation](cancellation.md): an acknowledged lease of a worker that never returns expires at its deadline and the job ends `infra_failed`, never replayed. Fairness between tenants and aging of large jobs are Q02; placement here is strict priority then age within what fits.

## Verification

`crates/sentinel-store/tests/dispatch.rs`: placement is pool-scoped (a granted shared pool places, a withdrawn grant stops at once), capacity-checked (the job that no longer fits waits with reason `Capacity`, or `WorkerOffline` with no session, or `NoMatchingWorker` with the exact shortfall) and reserves with the lease; an offer lapses back to `Queued` under its advanced fence only after `OFFER_ACK_MS`, a late acknowledgement is `Conflict`, a lapse cannot repeat or be undone by raw SQL, and the re-offer carries fence 2 which the old fence cannot acknowledge; renewal is fenced per attempt, never moves a lease backwards, names unacknowledged and foreign attempts to stop, refuses another worker and bounds the list; finishing keeps the reservation until terminal, refuses a stale fence, releases capacity and queues the dependent in the same transaction, and a failed dependency skips transitively.

`crates/sentinel-link/tests/link.rs`, against a running `Controller` over loopback TLS: the W01 refusals as before, plus — a run enqueued while a worker is connected has both ready jobs offered within half the reconciliation interval, acknowledged and reserved, the blocked job withheld; completion queues the dependent and the wake places it; the lease deadline the worker sees moves with its beats; a decline lapses and is re-offered under fence 2 at the next reconciliation; an offer left unread lapses after the ack timeout and the late acknowledgement is stale while the fresh one lands; a worker whose controller stops reconnects with back-off to the restarted controller under the same pin, presenting no enrollment the second time; stopping a worker closes its session without waiting for a beat.

`crates/sentinel/tests/cli.rs` (Linux, both role features): `admin bootstrap|tenant create|pool create|worker enroll`, then the real `sentinel server` listens on an ephemeral port and logs its fingerprint, a second server on the same data directory is refused, `sentinel worker --check` reports its link, the worker process enrolls on its first hello (`link_connected` with `enrolled: true`, the enrollment file removed, `worker.id` persisted), both stop cleanly on `SIGTERM`, and `admin worker list` shows the worker afterwards.

`crates/sentinel-store/tests/workers.rs`: enrollment needs platform administration, an active pool and a bounded lifetime; a spent, expired or revoked enrollment is refused and cannot be un-spent by raw SQL; a reused identifier or fingerprint conflicts while the fresh enrollment stays usable; a worker authenticates by fingerprint only, liveness moves forward at the bounded cadence and never backwards, pool and fingerprint are immutable by trigger, listing is gated on the platform or an admitted tenant's membership, revocation is final and not repeatable.

`crates/sentinel-link/tests/link.rs`, over real TLS on loopback with the store as admission: an unknown certificate without an enrollment is `NotEnrolled`; with one it is welcomed with the negotiated protocol, beats are recorded, the enrollment is then spent for an impostor, the enrolled identity reconnects with no enrollment at all, and after revocation the same certificate is `NotEnrolled` and cannot re-enroll under its identity; a wrong server fingerprint fails in the handshake before the hello and leaves the enrollment unspent; an unsupported protocol version and an expired enrollment are typed refusals; every server-side session ends in a clean refusal or goodbye. `sentinel-link` unit tests cover PEM round-trip with a stable fingerprint and base64 correctness. The `sentinel admin worker` surface was exercised end to end on Linux.

See [TODO.md](../TODO.md) for commands and results, [tenancy](tenancy.md) for pools and grants, and [protocol contracts](protocol.md) for negotiation and size limits.
