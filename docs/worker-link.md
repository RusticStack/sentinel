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

Refusals are typed and audited: an unknown, spent, expired or revoked secret (recorded as `WorkerEnrollmentRefused`; the controller redeems through `workers::redeem`, which returns the refusal as a value so the audit row commits); a pool that is not active; a reused identifier or fingerprint (`Conflict`, leaving the enrollment unspent for the real machine). Pool access for *placement* is A07's `require_pool_access`, checked per tenant at dispatch (W02); enrollment decides which pool's capacity a machine is.

## Sessions

A session is one TLS connection, framed as big-endian `u32` length + postcard message, capped at `MAX_CONTROL_MESSAGE_BYTES` before any allocation. The first exchange is `Hello` → `Welcome` or `Reject`:

- `Hello` carries C03's `negotiate::Hello` (protocol range, capabilities, arch), the worker's identifier and name, and optionally the enrollment secret.
- The controller runs `negotiate::negotiate` (highest common version, required capabilities) on **every** hello, then asks its `Admission` policy: a known fingerprint is welcomed, and what this hello negotiated is recorded (`workers::renegotiate`, in the same write as its capacity) — an upgraded worker gets the newer protocol and so sends its profile, a rolled-back one a version it speaks; dropping below protocol 7 clears the profile-only placement facts (labels, warm images). A known fingerprint presenting another architecture is refused `Identity`. An unknown one with a valid enrollment is enrolled and welcomed; anything else is a typed `Rejection` the worker must not retry unchanged — except `Unavailable`, the controller's "try again later" (its store could not answer), which the worker retries with jittered back-off.
- `Welcome` returns the negotiated set and the heartbeat interval. The worker refuses a welcome at a version outside the range its hello offered.
- The handshake and the hello together must finish within `HANDSHAKE_DEADLINE` (10 s, absolute: a peer dripping a byte just inside each read timeout is still cut), and at most `MAX_PENDING` (256) connections may be in that phase at once, a separate cap from the 1024 sessions: peers that have proved nothing can hold at most a quarter of the slots, each only briefly. Connections turned away by either cap are counted in `Stats::shed`.
- Every link socket has a write timeout of `HEARTBEAT_DEADLINE`, and a failed or timed-out write closes the connection: a peer that stops reading cannot hold a sender, the connection lock or a spec resolver. A session's sockets (control and bulk) are closed when it ends, whatever ended it.

The session is full duplex on one TLS connection: the rustls state sits behind a mutex held only while bytes move between it and a buffer, never across a socket call, so one thread reads the socket while any thread — the dispatcher — writes. An offer therefore reaches a worker the moment it is placed, not at its next beat.

The worker sends `Ping { seq, held }` every `HEARTBEAT_INTERVAL` (5 s), where `held` names the attempts it still holds (at most `MAX_LIST_ITEMS`). The controller answers `Pong { seq, lease_until_ms, stop, cancel }`: the leases of every held attempt it recognises are renewed to `now + DEFAULT_LEASE_MS` (30 s, never backwards — the protocol constant `limits::LEASE_MS`; the worker measures the same 30 s on its own monotonic clock from the moment it sent that `Ping`, never by comparing `lease_until_ms` with its wall clock), and `stop` lists what the worker must end at once because the controller no longer counts it as held — lapsed, finished elsewhere, or never its. Liveness is recorded at most once per `SEEN_RECORD_INTERVAL_MS` (60 s), and a beat with nothing to renew and liveness fresh costs no write at all. Either side that hears nothing for `HEARTBEAT_DEADLINE` (15 s, two missed beats: one delayed packet must not tear down a session carrying live work) reports `Lost`. A second hello, an out-of-sequence pong, an oversized frame or a held list over the bound is a protocol violation that ends the session.

`workers::revoke` refuses the fingerprint at its next authentication, and the identity can never enroll again. Revocation also ends the **live** session and fences its work (P08-7): from the moment the row says revoked, the store refuses that worker's acknowledgements, renewals (`dispatch::renew` answers `Forbidden`, which ends the session at its next beat), reports, log frames, artifact publication and cache transfers (`is_held`, `attempt_scope` and `attempt_log_scope` join the live worker). Revocation is written by the host-local admin command, another process, so the dispatcher compares one indexed fingerprint of the revoked set (`dispatch::revocations`, the `workers_revoked` index) on every pass; when it moves, the controller closes every connected session of a revoked worker (`Stats::revoked_sessions`) and `dispatch::reconcile_revoked` settles everything a revoked worker holds — acknowledged attempts `Reconciled` (never replayed), unacknowledged offers lapsed back to the queue — in sweep batches. The effect is therefore within one reconciliation interval (2 s) of the revocation, not at lease expiry; controller start runs the same sweep.

## Control and bulk (protocol 7, Q05)

One session, two TLS connections, one identity. The first connection is the
**control** connection: negotiation, heartbeats, offers, acknowledgements,
reports, abandons — everything whose latency decides whether live work
survives. A protocol-7 worker then dials a second connection to the same
address with the same certificate and opens it with `BulkHello { worker }`;
the controller attaches it only when a live control session presents the same
fingerprint and serves it at the protocol that control session negotiated.

- Bulk classes: `NeedSpec`/`Spec`/`Context`/`Source`/`NoSpec`, `Log`,
  `LogEnd`, `LogAck`/`LogRefused`/`LogEndAck`, the artifact messages and the
  cache transfer messages.
- Control classes: `Ping`/`Pong`, `Offer`/`Ack`/`Decline`, `Report`,
  `Abandon`, `Profile`, `Transport`, `Bye`.
- A control-class message on a bulk connection is a protocol violation and
  closes it. Bulk-class messages on the control connection are accepted as a
  **fallback**: if the second connection cannot be established (a firewall
  between the worker and the controller, a helper that is down), the worker
  keeps working over control and retries the bulk dial with doubling
  back-off (1 s to 30 s, ±25 % jitter from its own per-worker stream) while
  the session lasts. The back-off wait watches the session's stop flag in
  50 ms slices: the control session joins the bulk thread before it returns,
  so an uninterruptible sleep there once held a lost session's reconnect for
  up to 30 s — longer than a lease (P08-11).
- A bulk connection lives exactly as long as its control session: it has no
  heartbeat of its own, so the controller keeps an idle one open for as long
  as that session is registered and closes it when the session ends. When a
  bulk connection is lost, frames handed to it may never have arrived; every
  log pipe rewinds to its last acknowledgement before it sends anything on
  the fallback route (the route change is visible to it as a `Route` count),
  so no frame is acknowledged past without having been stored.

The point of the split is that neither direction of bulk traffic can delay a
beat. Each connection owns its own rustls state behind its own mutex, so a
log flood, a slow artifact reader or a multi-hundred-megabyte cache stream
can never hold the lock a pong or an offer needs; the control connection
stays a few frames per beat. The worker's `Reporter` prefers the bulk
connection for bulk-class sends the moment it is attached and falls back to
control when it is not; reports and abandons always go control.

`session::accept` therefore answers an enum: `Accepted::Control(WorkerSession)`
(admitted exactly as before) or `Accepted::Bulk(BulkSession)`. The controller
counts attached bulk connections (`Stats::bulk_attached`) and refusals
(`Stats::bulk_refused`: no live control session with that certificate).

## The worker profile and transport telemetry (protocol 7, Q01/Q07)

Immediately after `Welcome`, a protocol-7 worker sends `Profile`: the
scheduling labels it selects work by (`labels`, at most
`MAX_PROFILE_LABELS` = 16), the machine identity it shares with sibling
worker processes (`host_id`, all zero when unknown), the scratch disk it
offers jobs (`disk_bytes`, zero = not measured), and its availability
(`images`, `cache_bytes`, `load_ns`; zero = not measured). The extras are a
**message**, not new `Hello` fields, on purpose: postcard is not
self-describing, a struct decodes exactly the field list its reader knows, so
a trailing `Hello` field would make every older worker undecodable and
`#[serde(default)]` would never fire. `Profile` (with `#[serde(default)]`
fields of its own) is append-only like every other wire addition, and it is
sent only when the negotiated version carries it.

The controller records the profile together with the capacity in one
transaction (`dispatch::report_capacity` + `dispatch::report_profile`), which
is why a protocol-7 hello defers its own capacity write until then: placement
never sees a disk of zero for a worker that is about to report one. A
protocol-6 worker sends no profile, so its disk stays 0 and its labels stay
empty — jobs that require disk or labels never place there, while
unconstrained jobs place normally.

`Transport` carries what the process measured about its own path: `path`
(`Direct` without a helper; with one, what the helper's `tailcat ping`
reported at start — `Relay` for a pong via DERP, `Direct` for one from an
`ip:port` — and `Unknown` when no probe measured it), `rtt_ns` (a
control-session Ping/Pong pair; before the first beat, the latency that
`tailcat ping` itself reported, else absent), `reconnects` (control sessions
opened since process start), `helper_version` (the Tailcat helper's version, absent
without one), and `bytes_in`/`bytes_out` (cumulative counters over the
session's control connection and every bulk connection it has had, so a
bulk redial never restarts them; throughput is their rate between two
reports). It is
sent once per session after `Profile` and refreshed every 12 beats. The worker
process hands the link a live source (`worker::Handle::set_transport_source`,
fed from the helper's `Forward::telemetry()`): each session starts from the
path and latency the helper's **latest** probe measured, and each 12-beat
resend refreshes the path and helper version from it (round-trip time stays the
session's own beat), so a path that changed after process start is reported.
The controller keeps the latest per session (`Handle::transport(worker)`) and
`GET /api/v1/workers` shows it per connected worker as `transport` ([API](api.md));
a field nothing measured stays absent — never a zero claim.

## Cache transfers (protocol 7, Q08; cancel and refresh from 8)

Remote cache hydration prefers the bulk connection, in both directions,
with the cache crate owning the objects and the link owning framing; a
worker whose bulk connection is down sends the same messages on the control
connection (the bulk-class fallback):

- `CacheNeed(Need)` asks for one object by scope (tenant/repo/class/trust/
  platform/toolchain/name/key), with `offset` and `have` so a retry resumes
  instead of restarting. `CacheOffer(Upload)` offers an object the worker
  holds, `CachePush`/`CachePushEnd` stream it.
- `CacheGrant(Grant)` accepts a transfer at an offset, `CacheChunk` carries
  ordered chunks with a running digest, `CacheEnd` is terminal both ways, and
  `CacheRefused(Refused)` carries a stable refusal code.
- Protocol 8: `CacheCancel { attempt }` tells the controller the worker
  abandoned the attempt's transfer. A serve stops at its next chunk and
  answers `CacheRefused` with `aborted` as its terminal; an upload is dropped
  with its staging file and entry lock and answered once. The worker keeps
  the attempt *draining* until that terminal arrives and refuses a new
  transfer of it (`busy`) meanwhile, so a stale tail is never routed into the
  next stream; answers queue at most 64 deep per transfer and a caller that
  falls behind abandons the transfer instead of buffering without bound.
- Authorization is the **fenced attempt**, never the request
  (`dispatch::cache_scope`): the attempt must be owned by that worker — held
  for a fetch, or released within 10 minutes for an offer, which always
  follows the terminal report — and the transfer's tenant and repository must
  equal the attempt's while its trust is one the job's class admits (a
  protocol-6/7 worker names `pull_request` for an `unprotected` job). A
  worker cannot name a boundary it does not hold; refusals are `denied` and
  counted (`Stats::cache_denied`).
- The link caps one cache chunk at `MAX_CACHE_CHUNK_BYTES` (48 KiB, so the
  frame fits `MAX_CONTROL_MESSAGE_BYTES`) and refuses anything larger as
  `TooLarge` rather than splitting it: a chunk's running digest cannot be
  recomputed for a piece. The receiver moves decrypted plaintext out of
  rustls whenever its buffer fills, so a burst of full frames never
  overflows it.
- Downloads are streamed off the session thread (at most
  `MAX_CACHE_TRANSFERS` at a time per connection, one reused chunk buffer
  each) so a large hydration never stalls the reader; uploads (at most
  `MAX_CACHE_TRANSFERS` per connection, dropped after 60 s without a push)
  are fed frame by frame into the cache crate's receiving state, which
  hashes as bytes land and verifies the whole stream's digest before
  promoting it.

A local cache hit never touches the link. The controller serves from
`<data_dir>/remote-cache` when it has one (`Controller::set_remote_cache`,
which also starts that store's reclamation); without one every need is
refused `denied`.

**Profile refresh (protocol 8).** The worker opens every session with a
`Profile` whose availability is the executor's own record — the newest
held image keys (at most 64) and the cache store's estimated bytes — and,
from protocol 8, sends a later `Profile` whenever that record's version
moves (checked once per heartbeat). A protocol-7 controller accepts one
profile per session; a protocol-8 one treats a later one as a refresh.

## Dispatch (W02)

**The ready queue is the database.** A job is queued when its row says so (`jobs_ready`, the partial index on `(priority, created_seq) WHERE state_code = 1`); nothing in memory has to be rebuilt after a restart. Its resource needs (`cpu_millis`, `memory_bytes`) are copied from the compiled spec at run creation so placement never decodes a spec blob.

**A reservation is an attempt.** `dispatch::place` finds, in one indexed statement, the oldest ready job of the best priority that the worker's pool may serve — A07's `require_pool_access` rule inline: tenant active, pool active, tenant its owner or explicitly granted — whose image is resolved and which fits the worker's free capacity (its reported capacity less the sum of the attempts it holds, one statement over `attempts_held_by_worker`). It then calls `jobs::lease`: the `Leased` transition under the next fence and the attempt row, carrying the reservation, commit together or not at all. There is no separate reservation table to forget. A larger job at the head of the queue is passed over for a smaller one behind it; keeping it from starving is Q02.

**Offers are fenced and acknowledged.** The controller pushes `Offer { attempt, tenant, run, job, fence, lease_until, resources, image }` through the session. The worker answers `Ack` or `Decline` with the fence; the link dedups by attempt within a session, so a repeated offer of an accepted attempt is re-acknowledged and never re-executed. `dispatch::acknowledge` is compare-and-set on worker and fence — a repeat is idempotent, a stale one is `Conflict`. A decline, or no acknowledgement within `OFFER_ACK_MS` (5 s, found by the dispatcher's sweep over `attempts_pending_ack`), lapses the offer: the reservation is released and the job goes back to the queue through the new core edge `OfferLapsed` (`leased → queued`, fence unchanged), so a late acknowledgement or report from that attempt is stale by construction and the next lease strictly advances the fence. A declined job is not re-placed on the spot but at the next reconciliation, which bounds a worker that keeps refusing to one offer per interval. A `Decline` is fenced on its sender: only the worker holding the offer, under its fence, can give it back (`dispatch::decline`). A cancel recorded while the offer was out settles the job `canceled` the moment the offer goes back, dependents decided, rather than leaving it queued until the queue timeout.

**Wake, don't poll.** The dispatcher thread sleeps on a condition variable. Anything that changes the answer to "is there work for a connected worker?" wakes it: a worker arriving, `Controller::wake()` after an enqueue or completion, a decline. Each pass expires overdue leases, times out queued jobs and lapses unacknowledged offers — one writer transaction per sweep, every row re-checked inside it under its own savepoint, so a renewal that commits after the sweep read the attempt as due wins — runs the revocation check, then places. Placement first asks one question — is any job ready at all (`dispatch::any_ready`, one index seek)? — and does nothing more when none is, so a wake with an empty queue costs no writer round trip. Otherwise it places in **rounds**: each round ranks the connected workers and offers each of them one job, all in one writer transaction; a worker with nothing to take leaves the pass, and rounds repeat until none is left (at most `MAX_HELD_ATTEMPTS`). The ranking (Q03) is the share of the worker's reported CPU its held attempts already take (least committed first, read once per pass with `dispatch::held_by_worker` and kept current in memory), then its measured load per reported millicore (`load_ns` from its protocol-7 profile — the host's own busy time, so work that is not ours counts), then more warm cache (`cache_bytes`) first, then the smaller worker (best fit), then its id. A burst therefore spreads over identical workers one job each instead of filling whichever worker comes first (P08-6), and the writer sees one round trip per round rather than one per worker. Each worker is also told what the rest of its pool can hold (`dispatch::place_in_fleet`), so a job only that worker can run is offered there before work a smaller worker could take (Q10: a random order once let the only large worker fill with quarter-core jobs and strand a six-core one). Image locality is a hold, not a rank: a cold worker passes a job whose image a warm worker will free for within `LOCALITY_WAIT_MS` ([storage](storage.md#fleet-placement-q01q04)). Load and cache are what the worker's latest profile reported: the one that opened the session and, on protocol 8, each availability refresh it sends when its held images or cache bytes change. A store failure in any sweep or placement is counted (`Stats::sweep_errors`, `Stats::placement_errors`) and logged by error kind only, at most once a minute per class (P08-15); a failed round is retried a worker per transaction so one worker's failure cannot stall the fleet. `RECONCILE_INTERVAL` (2 s) is the safety net for a missed wake, not the clock; heartbeats never drive dispatch. Verified: a job enqueued while a worker is connected reaches it in well under half the reconciliation interval.

**Completion frees capacity and decides dependents in one transaction.** `dispatch::finish` applies the worker's report through the state machine under its fence; when the job reaches terminal, the reservation is released and every blocked job of the run whose dependencies have all finished is queued (`DependenciesSatisfied`) or ruled out (`Skip`, when a dependency did not succeed — transitively). The spec is read once, and only when the run still has a blocked job.

**Every queued job has a reason.** `dispatch::wait_reason` answers `Dependency`, `Policy` (image unresolved, cancel requested), `NoMatchingWorker { cpu_short, memory_short }` (no enrolled worker of a pool the tenant may use could ever fit it), `WorkerOffline` (such workers exist but none is connected), or `Capacity` (a connected worker fits it once its current work releases).

**Reports and specs.** After acknowledging, a worker asks for the run spec (`NeedSpec` → `Source` (protocol 2 only, bound sources) + `Context` + `Spec` chunks of `SPEC_CHUNK_BYTES`, reassembled up to `MAX_SPEC_BYTES`) and then reports each phase with `Report { attempt, fence, event }`. Nothing that could start work is served before the acknowledgement is durable: `job_context` and `spec_bytes` require `acked_ms`, and a request that raced ahead of its `Ack` (the bulk connection is not ordered with control) waits briefly for it; an offer whose ack write failed lapses without ever having run. Resolution — which may mint a GitHub token — runs on at most eight resolver threads fed by a bounded queue (per worker, no more than it may hold; fleet-wide 4096; a duplicate request is not queued twice), so a burst of placements is served in turn, never refused. A transient fault (reader overload, a busy writer, a token-mint timeout) is retried with back-off and otherwise left unanswered; the worker asks again every 10 s and, if the spec never arrives within 60 s, hands the attempt back with `Decline` — it never started, so it returns to the queue instead of ending `infra_failed`. `NoSpec` is definitive: the attempt is not the worker's, it was settled `canceled` (a cancel recorded before it started), or its source or spec is refused for good — the worker then reports `Failed(Preparation)` at once rather than leaving the lease to expire. The controller runs every report through `dispatch::report`: the attempt must be held by that worker under that fence, then the state machine decides; a stale or foreign report changes nothing and is counted in `stale_reports`. A terminal report releases the reservation, decides dependents and wakes the dispatcher. The `Executor` trait the worker implements is in [executor](executor.md). Log frames (`Log`/`LogEnd`, answered with `LogAck`/`LogRefused`) are acknowledged only once durable; a sequence jump is stored with its hole recorded rather than refused; see [logs](logs.md). `LogRefused` is permanent and sent only for a permanent cause — not the worker's attempt, a log already ended, the size cap, no disk reserve for evidence. A transient controller fault (a store read, a writer call, log I/O) is answered by closing the connection that carried the frame, so the worker rewinds to its last acknowledgement and resends; it never turns a passing job into a publication failure. Their scope is wider than a report's: any attempt the worker owns, released or not (`attempt_log_scope`) — a retransmission after the verdict still lands, since late bytes only complete the evidence and the verdict itself is sealed. Artifact publication stays held-only. `Abandon { attempt, fence }` is how a restarted worker hands back an attempt it found in its leftovers; see [reconciliation](reconciliation.md).

**Log end acknowledgement (protocol 5).** `LogEnd` is answered by `LogEndAck { attempt }` once the controller's `end` marker file is durable **and the attempt's `log_state` row says so** — the acknowledgement covers both commits, so `Executor::log_ended` releasing the spool never races a database that has not recorded it. A `LogEnd` the controller refuses (`last_seq` below what it stored, or an attempt the worker does not own) is answered `LogRefused` instead, on every protocol version. An unacknowledged `LogEnd` is resent on the next session; the controller's `finish` is idempotent, so the retransmit is answered the same way. Workers on protocol ≤ 4 are unchanged: nothing answers `LogEnd` and the spool drops at the send boundary; their terminal report may then stamp `incomplete` until the in-flight end lands and heals the row.

**Artifacts (protocol 4).** A worker on protocol 4 publishes declared artifacts during finalization, before the terminal `Report`: `ArtifactBegin { attempt, name, retain_secs }` is answered with `ArtifactGrant` (`granted`, or `refused`/`disabled` for a protocol-3 link, a stale attempt, an undeclared name, a duplicate row or a spent run budget). Granted, the worker streams `ArtifactFile { path, len, mode }` then `ArtifactData { seq, bytes }` frames (per-file sequences, ≤ `MAX_ARTIFACT_CHUNK_BYTES` each), ending with `ArtifactEnd`; `ArtifactAbsent` is the no-match outcome and also abandons a half-sent artifact. One artifact is in flight per attempt, entry paths are validated, and committed plus in-flight bytes count against `MAX_RUN_ARTIFACT_BYTES`. The controller's terminal answer is `ArtifactVerdict { name, code }`: `stored` means object rows, the `{job}/{name}` manifest and the artifact row committed in one transaction; `absent`/`failed` record the outcome durably; anything short of `stored` makes a `required` artifact a publication failure. A session drop mid-stream resolves the worker's wait as `stored`-only-if-committed — the controller's writer transaction is the verdict, not the socket.

**Worker side.** `worker::run` connects, presents the enrollment on its first hello only (spent once welcomed, whatever happens afterwards), serves the session, and on loss reconnects with back-off doubling from 1 s to 30 s with ±25 % jitter, reset after a session that lasted 30 s. A typed rejection is final — the loop returns rather than retrying an unchanged hello — except `Unavailable`, which is retried on the same jittered back-off so a fleet reconnecting after a controller restart does not stop on a busy store. The `Executor` trait is what W03 implements: take an offer or not, stop an attempt, report what is held, learn the renewed deadline. `Handle::stop` closes the socket from the process's thread, so shutdown never waits for a beat.

## Processes

`sentinel server` opens `<data_dir>/metadata.sqlite`, loads or generates `<data_dir>/controller.crt|.key`, listens on `listen` (default `127.0.0.1:7443`) and logs `link_listening` with the fingerprint workers must pin. `sentinel worker` with `controller` and `controller_fingerprint` configured loads or generates `<data_dir>/worker.crt|.key` and `<data_dir>/worker.id`, reads `enrollment_file` if present (removed once spent), measures its capacity (every core; total memory less a host reserve of one eighth clamped to 512 MiB–2 GiB; both overridable) and its profile (labels from config, host id derived from the machine id, scratch disk = free space of the data directory less a one-eighth reserve clamped to 512 MiB–2 GiB, CPU busy time over a 100 ms window; see [configuration](configuration.md)), and runs the loop above. With `[tailcat] enabled = true` the server runs the pinned helper for its link port before it serves, writes its `tc…` address to the owner-only `<data_dir>/tailcat/address` and logs only that path as `tailcat_listening`, and keeps the admitted node keys current from `<data_dir>/tailcat-allow` (`nodekey:… wrk_…` lines; a revoked worker's key is withdrawn within 10 s, and an empty list admits no peer); the worker runs its own helper, dials `127.0.0.1:<listen_port>`, and replaces the helper at once when a control session is lost, unless that helper started less than 10 s ago (see [configuration](configuration.md#optional-tailcat-transport) for what an allow-list change costs). Self-hosted DERP relays, their certificates and reachability are covered in [configuration](configuration.md#optional-tailcat-transport). Without the section — or with `enabled = false` — both use direct TLS exactly as before. With rootless Podman available the worker runs offers through the [executor](executor.md); without it every offer is declined (`executor_unavailable`, `offer_declined`), so jobs stay queued rather than sitting leased on a machine that cannot start them. Shutdown closes sessions and stops the dispatcher within 2 s, then drains the store within 5 s; a stalled store is reported and exits 1 ([storage](storage.md#bounds-and-failure-behavior)).

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

`crates/sentinel-link/tests/hardening.rs` (Part 04 audit): a worker refused `Unavailable` twice backs off and connects on the third hello while any other rejection stays final; a welcome outside the hello's range is refused; a transient log fault closes the connection and is never answered `LogRefused`; an idle bulk connection outlives the heartbeat deadline and ends with its session; a worker enrolled at protocol 6 is welcomed at 7 when it offers 7 (recorded, and its profile's disk reaches placement) and at 5 when rolled back; with the pre-admission cap full a new connection is shed, a dripping handshake is cut at its absolute deadline, and an enrolled worker is then admitted. Controller unit tests drive a burst of twenty spec requests through the eight-resolver desk (all served in order, none refused, duplicates and per-worker overflow held back); session unit tests prove a borrowed log frame encodes byte-for-byte like the owned message and that a peer which never reads fails a sender within its write timeout. `crates/sentinel-store/tests/execution.rs` covers the store edges: cancel decides dependents, a cancel recorded while offered settles on lapse or decline, decline is fenced and hands back an acknowledged, unstarted attempt to the queue, specs wait for the acknowledgement, expiry re-checks the lease, a worker `canceled` without a request is recorded as a runtime failure, renegotiation is recorded, and a refused enrollment is audited.

`crates/sentinel-link/tests/priority.rs` proves the protocol-7 split's one guarantee: with the bulk connection connected but stalled (its peer never reads, so the worker's bulk writes block on TCP backpressure), the next control beat still gets its `Pong` within the deadline, and the stalled bulk traffic then completes once the peer drains. It also proves the fallback: a bulk message on the control connection is served, not rejected. `a_failing_bulk_redial_never_delays_the_control_teardown` fails the bulk redials until the back-off is 4 s and closes the control connection: the session returns within 1.5 s (before the fix it waited out the sleep, 3.7 s in the failing run).

`crates/sentinel/tests/cli.rs` (Linux, both role features): `admin bootstrap|tenant create|pool create|worker enroll`, then the real `sentinel server` listens on an ephemeral port and logs its fingerprint, a second server on the same data directory is refused, `sentinel worker --check` reports its link, the worker process enrolls on its first hello (`link_connected` with `enrolled: true`, the enrollment file removed, `worker.id` persisted), both stop cleanly on `SIGTERM`, and `admin worker list` shows the worker afterwards.

`crates/sentinel-store/tests/workers.rs`: enrollment needs platform administration, an active pool and a bounded lifetime; a spent, expired or revoked enrollment is refused and cannot be un-spent by raw SQL; a reused identifier or fingerprint conflicts while the fresh enrollment stays usable; a worker authenticates by fingerprint only, liveness moves forward at the bounded cadence and never backwards, pool and fingerprint are immutable by trigger, listing is gated on the platform or an admitted tenant's membership, revocation is final and not repeatable.

`crates/sentinel-link/tests/link.rs`, over real TLS on loopback with the store as admission: an unknown certificate without an enrollment is `NotEnrolled`; with one it is welcomed with the negotiated protocol, beats are recorded, the enrollment is then spent for an impostor, the enrolled identity reconnects with no enrollment at all, and after revocation the same certificate is `NotEnrolled` and cannot re-enroll under its identity; a wrong server fingerprint fails in the handshake before the hello and leaves the enrollment unspent; an unsupported protocol version and an expired enrollment are typed refusals; every server-side session ends in a clean refusal or goodbye. The log stream is exercised end to end: frames of a held attempt are acknowledged once durable, a resend is not duplicated, a jump lands with its hole, a foreign attempt and a short `LogEnd` are refused, and under protocol 5 `LogEndAck` reaches `Executor::log_ended` with the marker durable while a protocol-3 session never sees one. `sentinel-link` unit tests cover PEM round-trip with a stable fingerprint and base64 correctness. The `sentinel admin worker` surface was exercised end to end on Linux.

See [TODO.md](../TODO.md) for commands and results, [tenancy](tenancy.md) for pools and grants, and [protocol contracts](protocol.md) for negotiation and size limits.
