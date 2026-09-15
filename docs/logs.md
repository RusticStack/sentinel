# Logs: frames, spool, acknowledgement and redaction (W05, D04)

Implemented in `sentinel-protocol::logs` (the frame and record encoding), `sentinel-worker::{redact, spool, logpipe}` (the worker side), `sentinel-store::logs` (the controller's segmented log files), the `Log`/`LogEnd`/`LogAck`/`LogEndAck`/`LogRefused` messages of the [worker link](worker-link.md), and `sentinel admin logs`.

## The path a byte takes

1. **Read.** The step's stdout and stderr are read from the `podman exec` pipes in chunks of at most 8 KiB by the reader threads (`process::Sink`). The 64 KiB tails kept for diagnostics are unchanged.
2. **Redact.** Each chunk passes through the attempt's `Redactor` before anything else sees it. Registered values (`Executor::register_secret`; S05/S06 register per attempt) are replaced by `***`. A value split across two reads is still caught: the redactor holds back exactly the bytes that are the beginning of some secret until the next chunk (or the end of the stream) settles them, and emits everything else at once. Values under 8 bytes are not registered.
3. **Spool.** The redacted bytes become a frame — at most `MAX_LOG_FRAME_BYTES` (32 KiB) of one stream of one step, numbered by a per-attempt sequence from 1 with no skips — and are appended to `<data_dir>/spool/<attempt>/frames` **before** they are sent. The spool is synced every 32 frames and at the end. It is bounded (`MAX_SPOOL_BYTES`, 256 MiB): frames past it are not written, and their sequence range is declared as a gap in the end marker rather than dropped in silence.
4. **Send.** Frames leave from the spool's send cursor, never more than `MAX_UNACKED_LOG_FRAMES` (256) in flight per attempt: a slow controller costs the worker disk and 8 MiB of window, nothing more. A lost session drops the reporter; the next session rewinds the cursor to the last acknowledgement and resends.
5. **Store.** The controller resolves the attempt's `(run, job)` once per session (`dispatch::attempt_scope` — held-by-this-worker included), then appends the frame into `logs/<run>/<job>/<attempt>/` in the same record encoding, in sequence. A repeat of a stored sequence (a resend) is accepted and not written twice. A sequence **jump is no longer refused**: the frame is stored and the skipped range is recorded as a hole, so a capped or lossy spool can still close — and a later retransmission inside a hole lands as a fill. The log is capped at `MAX_LOG_BYTES` (256 MiB).
6. **Acknowledge.** `LogAck { through }` is sent only after the frame is written **and `fdatasync`ed**. That is the durability boundary: what the acknowledgement covers is byte-for-byte what a reader sees, and only then does the worker's cursor (`spool/<attempt>/cursor`) move so a restart resends nothing that is already safe.
7. **Complete.** After the last step and the teardown, finalization flushes the redactor, syncs the spool, waits — bounded by `LOG_FLUSH_TIMEOUT` (60 s) — for every frame to be acknowledged, sends `LogEnd { last_seq, gaps }`, and **under protocol 5 keeps the spool until `LogEndAck`**: the controller sends it only after the `end` marker file is durable, so a lost session can no longer strand a log whose worker-side backup was already dropped (a retransmit is idempotent — `finish` of an already-ended log answers the same acknowledgement). Protocol 4 and earlier keep the send boundary: the spool drops once `LogEnd` is handed to the session. The controller refuses a `last_seq` below what it stored; a `last_seq` past it declares the never-stored tail as a gap. An attempt whose log could not be closed in time is `Failed(Publication)` if it would otherwise have passed; a failure keeps its own class.

The `end` marker file is what makes a log *complete* — an end record inside a segment without the marker is a finish interrupted mid-write, repaired on the next open. `sentinel admin logs --attempt att_… [--follow]` prints the frames to the matching stream, reports `log incomplete` without `--follow`, waits with it, and names the merged gaps. The API reads the same files with authorization (`?after=&limit=&wait=1&step=`).

## On the controller: segments, index and the end marker (D04)

Each attempt's log is a directory `logs/<run>/<job>/<attempt>/`:

```
seg-000000            # sealed segment, plain until compressed
seg-000001.z          # sealed segment, zlib (`SNLZ` format 1)
seg-000002            # the active segment — never compressed while open
index                 # sparse checkpoints (`SNLI` format 1)
end                   # the completeness marker (`SNLE`), atomic
```

- **Segments** hold the record stream and rotate at `SEGMENT_BYTES` (4 MiB). A sealed segment is queued to a single background compressor thread, which writes `seg-NNNNNN.z` (`SNLZ` | format | codec | zlib stream) and removes the plain file only after the compressed one is durable. The active segment stays plain so the next append is a `write` + `fdatasync` and nothing else.
- **The index** is a sidecar of 41-byte entries — `kind` | `seq` | `seg` | `step` | cumulative `lines` | cumulative `bytes` | wall-clock `ms` — checkpointed at each segment's first frame, every step change, and every 64 frontier frames, plus a seal record per closed segment. A tail by sequence seeks to the last checkpoint at or below `after` and decodes only from that segment; a `?step=` filter serves one step's frames from the same seek. Index entries are in sequence order — fills are never indexed, since a late-arriving sequence would break the seek.
- **Holes and gaps.** A jump records `(prev+1 ..= seq-1)` as a hole; a frame inside a hole fills it and narrows the range. At `finish` the marker's gap list merges three sources — observed holes, the worker's declared gaps (a capped spool), and the `last_seq` tail that was never stored — so a gap can never be silent; more than `MAX_MARKER_GAPS` (1,024) ranges coalesce the closest pair. A read that starts mid-stream does not report decode-observed holes: with earlier segments skipped, a jump cannot be told apart from a fill that already landed — the marker's list still applies.
- **Recovery.** Reopen sweeps `*.tmp`, truncates each plain segment to its complete-record prefix, keeps index entries only through the last seal record (later ones are provisional and regenerated by re-decoding the segments they name), rebuilds a missing or undecodable index from the stream, re-queues sealed-but-uncompressed segments, and lands the marker when the stream carries an end record without one. A compressed segment with a leftover plain twin keeps the `.z`.
- **Legacy.** Logs written before D04 live at `logs/<attempt>.log`; readers (`read_tail`, the API's `NotFound` fallback, `admin logs`) still serve them.

## Bounds

| Where | Bound |
|---|---|
| frame | 32 KiB |
| in flight per attempt | 256 frames |
| worker spool per attempt | 256 MiB, then gaps |
| controller log per attempt | 256 MiB, then refused |
| segment size | 4 MiB |
| index checkpoint cadence | 64 frontier frames |
| gap ranges on the wire | 256 |
| gap ranges in the end marker | 1,024, coalesced |
| finalization wait for acknowledgement | 60 s |

Memory on either side is the window plus one chunk; everything else is on disk. A worker crash loses at most the unsynced frames since the last sync; the reopened spool resumes the sequence after the last complete record, and what was lost is visible as the difference — it is never re-numbered over. A controller crash mid-write leaves a torn tail that is cut on the next open and re-sent by the worker, whose cursor never passed it.

## What is not here yet

Log retention and quotas are D-tasks (D06); reclaiming completed attempt directories is part of that work. Spool recovery after a worker restart is in [reconciliation](reconciliation.md): every leftover spool is delivered from its cursor and closed before the attempt is abandoned.

## Verification

`crates/sentinel-protocol` (`logs::tests`): records round-trip; every prefix of a record is `Incomplete`, never misread; an oversized frame does not encode.

`crates/sentinel-worker` unit tests: the redactor replaces a value split across three chunks, emits a partial value at flush rather than swallowing it, prefers the longest match, ignores short values and carries per stream; the spool survives a reopen with a torn tail cut, keeps its cursor, resends only what is unacknowledged, continues the sequence and advances its send cursor in bounded reads.

`crates/sentinel-store/tests/logs.rs`: frames stored in sequence and acknowledged once durable, a resend acknowledged without a second copy, a jump stored with its hole and the fill landing, tail by sequence/limit/step, the end refused below the stored frontier and complete with merged gaps (observed, declared, truncated tail), nothing after the end and an idempotent re-finish, a torn segment tail and torn index tail cut on reopen, sealed segments compressing and reading identically across the boundary, the index's step/line/time checkpoints, holes and fills surviving a store reopen, a pre-D04 flat file still reading, and the size cap completing through the gap list.

`crates/sentinel-link/tests/link.rs`: over real TLS, frames of a held attempt are acknowledged and readable, a resend is acknowledged again without duplication, a jump is stored with its hole, a foreign attempt and an end below the frontier are refused, the end completes the log with the hole folded into the gaps — and under protocol 5 `LogEndAck` reaches the worker's `log_ended` only after the marker is durable, while a protocol-3 session sees no such message.

`crates/sentinel-api/tests/api.rs`: the log route serves `?step=` filtered frames; unauthenticated and unknown attempts are refused as before.

`crates/sentinel-worker/tests/end_to_end.rs` (as `sentinelbench`, rootless Podman): a step that prints a registered secret, a stderr line and 2,000 stdout lines — the controller's log is complete with no gaps, in sequence, the secret is `***`, stdout and stderr are told apart with their step index, and the spool directory is gone when the attempt is done (under protocol 5 that means `LogEndAck` arrived).
