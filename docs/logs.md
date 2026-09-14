# Logs: frames, spool, acknowledgement and redaction (W05)

Implemented in `sentinel-protocol::logs` (the frame and record encoding), `sentinel-worker::{redact, spool, logpipe}` (the worker side), `sentinel-store::logs` (the controller's log files), the `Log`/`LogEnd`/`LogAck`/`LogRefused` messages of the [worker link](worker-link.md), and `sentinel admin logs`.

## The path a byte takes

1. **Read.** The step's stdout and stderr are read from the `podman exec` pipes in chunks of at most 8 KiB by the reader threads (`process::Sink`). The 64 KiB tails kept for diagnostics are unchanged.
2. **Redact.** Each chunk passes through the attempt's `Redactor` before anything else sees it. Registered values (`Executor::register_secret`; S05/S06 register per attempt) are replaced by `***`. A value split across two reads is still caught: the redactor holds back exactly the bytes that are the beginning of some secret until the next chunk (or the end of the stream) settles them, and emits everything else at once. Values under 8 bytes are not registered.
3. **Spool.** The redacted bytes become a frame — at most `MAX_LOG_FRAME_BYTES` (32 KiB) of one stream of one step, numbered by a per-attempt sequence from 1 with no skips — and are appended to `<data_dir>/spool/<attempt>/frames` **before** they are sent. The spool is synced every 32 frames and at the end. It is bounded (`MAX_SPOOL_BYTES`, 256 MiB): frames past it are not written, and their sequence range is declared as a gap in the end marker rather than dropped in silence.
4. **Send.** Frames leave from the spool's send cursor, never more than `MAX_UNACKED_LOG_FRAMES` (256) in flight per attempt: a slow controller costs the worker disk and 8 MiB of window, nothing more. A lost session drops the reporter; the next session rewinds the cursor to the last acknowledgement and resends.
5. **Store.** The controller checks once per session that the attempt is held by that worker, then appends the frame to `<data_dir>/logs/<attempt>.log` in the same record encoding, in sequence. A repeat of a stored sequence (a resend) is accepted and not written twice; a jump is refused, so a hole can never be silent; the file is capped at `MAX_LOG_BYTES` (256 MiB).
6. **Acknowledge.** `LogAck { through }` is sent only after the frame is written **and `fdatasync`ed**. That is the durability boundary: what the acknowledgement covers is byte-for-byte what a reader sees, and only then does the worker's cursor (`spool/<attempt>/cursor`) move so a restart resends nothing that is already safe.
7. **Complete.** After the last step and the teardown, finalization flushes the redactor, syncs the spool, waits — bounded by `LOG_FLUSH_TIMEOUT` (60 s) — for every frame to be acknowledged, sends `LogEnd { last_seq, gaps }`, and removes the spool. The controller writes the end record, refusing a `last_seq` other than what it stored. An attempt whose log could not be closed in time is `Failed(Publication)` if it would otherwise have passed; a failure keeps its own class.

The end record is what makes a log *complete*. `sentinel admin logs --attempt att_… [--follow]` prints the frames to the matching stream, reports `log incomplete` without `--follow`, waits with it, and names any gaps the worker declared. The API (W08) reads the same files with authorization.

## Bounds

| Where | Bound |
|---|---|
| frame | 32 KiB |
| in flight per attempt | 256 frames |
| worker spool per attempt | 256 MiB, then gaps |
| controller log per attempt | 256 MiB, then refused |
| gap ranges per end record | 256 |
| finalization wait for acknowledgement | 60 s |

Memory on either side is the window plus one chunk; everything else is on disk. A worker crash loses at most the unsynced frames since the last sync; the reopened spool resumes the sequence after the last complete record, and what was lost is visible as the difference — it is never re-numbered over. A controller crash mid-write leaves a torn tail that is cut on the next open and re-sent by the worker, whose cursor never passed it.

## What is not here yet

The API's tail/follow endpoint is W08; `admin logs` is the host-local reader. Log retention and quotas are D-tasks. Spool recovery after a worker restart is in [reconciliation](reconciliation.md): every leftover spool is delivered from its cursor and closed before the attempt is abandoned.

## Verification

`crates/sentinel-protocol` (`logs::tests`): records round-trip; every prefix of a record is `Incomplete`, never misread; an oversized frame does not encode.

`crates/sentinel-worker` unit tests: the redactor replaces a value split across three chunks, emits a partial value at flush rather than swallowing it, prefers the longest match, ignores short values and carries per stream; the spool survives a reopen with a torn tail cut, keeps its cursor, resends only what is unacknowledged, continues the sequence and advances its send cursor in bounded reads.

`crates/sentinel-store/tests/logs.rs`: frames stored in sequence and acknowledged, a jump refused, a resend acknowledged without a second copy, tail by sequence and by limit, the end refused when it disagrees with what was stored and complete with its gaps when it agrees, nothing after the end, a torn tail cut on reopen with the sequence resuming, the size cap.

`crates/sentinel-link/tests/link.rs`: over the link, frames of a held attempt are acknowledged and readable, a resend is acknowledged again without duplication, a jump and a foreign attempt are refused, the end completes the log.

`crates/sentinel-worker/tests/end_to_end.rs` (as `sentinelbench`, rootless Podman): a step that prints a registered secret, a stderr line and 2,000 stdout lines — the controller's log is complete with no gaps, in sequence, the secret is `***`, stdout and stderr are told apart with their step index, and the spool directory is gone when the attempt is done.
