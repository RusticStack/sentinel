# Feasibility probes (F07)

Bounded experiments run 2026-09-13 to settle four design questions before the vertical slice. Host: `DOOMBRINGER`, Ubuntu 24.04 on WSL2 (kernel `6.18.33.2-microsoft-standard-WSL2`, i7-13700KF, 24 logical CPUs), native ext4 root plus loop-mounted XFS (`reflink=1`) and Btrfs fixtures. WSL2 is a development reference; repeat on a dedicated Linux host before relying on absolute numbers. Raw records and scripts are under [`bench/`](../bench/). The reusable code lives in [`crates/sentinel-probes`](../crates/sentinel-probes) (`cargo probe <subcommand>`).

## 1. SQLite commit and dispatch

`sentinel-probes sqlite`: WAL mode, foreign keys, one writer. 2,000 jobs enqueued one transaction each, a 100,000-row lower-priority backlog inserted in one batch, then 2,000 dispatches, each a `BEGIN IMMEDIATE` / indexed pick / lease `UPDATE` / `COMMIT`. Record: [`bench/f07-storage.jsonl`](../bench/f07-storage.jsonl).

| Filesystem | `synchronous` | Enqueue commit median / p99 | Dispatch commit median / p99 | Ready pick with 100k backlog median / p99 | Batch insert |
|---|---|---:|---:|---:|---:|
| ext4 | FULL | 0.77 ms / 2.7 ms | 0.62 ms / 2.0 ms | 2.6 µs / 11.7 µs | 1.21 M rows/s |
| ext4 | NORMAL | 6 µs / 32 µs | 7 µs / 51 µs | 0.3 µs / 1.3 µs | 1.22 M rows/s |
| XFS | FULL | 0.65 ms / 3.7 ms | 0.57 ms / 2.2 ms | 2.2 µs / 6.0 µs | 1.29 M rows/s |
| XFS | NORMAL | 5 µs / 15 µs | 6 µs / 22 µs | 0.3 µs / 0.7 µs | 1.39 M rows/s |
| Btrfs | FULL | 2.27 ms / 6.0 ms | 2.31 ms / 26.5 ms | 2.7 µs / 10.3 µs | 1.14 M rows/s |
| Btrfs | NORMAL | 8 µs / 25 µs | 9 µs / 29 µs | 0.3 µs / 0.8 µs | 1.08 M rows/s |

Findings and decision:

- A durable (`FULL`) commit costs under 1 ms on ext4/XFS here and about 2 ms on Btrfs; the partial index keeps the ready pick flat at microseconds with 100k competing rows. One writer can therefore sustain well over 500 durable dispatches per second, far above any plausible CI intake. **Decision: SQLite WAL with `synchronous=FULL` for state transitions, one dedicated blocking writer thread, no batching needed at v1 scale.** `NORMAL` is 100x cheaper but loses the last transactions on power loss; it may be used only for data that is safe to replay (log spool metadata), never for leases or acknowledgements.
- Batched inserts exceed 1 M rows/s, so bulk imports and backfills are not a concern.
- `wal_checkpoint(TRUNCATE)` on a 4 MiB database took 2–7 ms. Checkpoint scheduling still needs measuring at realistic database sizes.

## 2. Rootless Podman resource enforcement

`bench/f07-podman-limits.sh` as the non-root user `sentinelbench` (Podman 4.9.3, runc, cgroup v2 via systemd, delegated controllers `cpu memory pids`). Record: [`bench/f07-podman-results.txt`](../bench/f07-podman-results.txt).

| Check | Result |
|---|---|
| `--cpus 1` with four busy loops for 5 s | PASS: 5.08 CPU-s used, 49 throttled periods, `cpu.max` `100000 100000` inside |
| `--memory 64m --memory-swap 64m`, 150 MiB written to a cgroup-charged tmpfs | PASS: `oom_kill 1`, `memory.max` hit 20 times, `memory.swap.max` 0 |
| `--pids-limit 32`, fork loop | PASS: 30 forks then failure |
| `--network none` | PASS: only `lo`, egress unreachable |
| `--read-only` with `--tmpfs /work` | PASS: rootfs write refused, tmpfs writable |
| `--cap-drop ALL --security-opt no-new-privileges` | PASS: `CapEff` all zero; uid 0 inside maps to host uid 1000, 1–65536 to 100000+ |
| `podman stop -t 1` on a sleeping process | PASS: 1.24 s wall, SIGTERM then SIGKILL |
| Bind-mounted workspace | Host-owned dir appears as `0:0` inside; files created inside are owned by the host user |

Not covered: the first probe versions produced false PASS/FAIL results for memory (a killed subshell still let the outer shell echo); the committed script is the corrected one. `io` and `cpuset` controllers are not delegated in this rootless setup, so I/O weight and pinning are unavailable without host configuration. **Decision: rootless Podman with per-job `--cpus`, `--memory`/`--memory-swap`, `--pids-limit`, `--network none` by default, read-only rootfs plus tmpfs/bind workspaces, all capabilities dropped, is confirmed enforceable and is the W03 executor baseline.** Verify controller delegation in the worker's preflight, since it depends on the host's systemd configuration.

## 3. Reflink versus safe copy

`sentinel-probes generate` created 20,000 files of 16 KiB (312 MiB) per filesystem; `sentinel-probes clone` copied the tree three ways with page cache dropped before the first clone, then read every destination file once.

| Filesystem | Mode | Clone wall | Per-file median / p99 | Read-back of clone |
|---|---|---:|---:|---:|
| ext4 | reflink (`FICLONE`) | unsupported (`EOPNOTSUPP`) | | |
| ext4 | explicit read/write | 2.00 s | 82 µs / 300 µs | 0.10 s |
| ext4 | `std::fs::copy` | 0.38 s | 13 µs / 54 µs | 0.10 s |
| XFS | reflink | 0.35 s | 13 µs / 88 µs | 0.76 s |
| XFS | explicit read/write | 0.97 s | 40 µs / 108 µs | 0.06 s |
| XFS | `std::fs::copy` | 0.34 s | 16 µs / 44 µs | 0.72 s |
| Btrfs | reflink | 0.31 s | 11 µs / 66 µs | 1.06 s |
| Btrfs | explicit read/write | 1.80 s | 65 µs / 535 µs | 0.08 s |
| Btrfs | `std::fs::copy` | 0.25 s | 10 µs / 39 µs | 0.86 s |

Findings and decision:

- Reflink clones are about 15 µs per file regardless of size, so a 20k-file cache tree attaches in ~0.3 s and shares blocks. On XFS and Btrfs `std::fs::copy` (`copy_file_range`) already reflinks transparently, which is why it matches `FICLONE`; on ext4 it still copies bytes but stays fast for small files through the kernel path.
- The safe copy costs 1–2 s for 312 MiB of small files: acceptable as a fallback but 3–6x a reflink, and it grows with bytes rather than file count.
- **First-touch cost is real and separate:** reading a fresh reflink clone took 0.7–1.1 s because its pages were not in cache, while the byte copy's pages were. Cache attachment time must never be reported as cache readiness; the runtime contract already says so.
- Per-file cost dominates for small files, so any clone backend will be `O(files)`; whole-tree snapshots (Btrfs subvolume, LVM) are the only way below that and remain a later, measured option.
- **Decision: implement cache materialisation as `FICLONE` per file with an explicit read/write fallback, detected per filesystem at worker start; recommend XFS with `reflink=1` or Btrfs for worker cache volumes and document ext4 as the slow-but-correct path.**

## 4. Tailcat unattended connectivity

`bench/f07-tailcat.sh` with Tailcat v0.6.0 (`sha256 d4658213…`, checksum verified against the release manifest), both ends on this host, public DERP map. Record: [`bench/f07-tailcat-results.txt`](../bench/f07-tailcat-results.txt).

| Check | Result |
|---|---|
| Persistent server and client keys without prompts or accounts | PASS (`genkey --key=default --fixed-region`, `genkey --client`) |
| Server start to printed address | PASS in 505 ms via DERP region 303 (Frankfurt) |
| `ping --until-direct` | PASS, direct path within the timeout |
| TCP echo through `forward` | 301 µs median / 527 µs p95 round trip versus 43 µs loopback; 36 MB/s versus 429 MB/s loopback |
| `serve --allow=nodekey:…` rejects an unlisted client | PASS |
| Same address after server restart with saved key | PASS |
| Existing `forward` recovers after server restart | **FAIL**: no reconnection within 30 s, nothing logged |

Findings and decision:

- Unattended operation works: keys persist, addresses are stable, and the allow-list restricts peers at the tunnel layer. Bootstrap needs the DERP relay reachable once; direct UDP then takes over.
- The helper adds roughly 250 µs per round trip and caps bulk throughput around 36 MB/s on this host (userspace WireGuard, single host). That is fine for control traffic and log streaming; large artifact or cache transfers over Tailcat should be avoided or measured separately on real WAN paths.
- A client-side `forward` does not survive a server restart. **Decision: the worker adapter must own the helper process, health-check the forwarded port, and restart the helper on failure; the Sentinel session layer reconnects with fenced leases as already planned. Pin v0.6.0 by checksum; treat the address and key files as credentials.** NAT traversal across real networks and an operator-owned DERP remain untested and are listed as W01 work.

## Retained and discarded

Kept: the `sentinel-probes` crate (SQLite and clone code paths will become the writer and cache-materialisation implementations), the three shell probes and their result records. Discarded: nothing else was built. Loop-mounted fixtures and the `sentinelbench` account remain on the development machine only.
