# Bounded filesystem hashing (C06)

`sentinel-pipeline::hash_files::hash_files` implements the worker-phase resolver. Expression grammar, event/ref filters, concurrency/dependency conditions and placement rules remain in [pipeline schema](pipeline-schema.md#expressions-c06).

## Limits and resource cost

| Resource | Limit |
|---|---:|
| Patterns | 8 |
| Bytes per pattern | 1,024 |
| Segments per pattern / directory traversal depth | 64 |
| Relative path bytes | 4,096 |
| Unique matched regular files | 10,000 |
| Shared traversal work units | 100,000 |
| Total hashed content | 256 MiB |
| Streaming content buffer | 64 KiB |

A work unit is a traversal invocation, a directory entry (including ignored/nonmatching entries), or a traversal open. The shared budget covers all patterns, including redundant recursive glob branches. Directory enumeration uses rustix's getdents-backed iterator rather than collecting a whole directory; the only retained result set is a bounded, sorted `BTreeSet` of unique paths. Recursion and simultaneously retained directory handles are depth-bounded. Pattern bytes and segments are validated before filesystem access.

`**` means zero or more directories; terminal `**` includes all regular files recursively. Names are exact UTF-8, with `/` as separator. Invalid UTF-8 and backslash-containing enumerated names fail rather than creating lossy/colliding keys. No host-path normalization is hashed. Overlapping patterns deduplicate before content reads; static-tree digests retain the existing record format.

Reads are capped by remaining file length and total budget. Early EOF, extra content beyond declared length, and observed length/mtime/ctime changes reject the result. One single-byte EOF lookahead detects growth: at most one extra content byte beyond the hash budget can be consumed before failure, even from an endlessly growing input. A read failure never yields a partial digest. Files larger than the remaining budget are rejected before content I/O. OS diagnostics are reduced to fixed messages, with no paths or input payloads.

## Linux confinement

The resolver opens its trusted checkout-root path once with `openat2(NO_SYMLINKS)`. Subsequent traversal and file opens use the pinned directory descriptor with `BENEATH | NO_SYMLINKS | NO_XDEV`. A concurrent replacement of any path component cannot redirect an open through a symlink or outside the pinned root. Nested mounts, including bind mounts, fail closed. Root mount selection is the worker's responsibility.

Before reading content, `O_PATH` pins and classifies the inode without opening devices/FIFOs for data I/O. Only regular inodes are reopened through the trusted host `/proc/self/fd/<fd>` entry while the descriptor is still owned. This extra open is needed to avoid a check/open race or side effects from opening a special file. Rooted directory descriptors are consumed directly by the directory iterator; enumeration uses no procfs path reconstruction.

Unavailable `openat2` (Linux before 5.6 or blocked by seccomp), missing host procfs, forbidden mounts/symlinks, and access errors fail closed with no insecure fallback. The worker-side resolver returns `UnsupportedPlatform` on Windows/macOS. CLI parsing, compilation, validation and explain remain portable and do not resolve filesystem hashes.

Only a missing literal path is treated as a normal nonmatch; errors while opening/enumerating a directory or reopening an enumerated match invalidate the operation. Matching symlinks/special files are rejected, not followed. A symlink encountered while recursively scanning `**` therefore fails the operation, even if its contents would not have matched.

## Snapshot and execution boundary

Confinement is not snapshot isolation. Same-length in-place writes can race a read, and individually valid regular files can be replaced between traversal and content opening. Metadata checks catch observed changes but do not prove an immutable tree. Workers must resolve source-derived keys against their private prepared checkout before starting writable jobs, or use an immutable snapshot for later resolution. Tenant-controlled hardlinks or mounts must not be introduced by checkout preparation. W03 owns that workspace lifecycle.

The resolver bounds memory, traversal work and content I/O, not the wall time of an individual kernel operation on a stalled filesystem. Worker execution deadlines/cancellation remain the worker's responsibility. No new benchmark latency claim is made.

## Verification

Eight Linux resolver tests cover static digest compatibility and pattern-order deduplication; recursive matches; root, intermediate-directory and leaf symlink replacement; FIFO rejection; missing-root errors; growth, truncation and read errors; actual byte exhaustion; deep trees; streaming budgets spent on nonmatches; 10,000 unique files with overlapping patterns and rejection at 10,001; non-UTF-8/backslash names; and bounded path length. Non-Linux tests verify explicit unsupported resolution without filesystem access. Existing expression, fixture, malformed-input and offline CLI tests remain the grammar/phase regression suite.

Verification commands and completion evidence are recorded in [TODO.md](../TODO.md). Linux checks use WSL2 and do not establish production throughput.
