//! K02 — job-private writable clones of immutable generations.
//! Capability-detected reflink (`FICLONE`) with a safe byte-copy fallback;
//! never writable hardlinks. See `docs/cache.md`.
