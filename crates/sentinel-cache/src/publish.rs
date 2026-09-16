//! K03 — the write path: stage under `writing/`, hash, seal with a
//! manifest, then swap `current` atomically under the per-entry writer
//! lock and the global writer bound. Trust scope is authorization.
