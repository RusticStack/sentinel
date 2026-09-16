//! K02 — the read path: resolve an entry's `current` generation, verify
//! its manifest against the request, pin it with a lease and clone it
//! into the job's private view. Every failure is an `Outcome::Miss`.
