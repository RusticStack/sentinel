//! K03 — reclamation: sweep expired leases, drop unsealed staging and
//! generations that are neither `current` nor pinned, and enforce the
//! byte caps. Never delete a live lease's generation.
