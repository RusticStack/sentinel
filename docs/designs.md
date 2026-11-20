# Open designs

Written designs that are deliberately **not built**. Each page states what would have to change, the constraints the rest of the system already imposes, the failure modes, and the evidence or owner decision needed before any of it is implemented. Nothing here is a commitment: an item is promoted into [TODO.md](../TODO.md) only with its use case, its dependencies and its measurement gate, as [the after-v0.1 backlog](backlog.md) requires, and the tracker is the only place that says what is next.

| Design | What it would change | State | Needs before implementation |
|---|---|---|---|
| [Multiple active controllers](multiple-controllers.md) | ownership of the metadata store, authority over placement, and where a worker's session lives | written, not built | a measured single-controller ceiling, or an availability requirement shorter than the restore objective |
| [External SSO](external-sso.md) | sign-in only: one more provider key beside `github` in `external_identities` | written, not built | the IdP a real deployment uses, and an owner decision on whether directory groups may derive membership |
| [Cloud autoscaling](cloud-autoscaling.md) | a demand read the scheduler does not expose today, and a scoped authority that may mint worker enrollments | written, not built | measured queue wait against fleet size, and the scoped-authority decision |

## Deliberately not built

- **No shared-SQLite HA mode.** A second controller opening the same database file is refused at startup (`Error::AlreadyOwned`, [storage](storage.md#bounds-and-failure-behavior)), and that refusal is the design, not a limitation to route around. SQLite's write-ahead log requires every process to be on the same host as the database file, so "the same database over a shared volume" is not a mode this store could support correctly even if the lock let it through; the lock is also an advisory lock on a local filesystem, not a distributed lease. What a second active controller would actually need is in [multiple controllers](multiple-controllers.md), and none of it is scheduled.
- **No SCIM, directory sync, or IdP groups mapped to repository grants.** [External SSO](external-sso.md) adds a sign-in proof and nothing else.
- **No job handoff between workers.** Nothing in Sentinel moves a running attempt from one machine to another, which is why [cloud autoscaling](cloud-autoscaling.md) bounds a scale-down by the work already leased rather than promising a migration.

## How these pages are kept honest

A design page names the code and the documents each claim rests on, and it separates what the system already guarantees from what the design would add. Where a decision is the owner's rather than the implementation's, the page says so and states the alternatives instead of picking one quietly. Anything measured here is quoted with where it came from; anything unmeasured says so.
