-- Worker-link admission state that must survive a controller restart and stay
-- bounded however many peers misbehave.
--
-- `link_known_sources` is the set of network sources that have authenticated a
-- worker within the last day. The controller reads it at start so a restart
-- under load admits the fleet through the reserved part of the handshake pool
-- instead of treating every worker as a stranger. A source is the 16-byte
-- address key the link already uses (IPv4 mapped into IPv6, IPv6 masked to its
-- /64); loopback is never stored, because behind a Tailcat helper every peer is
-- loopback and the address says nothing about who it is. Rows past the day are
-- pruned by the writer that refreshes them, and the table is capped at 4096.
CREATE TABLE link_known_sources(
    source BLOB PRIMARY KEY NOT NULL CHECK(length(source) = 16),
    seen_ms INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX link_known_sources_by_seen ON link_known_sources(seen_ms);

-- Refused worker enrollments, counted per hour. `auth_audit` is append-only, so
-- an unbounded stream of refusals would be an unbounded audit log; each peer
-- (a hash of its source key, or all zeros when unattributed) may write at most a
-- few audit rows per window and the window as a whole a few dozen, and every
-- refusal beyond that is only counted here. The first refusal of a later window
-- writes one summary audit row for the windows that suppressed some. Windows
-- are pruned after seven days; per window at most 64 peers get their own row
-- and the rest share the all-zero row.
CREATE TABLE worker_enrollment_refusals(
    window_ms INTEGER NOT NULL,
    peer BLOB NOT NULL CHECK(length(peer) = 16),
    recorded INTEGER NOT NULL DEFAULT 0 CHECK(recorded >= 0),
    suppressed INTEGER NOT NULL DEFAULT 0 CHECK(suppressed >= 0),
    summarized INTEGER NOT NULL DEFAULT 0 CHECK(summarized IN (0, 1)),
    PRIMARY KEY(window_ms, peer)
) WITHOUT ROWID;
CREATE INDEX worker_enrollment_refusals_unsummarized
    ON worker_enrollment_refusals(window_ms) WHERE suppressed > 0 AND summarized = 0;
