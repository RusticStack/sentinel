-- Stable receipts fence webhook replay; refresh work survives controller loss.
CREATE TABLE github_events(
    delivery TEXT PRIMARY KEY NOT NULL CHECK(length(delivery) BETWEEN 1 AND 128),
    digest BLOB NOT NULL CHECK(length(digest)=32),
    outcome TEXT NOT NULL CHECK(length(outcome) BETWEEN 1 AND 64),
    created_ms INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE github_refresh(
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),
    kind INTEGER NOT NULL CHECK(kind IN (0,1)),
    seq INTEGER NOT NULL DEFAULT 1,
    next_ms INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX github_refresh_due ON github_refresh(next_ms);
ALTER TABLE check_publications ADD COLUMN check_suite_id INTEGER CHECK(check_suite_id>0);
ALTER TABLE check_publications ADD COLUMN create_started_ms INTEGER;
CREATE INDEX check_publications_external ON check_publications(repo_id,external_id);
CREATE INDEX check_publications_suite ON check_publications(repo_id,check_suite_id);
