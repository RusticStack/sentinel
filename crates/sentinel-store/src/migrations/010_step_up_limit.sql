-- Part 03 audit: a session that keeps failing to prove presence is not the
-- person it was issued to. Online guessing of a six-digit code, or of the
-- password behind a stolen cookie, gets a handful of attempts and then the
-- session itself is gone — the login lockout never applied to step-up, and a
-- second factor must not be weaker than the first.
ALTER TABLE sessions ADD COLUMN step_up_failures INTEGER NOT NULL DEFAULT 0
    CHECK(step_up_failures >= 0);
