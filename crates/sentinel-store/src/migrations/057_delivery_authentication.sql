-- How a delivery was authenticated at the door (RW05). The secret gate used
-- to test `trigger != 'manual'`, a string the adapter that recorded the run's
-- provenance supplied; it now reads this fact from the stored delivery the
-- provenance names. 0 observed: no inbound authentication (a polled ref
-- transition the controller saw itself), 1 hook token (the per-repository
-- generic hook secret was presented), 2 signed webhook (the provider's HMAC
-- signature verified). Only 1 and 2 may release secrets to a run.
-- Rows written before this migration were accepted only after the generic
-- hook token or the GitHub signature was verified, so they carry the matching
-- value; anything else, including a polled or unknown provider, is 0 and
-- withholds secrets. An older binary inserts without the column and so
-- records 0, which only withholds: it is declared readable by 56.
ALTER TABLE webhook_deliveries
    ADD COLUMN authentication INTEGER NOT NULL DEFAULT 0
        CHECK(authentication IN (0, 1, 2));
UPDATE webhook_deliveries
   SET authentication = CASE provider WHEN 'github' THEN 2 WHEN 'generic' THEN 1 ELSE 0 END;

-- A delivery's authentication is written with the delivery and never moves.
DROP TRIGGER delivery_terms_immutable;
CREATE TRIGGER delivery_terms_immutable BEFORE UPDATE ON webhook_deliveries
WHEN NEW.id != OLD.id OR NEW.tenant_id != OLD.tenant_id OR NEW.repo_id != OLD.repo_id
  OR NEW.provider != OLD.provider OR NEW.external_id != OLD.external_id
  OR NEW.event != OLD.event OR NEW.ref_name IS NOT OLD.ref_name
  OR NEW.old_sha IS NOT OLD.old_sha OR NEW.new_sha IS NOT OLD.new_sha
  OR NEW.received_ms != OLD.received_ms
  OR NEW.authentication != OLD.authentication
  OR (OLD.run_id IS NOT NULL AND NEW.run_id IS NOT OLD.run_id)
  OR (OLD.state NOT IN (0, 1) AND NEW.state != OLD.state)
BEGIN
    SELECT RAISE(ABORT, 'delivery terms are immutable');
END;
