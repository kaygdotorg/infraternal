-- promotion rollback after join.
--
-- A root upgrade whose relay rolled the install back after the successor
-- joined is over: the rollback removed the successor's unit and files, so
-- nothing is left to uninstall (#399, J569 P3-1). The forward-only trigger
-- allowed `rolled_back` only from `installing`, so such a row was abandoned
-- with `cleanup = 'uninstall'` for a successor that no longer exists; its
-- certificate stayed admissible for that uninstall for its whole 7 days, and
-- the row read like a committed root install that may still be running.
-- This replaces the trigger with one that also allows `enrolled` to move to
-- `rolled_back`. Everything else is unchanged.
DROP TRIGGER remote_host_promotions_forward;

CREATE TRIGGER remote_host_promotions_forward
BEFORE UPDATE OF state ON remote_host_promotions
WHEN NEW.state IS NOT OLD.state AND NOT (
       (OLD.state = 'open' AND NEW.state IN ('elevating', 'failed', 'abandoned'))
    OR (OLD.state = 'elevating' AND NEW.state IN ('installing', 'wrong', 'failed', 'abandoned'))
    OR (OLD.state = 'installing' AND NEW.state IN ('enrolled', 'rolled_back', 'abandoned'))
    OR (OLD.state = 'enrolled' AND NEW.state IN ('handed_over', 'rolled_back', 'abandoned'))
)
BEGIN
    SELECT RAISE(ABORT, 'promotion state only moves forward');
END;
