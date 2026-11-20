-- remote promotion transaction.
--
-- The install transaction a root upgrade's relay ran (D376, #399, J465 P1).
-- When the relay dies after the successor joined, the host's install journal
-- (`/var/lib/infraternal/.bootstrap-lock`) is still open and the successor's
-- own uninstall refuses to run over it. The uninstall outbox then asks the
-- abandoned successor to roll back exactly this transaction first. It is an
-- id, not a secret, and is written once.
ALTER TABLE remote_host_promotions
    ADD COLUMN install_transaction BLOB CHECK (install_transaction IS NULL OR length(install_transaction) = 16);

CREATE TRIGGER remote_host_promotions_transaction_once
BEFORE UPDATE OF install_transaction ON remote_host_promotions
WHEN OLD.install_transaction IS NOT NULL AND NEW.install_transaction IS NOT OLD.install_transaction
BEGIN
    SELECT RAISE(ABORT, 'promotion install transaction is write-once');
END;
