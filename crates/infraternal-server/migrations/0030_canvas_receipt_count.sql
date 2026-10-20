-- Bound permanent retry admission without scanning an account's lifetime history [5,183,248].
ALTER TABLE canvas_heads ADD COLUMN receipt_count INTEGER NOT NULL DEFAULT 0 CHECK(receipt_count >= 0);
UPDATE canvas_heads SET receipt_count = (SELECT count(*) FROM canvas_receipts WHERE account = canvas_heads.account);

-- Keep the counter in the receipt transaction, including rollback and account removal.
CREATE TRIGGER canvas_receipt_insert AFTER INSERT ON canvas_receipts BEGIN
    UPDATE canvas_heads SET receipt_count = receipt_count + 1 WHERE account = NEW.account;
END;
CREATE TRIGGER canvas_receipt_delete AFTER DELETE ON canvas_receipts BEGIN
    UPDATE canvas_heads SET receipt_count = receipt_count - 1 WHERE account = OLD.account;
END;
CREATE TRIGGER canvas_receipt_account AFTER UPDATE OF account ON canvas_receipts WHEN OLD.account != NEW.account BEGIN
    UPDATE canvas_heads SET receipt_count = receipt_count - 1 WHERE account = OLD.account;
    UPDATE canvas_heads SET receipt_count = receipt_count + 1 WHERE account = NEW.account;
END;
