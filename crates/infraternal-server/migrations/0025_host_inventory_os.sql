-- Retain the already-collected public OS label for admitted hosts while offline [145][198], #194.
ALTER TABLE remote_host_bootstrap ADD COLUMN os TEXT CHECK(os IS NULL OR length(os) BETWEEN 1 AND 256);
