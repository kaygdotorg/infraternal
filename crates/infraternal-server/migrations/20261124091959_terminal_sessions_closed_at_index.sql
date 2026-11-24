-- Support batched pruning of closed terminal_sessions rows past the retention window (#579).
CREATE INDEX terminal_sessions_closed_at
ON terminal_sessions(closed_at)
WHERE closed_at IS NOT NULL;
