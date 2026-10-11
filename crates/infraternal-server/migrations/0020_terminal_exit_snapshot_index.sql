-- Keep the bounded per-account exit-status sidecar from sorting a user's full terminal history.
CREATE INDEX terminal_sessions_closed_exit_user
ON terminal_sessions(user_id, closed_at DESC, id DESC)
WHERE remote_host_id IS NULL AND closed_at IS NOT NULL AND exit_status IS NOT NULL;
