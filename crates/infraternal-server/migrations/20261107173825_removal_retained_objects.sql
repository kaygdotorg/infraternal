-- removal retained objects.
--
-- The kernel objects a removed host left in place because its installation did
-- not create them (#235, #409): a JSON array of names this server knows, such as
-- ["infraternal0"]. The removal outbox records it together with the host's
-- acceptance of its uninstall. NULL until the host answers.
ALTER TABLE remote_host_removals ADD COLUMN retained TEXT;
