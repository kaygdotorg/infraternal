-- remote host reported os.
--
-- The operating system a host's infraternal agent names in its link Hello
-- ("macOS" or "Linux", #146, D349). Hosts added over SSH keep the richer name
-- the SSH probe stored in remote_host_bootstrap.os; a host that joined by
-- invitation has no bootstrap row, so this column is the only place its OS is
-- known. The canvas offers app windows only for a host whose OS is macOS.
-- NULL until the host's first link after this migration.
ALTER TABLE remote_hosts ADD COLUMN reported_os TEXT;
