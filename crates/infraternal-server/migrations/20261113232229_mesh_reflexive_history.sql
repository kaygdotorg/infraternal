-- mesh reflexive history.
-- The server-reflexive addresses the coordinator published for a node before its current one
-- (#515, J585 F3): a JSON array of at most eight "ip:port" strings, oldest first. The server's
-- own mesh device can still hold one of them from a snapshot compiled earlier, so an unproven
-- reading of such an address is no evidence of a new NAT mapping. Public coordinates only,
-- never credentials.
ALTER TABLE mesh_nodes ADD COLUMN reflexive_history TEXT;
