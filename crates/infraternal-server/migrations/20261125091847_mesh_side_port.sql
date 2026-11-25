-- Whether a node takes marked small datagrams on `GotaTun`'s second UDP socket (#260, J1211).
-- `side_port_supported` records that the node understands `Peer::side_port` and reports its
-- capability; older nodes keep receiving snapshots without the field, because their decoder
-- refuses unknown fields, and are never reported as capable. `side_port` is the node's last
-- reported answer: it runs the side-mark receive rule and has its second socket on. Peers send it
-- marked datagrams from their own second socket only while it is 1 (kernel WireGuard and plain
-- GotaTun drop marked packets). Both are public facts about the machine, never credentials.
ALTER TABLE mesh_nodes ADD COLUMN side_port_supported INTEGER NOT NULL DEFAULT 0
    CHECK (side_port_supported IN (0, 1));
ALTER TABLE mesh_nodes ADD COLUMN side_port INTEGER NOT NULL DEFAULT 0
    CHECK (side_port IN (0, 1));
