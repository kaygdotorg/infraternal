-- Whether a node runs IPv4-only because IPv6 is off on its mesh link (#578, J1142).
-- `ipv6_supported` records that the node understands `Peer::ipv4_only` and reports its IPv6 state;
-- older nodes keep receiving snapshots without the field, because their decoder refuses unknown
-- fields, and are never reported as IPv4-only. `ipv4_only` is the node's last reported state: the
-- coordinator then publishes no AAAA name for it and its peers install no IPv6 route to it. Both are
-- public facts about the machine, never credentials.
ALTER TABLE mesh_nodes ADD COLUMN ipv6_supported INTEGER NOT NULL DEFAULT 0
    CHECK (ipv6_supported IN (0, 1));
ALTER TABLE mesh_nodes ADD COLUMN ipv4_only INTEGER NOT NULL DEFAULT 0
    CHECK (ipv4_only IN (0, 1));
