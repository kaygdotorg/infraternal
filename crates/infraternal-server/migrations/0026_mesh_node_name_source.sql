-- Who gave a Mesh node its name, so an automatic name never replaces a person's and a machine's report never
-- outranks the name the owner typed (#236). Ranked: hand > server > record > reported > placeholder.
--   hand        a person chose it (enrol, rename); never changed automatically
--   server      the server's own hostname, on the server's node
--   record      the host part of the address the owner added the host with
--   reported    the hostname the machine's infraternal agent reports
--   placeholder no name is known yet
-- Before this migration only attach wrote placeholders (`server`, `mesh-<host id>`), so a node still carrying
-- its placeholder is marked as one; every other existing name came from a person.
ALTER TABLE mesh_nodes ADD COLUMN name_source TEXT NOT NULL DEFAULT 'hand'
    CHECK (name_source IN ('hand','server','record','reported','placeholder'));
UPDATE mesh_nodes SET name_source='placeholder'
    WHERE (dataplane_host='server' AND name='server') OR name='mesh-'||dataplane_host;
