#!/usr/bin/env python3
"""Check migrated host revocation retires Mesh inventory atomically, including rollback (#173)."""
import pathlib
import sqlite3
import sys

connection = sqlite3.connect(':memory:')
connection.execute('PRAGMA foreign_keys=ON')
for migration in sorted(pathlib.Path('crates/infraternal-server/migrations').glob('*.sql')):
    connection.executescript(migration.read_text())
connection.execute("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')")
host = bytes.fromhex('0000000000000000000000000000002a')
connection.execute("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)", (host,))
connection.execute("INSERT INTO mesh_nodes(id,name,public_key,dataplane_host) VALUES(42,'removed',?,'00000000-0000-0000-0000-00000000002a')", (bytes([3])*32,))
connection.execute("INSERT INTO mesh_grants(id,name,from_kind,from_value,to_kind,to_value,both_ways,ports_json) VALUES(1,'service','node','42','tag','prod',0,'\"All\"')")
connection.commit()
connection.execute('UPDATE remote_hosts SET revoked_at=2 WHERE id=?', (host,))
counts = tuple(connection.execute('SELECT (SELECT count(*) FROM mesh_nodes),(SELECT count(*) FROM mesh_grants),(SELECT revision FROM mesh_state)').fetchone())
connection.rollback()
assert connection.execute('SELECT count(*) FROM mesh_nodes').fetchone()[0] == 1
assert connection.execute('SELECT count(*) FROM mesh_grants').fetchone()[0] == 1
assert connection.execute('SELECT revoked_at FROM remote_hosts').fetchone()[0] is None
assert counts == (0, 0, 1), f'revocation retained inventory: nodes/grants/revision={counts}'
connection.execute('UPDATE remote_hosts SET revoked_at=2 WHERE id=?', (host,))
connection.commit()
assert connection.execute('SELECT count(*) FROM mesh_dataplane_removed').fetchone()[0] == 1
connection.execute('UPDATE remote_hosts SET revoked_at=3 WHERE id=?', (host,))
connection.commit()
assert connection.execute('SELECT revision FROM mesh_state').fetchone()[0] == 1
print('PASS: retirement, transaction rollback, durable removal fence, idempotent revision (4 checks)')
