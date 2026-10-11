#!/usr/bin/env python3
"""Upgrade the recorded dev database shape and retain public ownership rows (#87)."""
from pathlib import Path
import sqlite3
import subprocess

root = Path('crates/infraternal-server/migrations')
base = 'd82d0fb9'
paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', base, '--', str(root)], text=True).splitlines()
assert paths, 'dev migration snapshot is required'
db = sqlite3.connect(':memory:')
db.execute('PRAGMA foreign_keys=ON')
for path in sorted(paths):
    db.executescript(subprocess.check_output(['git', 'show', f'{base}:{path}'], text=True))
db.execute("INSERT INTO users(id,name,owner,recovery_hash) VALUES('migration-owner','Migration fixture',1,'public-fixture-hash')")
prior = len(paths)
for path in sorted(root.glob('*.sql')):
    if str(path) not in paths:
        db.executescript(path.read_text())
assert db.execute("SELECT name FROM users WHERE id='migration-owner'").fetchone() == ('Migration fixture',)
assert db.execute("SELECT count(*) FROM remote_host_bootstrap").fetchone() == (0,)
assert db.execute("SELECT count(*) FROM remote_host_removals").fetchone() == (0,)
assert db.execute('PRAGMA foreign_key_check').fetchall() == []
assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',)
print(f'PASS: dev {base} shape ({prior} migrations) upgrades to {len(list(root.glob("*.sql")))} migrations; ownership retained, foreign keys and integrity clean')
