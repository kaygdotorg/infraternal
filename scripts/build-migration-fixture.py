#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build and verify the checked-in prod-schema SQLite migration fixture (#514).

Owner rule (2026-11-25): jobs must never copy production's database for
migration checks. Instead, this script deterministically builds a synthetic
SQLite database at the current release's schema, filled with made-up rows
covering every table, constraint and trigger.

Usage:
    python3 scripts/build-migration-fixture.py
    python3 scripts/build-migration-fixture.py --through 20261124214454
    python3 scripts/build-migration-fixture.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = ROOT / "crates/infraternal-server/migrations"
DEFAULT_FIXTURE = ROOT / "crates/infraternal-server/tests/fixtures/prod-schema.sqlite"

# Matches crates/infraternal-db/src/migrate.rs CREATE_HISTORY character for character.
CREATE_SQLX_MIGRATIONS = """
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
);
                """

# Fixed synthetic base timestamp (2025-10-10T00:00:00Z) so generated fixtures are
# byte-for-byte deterministic regardless of when the script runs.
T0 = 1_760_000_000
INSTALLED_ON = "2026-11-24 21:44:54"
WEEK = 604_800


def uuid_bytes(n: int) -> bytes:
    """Return a deterministic 16-byte synthetic UUID."""
    return n.to_bytes(16, "big")


def uuid_str(n: int) -> str:
    """Return the canonical hyphenated string form of uuid_bytes(n)."""
    h = uuid_bytes(n).hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def blob32(tag: int) -> bytes:
    """Return a deterministic 32-byte synthetic key, digest or fingerprint."""
    return bytes([tag & 0xFF]) * 32


def p256_pub(tag: int) -> bytes:
    """Return a deterministic 65-byte uncompressed P-256 point (0x04 || X || Y)."""
    return b"\x04" + bytes([tag & 0xFF]) * 64


def discover_migrations(through: int | None = None) -> list[tuple[int, str, Path]]:
    """Return (version, description, path) sorted by ascending numeric version."""
    migrations: list[tuple[int, str, Path]] = []
    for path in MIGRATIONS_DIR.glob("*.sql"):
        if not path.is_file():
            continue
        prefix, sep, rest = path.name.partition("_")
        if not sep:
            continue
        version = int(prefix)
        if through is not None and version > through:
            continue
        if rest.endswith(".up.sql"):
            description = rest[: -len(".up.sql")].replace("_", " ")
        elif rest.endswith(".down.sql"):
            continue
        else:
            description = rest[: -len(".sql")].replace("_", " ")
        migrations.append((version, description, path))
    migrations.sort(key=lambda item: (item[0], item[2].name))
    return migrations


def apply_migrations(
    conn: sqlite3.Connection,
    migrations: list[tuple[int, str, Path]],
    installed_on: str = INSTALLED_ON,
) -> list[int]:
    """Apply every unapplied migration in version order and record _sqlx_migrations."""
    conn.executescript(CREATE_SQLX_MIGRATIONS)
    applied_rows = dict(
        conn.execute("SELECT version, checksum FROM _sqlx_migrations ORDER BY version").fetchall()
    )
    newly_applied: list[int] = []
    for version, description, path in migrations:
        raw_sql = path.read_text(encoding="utf-8")
        checksum = hashlib.sha384(raw_sql.encode("utf-8")).digest()
        if version in applied_rows:
            if applied_rows[version] != checksum:
                raise RuntimeError(
                    f"checksum mismatch for migration {version} ({path.name})"
                )
            continue
        conn.executescript(raw_sql)
        conn.execute(
            "INSERT INTO _sqlx_migrations "
            "(version, description, installed_on, success, checksum, execution_time) "
            "VALUES (?, ?, ?, 1, ?, 0)",
            (version, description, installed_on, checksum),
        )
        conn.commit()
        newly_applied.append(version)
    return newly_applied


def seed_synthetic_data(conn: sqlite3.Connection) -> None:
    """Populate every application table with realistic, entirely made-up rows.

    All names, IDs, keys, hashes and addresses are synthetic (RFC 5737 / RFC 3849
    documentation prefixes and .example.test names). No production data is used.
    """
    # Normalize timestamps inserted by migrations using unixepoch() so the file
    # is byte-for-byte deterministic across runs.
    conn.execute("UPDATE login_rules SET created_at = ?", (T0,))
    conn.execute("UPDATE server_settings SET api_key_time_high_water = ?", (T0 + 100,))
    conn.execute("UPDATE recovery_clock SET elapsed = 120 WHERE singleton = 1")
    conn.execute("UPDATE session_login_sequence SET value = 10 WHERE singleton = 1")
    conn.execute("UPDATE wire_writer_clock SET value = 4 WHERE singleton = 1")
    conn.execute("UPDATE mesh_ssh_sequence SET value = 3 WHERE singleton = 1")

    # 1. Users and CA administrators:
    #    - One server owner (owner = 1, enforced by unique index `one_owner`;
    #      trigger `ca_administrator_on_initial_owner` auto-inserts into ca_administrators).
    #    - Two additional accounts (owner = 0) who own remote hosts, plus extra
    #      ca_administrators rows (active and inactive).
    conn.executemany(
        "INSERT INTO users(id, name, owner, recovery_hash, username, display_name, "
        "recovery_version, recovery_wrap_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ("u-owner", "Fixture Owner", 1, "synthetic-argon2-owner", "fixture-owner", "Fixture Owner", 2, 2),
            ("u-alice", "Fixture Alice", 0, "synthetic-argon2-alice", "fixture-alice", "Fixture Alice", 2, 2),
            ("u-bob", "Fixture Bob", 0, "synthetic-argon2-bob", "fixture-bob", "Fixture Bob", 1, 1),
        ],
    )
    conn.executemany(
        "INSERT INTO ca_administrators(user_id, generation, active) VALUES (?, ?, ?)",
        [
            ("u-alice", 2, 1),
            ("u-bob", 1, 0),
        ],
    )

    # 2. Passkeys, wraps, recovery, setup, server_ssh_key, plugin_settings.
    conn.executemany(
        "INSERT INTO passkeys(id, user_id, credential, prf_input, aaguid) VALUES (?, ?, ?, ?, ?)",
        [
            ("pk-owner-1", "u-owner", "synthetic-cred-owner-1", "synthetic-prf-1", "00000000-0000-4000-8000-000000000001"),
            ("pk-alice-1", "u-alice", "synthetic-cred-alice-1", None, "00000000-0000-4000-8000-000000000002"),
        ],
    )
    conn.executemany(
        "INSERT INTO wraps(user_id, kind, key_id, blob) VALUES (?, ?, ?, ?)",
        [
            ("u-owner", "passkey", "pk-owner-1", "synthetic-wrap-blob-1"),
            ("u-owner", "recovery", "rec-owner-1", "synthetic-wrap-blob-2"),
            ("u-alice", "passkey", "pk-alice-1", "synthetic-wrap-blob-3"),
        ],
    )
    conn.execute(
        "INSERT INTO recovery(user_id, token_hash, ready, expires) VALUES (?, ?, ?, ?)",
        ("u-bob", "synthetic-recovery-token-hash", T0 + 86_400, T0 + 172_800),
    )
    conn.executemany(
        "INSERT INTO recovery_audit(id, user_id, event, occurred_at) VALUES (?, ?, ?, ?)",
        [
            (1, "u-owner", "start", T0 + 10),
            (2, "u-owner", "cancel", T0 + 20),
            (3, "u-bob", "complete", T0 + 30),
        ],
    )
    conn.execute(
        "INSERT INTO setup(singleton, token_hash, expires) VALUES (1, ?, ?)",
        ("synthetic-setup-token-hash", T0 + 3_600),
    )
    conn.execute(
        "INSERT INTO server_ssh_key(singleton, public_key, envelope) VALUES (1, ?, ?)",
        (blob32(0x51), b"synthetic-ssh-envelope-v1"),
    )
    conn.executemany(
        "INSERT INTO plugin_settings(role, plugin, enabled, settings) VALUES (?, ?, ?, ?)",
        [
            ("server", "mesh", 1, json.dumps({"dns_domain": "mesh.example.test"})),
            ("server", "canvas", 1, "{}"),
            ("server", "desktop", 0, "{}"),
        ],
    )

    # 3. Sessions, API keys, approvals, API audit logs.
    conn.executemany(
        "INSERT INTO sessions(token_hash, user_id, device, expires, fresh, unlocked, "
        "passkey_id, tap_spent, tap_action, login_sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ("sess-owner-live", "u-owner", "Fixture Phone", T0 + 86_400, T0 + 3_600, 1, "pk-owner-1", 0, None, 1),
            ("sess-alice-locked", "u-alice", "Fixture Laptop", T0 + 43_200, T0 + 1_800, 0, "pk-alice-1", 1, "host.promote", 2),
            ("sess-bob-expired", "u-bob", "Fixture Browser", T0 - 3_600, T0 - 7_200, 0, None, 0, None, 3),
        ],
    )
    conn.executemany(
        "INSERT INTO api_keys(token_hash, user_id, device, scopes, renewed_at, expires_at, dead, hard_expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ("apikey-owner-live", "u-owner", "fixture-cli", "sessions:read,hosts:read", T0, T0 + 2_592_000, 0, T0 + 7_776_000),
            ("apikey-alice-dead", "u-alice", "fixture-ci", "sessions:read", T0 - 86_400, T0 - 3_600, 1, T0 + 86_400),
        ],
    )
    conn.executemany(
        "INSERT INTO approvals(token_hash, code_hash, scopes, device, user_id, expires, kind, "
        "request_json, approved_session_hash, inspect_attempts, lifetime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ("appr-signin-1", "code-signin-1", "sessions:read", "Fixture CLI", "u-owner", T0 + 900, "sign_in", None, "sess-owner-live", 1, 86_400),
            ("appr-join-1", "code-join-1", "host:join", "Fixture Node", "u-alice", T0 + 600, "join_machine", json.dumps({"mode": "rootful"}), None, 0, 600),
        ],
    )
    conn.executemany(
        "INSERT INTO api_action_audit(id, key_id, person_id, action_id, target_id, state, occurred_at, completed_at, result) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, "apikey-owner-live", "u-owner", "host.list", None, "complete", T0 + 50, T0 + 51, "ok"),
            (2, "apikey-owner-live", "u-owner", "host.remove", uuid_str(6), "pending", T0 + 60, None, None),
            (3, "apikey-alice-dead", "u-alice", "mesh.grant.add", "grant-1", "denied", T0 + 70, T0 + 70, "expired"),
            (4, "apikey-owner-live", "u-owner", "session.open", "sess-1", "failed", T0 + 80, T0 + 81, "unreachable"),
        ],
    )
    conn.executemany(
        "INSERT INTO api_read_audit(key_id, person_id, action_id, minute, calls, failed) VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("apikey-owner-live", "u-owner", "host.list", T0 // 60, 12, 0),
            ("apikey-alice-dead", "u-alice", "session.list", (T0 // 60) - 1, 3, 1),
        ],
    )

    # 4. Remote hosts across owners and every current mode (rootful, rootless).
    #    Leave room for `device` mode (host UUID 8) when a future migration adds
    #    `'device'` to remote_hosts.mode; host 3 already carries device_approved=1
    #    and device_os to exercise those columns today.
    h_rootful_ed = uuid_bytes(1)
    h_rootless_ed = uuid_bytes(2)
    h_rootful_p256 = uuid_bytes(3)
    h_promoting = uuid_bytes(4)
    h_pending_join = uuid_bytes(5)
    h_revoked = uuid_bytes(6)
    h_promoted = uuid_bytes(7)

    conn.executemany(
        "INSERT INTO remote_hosts(id, owner_id, mode, execution_uid, created_at, revoked_at, "
        "hostname, reported_os, device_approved, device_os) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (h_rootful_ed, "u-owner", "rootful", 0, T0, None, "alpha-box", "Debian GNU/Linux 13", 0, None),
            (h_rootless_ed, "u-alice", "rootless", 1000, T0 + 10, None, "beta-dev", "Ubuntu 24.04", 0, None),
            (h_rootful_p256, "u-bob", "rootful", 0, T0 + 20, None, "gamma-node", "macOS 26.5", 1, "iOS 26.0"),
            (h_promoting, "u-alice", "rootless", 1001, T0 + 30, None, "delta-work", "Debian GNU/Linux 13", 0, None),
            (h_pending_join, "u-owner", "rootful", 0, T0 + 40, None, "epsilon-join", None, 1, "macOS 26.5"),
            (h_revoked, "u-bob", "rootless", 1002, T0 + 50, None, "zeta-retired", "Alpine Linux 3.21", 0, None),
            (h_promoted, "u-owner", "rootful", 0, T0 + 60, None, "eta-promoted", "Debian GNU/Linux 13", 0, None),
        ],
    )

    # 5. Remote certificates: both key algorithms (ed25519 + p256), active, revoked,
    #    and a successor certificate (role='successor', execution_uid=0) exercising
    #    trigger `remote_certificates_successor_is_root_insert`.
    issuer_fp = blob32(0xAA)
    conn.executemany(
        "INSERT INTO remote_certificates(fingerprint, host_id, issuer_fingerprint, public_key, "
        "not_before, not_after, revoked_at, role, execution_uid, key_algorithm) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (blob32(0x11), h_rootful_ed, issuer_fp, blob32(0x21), T0, T0 + WEEK, None, "active", 0, "ed25519"),
            (blob32(0x12), h_rootful_ed, issuer_fp, blob32(0x22), T0 - WEEK, T0, T0 - 100, "active", 0, "ed25519"),
            (blob32(0x13), h_rootless_ed, issuer_fp, blob32(0x23), T0 + 10, T0 + 10 + WEEK, None, "active", 1000, "ed25519"),
            (blob32(0x14), h_rootful_p256, issuer_fp, p256_pub(0x24), T0 + 20, T0 + 20 + WEEK, None, "active", 0, "p256"),
            (blob32(0x15), h_promoting, issuer_fp, blob32(0x25), T0 + 30, T0 + 30 + WEEK, None, "active", 1001, "ed25519"),
            (blob32(0x16), h_promoting, issuer_fp, blob32(0x26), T0 + 35, T0 + 35 + WEEK, None, "successor", 0, "ed25519"),
            (blob32(0x17), h_revoked, issuer_fp, blob32(0x27), T0 + 50, T0 + 50 + WEEK, T0 + 500, "active", 1002, "ed25519"),
            (blob32(0x18), h_promoted, issuer_fp, blob32(0x28), T0 + 60, T0 + 60 + WEEK, None, "active", 0, "ed25519"),
        ],
    )

    # 6. Join tokens: rootless+ed25519 (900s, consumed), rootful+p256 (600s, unconsumed,
    #    with expected_key_digest), rootful+ed25519 (600s, consumed).
    conn.executemany(
        "INSERT INTO remote_join_tokens(host_id, mode, digest, issued_at, expires_at, "
        "consumed_at, expected_key_digest, key_algorithm) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (h_rootless_ed, "rootless", blob32(0x31), T0, T0 + 900, T0 + 120, None, "ed25519"),
            (h_pending_join, "rootful", blob32(0x32), T0 + 40, T0 + 640, None, blob32(0x3A), "p256"),
            (h_rootful_ed, "rootful", blob32(0x33), T0, T0 + 600, T0 + 45, blob32(0x3B), "ed25519"),
        ],
    )

    # 7. Remote identity rotation rows: Ed25519 complete, P-256 issued (65-byte keys),
    #    and Ed25519 challenged.
    conn.executemany(
        "INSERT INTO remote_identity_rotation(host_id, sequence, last_completed_at, phase, "
        "operation_id, challenge, predecessor_fingerprint, predecessor_public_key, "
        "issuer_fingerprint, issuer_generation, started_at, csr_digest, candidate_public_key, "
        "candidate_fingerprint, candidate_certificate, candidate_attempted_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (h_rootful_ed, 3, T0 + 100, "complete", None, None, None, None, None, None, None, None, None, None, None, None),
            (
                h_rootful_p256, 1, T0 + 20, "issued", uuid_bytes(0x41), blob32(0x42),
                blob32(0x14), p256_pub(0x24), issuer_fp, 1, T0 + 200, blob32(0x43),
                p256_pub(0x44), blob32(0x45), b"synthetic-p256-candidate-der", T0 + 210,
            ),
            (
                h_rootless_ed, 2, T0 + 10, "challenged", uuid_bytes(0x46), blob32(0x47),
                blob32(0x13), blob32(0x23), issuer_fp, 1, T0 + 220, None,
                None, None, None, None,
            ),
        ],
    )

    # 8. Remote certificate recovery: one pending and one completed row.
    conn.executemany(
        "INSERT INTO remote_certificate_recovery(host_id, predecessor_fingerprint, request_id, "
        "csr_digest, challenge, public_key_fingerprint, issuer_fingerprint, issuer_generation, "
        "predecessor_not_after, expires_at, certificate_fingerprint, certificate_der, completed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                h_rootful_ed, blob32(0x12), blob32(0x52), blob32(0x53), blob32(0x54),
                blob32(0x55), issuer_fp, 1, T0, T0 + 3_600,
                blob32(0x11), b"synthetic-recovered-cert-der", T0 + 90,
            ),
            (
                h_rootless_ed, blob32(0x13), blob32(0x56), blob32(0x57), blob32(0x58),
                blob32(0x59), issuer_fp, 1, T0 + 10 + WEEK, T0 + 7_200,
                None, None, None,
            ),
        ],
    )

    # 9. Remote host bootstrap, retirement intents, promotions, removals, access reports,
    #    host activity, login rules, preferred accounts.
    conn.executemany(
        "INSERT INTO remote_host_bootstrap(host_id, address, trust_lookup, os) VALUES (?, ?, ?, ?)",
        [
            (h_rootful_ed, "root@192.0.2.10", "alpha-box.example.test:22", "Debian GNU/Linux 13"),
            (h_rootless_ed, "alice@192.0.2.11", "beta-dev.example.test:22", "Ubuntu 24.04"),
            (h_rootful_p256, "root@198.51.100.12", "gamma-node.example.test:22", "macOS 26.5"),
        ],
    )
    conn.execute(
        "INSERT INTO remote_bootstrap_retirement_intents(host_id) VALUES (?)",
        (h_rootless_ed,),
    )
    conn.executemany(
        "INSERT INTO remote_host_promotions(attempt, host_id, person, method, account, from_uid, "
        "from_fingerprint, link_generation, state, tried, rooted, token_digest, expected_key_digest, "
        "successor_fingerprint, successor_key, started_at, expires_at, ended_at, cleanup, install_transaction) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                uuid_bytes(0x61), h_promoting, "u-alice", "sudo", "person", 1001,
                blob32(0x15), uuid_bytes(0x62), "enrolled", 1, 1, blob32(0x63), blob32(0x64),
                blob32(0x16), blob32(0x26), T0 + 300, T0 + 1_200, None, "none", uuid_bytes(0x65),
            ),
            (
                uuid_bytes(0x66), h_promoted, "u-owner", "su", "root", 1000,
                blob32(0x67), uuid_bytes(0x68), "handed_over", 1, 1, blob32(0x69), blob32(0x6A),
                blob32(0x18), blob32(0x28), T0 + 60, T0 + 960, T0 + 180, "done", uuid_bytes(0x6B),
            ),
        ],
    )
    conn.execute(
        "INSERT INTO remote_host_removals(host_id, owner_id, requested_at, uninstall, host_cleanup, completed_at, retained) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (h_revoked, "u-bob", T0 + 490, 1, "retained", T0 + 510, "logs"),
    )
    conn.executemany(
        "INSERT INTO remote_access_reports(host_id, person_id, report, recorded_at, seen_at) VALUES (?, ?, ?, ?, ?)",
        [
            (h_rootful_ed, "u-owner", json.dumps({"ok": True, "checked": 1}), T0 + 250, T0 + 260),
            (h_rootless_ed, "u-alice", json.dumps({"ok": True, "checked": 2}), T0 + 270, None),
        ],
    )
    conn.executemany(
        "INSERT INTO host_activity(id, host_id, at, person, kind, method, attempt, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, h_promoting, T0 + 300, "u-alice", "privilege.attempt", "sudo", uuid_bytes(0x61), None),
            (2, h_promoted, T0 + 180, "u-owner", "privilege.upgraded", "su", uuid_bytes(0x66), None),
            (3, h_rootless_ed, T0 + 200, "u-alice", "privilege.failed", "doas", None, "timeout"),
        ],
    )
    conn.executemany(
        "INSERT INTO login_names_match(host_id) VALUES (?)",
        [(b"",), (h_rootful_ed,)],
    )
    conn.executemany(
        "INSERT INTO login_rules(id, subject, account_kind, account, host_id, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (2, "u-alice", "named", "deploy", h_rootful_ed, T0 + 10),
            (3, "u-bob", "any", None, None, T0 + 20),
        ],
    )
    conn.executemany(
        "INSERT INTO preferred_accounts(user_id, account) VALUES (?, ?)",
        [("u-owner", "admin"), ("u-alice", "alice")],
    )
    conn.executemany(
        "INSERT INTO preferred_host_accounts(user_id, host_id, account) VALUES (?, ?, ?)",
        [
            ("u-owner", b"", "admin"),
            ("u-alice", h_rootful_ed, "deploy"),
        ],
    )

    # 10. Terminal sessions, WebSocket connections, terminal writers, startup hints.
    ts_local_open = uuid_bytes(0x71)
    ts_local_closed = uuid_bytes(0x72)
    ts_remote_open = uuid_bytes(0x73)
    ts_remote_closed = uuid_bytes(0x74)
    conn.executemany(
        "INSERT INTO terminal_sessions(id, user_id, created_at, last_seen, input_acked, "
        "closed_at, exit_status, input_acked_u64, remote_host_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (ts_local_open, "u-owner", T0, T0 + 300, 128, None, None, (128).to_bytes(8, "big"), None),
            (ts_local_closed, "u-owner", T0 - 1_000, T0 - 500, 64, T0 - 400, 0, (64).to_bytes(8, "big"), None),
            (ts_remote_open, "u-alice", T0 + 10, T0 + 310, 256, None, None, (256).to_bytes(8, "big"), h_rootless_ed),
            (ts_remote_closed, "u-bob", T0 + 20, T0 + 120, 32, T0 + 130, 1, (32).to_bytes(8, "big"), h_rootful_p256),
        ],
    )
    ws_active = uuid_bytes(0x7A)
    ws_inactive = uuid_bytes(0x7B)
    conn.executemany(
        "INSERT INTO websocket_connections(connection_id, token_hash, user_id, created_at, expires_at, active) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (ws_active, blob32(0x7C), "u-owner", T0, T0 + 86_400, 1),
            (ws_inactive, blob32(0x7D), "u-alice", T0 - 3_600, T0 - 1_800, 0),
        ],
    )
    conn.executemany(
        "INSERT INTO terminal_writers(writer_id, connection_id, client_stream, session_id, input_acked) "
        "VALUES (?, ?, ?, ?, ?)",
        [
            (1, ws_active, 1, ts_local_open, (128).to_bytes(8, "big")),
            (2, ws_active, 3, ts_remote_open, (256).to_bytes(8, "big")),
        ],
    )
    conn.executemany(
        "INSERT INTO terminal_startup_hints(user_id, host, enabled, shown) VALUES (?, ?, ?, ?)",
        [
            ("u-owner", "alpha-box", 1, 1),
            ("u-alice", "beta-dev", 0, 0),
        ],
    )

    # 11. Canvas layout tables (inserting into canvas_receipts fires `canvas_receipt_insert`,
    #     keeping canvas_heads.receipt_count accurate).
    conn.executemany(
        "INSERT INTO canvas_heads(account, revision, document, initialized) VALUES (?, ?, ?, ?)",
        [
            ("u-owner", 2, json.dumps({"revision": 2, "views": [], "look": {"v": 1, "themeChosen": True}}), 1),
            ("u-alice", 1, json.dumps({"revision": 1, "views": []}), 1),
        ],
    )
    conn.executemany(
        "INSERT INTO canvas_operations(account, revision, event) VALUES (?, ?, ?)",
        [
            ("u-owner", 1, json.dumps({"type": "canvas.layout.operation", "revision": 1, "noop": False})),
            ("u-owner", 2, json.dumps({"type": "canvas.layout.operation", "revision": 2, "noop": False})),
            ("u-alice", 1, json.dumps({"type": "canvas.layout.operation", "revision": 1, "noop": False})),
        ],
    )
    conn.executemany(
        "INSERT INTO canvas_receipts(account, op_id, request, revision) VALUES (?, ?, ?, ?)",
        [
            ("u-owner", "op-1", "digest-1", 1),
            ("u-owner", "op-2", "digest-2", 2),
            ("u-alice", "op-3", "digest-3", 1),
        ],
    )
    conn.execute(
        "INSERT INTO canvas_snapshots(account, revision, document) VALUES (?, ?, ?)",
        ("u-owner", 1, json.dumps({"revision": 1, "views": []})),
    )
    conn.execute(
        "INSERT INTO canvas_closed(account, window_id) VALUES (?, ?)",
        ("u-owner", "win-closed-1"),
    )

    # 12. Mesh peers, key rotation phases, routes, tags, roles, grants, SSH, audit.
    conn.execute(
        "UPDATE mesh_state SET revision = 5, node_id_high_water = 6, authority_epoch = ? WHERE singleton = 1",
        ("epoch-fixture-01",),
    )
    conn.execute(
        "UPDATE mesh_dataplane SET allocation_json = ?, default_policy = ?, rotation_period_secs = ? WHERE singleton = 1",
        (json.dumps({"prefix": "100.64.0.0/10", "next": 7}), "deny", WEEK),
    )
    # Insert 6 mesh nodes; trigger `mesh_node_rotation_seed` auto-seeds mesh_node_key_rotation.
    # Node 6 belongs to h_revoked and will be retired by `remote_hosts_retire_mesh` below.
    conn.executemany(
        "INSERT INTO mesh_nodes(id, name, public_key, last_seen, last_rtt_us, dataplane_host, endpoint, "
        "name_source, name_claim, key_rotation_supported, authority_epoch_supported, reflexive_endpoint, "
        "lan_endpoints, candidates_supported, reflexive_history, ipv6_supported, ipv4_only, routes_supported) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                1, "alpha-box", blob32(0x81), T0 + 300, 12_500, uuid_str(1), "192.0.2.10:10254",
                "hand", "alpha-box", 1, 1, "192.0.2.10:10254", json.dumps(["192.0.2.10:10254"]),
                1, json.dumps(["192.0.2.10:10254"]), 1, 0, 1,
            ),
            (
                2, "beta-dev", blob32(0x82), T0 + 290, 24_000, uuid_str(2), "192.0.2.11:10254",
                "reported", "beta-dev", 1, 1, "192.0.2.11:10254", json.dumps(["192.0.2.11:10254"]),
                1, None, 0, 1, 1,
            ),
            (
                3, "gamma-node", blob32(0x83), T0 + 280, 41_000, uuid_str(3), "198.51.100.12:10254",
                "record", None, 1, 1, None, None, 1, None, 1, 0, 1,
            ),
            (
                4, "delta-work", blob32(0x84), T0 + 270, 18_000, uuid_str(4), "198.51.100.13:10254",
                "server", None, 1, 0, None, None, 0, None, 0, 0, 0,
            ),
            (
                5, "linux-000000", blob32(0x85), T0 + 260, 33_000, uuid_str(5), "203.0.113.14:10254",
                "placeholder", None, 0, None, None, None, 0, None, 0, 0, 0,
            ),
            (
                6, "zeta-retired", blob32(0x86), T0 + 250, 19_000, uuid_str(6), "203.0.113.15:10254",
                "hand", None, 1, 1, None, None, 0, None, 0, 0, 0,
            ),
        ],
    )
    # Exercise all five mesh_node_key_rotation phases on the auto-seeded rows.
    conn.execute(
        "UPDATE mesh_node_key_rotation SET last_rotation = ?, schedule_boot_id = 'boot-1', "
        "schedule_monotonic = 100, sequence = 1 WHERE node_id = 1",
        (T0,),
    )
    conn.execute(
        "UPDATE mesh_node_key_rotation SET last_rotation = ?, schedule_boot_id = 'boot-2', "
        "schedule_monotonic = 200, rotation_phase = 'preparing', operation_id = 'rot-op-2', "
        "sequence = 2 WHERE node_id = 2",
        (T0,),
    )
    conn.execute(
        "UPDATE mesh_node_key_rotation SET last_rotation = ?, schedule_boot_id = 'boot-3', "
        "schedule_monotonic = 300, candidate_public_key = ?, previous_public_key = ?, "
        "rotation_phase = 'overlap', rotation_started_at = ?, rotation_boot_id = 'boot-3', "
        "rotation_monotonic = 310, operation_id = 'rot-op-3', sequence = 3, rotation_revision = 4, "
        "local_committed = 0 WHERE node_id = 3",
        (T0, blob32(0x93), blob32(0x83), T0 + 280),
    )
    conn.execute(
        "UPDATE mesh_node_key_rotation SET last_rotation = ?, schedule_boot_id = 'boot-4', "
        "schedule_monotonic = 400, candidate_public_key = NULL, previous_public_key = ?, "
        "rotation_phase = 'retiring', rotation_started_at = ?, rotation_boot_id = 'boot-4', "
        "rotation_monotonic = 410, operation_id = 'rot-op-4', sequence = 4, rotation_revision = 5, "
        "local_committed = 1 WHERE node_id = 4",
        (T0, blob32(0x84), T0 + 270),
    )
    conn.execute(
        "UPDATE mesh_node_key_rotation SET last_rotation = ?, schedule_boot_id = 'boot-5', "
        "schedule_monotonic = 500, candidate_public_key = NULL, previous_public_key = NULL, "
        "rotation_phase = 'cleanup', rotation_started_at = ?, rotation_boot_id = 'boot-5', "
        "rotation_monotonic = 510, operation_id = 'rot-op-5', sequence = 5, rotation_revision = 5, "
        "local_committed = 1 WHERE node_id = 5",
        (T0, T0 + 260),
    )
    conn.execute(
        "UPDATE mesh_node_key_rotation SET last_rotation = ? WHERE node_id = 6",
        (T0,),
    )

    conn.executemany(
        "INSERT INTO mesh_node_applied(node_id, revision, server_instance) VALUES (?, ?, ?)",
        [
            (1, 5, "srv-fixture-1"),
            (2, 5, "srv-fixture-1"),
            (3, 4, "srv-fixture-1"),
        ],
    )
    conn.executemany(
        "INSERT INTO mesh_tags(name, created_at) VALUES (?, ?)",
        [("servers", T0), ("workstations", T0 + 5)],
    )
    conn.executemany(
        "INSERT INTO mesh_tag_members(tag_name, node_id) VALUES (?, ?)",
        [("servers", 1), ("servers", 3), ("workstations", 2)],
    )
    conn.executemany(
        "INSERT INTO mesh_roles(name, created_at) VALUES (?, ?)",
        [("mesh-admin", T0), ("mesh-viewer", T0 + 5)],
    )
    conn.executemany(
        "INSERT INTO mesh_role_actions(role_name, action, scope_tag) VALUES (?, ?, ?)",
        [
            ("mesh-admin", "mesh.node.manage", None),
            ("mesh-viewer", "mesh.node.read", "servers"),
        ],
    )
    conn.executemany(
        "INSERT INTO mesh_user_roles(user_id, role_name) VALUES (?, ?)",
        [("u-owner", "mesh-admin"), ("u-alice", "mesh-viewer")],
    )
    conn.executemany(
        "INSERT INTO mesh_routes(id, node_id, network, advertised, approved_at, approved_by, masquerade) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 1, "192.0.2.0/24", 1, T0 + 100, "u-owner", 1),
            (2, 2, "198.51.100.0/24", 1, None, None, 0),
            (3, 3, "2001:db8:1::/48", 1, T0 + 110, "u-owner", 1),
        ],
    )
    conn.executemany(
        "INSERT INTO mesh_grants(id, name, from_kind, from_value, to_kind, to_value, both_ways, ports_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, "alpha-to-beta", "node", "1", "node", "2", 1, json.dumps(["22", "443"])),
            (2, "workstations-to-servers", "tag", "workstations", "tag", "servers", 0, json.dumps(["22"])),
            (3, "workstations-to-lan", "tag", "workstations", "network", "192.0.2.0/24", 0, json.dumps(["*"])),
            # This node grant references node 6 and is removed by trigger `remote_hosts_retire_mesh` below.
            (4, "retire-me-grant", "node", "6", "node", "1", 0, json.dumps(["22"])),
        ],
    )
    conn.executemany(
        "INSERT INTO mesh_audit(id, user_id, action, resource, revision, occurred_at, detail_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (1, "u-owner", "mesh.route.approve", "1", 4, T0 + 100, json.dumps({"network": "192.0.2.0/24"})),
            (2, "u-owner", "mesh.grant.add", "alpha-to-beta", 5, T0 + 120, json.dumps({"both_ways": True})),
        ],
    )
    conn.executemany(
        "INSERT INTO mesh_ssh_hosts(host, enabled) VALUES (?, ?)",
        [("alpha-box", 1), ("beta-dev", 0)],
    )
    conn.execute(
        "INSERT INTO mesh_ssh_certificates(digest, person, host, source_node, source_address, valid_before) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (blob32(0xA1), "u-owner", "alpha-box", 2, "192.0.2.11", T0 + 3_600),
    )
    conn.executemany(
        "INSERT INTO mesh_ssh_issued(digest, kind, principals, valid_before, issued_at) VALUES (?, ?, ?, ?, ?)",
        [
            (blob32(0xA1), "person", json.dumps(["fixture-owner"]), T0 + 3_600, T0),
            (blob32(0xA2), "host", json.dumps(["alpha-box.mesh.example.test"]), T0 + WEEK, T0),
        ],
    )

    # 13. Exercise retirement triggers (`remote_hosts_retire_mesh` and
    #     `remote_login_cleanup_on_retirement`) by revoking h_revoked now.
    #     This populates `mesh_dataplane_removed` and `remote_login_cleanup`,
    #     deletes node 6 and grant 4, and advances `mesh_state.revision`.
    conn.execute(
        "UPDATE remote_hosts SET revoked_at = ? WHERE id = ?",
        (T0 + 500, h_revoked),
    )
    conn.commit()


def verify_database(conn: sqlite3.Connection) -> list[str]:
    """Check integrity_check, foreign_key_check, and that every table has >= 1 row."""
    errors: list[str] = []
    integrity = [row[0] for row in conn.execute("PRAGMA integrity_check").fetchall()]
    if integrity != ["ok"]:
        errors.append(f"PRAGMA integrity_check failed: {integrity}")
    fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk_violations:
        errors.append(f"PRAGMA foreign_key_check failed: {fk_violations}")
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    ]
    empty = []
    for table in tables:
        count = conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
        if count == 0:
            empty.append(table)
    if empty:
        errors.append(f"empty tables in fixture: {', '.join(empty)}")
    return errors


def build_fixture(output: Path, through: int | None = None) -> tuple[int, int]:
    """Deterministically build the SQLite fixture at `output` and return (migrations, tables)."""
    migrations = discover_migrations(through=through)
    if not migrations:
        raise RuntimeError(f"no migrations found in {MIGRATIONS_DIR}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="infraternal-fixture-") as tmp:
        staged = Path(tmp) / "prod-schema.sqlite"
        conn = sqlite3.connect(staged)
        try:
            conn.execute("PRAGMA page_size = 4096")
            conn.execute("PRAGMA journal_mode = DELETE")
            conn.execute("PRAGMA foreign_keys = ON")
            apply_migrations(conn, migrations)
            seed_synthetic_data(conn)
            errors = verify_database(conn)
            if errors:
                raise RuntimeError("; ".join(errors))
            conn.execute("VACUUM")
            table_count = conn.execute(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' AND name != '_sqlx_migrations'"
            ).fetchone()[0]
        finally:
            conn.close()
        shutil.copyfile(staged, output)
    return len(migrations), table_count


def check_fixture(fixture: Path) -> int:
    """Verify the checked-in fixture is valid, deterministic, and migrates cleanly."""
    if not fixture.is_file():
        print(f"migration fixture: FAIL ({fixture} does not exist)", file=sys.stderr)
        return 1

    conn = sqlite3.connect(f"file:{fixture}?mode=ro", uri=True)
    try:
        errors = verify_database(conn)
        if errors:
            for error in errors:
                print(f"migration fixture: {error}", file=sys.stderr)
            return 1
        max_version = conn.execute("SELECT max(version) FROM _sqlx_migrations").fetchone()[0]
        applied_count = conn.execute("SELECT count(*) FROM _sqlx_migrations").fetchone()[0]
    finally:
        conn.close()

    with tempfile.TemporaryDirectory(prefix="infraternal-fixture-check-") as tmp:
        rebuilt = Path(tmp) / "rebuilt.sqlite"
        build_fixture(rebuilt, through=max_version)
        if rebuilt.read_bytes() != fixture.read_bytes():
            print(
                f"migration fixture: FAIL ({fixture} differs from deterministic build "
                f"through {max_version}; run scripts/build-migration-fixture.py)",
                file=sys.stderr,
            )
            return 1

        upgraded = Path(tmp) / "upgraded.sqlite"
        shutil.copyfile(fixture, upgraded)
        up_conn = sqlite3.connect(upgraded)
        try:
            up_conn.execute("PRAGMA foreign_keys = ON")
            pending = apply_migrations(up_conn, discover_migrations())
            errors = verify_database(up_conn)
            if errors:
                for error in errors:
                    print(f"migration fixture upgrade: {error}", file=sys.stderr)
                return 1
        finally:
            up_conn.close()

    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()[:16]
    print(
        f"migration fixture: PASS (version={max_version}, recorded={applied_count}, "
        f"pending_applied={len(pending)}, size={fixture.stat().st_size}B, sha256={digest})"
    )
    return 0


def main() -> int:
    """CLI entrypoint for building or checking the prod-schema migration fixture."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_FIXTURE,
        help=f"Output SQLite path (default: {DEFAULT_FIXTURE.relative_to(ROOT)})",
    )
    parser.add_argument(
        "--through",
        type=int,
        default=None,
        help="Apply migrations only up to and including this numeric version.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the checked-in fixture is valid, reproducible and upgrades cleanly.",
    )
    args = parser.parse_args()

    if args.check:
        return check_fixture(args.output)

    mig_count, table_count = build_fixture(args.output, through=args.through)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()[:16]
    print(
        f"built {args.output.relative_to(ROOT) if args.output.is_relative_to(ROOT) else args.output}: "
        f"{mig_count} migrations, {table_count} tables, {args.output.stat().st_size} bytes, sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
