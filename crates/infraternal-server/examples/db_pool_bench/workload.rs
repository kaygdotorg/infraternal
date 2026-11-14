//! The workload shared by both drivers in `db_pool_bench` (ported from J438's harness, #473).
//!
//! Seed rows, SQL text, operation mix, key draws and statistics are the same
//! for every variant, so only the driver and pool shape differ. The SQL is the
//! server's own, copied from origin/dev 6df0f5bd5; each constant names its source.
#![allow(
    dead_code,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::time::{Duration, Instant};

/// Fixed "now" so every run sees the same live/expired split.
pub const NOW: i64 = 1_800_000_000;
/// Session sliding window, same constant as `auth::SESSION` (30 days).
pub const SESSION: i64 = 30 * 24 * 3600;
/// Live session tokens seeded (80 per user for 50 users).
pub const LIVE_SESSIONS: u64 = 4000;
/// Users (design point D170/D246: 50 users).
pub const USERS: u64 = 50;
/// Owners that hold the 1,000 hosts (100 each).
pub const HOST_OWNERS: u64 = 10;
/// Ops already journalled per account at seed time (revision 64).
pub const SEED_REVISION: i64 = 64;
/// Same as `infraternal_plugin_canvas::model::CHECKPOINT`.
pub const CHECKPOINT: i64 = 128;

/// `auth/sessions.rs:72`: every authenticated request slides its session.
pub const SQL_SESSION: &str = "UPDATE sessions SET expires=CASE WHEN unlocked=1 THEN ? ELSE expires END WHERE token_hash=? AND expires>? AND (unlocked=1 OR ?) RETURNING user_id,device,fresh,(SELECT username FROM users WHERE id=sessions.user_id) AS username,(SELECT display_name FROM users WHERE id=sessions.user_id) AS display_name,(SELECT aaguid FROM passkeys WHERE id=sessions.passkey_id AND user_id=sessions.user_id) AS aaguid,(SELECT ready FROM recovery WHERE user_id=sessions.user_id) AS recovery_ready,(SELECT recovery_version=1 OR recovery_wrap_version=1 FROM users WHERE id=sessions.user_id) AS recovery_words_need_replacing,(SELECT owner FROM users WHERE id=sessions.user_id) AS owner";

/// `remote_inventory.rs:170`: the host list page (up to 129 rows).
pub const SQL_HOSTS: &str = "SELECT h.id,COALESCE(b.address,''),b.os,h.hostname,h.mode,CASE WHEN EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0) THEN CASE WHEN EXISTS(SELECT 1 FROM remote_certificates c WHERE c.host_id=h.id AND c.revoked_at IS NULL AND c.not_after>unixepoch()) THEN 'pending' ELSE 'retired-unreachable' END END FROM remote_hosts h LEFT JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.owner_id=? AND h.revoked_at IS NULL AND EXISTS(SELECT 1 FROM remote_certificates c WHERE c.host_id=h.id) AND (? IS NULL OR h.id>?) ORDER BY h.id LIMIT 129";

/// `canvas_store.rs:66`: layout journal resume (head + ops after a cursor).
pub const SQL_EVENTS: &str = "SELECT 0 AS kind,revision,document,initialized,NULL AS event FROM canvas_heads WHERE account=? UNION ALL SELECT 1,revision,NULL,NULL,event FROM canvas_operations WHERE account=? AND revision>? ORDER BY kind,revision";

// `canvas_store.rs` apply transaction, in execution order.
/// Create the account's layout head on first use.
pub const SQL_HEAD_INSERT: &str =
    "INSERT OR IGNORE INTO canvas_heads(account,revision,document,initialized) VALUES(?,0,?,0)";
/// Product reads `document` and parses the revision from JSON; the bench reads
/// the column instead so no JSON parser sits in the measured path.
pub const SQL_HEAD_SELECT: &str = "SELECT document,revision FROM canvas_heads WHERE account=?";
/// Look up an earlier receipt for this op id (idempotent retry), or the receipt count.
pub const SQL_RECEIPT: &str = "SELECT request,revision FROM canvas_receipts WHERE account=? AND op_id=? UNION ALL SELECT NULL,receipt_count FROM canvas_heads WHERE account=? LIMIT 1";
/// Which of the intent's windows were closed before (tombstones).
pub const SQL_CLOSED: &str =
    "SELECT window_id FROM canvas_closed WHERE account=? AND window_id IN (?,?)";
/// Whether the terminal the intent names belongs to this account.
pub const SQL_OWNED: &str =
    "SELECT EXISTS(SELECT 1 FROM terminal_sessions WHERE id=? AND user_id=?)";
/// Store the new head document and revision.
pub const SQL_HEAD_UPDATE: &str =
    "UPDATE canvas_heads SET revision=?,document=?,initialized=1 WHERE account=?";
/// Every `CHECKPOINT` revisions: snapshot the document...
pub const SQL_SNAPSHOT: &str = "INSERT INTO canvas_snapshots(account,revision,document) VALUES(?,?,?) ON CONFLICT(account) DO UPDATE SET revision=excluded.revision,document=excluded.document";
/// ...and drop the journalled ops it covers.
pub const SQL_OPS_DELETE: &str = "DELETE FROM canvas_operations WHERE account=?";
/// Otherwise journal the op.
pub const SQL_OP_INSERT: &str =
    "INSERT INTO canvas_operations(account,revision,event) VALUES(?,?,?)";
/// Record the op's receipt for idempotent retries.
pub const SQL_RECEIPT_INSERT: &str =
    "INSERT INTO canvas_receipts(account,op_id,request,revision) VALUES(?,?,?,?)";

/// Realistic rows at the D170 design point: 50 users, 4,000 live + 4,000
/// expired sessions, 1,000 hosts with certificates and bootstrap rows, 200
/// terminal sessions, a ~6 KB layout document per user with 64 journalled ops,
/// 2,000 receipts and 50 tombstones each. Shared with the D379 compatibility tests.
pub const SEED: &str = include_str!("seed.sql");

/// A small, dependency-free PRNG so every driver draws the same key sequence.
pub struct Rng(u64);
impl Rng {
    /// Seed per task so concurrent tasks hit different rows.
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    /// xorshift64*.
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// A draw in `0..n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The measured operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// The session slide (a write).
    Session,
    /// The host list page (a read).
    Hosts,
    /// The layout resume (a read).
    Events,
    /// The 8-statement layout write.
    Apply,
}

/// Workload names accepted on the command line.
pub fn parse_workload(name: &str) -> Option<&'static str> {
    ["session", "hosts", "events", "apply", "mixed"]
        .into_iter()
        .find(|w| *w == name)
}

/// Pick the next op for a workload. "mixed" approximates a busy session:
/// 80% auth lookups, 8% host list, 8% layout resume, 4% layout writes.
pub fn pick(workload: &str, rng: &mut Rng) -> Op {
    match workload {
        "session" => Op::Session,
        "hosts" => Op::Hosts,
        "events" => Op::Events,
        "apply" => Op::Apply,
        _ => match rng.below(100) {
            0..=79 => Op::Session,
            80..=87 => Op::Hosts,
            88..=95 => Op::Events,
            _ => Op::Apply,
        },
    }
}

/// Ops per task: (single-task count, per-task count at concurrency > 1).
pub fn ops_for(workload: &str, concurrency: usize) -> usize {
    let (single, per_task) = match workload {
        "hosts" => (4_000, 80),
        "events" => (10_000, 200),
        "apply" => (3_000, 60),
        // "session" and "mixed".
        _ => (20_000, 400),
    };
    if concurrency == 1 { single } else { per_task }
}

/// Inputs for one op, drawn identically by every driver.
pub struct Draw {
    /// A live session token for the session slide.
    pub token: String,
    /// A host owner for the host list.
    pub owner: String,
    /// A layout account for resume and write.
    pub account: String,
    /// A fresh op id for the layout write.
    pub op_id: String,
    /// A terminal id for the ownership check.
    pub terminal: [u8; 16],
}

/// Draw keys for one op.
pub fn draw(rng: &mut Rng, task: usize, seq: usize) -> Draw {
    let token = format!("tok-{}", rng.below(LIVE_SESSIONS));
    let owner = format!("u{:02}", rng.below(HOST_OWNERS));
    let account = format!("u{:02}", rng.below(USERS));
    let op_id = format!("bench-{task}-{seq}-{}", rng.next());
    let mut terminal = [0u8; 16];
    let id: u128 = 100_000 + u128::from(rng.below(200));
    terminal.copy_from_slice(&id.to_be_bytes());
    Draw {
        token,
        owner,
        account,
        op_id,
        terminal,
    }
}

/// One fixed-size layout event JSON, like a real "move window" intent.
pub fn event_json(revision: i64, op_id: &str) -> String {
    format!(
        "{{\"type\":\"canvas.layout.operation\",\"revision\":{revision},\"op_id\":\"{op_id}\",\"intent\":{{\"type\":\"move\",\"window_id\":\"w-3\",\"x\":121,\"y\":80}},\"noop\":false}}"
    )
}

/// The new head document (same 6 KB size as the seed).
pub fn document_json(revision: i64) -> String {
    format!(
        "{{\"revision\":{revision},\"views\":\"{}\"}}",
        "0".repeat(6000)
    )
}

/// Syscall counters taken by [`io_mark`] right before the measured loop.
static IO_MARK: std::sync::Mutex<(u64, u64)> = std::sync::Mutex::new((0, 0));

/// Read/write syscall counters of this process (from /proc/self/io).
pub fn io_counts() -> (u64, u64) {
    let io = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
    let field = |name: &str| {
        io.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    (field("syscr:"), field("syscw:"))
}

/// Remember the syscall counters right before the measured loop.
pub fn io_mark() {
    *IO_MARK.lock().unwrap() = io_counts();
}

/// Print one run's JSON line: latency percentiles and maximum, throughput, syscalls per op
/// and `wal_bytes`, the WAL file's size at the end of the run with the pool
/// still open.
pub fn report(
    variant: &str,
    workload: &str,
    concurrency: usize,
    mut samples: Vec<u64>,
    elapsed: Duration,
    wal_bytes: u64,
) {
    samples.sort_unstable();
    let q = |p: f64| samples[((samples.len() as f64 - 1.0) * p).round() as usize] as f64 / 1000.0;
    let n = samples.len();
    let mean = samples.iter().sum::<u64>() as f64 / n as f64 / 1000.0;
    let (r0, w0) = *IO_MARK.lock().unwrap();
    let (r1, w1) = io_counts();
    println!(
        "{{\"read_syscalls_per_op\":{:.2},\"write_syscalls_per_op\":{:.2},\"variant\":\"{variant}\",\"workload\":\"{workload}\",\"conc\":{concurrency},\"n\":{n},\"p50_us\":{:.1},\"p99_us\":{:.1},\"p999_us\":{:.1},\"max_us\":{:.1},\"mean_us\":{mean:.1},\"ops_per_s\":{:.0},\"elapsed_s\":{:.3},\"wal_bytes\":{wal_bytes}}}",
        (r1 - r0) as f64 / n as f64,
        (w1 - w0) as f64 / n as f64,
        q(0.5),
        q(0.99),
        q(0.999),
        q(1.0),
        n as f64 / elapsed.as_secs_f64(),
        elapsed.as_secs_f64()
    );
}

/// Resident and peak memory of this process, in KiB, from /proc.
pub fn rss_kib() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    (field("VmRSS:"), field("VmHWM:"))
}

/// Threads in this process, from /proc.
pub fn threads() -> u64 {
    std::fs::read_dir("/proc/self/task").map_or(0, |d| d.count() as u64)
}

/// Time since `start`, in microseconds, as a JSON fragment helper.
pub fn us(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e6
}
