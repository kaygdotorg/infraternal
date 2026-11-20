//! Process and machine accounting from /proc.
//!
//! A `Selection` names the processes that belong to one system under test:
//! explicit PIDs with all their descendants, plus processes whose command
//! line contains a marker (daemons that re-parent to init, such as a tmux
//! server). Shells and the kit's own helpers can be excluded by name, so the
//! numbers show the multiplexer or mesh daemon itself; `--only-comm` selects
//! just those (the shells) for the complementary number.
//!
//! Memory is reported as RSS and PSS. PSS divides shared pages between the
//! processes that map them, so a 50-process total is not inflated by a
//! static binary's text being counted 50 times.
use crate::args::Args;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;

/// Return the kernel's process CPU-tick frequency.
pub fn hz() -> f64 {
    // SAFETY: sysconf has no preconditions.
    (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }) as f64
}

/// Whole-machine (busy, total) jiffies from /proc/stat.
pub fn cpu_jiffies() -> (u64, u64) {
    let stat = fs::read_to_string("/proc/stat").unwrap_or_default();
    let fields: Vec<u64> = stat
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    let total: u64 = fields.iter().take(8).sum();
    let idle = fields.get(3).copied().unwrap_or(0) + fields.get(4).copied().unwrap_or(0);
    (total - idle, total)
}

/// Aggregate resident and proportional memory values in KiB.
#[derive(Default, Clone, Copy)]
pub struct MemTotals {
    pub rss_kb: u64,
    pub pss_kb: u64,
}

impl MemTotals {
    /// Keep the larger RSS and PSS values independently for peak sampling.
    pub fn max(self, other: Self) -> Self {
        Self { rss_kb: self.rss_kb.max(other.rss_kb), pss_kb: self.pss_kb.max(other.pss_kb) }
    }
}

/// Process fields needed to find selected process trees and their descendants.
struct Proc {
    pid: u32,
    ppid: u32,
    comm: String,
    cmdline: String,
}

/// Read process identifiers, parents, names, and command lines from `/proc`.
fn all_procs() -> Vec<Proc> {
    let mut out = Vec::new();
    let Ok(dir) = fs::read_dir("/proc") else { return out };
    for entry in dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else { continue };
        let comm = stat[open + 1..close].to_owned();
        let ppid = stat[close + 2..].split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
            .unwrap_or_default();
        out.push(Proc { pid, ppid, comm, cmdline });
    }
    out
}

/// Read one KiB-valued memory field from a process status file.
fn status_kb(pid: u32, file: &str, key: &str) -> u64 {
    fs::read_to_string(format!("/proc/{pid}/{file}"))
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Return user and system CPU ticks from `/proc/<pid>/stat`.
fn ticks(pid: u32) -> u64 {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let Some(close) = stat.rfind(')') else { return 0 };
    let f: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    // utime and stime are fields 14 and 15; counting from the state (field 3) they are at 11 and 12.
    let field = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    field(11) + field(12)
}

/// Context switches of every thread: each one is a wakeup or a preemption.
fn switches(pid: u32) -> u64 {
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else { return 0 };
    tasks
        .flatten()
        .map(|t| {
            let s = fs::read_to_string(t.path().join("status")).unwrap_or_default();
            s.lines()
                .filter(|l| l.starts_with("voluntary_ctxt_switches") || l.starts_with("nonvoluntary_ctxt_switches"))
                .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                .sum::<u64>()
        })
        .sum()
}

/// Select process trees by root PID or command-line marker for accounting.
pub struct Selection {
    roots: Vec<u32>,
    markers: Vec<String>,
    exclude: HashSet<String>,
    only: HashSet<String>,
}

impl Selection {
    /// Build a selection from comma-separated PID and command filters.
    pub fn from_args(args: &Args) -> Self {
        let list = |k: &str| -> Vec<String> {
            args.opt(k).map(|v| v.split(',').filter(|s| !s.is_empty()).map(str::to_owned).collect()).unwrap_or_default()
        };
        Self {
            roots: list("pids").iter().filter_map(|p| p.parse().ok()).collect(),
            markers: list("cmdline-contains"),
            exclude: list("exclude-comm").into_iter().collect(),
            only: list("only-comm").into_iter().collect(),
        }
    }

    /// Report whether no PID roots or command-line markers were supplied.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty() && self.markers.is_empty()
    }

    /// Resolve selected roots, include their descendants, and apply name filters.
    fn pids(&self) -> Vec<(u32, String)> {
        if self.is_empty() {
            return Vec::new();
        }
        let procs = all_procs();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for p in &procs {
            children.entry(p.ppid).or_default().push(p.pid);
        }
        let mut chosen: HashSet<u32> = HashSet::new();
        let mut stack: Vec<u32> = self.roots.clone();
        for p in &procs {
            if self.markers.iter().any(|m| p.cmdline.contains(m.as_str())) {
                stack.push(p.pid);
            }
        }
        while let Some(pid) = stack.pop() {
            if chosen.insert(pid) {
                stack.extend(children.get(&pid).into_iter().flatten());
            }
        }
        let me = std::process::id();
        procs
            .into_iter()
            .filter(|p| chosen.contains(&p.pid) && p.pid != me && !self.exclude.contains(&p.comm))
            .filter(|p| self.only.is_empty() || self.only.contains(p.comm.trim_start_matches('-')))
            .map(|p| (p.pid, p.comm))
            .collect()
    }

    /// Sum VmRSS and PSS over the selected process tree.
    pub fn mem(&self) -> MemTotals {
        self.pids().iter().fold(MemTotals::default(), |acc, (pid, _)| MemTotals {
            rss_kb: acc.rss_kb + status_kb(*pid, "status", "VmRSS:"),
            pss_kb: acc.pss_kb + status_kb(*pid, "smaps_rollup", "Pss:"),
        })
    }

    /// Sum process CPU ticks over the selected process tree.
    pub fn cpu_ticks(&self) -> u64 {
        self.pids().iter().map(|(pid, _)| ticks(*pid)).sum()
    }

    /// Return per-process and aggregate RSS/PSS data as JSON.
    pub fn report(&self) -> Value {
        let procs: Vec<Value> = self
            .pids()
            .iter()
            .map(|(pid, comm)| {
                json!({"pid": pid, "comm": comm,
                       "rss_kb": status_kb(*pid, "status", "VmRSS:"),
                       "pss_kb": status_kb(*pid, "smaps_rollup", "Pss:")})
            })
            .collect();
        let rss: u64 = procs.iter().map(|p| p["rss_kb"].as_u64().unwrap_or(0)).sum();
        let pss: u64 = procs.iter().map(|p| p["pss_kb"].as_u64().unwrap_or(0)).sum();
        json!({"count": procs.len(), "rss_kb": rss, "pss_kb": pss, "procs": procs})
    }

    /// Sum voluntary and involuntary thread context switches in the selection.
    fn switches(&self) -> u64 {
        self.pids().iter().map(|(pid, _)| switches(*pid)).sum()
    }
}

/// `proc-mem`: one memory report for a selection.
pub fn mem_cmd(args: &Args) {
    println!("{}", Selection::from_args(args).report());
}

/// `proc-idle`: CPU time and wakeups of a selection over a quiet window.
pub fn idle_cmd(args: &Args) {
    let sel = Selection::from_args(args);
    let seconds: f64 = args.num("seconds", 30.0);
    let t0 = sel.cpu_ticks();
    let s0 = sel.switches();
    let m0 = cpu_jiffies();
    std::thread::sleep(std::time::Duration::from_secs_f64(seconds));
    let t1 = sel.cpu_ticks();
    let s1 = sel.switches();
    let m1 = cpu_jiffies();
    let cpu_s = t1.saturating_sub(t0) as f64 / hz();
    println!(
        "{}",
        json!({
            "seconds": seconds,
            "cpu_s": cpu_s,
            "cpu_s_per_minute": cpu_s / seconds * 60.0,
            "cpu_percent_of_one_core": cpu_s / seconds * 100.0,
            "context_switches_per_s": s1.saturating_sub(s0) as f64 / seconds,
            "machine_busy_s": m1.0.saturating_sub(m0.0) as f64 / hz(),
            "mem": sel.report(),
        })
    );
}
