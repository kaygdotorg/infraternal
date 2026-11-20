//! `h2h`: the one measurement binary of the head-to-head kit (#260).
//!
//! Every system under test is measured by these same subcommands, so the
//! harness is never the difference between two results. Output is one JSON
//! object per invocation on stdout; the kit's scripts collect them.
//!
//! Network: `net-server`, `net-tput`, `net-lat`, `net-pps`, `net-wait`, `now`.
//! Terminal: `term-echo`, `term-flood`, `term-type`, `term-attach`, `term-hold`,
//! `echo-inner`
//! with `--backend pty --client '<command>'` (tmux, Zellij, SSH) or
//! `--backend ix --server … --origin … --cookie-file … --session …`.
//! infraternal setup: `ix-register`, `ix-open`. Accounting: `proc-mem`, `proc-idle`.
/// Parse the shared command-line option format.
mod args;
/// Read timestamps from the host's shared monotonic clock.
mod clock;
/// Drive the authenticated native-viewer measurement path.
mod ix;
/// Run the same network probes against each tunnel implementation.
mod net;
/// Sample process memory, CPU time, and scheduling activity.
mod procstat;
/// Provide a PTY-backed viewer for terminal measurements.
mod pty;
/// Summarise probe samples with shared percentile rules.
mod stats;
/// Run terminal procedures through a common viewer interface.
mod term;
/// Strip terminal control sequences before matching output markers.
mod vt;

use args::{Args, die};
use term::Screen;

/// Build the selected PTY or native-viewer screen used by terminal probes.
fn screen(args: &Args) -> Screen {
    match args.str("backend").as_str() {
        "pty" => {
            let cols: u16 = args.num("cols", 120);
            let rows: u16 = args.num("rows", 40);
            Screen::new(Box::new(pty::Pty::spawn(&args.str("client"), cols, rows, &[])))
        }
        "ix" => ix::screen(args),
        other => die(&format!("unknown backend {other}")),
    }
}

/// Dispatch one measurement command and write its result to stdout.
fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = raw.split_first() else { die("usage: h2h <command> [--key value]…") };
    let args = Args::parse(rest);
    match command.as_str() {
        "now" => println!("{}", clock::now_ns()),
        "net-server" => net::server(&args),
        "net-tput" => net::tput(&args),
        "net-lat" => net::lat(&args),
        "net-pps" => net::pps(&args),
        "net-wait" => net::wait(&args),
        "proc-mem" => procstat::mem_cmd(&args),
        "proc-idle" => procstat::idle_cmd(&args),
        "ix-register" => ix::register(&args),
        "ix-open" => ix::open(&args),
        "echo-inner" => term::echo_inner(),
        "term-echo" => term::echo(&args, screen(&args)),
        "term-flood" => term::flood(&args, screen(&args)),
        "term-hold" => term::hold(&args, screen(&args)),
        "term-type" => term::type_cmd(&args, screen(&args)),
        "term-attach" => term::attach(&args, &|| screen(&args)),
        other => die(&format!("unknown command {other}")),
    }
}
