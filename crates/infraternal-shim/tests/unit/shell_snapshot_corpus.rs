//! Live shells get exact Snapshots, proven against real recorded sessions
//! (#521, #583).
//!
//! The recordings in `tests/fixtures/shell-*.events` are real bash, zsh and
//! fish sessions (`capture_shells.py`): wrapped commands, a multiline prompt,
//! a right prompt, scrolling output, a continuation prompt, a clear, and
//! resizes in the middle of an edit. The `-long` recordings edit commands
//! longer than their small screen, so the edited line crosses the
//! history/screen boundary. Each is replayed through the shim's
//! `Terminal` exactly as the PTY delivered it. After every record (one read
//! from the PTY, or one resize) the test asks for the Snapshot the shim would
//! send a reattaching viewer, then:
//!
//! 1. builds a viewer from the Snapshot alone and compares it with the shim's
//!    engine under the strict oracle: every cell and its style, soft-wrap and
//!    continuation flags, cursor (position, pending wrap, style, saved
//!    cursor), modes, scroll region, tab stops, charsets, colours, the prompt
//!    redraw flag and up to 256 rows of history;
//! 2. feeds that viewer the rest of the session, resizes included, and
//!    compares it with a viewer that replayed the whole session raw, so a
//!    Snapshot that looks right but carries the wrong hidden state (a wrap
//!    flag, a saved cursor) is caught when the shell later relies on it.
//!
//! A screen whose top row is joined to the last history row (a line wrapped
//! from history, or a history row that wraps into the top row without marking
//! it as its continuation) used to be refused: 103 of bash's 347 cut points
//! and 3 of zsh's 328. The painter now rebuilds that soft wrap (J1238, #521),
//! and those recordings export exactly at every point.
//!
//! One state is still refused on purpose, and every refusal keeps the exact
//! raw replay for a reattach (or the flagged repaint for a gap): a shell that
//! marks its prompt with OSC 133 (fish does by default) leaves semantic prompt
//! state the serializer cannot import. The test counts refusals instead of
//! hiding them, and fails if a recording is refused more often.
use super::*;

/// One record of a recorded session, in the order the shim saw it.
enum Event {
    /// Bytes from one PTY read.
    Output(Vec<u8>),
    /// The PTY was resized to `(cols, rows)` here.
    Resize(u16, u16),
}

/// Parses `tests/fixtures/shell-<name>.events` (format in `capture_shells.py`).
fn events(name: &str) -> Vec<Event> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/shell-{name}.events"));
    let data = std::fs::read(&path).unwrap();
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let end = at + data[at..].iter().position(|&b| b == b'\n').unwrap();
        let header = std::str::from_utf8(&data[at..end]).unwrap();
        at = end + 1;
        let mut words = header.split(' ');
        match words.next() {
            Some("O") => {
                let len: usize = words.next().unwrap().parse().unwrap();
                out.push(Event::Output(data[at..at + len].to_vec()));
                at += len;
            }
            Some("R") => {
                let cols = words.next().unwrap().parse().unwrap();
                let rows = words.next().unwrap().parse().unwrap();
                out.push(Event::Resize(cols, rows));
            }
            other => panic!("{name}: bad record {other:?}"),
        }
    }
    out
}

/// Applies one record to a terminal, as the shim's loop does.
fn apply(terminal: &mut Terminal, event: &Event) {
    match event {
        Event::Output(bytes) => terminal.process(bytes),
        Event::Resize(cols, rows) => terminal.resize(*cols, *rows).unwrap(),
    }
}

/// A new terminal at the recording's first size, the way the shim spawns one.
fn spawned(events: &[Event]) -> Terminal {
    let Event::Resize(cols, rows) = events[0] else {
        panic!("a recording starts with its size")
    };
    Terminal::new(cols, rows).unwrap()
}

/// How one recording fared: cut points tried, exact Snapshots that matched,
/// Snapshots the serializer refused, and the record numbers of the refusals
/// as inclusive ranges, so a refusal can be traced back to the recording.
#[derive(Debug, Default, PartialEq)]
struct Tally {
    cuts: usize,
    exact: usize,
    refused: usize,
    refused_at: Vec<(usize, usize)>,
}

/// Replays `name`, snapshotting after every record. Panics on the first
/// Snapshot whose viewer differs from the shim, or whose viewer later
/// differs from the full raw replay.
///
/// The oracle takes the source first and the rebuilt terminal second: a
/// rebuilt terminal may hold less history than its source (the export's
/// tail is bounded), never more.
fn check(name: &str) -> Tally {
    let events = events(name);
    let mut raw = spawned(&events);
    for event in &events[1..] {
        apply(&mut raw, event);
    }
    let mut shim = spawned(&events);
    let mut tally = Tally::default();
    for (cut, event) in events.iter().enumerate().skip(1) {
        apply(&mut shim, event);
        tally.cuts += 1;
        let bytes = match shim.snapshot() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
                tally.refused += 1;
                match tally.refused_at.last_mut() {
                    Some((_, last)) if *last + 1 == cut => *last = cut,
                    _ => tally.refused_at.push((cut, cut)),
                }
                continue;
            }
            Err(error) => panic!("{name} cut {cut}: {error}"),
        };
        let (cols, rows) = shim.dimensions;
        let mut viewer = Terminal::new(cols, rows).unwrap();
        viewer.process(&bytes);
        assert_eq!(
            shim.engine.state_difference(&viewer.engine),
            0,
            "{name} cut {cut}: the viewer rebuilt from the Snapshot differs from the shim"
        );
        for later in &events[cut + 1..] {
            apply(&mut viewer, later);
        }
        assert_eq!(
            raw.engine.state_difference(&viewer.engine),
            0,
            "{name} cut {cut}: after the rest of the session the viewer differs from a raw replay"
        );
        tally.exact += 1;
    }
    assert_eq!(
        shim.engine.state_difference(&raw.engine),
        0,
        "{name}: the shim must end where a raw replay ends"
    );
    println!("shell snapshot corpus {name}: {tally:?}");
    tally
}

/// bash with a one-line prompt: every cut point exports exactly, including
/// those where the screen's top row is joined to history (a few cuts early on,
/// and from record 245, a 300-column line at 70 columns, to the end).
#[test]
fn a_bash_session_snapshots_exactly_at_every_point() {
    let tally = check("bash");
    assert_eq!(tally.refused, 0, "{tally:?}");
}

/// bash with a coloured two-line prompt: every cut point exports exactly.
#[test]
fn a_bash_session_with_a_multiline_prompt_snapshots_exactly_at_every_point() {
    let tally = check("bash-multiline");
    assert_eq!(tally.refused, 0, "{tally:?}");
}

/// zsh with a coloured prompt and a right prompt, which zsh redraws on every
/// resize: every cut point exports exactly, including the few where the top
/// visible row continues a line wrapped from history.
#[test]
fn a_zsh_session_with_a_right_prompt_snapshots_exactly_at_every_point() {
    let tally = check("zsh");
    assert_eq!(tally.refused, 0, "{tally:?}");
}

/// fish marks its prompt with OSC 133 from the first prompt on, which the
/// serializer refuses, so its reattach keeps the raw replay. Whatever it does
/// export must still be exact.
#[test]
fn a_fish_session_with_prompt_marks_never_exports_an_inexact_snapshot() {
    let tally = check("fish");
    assert!(tally.refused > 0, "{tally:?}");
}

/// Long wrapped lines that have scrolled about 256 rows up used to refuse the
/// whole Snapshot whenever the oldest exported history row continued a wrap.
/// The export now starts at the next whole line instead (`historyStart` in
/// `native/snapshot.zig`, #521). Lines here take three rows each and the
/// screen holds only short lines, so 256 rows up (256 = 3 * 85 + 1) is the
/// last row of a wrapped line; one more short line moves the boundary onto a
/// line start, the control.
#[test]
fn a_wrapped_line_on_the_history_tail_boundary_shortens_the_tail_instead_of_refusing() {
    for shorts in [23, 24] {
        let mut shim = Terminal::new(80, 24).unwrap();
        for line in 0..400 {
            // 230 columns: every line wraps onto exactly three rows.
            shim.process(format!("{line:04} {}\r\n", "x".repeat(225)).as_bytes());
        }
        for _ in 0..shorts {
            shim.process(b"short\r\n");
        }
        let bytes = shim.snapshot().unwrap();
        let mut viewer = Terminal::new(80, 24).unwrap();
        viewer.process(&bytes);
        assert_eq!(
            shim.engine.state_difference(&viewer.engine),
            0,
            "{shorts} short lines"
        );
    }
}

/// bash editing commands longer than its small screen (`LONG_SCRIPT` in
/// `capture_shells.py`): the edited line crosses the history/screen boundary
/// while readline redraws it, moves over it, recalls it and is resized.
#[test]
fn a_bash_session_editing_lines_longer_than_the_screen_snapshots_exactly() {
    let tally = check("bash-long");
    assert_eq!(tally.refused, 0, "{tally:?}");
}

/// zsh editing commands longer than its small screen, with its right prompt.
#[test]
fn a_zsh_session_editing_lines_longer_than_the_screen_snapshots_exactly() {
    let tally = check("zsh-long");
    assert_eq!(tally.refused, 0, "{tally:?}");
}
