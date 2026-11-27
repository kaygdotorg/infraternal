//! Fuzz entry point for the shim's VT stream: PTY output into terminal state and back out as a snapshot.
//!
//! Every byte a program writes reaches [`Terminal::process`] in whatever
//! pieces the PTY read returned, and a viewer that attaches later gets
//! [`Terminal::snapshot`]: a repaint plus the unfinished escape sequence (the
//! "carry") so the live stream can continue it. [`verify_vt_stream_sample`]
//! checks, for one fuzz input:
//!
//! - **chunking does not matter:** the same output fed in input-chosen
//!   pieces or in one piece per segment, with the same resizes in between,
//!   gives byte-identical snapshots (or both refuse);
//! - **a snapshot is bounded:** it fits one shim frame, and the bounded
//!   approximate repaint always does;
//! - **a snapshot continues the stream** (when the input's flag bit asks):
//!   a fresh terminal of the same size fed the snapshot, then the same
//!   further output as the original, ends with the same snapshot as the
//!   original, except that hyperlinks the program opened without an id may
//!   be numbered differently as long as the same characters share a link
//!   (the `links` module). A failure is told apart by cutting the carry off
//!   the snapshot and replaying again: when that makes the two agree, the
//!   carry is at fault (`CARRY-CLASS`); otherwise the repaint is
//!   (`REPAINT-CLASS`). The two classes have different owners, and a known
//!   gap in one must not hide a regression in the other.
//!
//! The native engine's own code is not coverage-instrumented; the carry
//! parser and the snapshot framing around it are.
//!
//! Only built for tests and the `parser-checks` feature (the fuzz harness).

use crate::{frame::MAX_FRAME, terminal::Terminal};
use std::fmt::Write as _;

/// Compares hyperlink grouping between the original's snapshot and a viewer's.
mod links;

/// One run of output, then the size both terminals change to after it (none for the last run).
type Segment<'a> = (&'a [u8], Option<(u16, u16)>);

/// A terminal size from one selector byte: 1 to 160 columns, 1 to 60 rows.
fn size(selector: u8) -> (u16, u16) {
    let cols = u16::from(selector) % 160 + 1;
    let rows = u16::from(selector / 4) % 60 + 1;
    (cols, rows)
}

/// Fuzz the VT stream with one input; panics when an invariant above breaks.
///
/// Layout: byte 0 is the starting size, byte 1 holds flags (bit 0: also check
/// continuation), byte 2 is the length of the chunk schedule that follows.
/// The remaining output is split into segments at `0xFE 0xFE <size>`
/// markers, each marker resizing both terminals before the next segment; the
/// last segment is the "further output" of the continuation check.
#[doc(hidden)]
pub fn verify_vt_stream_sample(data: &[u8]) {
    let [start, flags, schedule_len, rest @ ..] = data else {
        return;
    };
    let (schedule, output) = rest.split_at(usize::from(*schedule_len).min(rest.len()));
    let (cols, rows) = size(*start);
    let (Ok(mut pieces), Ok(mut whole)) = (Terminal::new(cols, rows), Terminal::new(cols, rows))
    else {
        return;
    };
    let mut segments: Vec<Segment<'_>> = Vec::new();
    let mut remaining = output;
    while let Some(at) = remaining
        .windows(3)
        .position(|w| w[0] == 0xFE && w[1] == 0xFE)
    {
        segments.push((&remaining[..at], Some(size(remaining[at + 2]))));
        remaining = &remaining[at + 3..];
        if segments.len() == 16 {
            break;
        }
    }
    segments.push((remaining, None));

    let mut step = 0;
    let Some(((last, _), earlier)) = segments.split_last() else {
        return;
    };
    let mut size_now = (cols, rows);
    for (segment, resize) in earlier {
        feed(&mut pieces, segment, schedule, &mut step);
        whole.process(segment);
        if let Some((cols, rows)) = resize {
            let a = pieces.resize(*cols, *rows).is_ok();
            let b = whole.resize(*cols, *rows).is_ok();
            assert_eq!(a, b, "the same resize succeeded on only one terminal");
            size_now = (*cols, *rows);
        }
    }
    let snapshot = compare(&pieces, &whole);

    if flags & 1 == 0 {
        feed(&mut pieces, last, schedule, &mut step);
        whole.process(last);
        compare(&pieces, &whole);
        return;
    }
    // Continuation: a viewer rebuilt from the snapshot keeps up with the stream.
    let Some(snapshot) = snapshot else {
        return;
    };
    let repaint_len = snapshot.len() - whole.carry_len();
    let viewer_input = links::mark_restored(&snapshot, repaint_len);
    whole.process(last);
    let Ok(original) = whole.snapshot() else {
        return;
    };
    let Some(rebuilt) = replay(&viewer_input, size_now, last) else {
        return;
    };
    if !links::same_screen(&original, &rebuilt) {
        let carry_at_fault = replay(&viewer_input[..repaint_len], size_now, last)
            .is_some_and(|bare| links::same_screen(&original, &bare));
        let class = if carry_at_fault {
            "CARRY-CLASS"
        } else {
            "REPAINT-CLASS"
        };
        panic!(
            "{class}: a snapshot did not continue the stream: {}",
            first_difference(&original, &rebuilt)
        );
    }
}

/// The snapshot a fresh terminal of `size` ends with after `replayed` and then
/// `last` (none when the terminal cannot be made or refuses to snapshot).
fn replay(replayed: &[u8], size: (u16, u16), last: &[u8]) -> Option<Vec<u8>> {
    let mut viewer = Terminal::new(size.0, size.1).ok()?;
    viewer.process(replayed);
    viewer.process(last);
    viewer.snapshot().ok()
}

/// Feed `bytes` to `terminal` in pieces whose sizes come from `schedule`.
fn feed(terminal: &mut Terminal, mut bytes: &[u8], schedule: &[u8], step: &mut usize) {
    while !bytes.is_empty() {
        let selector = schedule
            .get(*step % schedule.len().max(1))
            .copied()
            .unwrap_or(0);
        *step = step.wrapping_add(1);
        let size = match selector % 4 {
            0 => 1,
            1 => 2,
            2 => usize::from(selector) + 1,
            _ => bytes.len(),
        };
        let (piece, rest) = bytes.split_at(size.min(bytes.len()));
        terminal.process(piece);
        bytes = rest;
    }
}

/// Where two snapshots first differ, with up to 48 escaped bytes of each
/// from just before that point (and both whole when they are small), so a
/// failure can be read without a debugger.
fn first_difference(left: &[u8], right: &[u8]) -> String {
    let at = left
        .iter()
        .zip(right)
        .position(|(a, b)| a != b)
        .unwrap_or(left.len().min(right.len()));
    let from = at.saturating_sub(16);
    let window = |bytes: &[u8]| {
        bytes[from.min(bytes.len())..(from + 48).min(bytes.len())]
            .escape_ascii()
            .to_string()
    };
    let mut text = format!(
        "lengths {} and {}, first difference at byte {at}: {:?} vs {:?}",
        left.len(),
        right.len(),
        window(left),
        window(right)
    );
    // Small snapshots are shown whole: the difference can depend on bytes
    // far from where it shows.
    if left.len().max(right.len()) <= 4096 {
        let _ = write!(
            text,
            "\nleft:  {}\nright: {}",
            left.escape_ascii(),
            right.escape_ascii()
        );
    }
    text
}

/// Both terminals' snapshots agree and are bounded; returns the snapshot.
fn compare(pieces: &Terminal, whole: &Terminal) -> Option<Vec<u8>> {
    assert!(pieces.approximate_snapshot().len() <= MAX_FRAME);
    match (pieces.snapshot(), whole.snapshot()) {
        (Ok(a), Ok(b)) => {
            assert!(a.len() <= MAX_FRAME);
            assert!(
                a == b,
                "chunk boundaries changed the snapshot: {}",
                first_difference(&a, &b)
            );
            Some(a)
        }
        (Err(_), Err(_)) => None,
        _ => panic!("chunk boundaries changed whether a snapshot fits"),
    }
}

/// Replays the committed seed corpus through the fuzz entry point, so the
/// ordinary test run exercises it on the stable toolchain (ENGINEERING P5).
#[cfg(test)]
mod seed_corpus {
    /// Every committed seed runs through the entry point without a panic.
    #[test]
    fn every_seed_replays_without_breaking_an_invariant() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fuzz/corpus/vt_stream_snapshot"
        );
        let mut seeds = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            super::verify_vt_stream_sample(&std::fs::read(entry.unwrap().path()).unwrap());
            seeds += 1;
        }
        assert!(seeds > 0, "no seeds in {dir}");
    }
}

/// Inputs the 2026-11-21 campaign found (#561), kept as named regressions.
#[cfg(test)]
mod found {
    /// ESC followed by a C1-range byte (0x80-0x9F) and a printable: a fresh
    /// terminal fed the snapshot must end in the same state as the original.
    /// (The leading reset only makes a snapshot representable; the resize
    /// marker only makes the hook take its snapshot after the output.)
    ///
    /// Fails today (#561): the engine applies the VT500 "anywhere" C1
    /// transitions inside escape, CSI, DCS-header and SOS/PM/APC states (here
    /// 0x9C ends the escape and the next byte prints), while the carry
    /// observer (vte) ignores C1 bytes there. The carry keeps `ESC 0x9C '`,
    /// and a viewer replaying it prints `'` a second time.
    #[test]
    fn snapshot_continues_after_esc_c1_byte_and_resize() {
        for input in [
            &b"\x50\x01\x00\x1bc\x1b\x9c'\xfe\xfe'"[..],
            b"\x50\x01\x00\x1bc\x1b\x9cX\r\n\xfe\xfe'",
            b"\x50\x01\x00\x1bc\x1b\x80'\xfe\xfe\x50",
        ] {
            super::verify_vt_stream_sample(input);
        }
    }

    /// An OSC 8 that an ESC ended, followed by a sequence still unfinished at
    /// the cut. The engine opened the link at that ESC, taking the next
    /// implicit id, so a carry that still held the OSC made the viewer open
    /// it a second time under another id (#594). The first input is the
    /// minimal form; the fuzzer's is the committed seed
    /// `implicit-link-after-ended-string`.
    #[test]
    fn snapshot_does_not_replay_a_link_the_engine_already_opened() {
        for unfinished in [&b"P"[..], b"P1$r", b"_x", b"]0;title", b"[1;"] {
            let mut input = b"\x50\x01\x00\x1b]8;;http://a\x1b\\A\x1b]8;;http://b\x1b".to_vec();
            input.extend_from_slice(unfinished);
            input.extend_from_slice(b"\xfe\xfe\x50\x1b\\B");
            super::verify_vt_stream_sample(&input);
        }
    }

    /// A Snapshot keeps the selected status display (DECSASD), under which
    /// the engine drops printed text. A viewer that lost the selection printed
    /// the further output (#594). The committed seed `status-display-selected`
    /// is the same defect behind a resize.
    #[test]
    fn snapshot_continues_with_the_status_display_selected() {
        super::verify_vt_stream_sample(b"\x50\x01\x00\x1bc\x1b[1$}\xfe\xfe\x50P");
    }

    /// A reflow that shrinks 81 columns to 40 leaves wrapped rows on a
    /// terminal that never printed a character, so its REP source is empty.
    /// Repainting a wrapped edge prints a stand-in glyph, which would give
    /// the viewer a REP source the original does not have, so the snapshot
    /// must refuse instead (#561, finding 6; the first report of it blamed
    /// the scroll region, which was only where the two snapshots first differ).
    ///
    /// Fails today: the viewer's snapshot gains a REP restore the original's
    /// lacks. The input is the fuzzer's 153-byte crash.
    #[test]
    fn snapshot_refuses_painted_text_without_a_rep_source() {
        super::verify_vt_stream_sample(b"\x50\x63\x00\x1b\x01\x00\x00\x00\x00\x00\x00\x06\x01\x05\x1c\x08\x00\x63\x1b\x05\x08\x2a\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\x23\x00\x00\x00\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\xff\xff\xff\xff\xff\x00\xfe\xfe\x27\x2e");
    }

    /// A zero-width codepoint that the grapheme rules separate from its base
    /// (here U+061C after `w`, bytes D8 9C) is stored on the cell when
    /// clustering is off, and dropped when it is on. The repaint replayed
    /// every cell's extras with clustering on, so the viewer lost it
    /// (#561, finding 5; the reported case was U+030C on a U+FFFD cell).
    ///
    /// Fails today: the original's cell carries the mark, the rebuilt one
    /// does not. The input is the fuzzer's 30-byte crash.
    #[test]
    fn snapshot_keeps_a_mark_the_boundary_rules_would_drop() {
        super::verify_vt_stream_sample(b"\x25\x01\x00\x1b\x1b\x63\x9c\x77\xd8\x9c\x88\xff\x3b\x3e\xff\xff\x00\x9d\x63\xfe\xfe\x06\xeb\x58\xe5\xfe\x1b\xff\x50\x3b");
    }
}

/// The classifier's cut point must be exactly the carry.
#[cfg(test)]
mod classifier {
    use crate::terminal::Terminal;

    /// With an unfinished CSI on the terminal, the snapshot ends in exactly
    /// the `carry_len` bytes of it, and with nothing pending there are none.
    #[test]
    fn carry_len_is_the_unfinished_sequence_at_the_end_of_a_snapshot() {
        let mut terminal = Terminal::new(80, 24).unwrap();
        terminal.process(b"\x1bchello");
        assert_eq!(terminal.carry_len(), 0);
        terminal.process(b"\x1b[1;");
        let snapshot = terminal.snapshot().unwrap();
        assert_eq!(terminal.carry_len(), 4);
        assert!(snapshot.ends_with(b"\x1b[1;"));
    }
}

/// The continuation check ignores how a restored viewer numbers links, and
/// nothing else about them (#594).
#[cfg(test)]
mod link_groups {
    use super::{links, replay, verify_vt_stream_sample};
    use crate::terminal::Terminal;

    /// Whether a viewer restored from the snapshot taken after `prefix`, then
    /// fed `suffix`, passes the check against the original. `damage` edits what
    /// the viewer is fed, standing in for a painter that restores links wrongly.
    fn continues(prefix: &str, suffix: &str, damage: impl Fn(String) -> String) -> bool {
        let mut original = Terminal::new(81, 21).unwrap();
        original.process(b"\x1bc");
        original.process(prefix.as_bytes());
        let snapshot = original.snapshot().unwrap();
        let fed = links::mark_restored(&snapshot, snapshot.len() - original.carry_len());
        let fed = String::from_utf8(fed).unwrap();
        let damaged = damage(fed);
        original.process(suffix.as_bytes());
        let viewer = replay(damaged.as_bytes(), (81, 21), suffix.as_bytes()).unwrap();
        links::same_screen(&original.snapshot().unwrap(), &viewer)
    }

    /// Two links to one URI, opened without ids and closed, on two rows.
    const TWO: &str = "\x1b]8;;u\x1b\\A\x1b]8;;\x1b\\\r\n\x1b]8;;u\x1b\\B\x1b]8;;\x1b\\";
    /// One link spanning two rows.
    const ONE: &str = "\x1b]8;;u\x1b\\A\r\nB\x1b]8;;\x1b\\";

    /// A link opened after the restore gets a smaller number in the viewer
    /// than in the original, and may get the number a restored link had. The
    /// bytes differ; the grouping does not. The same holds for a link left
    /// open across the cut.
    #[test]
    fn a_renumbered_link_is_not_a_divergence() {
        let suffix = "\r\n\x1b]8;;u\x1b\\C\x1b]8;;\x1b\\";
        for prefix in [TWO, ONE, "\x1b]8;;u\x1b\\A"] {
            assert!(continues(prefix, suffix, |fed| fed), "{prefix:?}");
            let mut input = format!("\x50\x01\x00\x1bc{prefix}").into_bytes();
            input.extend_from_slice(b"\xfe\xfe\x50");
            input.extend_from_slice(suffix.as_bytes());
            verify_vt_stream_sample(&input);
        }
        let mut original = Terminal::new(81, 21).unwrap();
        original.process(format!("\x1bc{TWO}").as_bytes());
        let mut viewer = Terminal::new(81, 21).unwrap();
        viewer.process(&original.snapshot().unwrap());
        original.process(suffix.as_bytes());
        viewer.process(suffix.as_bytes());
        assert_ne!(original.snapshot().unwrap(), viewer.snapshot().unwrap());
    }

    /// Each kind of wrong restore is still reported.
    #[test]
    fn a_wrong_restore_is_a_divergence() {
        let second = "\x1b]8;id=infraternal-restored-1;u\x1b\\";
        let first = "\x1b]8;id=infraternal-restored-0;u\x1b\\";
        // Two links merged into one.
        assert!(!continues(TWO, "", |fed| {
            assert!(fed.contains(second));
            fed.replace(second, first)
        }));
        // One link split: everything painted after the first row's letter gets
        // another id. All later openings change, because the repaint ends by
        // printing the last cell again to restore the repeat character.
        assert!(!continues(ONE, "", |fed| {
            let (head, tail) = fed.split_once('A').unwrap();
            assert!(tail.contains(first));
            format!("{head}A{}", tail.replace(first, second))
        }));
        // A link lost, and a link pointing elsewhere.
        assert!(!continues(TWO, "", |fed| fed.replace(second, "")));
        assert!(!continues(TWO, "", |fed| {
            fed.replace(second, &second.replace(";u", ";v"))
        }));
        // An id the program chose must come back exactly.
        let chosen = "\x1b]8;id=mine;u\x1b\\A";
        assert!(continues(chosen, "B", |fed| fed));
        assert!(!continues(chosen, "B", |fed| {
            assert!(fed.contains("id=mine;"));
            fed.replace("id=mine;", "id=yours;")
        }));
    }

    /// Only the repaint is renamed: unfinished input must reach the viewer as
    /// the program wrote it.
    #[test]
    fn marking_leaves_the_carry_alone() {
        let opening = b"\x1b]8;id=infraternal-implicit-0;u\x1b\\";
        let snapshot = [&opening[..], opening].concat();
        let marked = links::mark_restored(&snapshot, opening.len());
        assert_eq!(&marked[opening.len()..], opening);
        assert_eq!(
            &marked[..opening.len()],
            b"\x1b]8;id=infraternal-restored-0;u\x1b\\"
        );
    }
}
