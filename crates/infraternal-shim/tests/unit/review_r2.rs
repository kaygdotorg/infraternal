//! Break-it review r2 (#205, D270): bounded shared-host terminals must keep
//! exact state under long ordinary output and oversized control strings.
//!
//! Each check compares a bounded terminal against a second bounded terminal
//! fed an equivalent stream whose ignored string payloads stay under the
//! 4 KiB forwarding limit, so any difference comes from the discard path.
use super::*;

/// Ordinary scrolling output must never reach native allocation refusal:
/// refusal latches `requires_approximation` and every later attach of the
/// session loses its exact repaint. The host gives a single session a
/// 17 MiB history share (`HOST_HISTORY_BYTES / n`, capped at 17 MiB), while
/// the non-compact per-terminal reservation ceiling is 8 MiB.
#[test]
fn review_r2_host_history_share_fits_the_native_reservation() {
    // Shares the host hands out for 1, 4 and 10 sessions. Measured: every
    // share of at least about 6.7 MiB (10 or fewer sessions) refuses after
    // roughly 360 KB of output; 11 or more sessions do not.
    for sessions in [1_usize, 4, 10] {
        let history = (64 * 1024 * 1024 / sessions).min(17 * 1024 * 1024);
        let mut terminal = Terminal::with_history_budget(80, 24, history).unwrap();
        // Faithful snapshots require the RIS-initialized prompt flag; a
        // fresh native terminal is never certifiable (snapshot.zig).
        terminal.process(b"\x1bc");
        let mut line = [b'y'; 81];
        line[79] = b'\r';
        line[80] = b'\n';
        let chunk = line.repeat(200);
        // 40 MB of ordinary output: far past any history share, so the
        // native list must recycle its oldest pages instead of allocating.
        for _ in 0..2500 {
            terminal.process(&chunk);
        }
        let (used, peak, refused) = terminal.memory();
        assert!(
            !refused,
            "{sessions} session(s), history share {history}: ordinary output reached native \
             allocation refusal (used {used}, peak {peak}); the session is now permanently \
             approximate"
        );
        assert!(
            terminal.snapshot().is_ok(),
            "{sessions} session(s): exact snapshot lost after ordinary output"
        );
    }
}

/// Deterministic generator; no timing or randomness from the environment.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// One ignored control string: introducer, a header that makes the string
/// inert (unknown OSC number, unknown DCS final), filler and a terminator.
fn string(rng: &mut Lcg, filler: usize, out_long: &mut Vec<u8>, out_short: &mut Vec<u8>) {
    let introducer = *b"]P_^X"
        .get(usize::try_from(rng.below(5)).unwrap())
        .unwrap();
    let osc = introducer == b']';
    let header: &[u8] = match introducer {
        b']' => b"9999;",
        b'P' => b"x",
        _ => b"",
    };
    // Raw C1 introducers in ground state are covered separately below.
    let c1 = false;
    let _ = rng.below(4);
    let start: Vec<u8> = if c1 {
        vec![introducer + 0x40]
    } else {
        vec![0x1b, introducer]
    };
    let mut body = Vec::with_capacity(filler);
    for _ in 0..filler {
        let class = rng.below(16);
        let byte = match class {
            0 => b'\n',
            1 => b'\t',
            2 => 0x7f,
            3 if osc => 0xa0 + u8::try_from(rng.below(0x5f)).unwrap(),
            _ => 0x20 + u8::try_from(rng.below(0x5f)).unwrap(),
        };
        body.push(byte);
    }
    let terminator: &[u8] = match rng.below(if osc { 5 } else { 4 }) {
        1 => b"\x18",
        2 => b"\x1a",
        3 if osc => b"\x07",
        3 => b"\x9c",
        _ => b"\x1b\\",
    };
    for (out, len) in [(out_long, filler), (out_short, filler.min(64))] {
        out.extend_from_slice(&start);
        out.extend_from_slice(header);
        out.extend_from_slice(&body[..len]);
        out.extend_from_slice(terminator);
    }
}

fn feed_fragmented(rng: &mut Lcg, terminal: &mut Terminal, bytes: &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        // Mix one-byte fragments (splitting ESC from its follower) with
        // large reads, as a PTY delivers them.
        let len = match rng.below(4) {
            0 => 1,
            1 => 2,
            2 => usize::try_from(rng.below(64)).unwrap() + 1,
            _ => usize::try_from(rng.below(20_000)).unwrap() + 1,
        };
        let end = bytes.len().min(at + len);
        terminal.process(&bytes[at..end]);
        at = end;
    }
}

/// A session alternating oversized and ordinary strings with text and SGR
/// must render exactly what it renders with short payloads: discarding the
/// excess may never print payload, swallow the next command or leave the
/// native parser inside a string.
#[test]
fn review_r2_alternating_oversized_strings_keep_following_output_exact() {
    for seed in 0..48_u64 {
        let mut rng = Lcg(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut long = Vec::new();
        let mut short = Vec::new();
        for round in 0..24 {
            let filler = match rng.below(6) {
                0 => 10,
                1 => 4090 + usize::try_from(rng.below(12)).unwrap(),
                2 => 8192,
                3 => 70_000,
                4 => 1024 * 1024,
                _ => 4096,
            };
            string(&mut rng, filler, &mut long, &mut short);
            let text = format!("\x1b[3{}mr{round}s{seed}\x1b[0m\r\n", round % 8);
            long.extend_from_slice(text.as_bytes());
            short.extend_from_slice(text.as_bytes());
        }
        let mut bounded = Terminal::with_history_budget(80, 24, 65536).unwrap();
        feed_fragmented(&mut rng, &mut bounded, &long);
        let mut expected = Terminal::with_history_budget(80, 24, 65536).unwrap();
        expected.process(&short);
        assert!(!bounded.memory().2, "seed {seed}: discard reached refusal");
        assert_eq!(
            bounded.research_state_difference(&expected),
            0,
            "seed {seed}: oversized strings changed the following screen or parser state"
        );
        // The carry must also agree, or a reattached viewer resumes inside
        // a string that the host already left.
        assert_eq!(bounded.pending, expected.pending, "seed {seed}: carry");
        // Faithful snapshot of these mixtures is refused by the painter for
        // the short oracle too, so snapshot success is not compared here.
    }
}

/// An ESC inside a discarded string aborts it and begins a new command, as
/// it does inside a short string. Split the ESC from its follower.
#[test]
fn review_r2_escape_command_inside_discard_matches_short_string() {
    for introducer in *b"]P_^X" {
        for follower in [
            &b"[31mRED"[..],
            b"7SAVED",
            b"]0;t\x07T",
            b"P\x1b\\D",
            b"cRIS",
        ] {
            let mut long = vec![0x1b, introducer];
            long.extend(std::iter::repeat_n(b'z', 10_000));
            let mut short = vec![0x1b, introducer];
            short.extend(std::iter::repeat_n(b'z', 10));
            let mut bounded = Terminal::with_history_budget(80, 24, 65536).unwrap();
            bounded.process(&long);
            bounded.process(b"\x1b");
            bounded.process(follower);
            bounded.process(b"after");
            let mut expected = Terminal::with_history_budget(80, 24, 65536).unwrap();
            expected.process(&short);
            expected.process(b"\x1b");
            expected.process(follower);
            expected.process(b"after");
            assert_eq!(
                bounded.research_state_difference(&expected),
                0,
                "string {introducer} then ESC {:?}",
                String::from_utf8_lossy(follower)
            );
            assert_eq!(bounded.pending, expected.pending);
        }
    }
}

/// A raw C1 introducer in ground state is not counted by the limiter. Feed
/// one with a 32 MiB payload: either the native parser treats it as text
/// (then both engines agree) or it must still stay inside the session share.
#[test]
fn review_r2_ground_c1_introducer_stays_within_the_session_share() {
    for introducer in [0x9d_u8, 0x90, 0x9f, 0x9e, 0x98] {
        let mut bounded = Terminal::with_history_budget(80, 24, 65536).unwrap();
        bounded.process(&[introducer]);
        for _ in 0..4096 {
            bounded.process(&[b'q'; 8192]);
        }
        bounded.process(b"\x07\x1b\\after");
        let (ordinary, _, _, _, carry) = bounded.ownership().unwrap();
        assert!(
            ordinary <= 256 * 1024,
            "C1 {introducer:#x}: native metadata"
        );
        assert!(carry <= 4096, "C1 {introducer:#x}: carry {carry}");
        assert!(
            !bounded.memory().2,
            "C1 {introducer:#x}: ground C1 string reached native allocation refusal"
        );
    }
}

/// Below the 4 KiB string limit the limiter must be transparent: a bounded
/// terminal and the per-session engine must reach the same state for the
/// same short bytes. Any difference means the limiter's syntax model left
/// the native parser's (for example entering a string the native parser
/// never entered, which later drops ordinary text past 4 KiB).
#[test]
fn review_r2_limiter_is_transparent_for_short_control_mixtures() {
    const ALPHABET: &[u8] = &[
        0x1b, 0x1b, 0x1b, b'[', b']', b'P', b'_', b'^', b'X', b'\\', 0x07, 0x18, 0x1a, 0x9b, 0x9c,
        0x9d, 0x90, 0x9f, 0xc3, 0xc2, 0xe2, 0xa0, 0xdd, b'a', b'0', b';', b'm', b'\n', b' ', b'(',
        b'#', b'q', 0x80, 0x84,
    ];
    let mut failures = Vec::new();
    for seed in 0..4000_u64 {
        let mut rng = Lcg(seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1);
        let len = usize::try_from(rng.below(24)).unwrap() + 1;
        let mut bytes: Vec<u8> = (0..len)
            .map(|_| ALPHABET[usize::try_from(rng.below(ALPHABET.len() as u64)).unwrap()])
            .collect();
        // Leave every string, then print text that must be visible.
        bytes.extend_from_slice(b"\x18\x1b\\VISIBLE\r\n");
        let mut bounded = Terminal::with_history_budget(80, 24, 65536).unwrap();
        bounded.process(&bytes);
        let mut native = Terminal::new(80, 24).unwrap();
        native.process(&bytes);
        if bounded.research_state_difference(&native) != 0 {
            failures.push(bytes);
        }
    }
    failures.sort_by_key(Vec::len);
    let shown: Vec<String> = failures
        .iter()
        .take(8)
        .map(|b| format!("{b:02x?}"))
        .collect();
    assert!(
        failures.is_empty(),
        "{} of 4000 short inputs diverge from the per-session engine; shortest: {shown:#?}",
        failures.len()
    );
}

/// C1 bytes inside a DCS payload stay payload data and never become commands.
#[test]
fn review_r2_c1_controls_in_dcs_payload_remain_inert() {
    // 0x90 starts DCS from Escape; '^' completes its header. The later C1
    // bytes are payload in libghostty-vt 1.0, so X must stay hidden too.
    let bytes = b"\x1b\x90^0\x90\x80X\x18\x1b\\";
    let mut bounded = Terminal::with_history_budget(80, 24, 65536).unwrap();
    bounded.process(bytes);
    let mut native = Terminal::new(80, 24).unwrap();
    native.process(bytes);

    assert_eq!(
        bounded.engine.state_difference(&native.engine),
        0,
        "DCS payload C1 bytes changed the terminal screen or modes"
    );
}

/// ESC followed by a non-ASCII byte and then a raw C1 byte: the limiter
/// must not invent an OSC that swallows the following ordinary text.
#[test]
fn review_r2_escape_high_byte_does_not_start_a_hidden_string() {
    // Carriage returns keep the text on one row, so no history is compared.
    let text = "plain text that must stay visible\r".repeat(200);
    for prefix in [&b"\x1b\xc3\x9d"[..], b"\x1b\xa0\x9d", b"\x1b\xe2\x80\x9d"] {
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(text.as_bytes());
        bytes.extend_from_slice(b"END");
        let mut bounded = Terminal::with_history_budget(80, 24, 65536).unwrap();
        bounded.process(&bytes);
        let mut native = Terminal::new(80, 24).unwrap();
        native.process(&bytes);
        // The carry is canonical 7-bit syntax in bounded mode, so compare
        // only the native engines here.
        assert_eq!(
            bounded.engine.state_difference(&native.engine),
            0,
            "prefix {prefix:02x?}: bounded terminal hid ordinary text"
        );
    }
}

/// A viewer resize with full history must reflow inside the reservation:
/// a refusal falls back to an approximate rebuild, so one ordinary window
/// resize would permanently cost the session its exact repaint. Shares are
/// the host's for 32 and 64 sessions. Below that, ordinary wrapped output
/// already refuses before the resize (11 sessions measured; see the
/// history-share test), so those shares do not isolate the resize.
#[test]
fn review_r2_resize_with_full_history_share_stays_exact() {
    for sessions in [32_usize, 64] {
        let history = (64 * 1024 * 1024 / sessions).min(17 * 1024 * 1024);
        let mut terminal = Terminal::with_history_budget(80, 24, history).unwrap();
        terminal.process(b"\x1bc");
        let mut line = b"0123456789".repeat(7);
        line.extend_from_slice(b"wrap-me-at-sixty\r\n");
        let chunk = line.repeat(100);
        let mut written = 0;
        while written < 3 * history {
            terminal.process(&chunk);
            written += chunk.len();
        }
        let before = terminal.memory();
        for (cols, rows) in [(60, 30), (120, 40), (80, 24), (200, 50), (80, 24)] {
            let result = terminal.resize(cols, rows);
            assert!(
                result.is_ok() && !terminal.requires_approximation(),
                "{sessions} sessions (history {history}): resize to {cols}x{rows} lost exact state \
                 (native before {before:?}, after {:?}, result {result:?})",
                terminal.memory()
            );
        }
    }
}

/// A resize storm from a viewer must not ratchet native memory: after the
/// storm returns to the original geometry, usage stays near its pre-storm
/// level and below the reservation.
#[test]
fn review_r2_resize_storm_does_not_ratchet_native_memory() {
    let mut terminal = Terminal::with_history_budget(80, 24, 65536).unwrap();
    terminal.process(b"\x1bc");
    terminal.process(&b"storm line\r\n".repeat(500));
    let baseline = terminal.memory().0;
    for round in 0..400_u16 {
        let cols = 20 + (round * 37) % 400;
        let rows = 5 + (round * 13) % 400;
        let cols = if usize::from(cols) * usize::from(rows) > 200_000 {
            80
        } else {
            cols
        };
        let _ = terminal.resize(cols, rows);
        terminal.process(b"x\r\n");
    }
    terminal.resize(80, 24).unwrap();
    let (used, peak, refused) = terminal.memory();
    assert!(
        !refused,
        "storm reached native allocation refusal (peak {peak})"
    );
    assert!(
        used <= baseline * 4 + 1024 * 1024,
        "native memory ratcheted from {baseline} to {used} after the storm"
    );
}
