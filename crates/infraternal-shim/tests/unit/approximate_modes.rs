//! Input and terminal modes survive both repaints (#524).
//!
//! A repaint starts with RIS, which turns every mode the program set back to
//! its default. The approximate painter used to restore only colours, the
//! alternate screen, autowrap *on* and cursor visibility, so after a reconnect
//! or a flood repaint the browser's terminal no longer bracketed pastes
//! (a pasted multi-line command ran line by line), stopped reporting the mouse,
//! sent the wrong cursor keys and lost focus events, while the program on the
//! host still had all of them on.
//!
//! Each case here turns one piece of state on in a host terminal, repaints it
//! into a viewer that had other state, and checks that the viewer's engine
//! reports the same state. Most cases also replay the same later output on
//! both sides and compare again, because some state (wrap, origin, the Kitty
//! key stack, charsets) only shows when the program keeps writing.
use super::*;

/// A terminal in the canonical post-RIS context every repaint starts from.
///
/// A new terminal already starts in that context (#521); the explicit RIS
/// keeps these cases there even if construction changes.
fn reset_terminal(cols: u16, rows: u16) -> Terminal {
    let mut terminal = Terminal::new(cols, rows).unwrap();
    terminal.process(b"\x1bc");
    terminal
}

/// A viewer that already holds unrelated modes and text, as a browser does
/// when it reconnects to a session it was showing before.
fn stale_viewer() -> Terminal {
    let mut viewer = reset_terminal(80, 24);
    viewer.process(b"\x1b[?1h\x1b[?1004h\x1b[?2004h\x1b[?1003h\x1b[?1015h\x1b[4 qold screen\r\n");
    viewer
}

/// One piece of program state: the bytes that set it, and optional later
/// output whose effect depends on it.
struct Case {
    name: &'static str,
    setup: &'static [u8],
    later: &'static [u8],
}

/// Every mode and input flag a program can leave on, each with a probe.
///
/// The host screen starts blank so cases that leave the alternate screen land
/// on a primary screen the approximate painter (which paints only the active
/// screen) also left blank.
const CASES: &[Case] = &[
    Case { name: "bracketed paste 2004", setup: b"\x1b[?2004h", later: b"" },
    Case { name: "mouse 1000 + SGR 1006", setup: b"\x1b[?1000h\x1b[?1006h", later: b"" },
    Case { name: "mouse button 1002", setup: b"\x1b[?1002h", later: b"" },
    Case { name: "mouse any 1003 + SGR 1006", setup: b"\x1b[?1003h\x1b[?1006h", later: b"" },
    Case { name: "mouse X10 9", setup: b"\x1b[?9h", later: b"" },
    Case { name: "mouse UTF-8 1005", setup: b"\x1b[?1000h\x1b[?1005h", later: b"" },
    Case { name: "mouse urxvt 1015", setup: b"\x1b[?1000h\x1b[?1015h", later: b"" },
    Case { name: "mouse SGR pixels 1016", setup: b"\x1b[?1002h\x1b[?1016h", later: b"" },
    // The effective event is the last one set, not the highest number.
    Case { name: "mouse order 1006 1003 1000", setup: b"\x1b[?1006h\x1b[?1003h\x1b[?1000h", later: b"" },
    Case { name: "cursor keys DECCKM 1", setup: b"\x1b[?1h", later: b"" },
    Case { name: "focus events 1004", setup: b"\x1b[?1004h", later: b"" },
    Case { name: "autowrap off ?7l", setup: b"\x1b[?7l", later: b"\x1b[3;1H0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789" },
    Case { name: "keypad DECKPAM", setup: b"\x1b=", later: b"" },
    Case { name: "keypad mode 66", setup: b"\x1b[?66h", later: b"" },
    Case { name: "cursor hidden ?25l", setup: b"\x1b[?25l", later: b"" },
    Case { name: "cursor blink ?12h", setup: b"\x1b[?12h", later: b"" },
    Case { name: "reverse video ?5h", setup: b"\x1b[?5h", later: b"" },
    Case { name: "insert mode IRM", setup: b"\x1b[4h", later: b"\x1b[1;1Habc\x1b[1;1Hxy" },
    Case { name: "linefeed mode LNM", setup: b"\x1b[20h", later: b"\x1b[4;5Hab\ncd" },
    Case { name: "alt sends escape 1039", setup: b"\x1b[?1039h", later: b"" },
    Case { name: "alt esc prefix off 1036", setup: b"\x1b[?1036l", later: b"" },
    Case { name: "alternate scroll off 1007", setup: b"\x1b[?1007l", later: b"" },
    Case { name: "backarrow DECBKM 67", setup: b"\x1b[?67h", later: b"" },
    Case { name: "reverse wrap 45", setup: b"\x1b[?45h", later: b"" },
    Case { name: "grapheme clustering 2027", setup: b"\x1b[?2027h", later: "\x1b[5;1H\u{1f469}\u{200d}\u{1f4bb}".as_bytes() },
    Case { name: "colour scheme reports 2031", setup: b"\x1b[?2031h", later: b"" },
    Case { name: "in-band size reports 2048", setup: b"\x1b[?2048h", later: b"" },
    Case { name: "clipboard paste events 5522", setup: b"\x1b[?5522h", later: b"" },
    // Modes that default on and a program turned off must be written as off.
    Case { name: "send/receive off SRM 12", setup: b"\x1b[12l", later: b"" },
    Case { name: "numlock keypad off 1035", setup: b"\x1b[?1035l", later: b"" },
    Case { name: "visibility reports 2033", setup: b"\x1b[?2033h", later: b"" },
    Case { name: "modifyOtherKeys 2", setup: b"\x1b[>4;2m", later: b"" },
    Case { name: "mouse shift capture", setup: b"\x1b[>1s", later: b"" },
    Case { name: "cursor style bar", setup: b"\x1b[6 q", later: b"" },
    Case { name: "cursor style blinking underline", setup: b"\x1b[3 q", later: b"" },
    // Popping must expose the same flags the program pushed under them.
    Case { name: "kitty keyboard stack", setup: b"\x1b[>1u\x1b[>5u", later: b"\x1b[<u" },
    Case { name: "G1 line drawing + SO", setup: b"\x1b)0\x0e", later: b"\x1b[6;1Hqqx" },
    Case { name: "scroll region", setup: b"\x1b[3;10r\x1b[10;1H", later: b"a\nb\nc\nd" },
    Case { name: "origin mode", setup: b"\x1b[5;20r\x1b[?6h\x1b[3;4H", later: b"X\x1b[1;1HY" },
    Case { name: "left/right margins", setup: b"\x1b[?69h\x1b[10;40s\x1b[2;1H\x1b[15G", later: b"0123456789012345678901234567890123456789" },
    Case { name: "status line selected DECSASD", setup: b"\x1b[1$}", later: b"status text\x1b[0$}main" },
    Case { name: "status line selected under margins", setup: b"\x1b[3;10r\x1b[?6h\x1b[1$}", later: b"status\x1b[0$}main" },
    Case { name: "alternate screen 1049", setup: b"\x1b[5;7H\x1b[?1049hvim", later: b"\x1b[?1049lZ" },
    Case { name: "alternate screen 1047", setup: b"\x1b[?1047hless", later: b"\x1b[?1047lZ" },
    Case { name: "alternate screen 47", setup: b"\x1b[?47hmore", later: b"\x1b[?47lZ" },
    // 1049 must be the switch when 1047 or 47 is also on: entered second,
    // it would save the alternate screen's cursor, and its exit would put
    // the cursor home instead of where the program left the shell.
    Case { name: "alternate screen 1049 + 1047", setup: b"\x1b[5;7H\x1b[?1049h\x1b[?1047hvim", later: b"\x1b[?1049lZ" },
    Case { name: "mouse inside the alternate screen", setup: b"\x1b[?1049h\x1b[?1000h\x1b[?1006h\x1b[?2004h", later: b"" },
    Case { name: "kitty keys on both screens", setup: b"\x1b[>1u\x1b[?1049h\x1b[>3u", later: b"\x1b[?1049l\x1b[<u" },
];

/// What `state_difference` (strict) also checks but a bounded repaint never
/// promised: history, saved cursors, tab stops. Use the non-strict oracle,
/// which compares the active screen, cursor, every mode, margins and the
/// input flags.
fn approximate_mismatch(host: &Terminal, viewer: &Terminal) -> usize {
    host.engine.difference(&viewer.engine)
}

/// Every case keeps its state through an approximate repaint (#524).
#[test]
fn approximate_repaint_keeps_every_mode() {
    let mut failures = Vec::new();
    for case in CASES {
        let mut host = reset_terminal(80, 24);
        host.process(case.setup);
        let repaint = host.approximate_snapshot();
        let mut viewer = stale_viewer();
        viewer.process(&repaint);
        let now = approximate_mismatch(&host, &viewer);
        host.process(case.later);
        viewer.process(case.later);
        let later = approximate_mismatch(&host, &viewer);
        if now != 0 || later != 0 {
            failures.push(format!(
                "{}: after repaint {now}, after later output {later}",
                case.name
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "approximate repaint lost state:\n{}",
        failures.join("\n")
    );
}

/// Every case also keeps its state through a faithful repaint, which the
/// exact painter promises in full (strict oracle).
#[test]
fn faithful_repaint_keeps_every_mode() {
    let mut failures = Vec::new();
    for case in CASES {
        let mut host = reset_terminal(80, 24);
        host.process(case.setup);
        let repaint = host
            .snapshot()
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        let mut viewer = stale_viewer();
        viewer.process(&repaint);
        let now = host.engine.state_difference(&viewer.engine);
        host.process(case.later);
        viewer.process(case.later);
        let later = host.engine.state_difference(&viewer.engine);
        if now != 0 || later != 0 {
            failures.push(format!(
                "{}: after repaint {now}, after later output {later}",
                case.name
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "faithful repaint lost state:\n{}",
        failures.join("\n")
    );
}

/// A full-screen program's whole input setup survives together, as a full-screen
/// program leaves it: alternate screen, SGR mouse, bracketed paste, cursor
/// keys, keypad, focus events, a bar cursor and Kitty flags.
#[test]
fn approximate_repaint_keeps_a_full_screen_programs_setup() {
    let mut host = reset_terminal(80, 24);
    host.process(b"$ vim notes\r\n\x1b[?1049h\x1b[22;0;0t\x1b[?1h\x1b=\x1b[?2004h\x1b[?1004h\x1b[?1002h\x1b[?1006h\x1b[>4;2m\x1b[>1u\x1b[6 q\x1b[?25l");
    host.process(b"\x1b[H\x1b[2Jline one\r\nline two\x1b[1;1H\x1b[?25h");
    let repaint = host.approximate_snapshot();
    let mut viewer = stale_viewer();
    viewer.process(&repaint);
    assert_eq!(approximate_mismatch(&host, &viewer), 0, "vim-like setup");
}

/// A plain shell prompt costs only the modes it really set: the repaint grows
/// by the bracketed-paste switch the shell turned on, not by a list of every
/// default mode. Prints bytes and time for the record; asserts bytes only.
#[test]
fn mode_restore_costs_bytes_not_a_mode_list() {
    let mut plain = reset_terminal(80, 24);
    plain.process(b"kayg@host ~ $ ");
    let mut shell = reset_terminal(80, 24);
    shell.process(b"kayg@host ~ $ \x1b[?2004h");
    let plain_len = plain.approximate_snapshot().len();
    let shell_len = shell.approximate_snapshot().len();
    assert!(
        shell_len <= plain_len + 8,
        "bracketed paste costs one 8-byte switch: plain {plain_len}, with 2004 {shell_len}"
    );
    let mut vim = reset_terminal(200, 50);
    vim.process(
        b"\x1b[?1049h\x1b[?1h\x1b=\x1b[?2004h\x1b[?1004h\x1b[?1002h\x1b[?1006h\x1b[>4;2m\x1b[6 q",
    );
    for row in 0..50 {
        vim.process(format!("\x1b[{};1H\x1b[3{}m{:-<199}", row + 1, row % 8, row).as_bytes());
    }
    let started = std::time::Instant::now();
    let mut bytes = 0;
    for _ in 0..200 {
        bytes = vim.approximate_snapshot().len();
    }
    let per = started.elapsed() / 200;
    eprintln!(
        "J766 approximate repaint: plain 80x24 {plain_len} B, +2004 {shell_len} B, vim 200x50 {bytes} B in {per:?}"
    );
}

/// The modes a full-screen program leaves on, plus enough cells and colour
/// changes that the repaint is far larger than the mode tail.
const BUSY_MODES: &[u8] = b"\x1b[?2004h\x1b[?1h\x1b[?66h\x1b[?1004h\x1b[?1000h\x1b[?1006h\x1b[>4;2m\x1b[>1u\x1b[>3u\x1b[6 q\x1b[?7l\x1b[2;23r";

/// A repaint clipped to a small frame drops cells, never modes: the tail is
/// reserved before any cell is written (#524). Clips the same screen to half
/// its unclipped size, then clears both screens and compares everything
/// else the oracle checks, so missing cells are expected and nothing more.
#[test]
fn a_clipped_repaint_drops_cells_not_modes() {
    let mut host = reset_terminal(80, 24);
    host.process(BUSY_MODES);
    for row in 1..=24 {
        host.process(format!("\x1b[{row};1H").as_bytes());
        for col in 0..79 {
            host.process(format!("\x1b[3{}m{}", col % 8, col % 10).as_bytes());
        }
    }
    host.process(b"\x1b[0m\x1b[5;5H");
    let full = host.approximate_snapshot();
    let mut frame = vec![0; full.len() / 2];
    let len = host.engine.approximate_snapshot(&mut frame);
    assert!(
        len > 0 && len < full.len(),
        "clipped to {len} of {} bytes",
        full.len()
    );
    let mut viewer = stale_viewer();
    viewer.process(&frame[..len]);
    host.process(b"\x1b[H\x1b[2J");
    viewer.process(b"\x1b[H\x1b[2J");
    assert_eq!(
        approximate_mismatch(&host, &viewer),
        0,
        "a clipped repaint lost a mode"
    );
}

/// The worst case for the mode tail's fixed buffer: a program that flips
/// every mode a repaint restores away from its default, fills both Kitty
/// stacks, designates every charset and sets margins with origin mode. The
/// tail must still fit, or the repaint would fall back to a blank screen.
/// Prints the tail's size for the record.
#[test]
fn a_program_that_flips_every_mode_still_gets_its_repaint() {
    let every = [
        b"\x1b[>31u\x1b[>30u\x1b[?1049h\x1b[?1047h\x1b[?47h".as_slice(),
        b"\x1b[2h\x1b[4h\x1b[12l\x1b[20h",
        b"\x1b[?1h\x1b[?4h\x1b[?5h\x1b[?7l\x1b[?8h\x1b[?12h\x1b[?25l\x1b[?40h\x1b[?45h\x1b[?66h\x1b[?67h",
        b"\x1b[?9h\x1b[?1002h\x1b[?1003h\x1b[?1000h\x1b[?1005h\x1b[?1015h\x1b[?1016h\x1b[?1006h",
        b"\x1b[?1004h\x1b[?1007l\x1b[?1035l\x1b[?1036l\x1b[?1039h\x1b[?1045h",
        b"\x1b[?2004h\x1b[?2027h\x1b[?2031h\x1b[?2033h\x1b[?2048h\x1b[?5522h",
        b"\x1b[>4;2m\x1b[>1s\x1b[2 q",
        b"\x1b[>31u\x1b[>30u\x1b[>29u\x1b[>28u\x1b[>27u\x1b[>26u\x1b[>25u\x1b[>24u\x1b[>23u",
        b"\x1b(0\x1b)0\x1b*A\x1b+0\x0e\x1b~",
        b"\x1b[?69h\x1b[10;70s\x1b[5;20r\x1b[?6h\x1b[3;4H",
    ]
    .concat();
    let mut host = reset_terminal(80, 24);
    host.process(&every);
    let repaint = host.approximate_snapshot();
    let mut viewer = stale_viewer();
    viewer.process(&repaint);
    assert_eq!(
        approximate_mismatch(&host, &viewer),
        0,
        "every mode flipped"
    );
    let later = b"qx\x1b[1;1HY\x1b[<u\x1b[?1049l\x1b[<uZ";
    host.process(later);
    viewer.process(later);
    assert_eq!(
        approximate_mismatch(&host, &viewer),
        0,
        "after later output"
    );
    let mut blank = reset_terminal(80, 24);
    blank.process(b"\x1b[?1049h");
    eprintln!(
        "J824 every-mode repaint {} B, alternate-screen blank {} B",
        repaint.len(),
        blank.approximate_snapshot().len()
    );
}
