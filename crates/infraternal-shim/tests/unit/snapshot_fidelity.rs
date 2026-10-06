//! Differential replay checks for future-output state, with deterministic case IDs [13][40].
use super::*;

fn replay(name: &str, prefix: &[u8], cols: u16, rows: u16) {
    let mut a = Terminal::new(cols, rows).unwrap();
    a.process(prefix);
    let mut b = Terminal::new(cols, rows).unwrap();
    b.process(&a.snapshot().unwrap());
    assert_eq!(
        a.engine.state_difference(&b.engine),
        0,
        "{name}: immediate state"
    );
    // REP runs before any print can hide a wrong source; then exercise wrap,
    // saved cursor, tabs and a newline at the region bottom on both screens.
    for continuation in [
        b"\x1b[2b".as_slice(),
        "e\u{301}界👩‍💻".as_bytes(),
        b"\t\x1b8\nZ",
        b"\x1b[?47h\x1b8\t\nQ\x1b[?47l",
    ] {
        a.process(continuation);
        b.process(continuation);
        assert_eq!(
            a.engine.state_difference(&b.engine),
            0,
            "{name}: continuation state"
        );
    }
}

#[test]
fn fidelity_f1_rep() {
    replay("F1-alternate-rep", b"\x1b[?47hALT\x1b[?47lMAIN", 12, 5);
}
#[test]
fn fidelity_cursor() {
    replay(
        "saved-origin-outside-region",
        "\x1b[?6h\x1b7\x1b[2;4r\x1b8🙂".as_bytes(),
        12,
        5,
    );
}
#[test]
fn fidelity_edge() {
    replay(
        "wrapped-head-before-region-change",
        "\x1b[31;4:3m\x1b[?6h\x1b[1;12H\x1b[?2027h👩‍💻\x1b[2;4r\x1b[31;4:3mabc".as_bytes(),
        12,
        5,
    );
}

#[test]
#[ignore = "red regression: enable after adapter fixes"]
fn fidelity_handwritten() {
    for (name, input) in [
        ("F1-alternate-rep", "\x1b[?47hALT\x1b[?47lMAIN"),
        ("cursor-after-rep", "last\x1b[2;4H"),
        ("line-edge-wide", "\x1b[1;12H界"),
        ("line-edge-combining", "\x1b[1;12He\u{301}"),
        ("line-edge-zwj", "\x1b[?2027h\x1b[1;11H👩‍💻"),
        ("saved-origin-region", "\x1b[2;4r\x1b[?6h\x1b[3;3HX\x1b7"),
        ("custom-tabs", "\x1b[3g\x1b[1;3H\x1bH\x1b[1;9H\x1bHtext"),
        (
            "style-link",
            "\x1b[38;2;12;34;56;4:3m\x1b]8;id=case;https://example.org\x1b\\色🙂\x1b[5 q\x1b[?25l",
        ),
        ("erased-rep-source", "X\x1b[2J"),
    ] {
        replay(name, input.as_bytes(), 12, 5);
    }
}

fn generated(count: usize) {
    let tokens = [
        "abc",
        "界",
        "🙂",
        "e\u{301}",
        "\x1b[?2027h👩‍💻",
        "\r\n",
        "\t",
        "\x1b[2b",
        "\x1b[1;12H",
        "\x1b[3;11H",
        "\x1b[2;4r",
        "\x1b[r",
        "\x1b[?6h",
        "\x1b[?6l",
        "\x1b7",
        "\x1b8",
        "\x1b[?47h",
        "\x1b[?47l",
        "\x1b[31;4:3m",
        "\x1b[0m",
        "\x1b[3g",
        "\x1bH",
        "\x1b[2J",
        "\x1b[?7l",
        "\x1b[?7h",
    ];
    let mut seed = 0x2260_1006_u64;
    for case in 0..count {
        let mut input = Vec::new();
        for _ in 0..24 {
            // xorshift64 uses a fixed nonzero seed; case IDs reproduce failures
            // without ever putting terminal payloads in assertion output.
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let index = usize::try_from(seed % u64::try_from(tokens.len()).unwrap()).unwrap();
            input.extend_from_slice(tokens[index].as_bytes());
        }
        replay(&format!("seed-22601006-case-{case}"), &input, 12, 5);
    }
}

#[test]
#[ignore = "red regression: enable after adapter fixes"]
fn fidelity_seeded_smoke() {
    generated(1000);
}

#[test]
#[ignore = "nightly differential corpus: 20,000 deterministic cases"]
fn fidelity_seeded_nightly() {
    generated(20_000);
}

#[test]
fn fidelity_spacer_head_attributes() {
    replay(
        "spacer-head-independent-attributes",
        "\x1b[1;12H界\x1b[31;4:3m\x1b]8;id=edge;https://example.org\x1b\\\x1b[2;1H界".as_bytes(),
        12,
        5,
    );
}

#[test]
#[ignore = "red regression: enable after orphaned-head fix"]
fn fidelity_orphaned_spacer_head() {
    replay(
        "spacer-head-after-region-scroll",
        "\x1b[1;12H界\x1b[2;4r\x1b[4;1H\n".as_bytes(),
        12,
        5,
    );
}

#[test]
fn fidelity_saved_cursor_over_changed_edge() {
    replay(
        "saved-wrap-over-spacer-head",
        "\x1b[1;12HX\x1b7\x1b[1;12H界".as_bytes(),
        12,
        5,
    );
}
