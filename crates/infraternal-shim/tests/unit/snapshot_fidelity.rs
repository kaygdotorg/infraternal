//! Differential replay checks for future-output state, with deterministic case IDs [13][40].
use super::*;

// A wire Snapshot begins with RIS. Keep faithful-repaint fixtures in that
// canonical context; fresh C initialization has a distinct redraw default,
// covered by an explicit rejection regression rather than normalized away.
fn reset_terminal(cols: u16, rows: u16) -> std::io::Result<Terminal> {
    let mut terminal = Terminal::new(cols, rows)?;
    terminal.process(b"\x1bc");
    Ok(terminal)
}

fn replay(name: &str, prefix: &[u8], cols: u16, rows: u16) {
    check_replay(name, prefix, None, cols, rows).unwrap_or_else(|error| panic!("{name}: {error}"));
}

fn check_replay(
    name: &str,
    prefix: &[u8],
    recorded: Option<&[u8]>,
    cols: u16,
    rows: u16,
) -> std::io::Result<()> {
    let mut a = reset_terminal(cols, rows).unwrap();
    a.process(prefix);
    let mut b = reset_terminal(cols, rows).unwrap();
    let snapshot = a.snapshot()?;
    b.process(&snapshot);
    assert_eq!(
        a.engine.state_difference(&b.engine),
        0,
        "{name}: immediate state"
    );
    if let Some(continuation) = recorded {
        a.process(continuation);
        b.process(continuation);
        assert_eq!(
            a.engine.state_difference(&b.engine),
            0,
            "{name}: recorded continuation"
        );
    }
    let right_margin = format!("\x1b[?6l\x1b[1;{cols}HXZ");
    // REP runs before any print can hide a wrong source; then exercise wrap,
    // saved cursor, tabs and a newline at the region bottom on both screens.
    for continuation in [
        b"\x1b[2b".as_slice(),
        "e\u{301}界👩‍💻".as_bytes(),
        b"\t\x1b8\nZ",
        right_margin.as_bytes(),
        b"\x1b[?6h\x1b[999;1H\nZ",
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
    Ok(())
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
        (
            "saved-wrap-independent-rep",
            "\x1b[1;12HX\x1b7\x1b[3;1HY\x1b8",
        ),
        ("erased-saved-wrap", "\x1b[1;12HX\x1b7\x1b[2J\x1b8"),
        ("ignored-wide-rep", "\x1b[1;12HX\x1b[?7l界"),
        ("wrapped-into-erased-row", "\x1b[1;12HXY\x1b[2K"),
        (
            "inactive-saved-margin-wrap",
            "\x1b[?69h\x1b[4;10s\x1b[?6h\x1b[1;7HX\x1b7\x1b[?47h\x1b[?69l\x1b[r\x1b[?6lALT",
        ),
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
    let mut replayed = 0;
    let mut api_gaps = 0;
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
        let name = format!("seed-22601006-case-{case}");
        match check_replay(&name, &input, None, 12, 5) {
            Ok(()) => replayed += 1,
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
                api_gaps += 1;
                if api_gaps == 1 {
                    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../../target/snapshot-fidelity");
                    std::fs::create_dir_all(&root).unwrap();
                    std::fs::write(root.join(format!("{name}-api-gap.vt")), &input).unwrap();
                }
            }
            Err(error) => panic!("{name}: unexpected snapshot error: {error}"),
        }
    }
    println!(
        "snapshot corpus: cases={count} replayed={replayed} explicit_api_gaps={api_gaps} seed=22601006"
    );
    assert_eq!(replayed + api_gaps, count);
}

#[test]
fn fidelity_seeded_smoke() {
    generated(1000);
}

#[test]
#[ignore = "nightly differential corpus: 20,000 deterministic cases"]
fn fidelity_seeded_nightly() {
    generated(20_000);
}

#[test]
fn fidelity_rejects_unrepresentable_rep_without_mutating_source() {
    // A full primary grid, a REP source retained only on alternate, and no
    // saved wrap anchor cannot be reconstructed using ordinary VT alone.
    let mut prefix = b"A".repeat(60);
    prefix.extend_from_slice(b"\x1b[?47hX\x1b[?47l");
    let mut a = reset_terminal(12, 5).unwrap();
    a.process(&prefix);
    let Err(rejection) = a.snapshot() else {
        panic!("API gap must reject the snapshot");
    };
    assert_eq!(rejection.kind(), std::io::ErrorKind::Unsupported);
    let mut control = reset_terminal(12, 5).unwrap();
    control.process(&prefix);
    a.process(b"\x1b[2b");
    control.process(b"\x1b[2b");
    assert_eq!(a.engine.state_difference(&control.engine), 0);
    // Once output provides an ordinary reconstructible source, snapshot
    // remains available: rejecting the gap never damages live terminal state.
    a.process(&b"\r\n".repeat(6));
    a.process(b"X");
    let mut restored = reset_terminal(12, 5).unwrap();
    restored.process(&a.snapshot().unwrap());
    assert_eq!(a.engine.state_difference(&restored.engine), 0);
}

#[test]
fn fidelity_recorded_corpus() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["vim", "htop", "less", "unicode"] {
        let prefix = std::fs::read(root.join(format!("tests/fixtures/{name}.vt"))).unwrap();
        let continuation =
            std::fs::read(root.join(format!("tests/fixtures/{name}.continue.vt"))).unwrap();
        check_replay(name, &prefix, Some(&continuation), 200, 60).unwrap();
    }
    // The supplied base has no spikes directory. Include any restored stress
    // corpus on subsequent runs, while reporting its coverage explicitly.
    let stress = root.join("../../spikes/stress");
    let mut fixtures = Vec::new();
    if stress.is_dir() {
        for entry in std::fs::read_dir(&stress).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                fixtures.push(entry.path());
            }
        }
    }
    fixtures.sort();
    for path in &fixtures {
        let prefix = std::fs::read(path).unwrap();
        check_replay(&path.display().to_string(), &prefix, None, 200, 60).unwrap();
    }
    println!(
        "recorded snapshot corpus: tracked_fixtures=4 stress_fixtures={}",
        fixtures.len()
    );
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
fn fidelity_orphaned_spacer_head() {
    // Region scrolling leaves an independent continuation flag on a blank
    // row. Without a nonprinting row-flag setter the bounded painter must
    // reject it, even though the visible spacer head can be reconstructed.
    let error = check_replay(
        "spacer-head-after-region-scroll",
        "\x1b[1;12H界\x1b[2;4r\x1b[4;1H\n".as_bytes(),
        None,
        12,
        5,
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
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

#[test]
fn fidelity_variation_tail_attributes() {
    replay("variation-tail-independent-attributes", "\x1b[?2027h❤\x1b[38;2;12;34;56;48;2;65;43;21;4:3m\x1b]8;id=tail;https://example.org/tail\x1b\\\u{fe0f}".as_bytes(), 12, 5);
}

#[test]
fn fidelity_variation_wrap_attributes() {
    replay("variation-wrap-direct", "\x1b[?2027h\x1b[1;12H❤\x1b[38;2;12;34;56;48;2;65;43;21;4:3m\x1b]8;id=tail;https://example.org/tail\x1b\\\u{fe0f}".as_bytes(), 12, 5);
    replay("variation-wrap-with-prior-combining", "\x1b[?2027h\x1b[1;12H❤\u{301}\x1b[38;2;12;34;56;48;2;65;43;21;4:3m\x1b]8;id=tail;https://example.org/tail\x1b\\\u{fe0f}".as_bytes(), 12, 5);
}

#[test]
fn fidelity_saved_modes_future_restore() {
    let mut a = reset_terminal(80, 24).unwrap();
    a.process(b"\x1b[?1000h\x1b[?1000s\x1b[?1000lX");
    let mut b = reset_terminal(80, 24).unwrap();
    b.process(&a.snapshot().unwrap());
    a.process(b"\x1b[?1000r");
    b.process(b"\x1b[?1000r");
    assert_eq!(
        a.engine.state_difference(&b.engine),
        0,
        "saved mouse mode restore"
    );
}

#[test]
fn fidelity_prompt_resize_requires_explicit_rejection() {
    let prefix = b"\x1b]133;A;redraw=1\x07$ hello";
    let mut a = reset_terminal(80, 24).unwrap();
    a.process(prefix);
    match a.snapshot() {
        Ok(snapshot) => {
            let mut b = reset_terminal(80, 24).unwrap();
            b.process(&snapshot);
            a.resize(40, 24).unwrap();
            b.resize(40, 24).unwrap();
            assert_eq!(
                a.engine.state_difference(&b.engine),
                0,
                "semantic resize continuation"
            );
            panic!("semantic state requires explicit rejection until lossless restore exists");
        }
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::Unsupported),
    }
    let mut control = reset_terminal(80, 24).unwrap();
    control.process(prefix);
    a.resize(40, 24).unwrap();
    control.resize(40, 24).unwrap();
    assert_eq!(
        a.engine.state_difference(&control.engine),
        0,
        "rejection leaves prompt resize intact"
    );
}

#[test]
fn fidelity_fresh_c_redraw_default_is_explicitly_rejected() {
    let a = Terminal::new(80, 24).unwrap();
    assert!(
        matches!(a.snapshot(), Err(e) if e.kind() == std::io::ErrorKind::Unsupported),
        "RIS changes the fresh C redraw default; faithful snapshot must reject"
    );
}

#[test]
fn fidelity_iso_protection_erase() {
    let mut a = reset_terminal(80, 24).unwrap();
    a.process(b"\x1bVX\x1bW\r");
    let mut b = reset_terminal(80, 24).unwrap();
    b.process(&a.snapshot().unwrap());
    a.process(b"\x1b[X");
    b.process(b"\x1b[X");
    assert_eq!(
        a.engine.state_difference(&b.engine),
        0,
        "ISO protected erase continuation"
    );
}
