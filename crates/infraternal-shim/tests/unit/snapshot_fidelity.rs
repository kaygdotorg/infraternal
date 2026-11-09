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

// Preserve the pinned C constructor as a separately reported corpus context.
// Canonical fixtures deliberately use RIS; neither context changes production.
fn corpus_terminal(cols: u16, rows: u16) -> std::io::Result<Terminal> {
    if std::env::var("VT_SNAPSHOT_INITIAL").as_deref() == Ok("fresh-c") {
        Terminal::new(cols, rows)
    } else {
        reset_terminal(cols, rows)
    }
}

fn check_replay(
    name: &str,
    prefix: &[u8],
    recorded: Option<&[u8]>,
    cols: u16,
    rows: u16,
) -> std::io::Result<()> {
    let mut a = corpus_terminal(cols, rows).unwrap();
    a.process(prefix);
    let mut b = corpus_terminal(cols, rows).unwrap();
    let snapshot = a.snapshot()?;
    b.process(&snapshot);
    assert_eq!(
        a.engine.state_difference(&b.engine),
        0,
        "{name}: immediate state"
    );
    let right_margin = format!("\x1b[?6l\x1b[1;{cols}HXZ");
    // Every continuation starts from the original boundary. Cumulative probes
    // can overwrite the very state a later probe is intended to observe.
    let mut continuations = vec![
        b"\x1b[2b".as_slice(),
        "e\u{301}界👩‍💻".as_bytes(),
        b"\t\x1b8\nZ",
        right_margin.as_bytes(),
        b"\x1b[?6h\x1b[999;1H\nZ",
        b"\x1b[?47h\x1b8\t\nQ\x1b[?47l",
        b"\x1b[?1000r",
        b"\x1b[X\x1b[?2J",
        b"\x1b[<8u\x1b[?47h\x1b[<8u\x1b[?47l",
    ];
    if let Some(continuation) = recorded {
        continuations.push(continuation);
    }
    for (branch, continuation) in continuations.iter().enumerate() {
        let mut original = corpus_terminal(cols, rows).unwrap();
        original.process(prefix);
        let mut restored = corpus_terminal(cols, rows).unwrap();
        restored.process(&snapshot);
        original.process(continuation);
        restored.process(continuation);
        assert_eq!(
            original.engine.state_difference(&restored.engine),
            0,
            "{name}: continuation branch {branch}"
        );
    }
    for (next_cols, next_rows) in [(cols.max(2) / 2, rows), (cols + 3, rows + 1)] {
        let mut original = corpus_terminal(cols, rows).unwrap();
        original.process(prefix);
        let mut restored = corpus_terminal(cols, rows).unwrap();
        restored.process(&snapshot);
        original.resize(next_cols, next_rows).unwrap();
        restored.resize(next_cols, next_rows).unwrap();
        assert_eq!(
            original.engine.state_difference(&restored.engine),
            0,
            "{name}: resize {next_cols}x{next_rows}"
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

fn generated(count: usize, extended: bool) {
    let mut tokens = vec![
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
    if extended {
        tokens.extend([
            "\x1b[?1000h\x1b[?1000s\x1b[?1000l",
            "\x1b[?1000r",
            "\x1b(0",
            "\x1b(B",
            "\x1b*0\x1bN",
            "\x1bV",
            "\x1bW",
            "\x1b[1\"q",
            "\x1b[0\"q",
            "\x1b[>1u",
            "\x1b[>2u",
            "\x1b[<u",
            "\x1b]10;rgb:12/34/56\x07",
            "\x1b]11;rgb:65/43/21\x07",
            "\x1b]12;rgb:ab/cd/ef\x07",
            "\x1b]8;id=corpus;https://example.org\x1b\\",
            "\x1b]8;;\x1b\\",
            "\x1b]133;A;redraw=1\x07$ prompt",
            "\x1b]133;B\x07input",
            "\x1b]133;C\x07output",
        ]);
    }
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
        let name = format!("seed-22601006-extended-{extended}-case-{case}");
        if let Ok(directory) = std::env::var("VT_SNAPSHOT_CASES") {
            let root = std::path::Path::new(&directory);
            std::fs::create_dir_all(root).unwrap();
            std::fs::write(root.join(format!("{name}.vt")), &input).unwrap();
        }
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
        "snapshot corpus: cases={count} replayed={replayed} rejected={api_gaps} divergent=0 extended={extended} initial={} seed=22601006",
        if std::env::var("VT_SNAPSHOT_INITIAL").as_deref() == Ok("fresh-c") {
            "fresh-c"
        } else {
            "RIS"
        }
    );
    assert_eq!(replayed + api_gaps, count);
}

#[test]
fn fidelity_seeded_smoke() {
    generated(1000, false);
}

#[test]
#[ignore = "nightly differential corpus: 20,000 deterministic cases"]
fn fidelity_seeded_nightly() {
    generated(20_000, false);
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
/// Checks that an orphaned spacer head survives scrolling, later writes, and resize replay.
fn fidelity_orphaned_spacer_head_after_region_scroll_replays() {
    // The 1.0 grid keeps the orphaned spacer head representable through VT.
    // Check immediate state, future writes, and geometry changes together.
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

#[test]
fn fidelity_oracle_detects_hidden_state() {
    // Pair real engines directly: these probes test observation independently
    // of Snapshot construction, so a serializer bug cannot define equality.
    let probes: &[(&str, &[u8], &[u8])] = &[
        ("live charset", b"\x1b(0", b""),
        ("live single shift", b"\x1b*0\x1bN", b"\x1b*0"),
        ("live protection", b"\x1b[1\"q", b"\x1b[1\"q\x1b[0\"q"),
        (
            "live hyperlink",
            b"\x1b]8;id=a;https://example.org\x1b\\",
            b"\x1b]8;id=b;https://example.org\x1b\\",
        ),
        (
            "inactive keyboard ring",
            b"\x1b[?47h\x1b[>1u\x1b[>2u\x1b[?47l",
            b"\x1b[?47h\x1b[>3u\x1b[>2u\x1b[?47l",
        ),
        ("foreground color", b"\x1b]10;rgb:12/34/56\x07", b""),
        ("background color", b"\x1b]11;rgb:12/34/56\x07", b""),
        ("cursor color", b"\x1b]12;rgb:12/34/56\x07", b""),
        ("semantic content", b"\x1b]133;A;redraw=1\x07X", b"X"),
        ("saved mode", b"\x1b[?1000h\x1b[?1000s\x1b[?1000lX", b"X"),
        ("ISO protected mode", b"\x1bV\x1bW", b"\x1b[1\"q\x1b[0\"q"),
    ];
    for &(name, left, right) in probes {
        let mut a = reset_terminal(80, 24).unwrap();
        let mut b = reset_terminal(80, 24).unwrap();
        a.process(left);
        b.process(right);
        assert_ne!(
            a.engine.state_difference(&b.engine),
            0,
            "unchecked field: {name}"
        );
    }
}

#[test]
fn fidelity_extended_smoke() {
    generated(1000, true);
}

#[test]
#[ignore = "nightly expanded differential corpus: 20,000 deterministic cases"]
fn fidelity_extended_nightly() {
    generated(20_000, true);
}

#[test]
#[ignore = "diagnostic replay of an explicitly selected fixture file"]
fn fidelity_diagnostic_fixture() {
    let path = std::env::var("VT_SNAPSHOT_FIXTURE").expect("fixture path required");
    let input = std::fs::read(path).unwrap();
    match check_replay("diagnostic fixture", &input, None, 12, 5) {
        Ok(()) => {}
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::Unsupported),
    }
}

#[test]
fn fidelity_single_shift_survives_rep_seed() {
    check_replay("single-shift after ASCII", b"abc\x1b*0\x1bN", None, 12, 5).unwrap();
}

#[test]
fn fidelity_iso_protection_does_not_keep_rep_scratch() {
    check_replay(
        "protected DEC charset REP seed",
        b"\x1bV\x1b(0t",
        None,
        12,
        5,
    )
    .unwrap();
}

#[test]
/// Checks that shifted character sets preserve wide text through continuation and resize replay.
fn fidelity_charset_shifted_wide_text_replays() {
    // This 1.0 input is fully represented by the bounded painter; verify the
    // continuation and resize behavior instead of preserving an old rejection.
    let prefix = "\x1b*0\x1bN界".as_bytes();
    replay("charset-shifted-wide-text", prefix, 12, 5);
}

#[test]
fn fidelity_inherited_protection_off_mode_is_explicitly_rejected() {
    let prefix = b"\x1bV\x1b[?47h";
    let mut a = reset_terminal(12, 5).unwrap();
    a.process(prefix);
    assert!(
        matches!(a.snapshot(), Err(error) if error.kind() == std::io::ErrorKind::Unsupported),
        "protected cursor inherited into an off-mode screen needs explicit import"
    );
    let mut control = reset_terminal(12, 5).unwrap();
    control.process(prefix);
    a.process(b"X");
    control.process(b"X");
    assert_eq!(
        a.engine.state_difference(&control.engine),
        0,
        "rejection preserves inherited protection"
    );
}

/// Ensures restoring a bounded history tail adds no synthetic padding rows.
#[test]
fn fidelity_snapshot_history_tail_contains_no_padding_rows() {
    for lines in [7, 1005] {
        let mut source = reset_terminal(12, 5).unwrap();
        source.process(&b"line\r\n".repeat(lines));
        let expected = source.engine.history_rows().unwrap().min(256);
        let mut restored = reset_terminal(12, 5).unwrap();
        restored.process(&source.snapshot().unwrap());
        assert_eq!(
            restored.engine.history_rows().unwrap(),
            expected,
            "retained tail must not append blank padding to history"
        );
        assert_eq!(
            source.engine.state_difference(&restored.engine),
            0,
            "bounded history tail and active state must agree"
        );
    }
}

#[test]
fn fidelity_oracle_observes_archived_cells_with_equal_active_screens() {
    let mut a = reset_terminal(12, 5).unwrap();
    let mut b = reset_terminal(12, 5).unwrap();
    a.process(b"old A\r\n");
    b.process(b"old B\r\n");
    for terminal in [&mut a, &mut b] {
        terminal.process(b"\r\n\r\n\r\n\r\n\r\nQ\x1b[2J\x1b[1;1H");
    }
    assert_ne!(
        a.engine.state_difference(&b.engine),
        0,
        "archived cells are part of the retained-tail oracle scope"
    );
}

#[test]
fn fidelity_snapshot_resets_stale_viewer_color_overrides() {
    let mut source = reset_terminal(12, 5).unwrap();
    source.process(b"SOURCE");
    let snapshot = source.snapshot().unwrap();
    let mut viewer = reset_terminal(12, 5).unwrap();
    viewer.process(b"\x1b]4;3;rgb:11/22/33\x1b\\\x1b]10;rgb:44/55/66\x1b\\\x1b]11;rgb:77/88/99\x1b\\\x1b]12;rgb:aa/bb/cc\x1b\\");
    viewer.process(&snapshot);
    assert_eq!(
        source.engine.state_difference(&viewer.engine),
        0,
        "fresh source must clear stale palette and dynamic overrides in an existing viewer"
    );
}

#[test]
fn fidelity_screen_entry_consumes_inherited_shift_before_saving() {
    // Primary retains its unconsumed shift while alternate text consumes its
    // copy. Repaint must not inherit that shift into alternate DECSC state.
    for prefix in [
        "\x1b*0\x1bN\x1b[?47he\u{301}\x1b7",
        "\x1b*0\x1bN\x1b[?47h\x1b8\x1b7",
    ] {
        check_replay("screen-entry saved charset", prefix.as_bytes(), None, 12, 5).unwrap();
    }
}

#[test]
fn fidelity_semantic_validation_matches_exported_history_extent() {
    for lines in [20, 400] {
        // OSC 133 B tags input without marking the screen as a seen prompt.
        // C returns the live cursor to output. Only archived cell metadata
        // differs; old rows outside the bounded Snapshot tail are omitted.
        let mut prefix = b"\x1b]133;B\x07INPUT\x1b]133;C\x07\r\n".to_vec();
        prefix.extend_from_slice(&b"output\r\n".repeat(lines));
        if lines < 256 {
            let error = check_replay("retained semantic input", &prefix, None, 12, 5).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        } else {
            check_replay("omitted older semantic input", &prefix, None, 12, 5).unwrap();
        }
    }
}

#[test]
fn fidelity_mouse_effective_fields_follow_order_independently_of_booleans() {
    let pairs: &[(&[u8], &[u8])] = &[
        (b"\x1b[?1003h\x1b[?1000hX", b"\x1b[?1000h\x1b[?1003hX"),
        (b"\x1b[?1005h\x1b[?1006hX", b"\x1b[?1006h\x1b[?1005hX"),
        (b"\x1b[?1000h\x1b[?1002lX", b"\x1b[?1002l\x1b[?1000hX"),
        (b"\x1b[?1006h\x1b[?1005lX", b"\x1b[?1005l\x1b[?1006hX"),
    ];
    for (case, &(left, right)) in pairs.iter().enumerate() {
        let mut a = reset_terminal(80, 24).unwrap();
        let mut b = reset_terminal(80, 24).unwrap();
        a.process(left);
        b.process(right);
        assert_ne!(
            a.engine.state_difference(&b.engine),
            0,
            "effective mouse field {case}"
        );
        check_replay(&format!("mouse ordering left {case}"), left, None, 80, 24).unwrap();
        check_replay(&format!("mouse ordering right {case}"), right, None, 80, 24).unwrap();
    }
}

#[cfg(test)]
#[path = "fresh_captures.rs"]
mod fresh_captures;
