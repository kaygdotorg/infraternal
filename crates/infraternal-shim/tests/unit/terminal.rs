//! Terminal regression and measurement harness, separated from production code [40].
use super::*;

// A wire Snapshot begins with RIS. Keep faithful-repaint fixtures in that
// canonical context; fresh C initialization has a distinct redraw default,
// covered by an explicit rejection regression rather than normalized away.
fn reset_terminal(cols: u16, rows: u16) -> std::io::Result<Terminal> {
    let mut terminal = Terminal::new(cols, rows)?;
    terminal.process(b"\x1bc");
    Ok(terminal)
}

#[cfg(test)]
mod tests {
    //! Exercises terminal invariants against real data and frozen expectations.
    use super::*;
    #[test]
    fn fixtures_and_continuations_repaint() {
        for name in ["vim", "htop", "less", "unicode"] {
            let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
            let bytes = std::fs::read(dir.join(format!("{name}.vt"))).unwrap();
            let continuation = std::fs::read(dir.join(format!("{name}.continue.vt"))).unwrap();
            let mut original = reset_terminal(200, 60).unwrap();
            original.process(&bytes);
            let mut restored = reset_terminal(200, 60).unwrap();
            restored.process(&original.snapshot().unwrap());
            compare(&original, &restored, name);
            original.process(&continuation);
            restored.process(&continuation);
            compare(&original, &restored, name);
        }
    }
    #[test]
    fn alternate_variants_and_nested_switches_repaint() {
        for mode in [47, 1047, 1049] {
            for nested in [false, true] {
                let prefix = format!("PRIMARY\x1b[?{mode}hALTERNATE");
                let mut a = reset_terminal(200, 60).unwrap();
                a.process(prefix.as_bytes());
                if nested {
                    a.process(b"\x1b[?1049hNESTED\x1b[?47l\x1b[?1047l");
                }
                let mut b = reset_terminal(200, 60).unwrap();
                b.process(&a.snapshot().unwrap());
                compare(&a, &b, "alternate variant immediate");
                let suffix = format!("\x1b[?{mode}lX\x1b[?1049lY");
                a.process(suffix.as_bytes());
                b.process(suffix.as_bytes());
                compare(&a, &b, "alternate variant continuation");
            }
        }
    }
    #[test]
    fn margins_tabs_charsets_and_modes_continue() {
        let mut a = reset_terminal(200, 60).unwrap();
        a.process(b"PRIMARY\r\n\x1b[?1049h\x1b[3;50r\x1b[?6h\x1b[?2004h\x1b[?1006h\x1b[?1003h\x1b[5 q\x1b[3g\x1b[4;12H\x1bH\x1b(0lqqk\x1b7\x1b[10;1H");
        let mut b = reset_terminal(200, 60).unwrap();
        b.process(&a.snapshot().unwrap());
        compare(&a, &b, "modes");
        let suffix = b"\x1b8x\tqq\x1b[49;1Hlast\nscroll\x1b[?1049l";
        a.process(suffix);
        b.process(suffix);
        compare(&a, &b, "continued modes");
    }
    fn compare(a: &Terminal, b: &Terminal, name: &str) {
        assert_eq!(
            a.engine.difference(&b.engine),
            0,
            "{name}: native cell/style/cursor/mode difference"
        );
    }
    #[test]
    fn partial_csi_and_utf8_continue() {
        for (prefix, suffix) in [
            (b"hello\x1b[31".as_slice(), b"mX".as_slice()),
            (b"hello\xe2\x98", b"\x83"),
            (b"hello\x1b[\n31", b"mX"),
            (b"\x1b]4;1;rgb:ff/00/00\x1b", b"\\X"),
        ] {
            let mut a = reset_terminal(200, 60).unwrap();
            a.process(prefix);
            let mut b = reset_terminal(200, 60).unwrap();
            b.process(&a.snapshot().unwrap());
            a.process(suffix);
            b.process(suffix);
            compare(&a, &b, "partial");
        }
    }
    #[test]
    fn retained_alternate_saved_cursor_and_keyboard_stack_continue() {
        let mut a = reset_terminal(200, 60).unwrap();
        a.process(b"PRIMARY\x1b[?47h\x1b[31mALT\x1b7\x1b[?47l");
        for flags in 1..=12 {
            a.process(format!("\x1b[>{flags}u").as_bytes());
        }
        let mut b = reset_terminal(200, 60).unwrap();
        b.process(&a.snapshot().unwrap());
        compare(&a, &b, "inactive alternate and wrapped keyboard stack");
        for _ in 0..10 {
            a.process(b"\x1b[<u");
            b.process(b"\x1b[<u");
            compare(&a, &b, "keyboard pop continuation");
        }
        let suffix = b"\x1b[?47h\x1b8Z\x1b[?47l";
        a.process(suffix);
        b.process(suffix);
        compare(&a, &b, "inactive alternate saved cursor continuation");
    }
    #[test]
    fn pending_wrap_and_saved_wrap_continue_with_wide_cells() {
        for prefix in [
            "\x1b[1;200HX",
            "\x1b[1;199H界",
            "\x1b[1;199H界\x1b7\x1b[5;4H",
            "\x1b[?2027h\x1b[1;199H👩‍💻",
            "\x1b[?69h\x1b[4;40s\x1b[1;40HX\x1b7\x1b[5;4H",
            "\x1b[1;200HX\x1b[?7l",
        ] {
            let mut a = reset_terminal(200, 60).unwrap();
            a.process(prefix.as_bytes());
            let mut b = reset_terminal(200, 60).unwrap();
            b.process(&a.snapshot().unwrap());
            compare(&a, &b, "wide pending wrap");
            let suffix = "e\u{301}界\x1b8Z".as_bytes();
            a.process(suffix);
            b.process(suffix);
            compare(
                &a,
                &b,
                &format!("wide saved wrap continuation for {prefix:?}"),
            );
        }
    }
    #[test]
    fn long_unfinished_hyperlink_and_control_strings_continue() {
        for opener in [
            b"\x1b]8;id=carry;https://example.org/".as_slice(),
            b"\x1b]2;",
        ] {
            let mut prefix = opener.to_vec();
            prefix.extend_from_slice(&vec![b'x'; 8000]);
            let mut a = reset_terminal(200, 60).unwrap();
            a.process(&prefix);
            let mut b = reset_terminal(200, 60).unwrap();
            b.process(&a.snapshot().unwrap());
            a.process(b"\x1b\\linked");
            b.process(b"\x1b\\linked");
            compare(&a, &b, "long unfinished OSC");
        }
        for (prefix, suffix) in [
            (b"hello\x1bP1$q".as_slice(), b"m\x1b\\X".as_slice()),
            (b"hello\x1b_ignored", b"\x1b\\X"),
            (b"hello\x1b]8;;https://example.org", b"\x07X"),
        ] {
            let mut a = reset_terminal(200, 60).unwrap();
            a.process(prefix);
            let mut b = reset_terminal(200, 60).unwrap();
            b.process(&a.snapshot().unwrap());
            a.process(suffix);
            b.process(suffix);
            compare(&a, &b, "control string carry");
        }
    }
    #[test]
    fn unfinished_sequence_over_frame_limit_fails_without_losing_runtime_state() {
        let mut a = reset_terminal(200, 60).unwrap();
        a.process(b"\x1b]2;");
        a.process(&vec![b'x'; MAX_FRAME]);
        assert!(a.snapshot().is_err());
        a.process(b"\x1b\\OK");
        let mut b = reset_terminal(200, 60).unwrap();
        b.process(&a.snapshot().unwrap());
        compare(&a, &b, "oversized carry completed");
    }
    /// Keeps byte-bounded history repaintable after a geometry change.
    #[test]
    fn byte_budget_prunes_history_and_resize_remains_repaintable() {
        let mut a = reset_terminal(200, 60).unwrap();
        a.process(&b"typical ASCII output\r\n".repeat(100_000));
        let history = a.engine.history_rows().unwrap();
        assert!(
            (5000..20000).contains(&history),
            "17 MiB budget retained {history} rows"
        );
        a.resize(120, 40).unwrap();
        let mut b = reset_terminal(120, 40).unwrap();
        b.process(&a.snapshot().unwrap());
        compare(&a, &b, "resize with byte-bounded history");
        a.process(b"\tX\r\nZ");
        b.process(b"\tX\r\nZ");
        compare(&a, &b, "resize continuation");
    }
    #[test]
    fn saved_origin_survives_changed_margins() {
        for prefix in [
            b"\x1b[3;50r\x1b[?6h\x1b[4;12HX\x1b7\x1b[20;40r\x1b[?6l\x1b[1;1H".as_slice(),
            b"\x1b[?69h\x1b[4;100s\x1b[3;50r\x1b[?6h\x1b[4;12HX\x1b7\x1b[10;2H",
        ] {
            let mut a = reset_terminal(200, 60).unwrap();
            a.process(prefix);
            let mut b = reset_terminal(200, 60).unwrap();
            b.process(&a.snapshot().unwrap());
            compare(&a, &b, "origin and margins repaint");
            a.process(b"\x1b8Z");
            b.process(b"\x1b8Z");
            compare(&a, &b, "saved origin and changed margins continuation");
        }
    }
    #[test]
    fn implicit_hyperlinks_retain_groups_across_rows_and_continuation() {
        let mut a = reset_terminal(200, 60).unwrap();
        a.process(b"\x1b]8;;https://example.org/implicit\x1b\\A\r\nB");
        let mut b = reset_terminal(200, 60).unwrap();
        b.process(&a.snapshot().unwrap());
        compare(&a, &b, "implicit multi-row link");
        a.process(b"C");
        b.process(b"C");
        compare(&a, &b, "active implicit link continuation");
    }
}

#[test]
fn approximate_repaint_is_bounded_clips_at_complete_cells_and_preserves_source() {
    let mut source = Terminal::new(1000, 200).unwrap();
    let mut control = Terminal::new(1000, 200).unwrap();
    let line = format!(
        "{}e\u{301}X",
        "\x1b[38;2;123;234;45m界\x1b[38;2;67;89;101m色".repeat(249)
    );
    let input = format!(
        "\x1bc{}",
        std::iter::repeat_n(line, 200)
            .collect::<Vec<_>>()
            .join("\r\n")
    );
    source.process(input.as_bytes());
    control.process(input.as_bytes());
    assert!(
        matches!(source.snapshot(), Err(error) if error.kind() != std::io::ErrorKind::Unsupported),
        "alternating-color maximum-size screen must exercise frame capacity fallback"
    );
    let output = source.approximate_snapshot();
    assert!(
        output.len() <= MAX_FRAME - 10,
        "negotiated bound includes flags and sequence"
    );
    assert!(
        std::str::from_utf8(&output).is_ok(),
        "clipping never splits UTF-8"
    );
    let mut viewer = Terminal::new(1000, 200).unwrap();
    viewer.process(&output);
    assert!(
        viewer.pending.is_empty(),
        "clipped repaint ends in parser ground state"
    );
    viewer.process(b"\x1b[1;1HCLIP_CONTINUATION");
    source.process(b"\x1b[2bX");
    control.process(b"\x1b[2bX");
    assert_eq!(
        source.engine.state_difference(&control.engine),
        0,
        "approximation leaves the live source untouched"
    );
}

#[test]
fn approximate_repaint_keeps_complete_pending_syntax_or_omits_it_whole() {
    let mut source = Terminal::new(12, 5).unwrap();
    source.process(b"\x1bc\x1b]2;unfinished");
    let output = source.approximate_snapshot();
    assert!(
        output.ends_with(b"\x1b]2;unfinished"),
        "bounded pending syntax survives fallback"
    );
    source.process(&b"x".repeat(MAX_FRAME));
    let output = source.approximate_snapshot();
    assert!(output.len() <= MAX_FRAME - 10);
    assert!(
        !output.ends_with(b"unfinished"),
        "oversized control string is omitted as one unit"
    );
}

// A shared host cannot let either the native parser or its carry observer
// retain an adversarial string past the per-session control-string budget.
#[cfg(feature = "process-per-user")]
#[test]
fn control_strings_cannot_grow_session_carry_without_bound() {
    for introducer in *b"]P_^X" {
        let mut terminal = Terminal::with_history_budget(80, 24, 65536).unwrap();
        terminal.process(&[0x1b, introducer]);
        for _ in 0..256 {
            terminal.process(&[b'x'; 8192]);
        }
        assert!(
            terminal.pending.capacity() <= 4096,
            "string {introducer}: carry allocated {} bytes",
            terminal.pending.capacity()
        );
        // A small Rust carry alone does not establish native isolation: the
        // selected engine owns its own control-string and metadata storage.
        let (ordinary, _, _, _, carry) = terminal.ownership().unwrap();
        assert!(
            ordinary <= 256 * 1024,
            "native metadata exceeded its session share"
        );
        assert!(
            carry <= 4096,
            "accounted parser carry exceeded its session share"
        );
        assert!(
            !terminal.memory().2,
            "string {introducer}: streaming discard reached native allocation refusal"
        );
        terminal.process(b"\x1b\\after\x1b[31mred");
        assert!(
            terminal.pending.is_empty(),
            "discard state failed to terminate"
        );
        let mut expected = Terminal::with_history_budget(80, 24, 65536).unwrap();
        expected.process(b"after\x1b[31mred");
        assert_eq!(
            terminal.research_state_difference(&expected),
            0,
            "string {introducer}: discarded string escaped into display or lost following CSI"
        );
    }
}

#[cfg(feature = "process-per-user")]
#[test]
fn snapshot_during_discard_preserves_the_unfinished_string_boundary() {
    for mid in [b"".as_slice(), b"\x1b".as_slice()] {
        let mut original = Terminal::with_history_budget(80, 24, 65536).unwrap();
        original.process(b"\x1bcVISIBLE\x1b]0;");
        original.process(&[b'x'; 8192]);
        original.process(mid);
        let mut restored = Terminal::with_history_budget(80, 24, 65536).unwrap();
        restored.process(&original.snapshot().unwrap());
        // A snapshot in the middle of ST retains the dropped ESC too. The
        // following live wire contains only the as-yet-unreceived suffix.
        let suffix = if mid.is_empty() {
            b"tail-that-must-stay-in-the-string\x1b\\AFTER".as_slice()
        } else {
            b"\\AFTER".as_slice()
        };
        original.process(suffix);
        restored.process(suffix);
        assert_eq!(
            original.research_state_difference(&restored),
            0,
            "split ST: {mid:?}"
        );
    }
}
