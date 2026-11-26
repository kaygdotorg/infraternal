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
    /// A combined phone rotation pulls history into the newly available rows.
    #[test]
    fn growing_rows_while_shrinking_columns_pulls_scrollback() {
        let mut combined = reset_terminal(5, 2).unwrap();
        let mut separate = reset_terminal(5, 2).unwrap();
        for terminal in [&mut combined, &mut separate] {
            terminal.process(b"1A\r\n2B\r\n3C\r\n");
        }
        combined.resize(4, 4).unwrap();
        separate.resize(5, 4).unwrap();
        separate.resize(4, 4).unwrap();
        assert_eq!(combined.engine.history_rows().unwrap(), 0);
        compare(&combined, &separate, "combined rotation pulls scrollback");
    }

    /// Repeated rotations retain cursor pins with reflow enabled or disabled on both screens.
    #[test]
    fn repeated_phone_rotations_with_scrollback_remain_repaintable() {
        for (alternate, wraparound) in [(false, true), (false, false), (true, true)] {
            let mut terminal = reset_terminal(80, 24).unwrap();
            if alternate {
                terminal.process(b"\x1b[?1049h");
            }
            // Disabling wraparound selects the native column-growth path
            // whose page backfill must remap cursor pins before freeing pages.
            if !wraparound {
                terminal.process(b"\x1b[?7l");
            }
            terminal.process(&"row 界 e\u{301}\r\n".repeat(2000).into_bytes());
            for cycle in 0..32 {
                for (cols, rows) in [(40, 48), (120, 16), (80, 24), (41, 47)] {
                    terminal.resize(cols, rows).unwrap();
                    terminal.process(format!("rotation {cycle}\r\n").as_bytes());
                    let mut restored = reset_terminal(cols, rows).unwrap();
                    restored.process(&terminal.snapshot().unwrap());
                    compare(&terminal, &restored, "rotation snapshot");
                    terminal.process(b"\x1b7X\x1b8Y\r\n");
                    restored.process(b"\x1b7X\x1b8Y\r\n");
                    compare(&terminal, &restored, "rotation cursor continuation");
                }
            }
        }
    }
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

/// #561: the carry follows the engine on C1 bytes inside a sequence. The
/// engine obeys 0x9C there (it ends the escape), so nothing is left to carry
/// and a snapshot must not repeat the text that followed it.
#[test]
fn carry_ends_where_the_engine_ends_a_sequence_on_a_c1_byte() {
    let mut terminal = reset_terminal(20, 3).unwrap();
    terminal.process(b"\x1b\x9c'");
    assert!(terminal.pending.is_empty(), "ESC 0x9C finished the escape");
    terminal.process(b"\x1b[1\x84X");
    assert!(terminal.pending.is_empty(), "a C1 control ends a CSI");
    // An introducer replaces the sequence it interrupts, and only it is carried,
    // as ESC plus its 7-bit letter: a viewer starts at ground, where 0x9B is not a CSI.
    terminal.process(b"\x1b[1;2\x9b3");
    assert_eq!(terminal.pending, b"\x1b[3", "carried in its 7-bit form");
    // Snapshot continuation itself is pinned by `vt_checks` and its fuzz target.
    terminal.process(b"m");
    assert!(terminal.pending.is_empty(), "the CSI ended");
}

/// C0 controls inside DCS or APC data are payload, so the carry keeps them;
/// inside a CSI the engine runs them, so the carry drops them.
#[test]
fn carry_keeps_c0_payload_of_strings_only() {
    let mut terminal = reset_terminal(20, 3).unwrap();
    terminal.process(b"\x1b[1\n2");
    assert_eq!(terminal.pending, b"\x1b[12");
    terminal.process(b"m\x1b_a\nb");
    assert_eq!(terminal.pending, b"\x1b_a\nb");
}

/// #594: the engine ends a control string at the ESC that follows it and runs
/// it there, so only what comes from that ESC on is unfinished. Keeping the
/// string made a viewer run it a second time, and let a run of strings without
/// a `\` grow the carry for ever.
#[test]
fn carry_drops_a_string_the_engine_ran_at_the_next_escape() {
    let mut terminal = reset_terminal(20, 3).unwrap();
    for (output, carried) in [
        (&b"\x1b]8;;http://a\x1b"[..], &b"\x1b"[..]),
        (b"P1$qm\x1b", b"\x1b"),
        (b"_apc\x1b[1;", b"\x1b[1;"),
        (b"m\x1b]0;one\x1b]0;two\x1bP", b"\x1bP"),
        // A C1 introducer ends a SOS, PM or APC string too, and starts anew.
        (b"\x1b\\\x1b_apc\x9dosc", b"\x1b]osc"),
        // The same bytes inside the string they continue stay where they are:
        // payload of an OSC or DCS data, or more of an APC.
        (b"\x07\x1b]0;\xc2\x9d", b"\x1b]0;\xc2\x9d"),
        (b"\x07\x1b_a\x9fb", b"\x1b_a\x9fb"),
    ] {
        terminal.process(output);
        assert_eq!(terminal.pending, carried, "after {}", output.escape_ascii());
    }
}

/// #594: a viewer rebuilt while the next string is unfinished keeps the link
/// the engine opened at the ESC, under the same implicit id, and a snapshot
/// taken between the ESC and the `\` of a terminator resumes on the `\`.
#[test]
fn a_viewer_does_not_open_an_already_opened_link_again() {
    for (prefix, suffix) in [
        (
            &b"\x1b]8;;http://a\x1b\\A\x1b]8;;http://b\x1bP1$"[..],
            &b"r\x1b\\B"[..],
        ),
        (b"\x1b]8;;http://a\x1b\\A\x1b]8;;http://b\x1b", b"\\B"),
    ] {
        let mut original = reset_terminal(20, 3).unwrap();
        original.process(prefix);
        let mut viewer = reset_terminal(20, 3).unwrap();
        viewer.process(&original.snapshot().unwrap());
        original.process(suffix);
        viewer.process(suffix);
        assert_eq!(
            original.snapshot().unwrap(),
            viewer.snapshot().unwrap(),
            "{}",
            prefix.escape_ascii()
        );
    }
}

/// #561: bytes of a UTF-8 character the engine already replaced must leave
/// the carry, or a viewer prints the replacement character a second time.
#[test]
fn carry_drops_utf8_bytes_the_engine_already_replaced() {
    let mut terminal = reset_terminal(20, 3).unwrap();
    terminal.process(&[0xeb, 0xed]);
    assert_eq!(terminal.pending, [0xed], "EB was replaced when ED arrived");
    terminal.process(b"\xbc");
    assert!(terminal.pending.is_empty(), "ED then BC: both replaced");
    terminal.process(&[0xe2, 0x82]);
    assert_eq!(terminal.pending, [0xe2, 0x82]);
    terminal.process(&[0xac]);
    assert_eq!(terminal.pending, [] as [u8; 0]);
}

/// #575 with #561: under libghostty-vt 1.0.2 the painter keeps a soft wrap into
/// a dropped row by scrolling a one-line region (delete-line would now end the
/// wrap). The carry is appended after that repaint, so a viewer must replay the
/// region scroll and then resume each kind of unfinished sequence exactly where
/// the original stands: the same cells, wrap flags and spacer head, and the
/// same parser state for the rest of the stream.
#[test]
fn carry_resumes_after_a_region_scroll_repaint_of_a_kept_wrap() {
    // A wide glyph at the last column wraps row 1 into row 2 (row 1 keeps a
    // spacer head); scrolling region 2-4 then drops row 2 but not the wrap.
    let setup = "\x1b[1;12H界\x1b[2;4r\x1b[4;1H\n".as_bytes();
    for (pending, rest) in [
        (&b"\x1b]0;tit"[..], &b"le\x07after"[..]),
        (b"\x1b[3", b"1mred"),
        (b"\x1bP1$", b"r\x1b\\x"),
        (&[0xe2, 0x82][..], &[0xac, b'!'][..]),
    ] {
        let mut original = reset_terminal(12, 5).unwrap();
        original.process(setup);
        original.process(pending);
        assert_eq!(original.pending, pending, "carried as written");
        let snapshot = original.snapshot().unwrap();
        // CSI 2;5 r is the painter's region scroll for the row after row 1.
        assert!(
            snapshot.windows(6).any(|w| w == b"\x1b[2;5r"),
            "the repaint kept the wrap with a region scroll"
        );
        assert!(snapshot.ends_with(pending), "the carry follows the repaint");
        let mut viewer = Terminal::new(12, 5).unwrap();
        viewer.process(&snapshot);
        assert_eq!(
            viewer.pending, pending,
            "{pending:?}: the viewer resumes the carry"
        );
        original.process(rest);
        viewer.process(rest);
        assert_eq!(
            original.engine.difference(&viewer.engine),
            0,
            "{pending:?}: the viewer diverged after the carry finished"
        );
        assert_eq!(original.snapshot().unwrap(), viewer.snapshot().unwrap());
    }
}
