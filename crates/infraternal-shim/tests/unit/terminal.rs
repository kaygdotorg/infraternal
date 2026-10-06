//! Terminal regression and measurement harness, separated from production code [40].
use super::*;
#[cfg(test)]
mod tests {
    //! Exercises terminal invariants against real data and frozen expectations.
    use super::*;
    #[test]
    fn fixtures_and_continuations_repaint() {
        for name in ["vim", "htop", "less"] {
            let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
            let bytes = std::fs::read(dir.join(format!("{name}.vt"))).unwrap();
            let continuation = std::fs::read(dir.join(format!("{name}.continue.vt"))).unwrap();
            let mut original = Terminal::new(200, 60).unwrap();
            original.process(&bytes);
            let mut restored = Terminal::new(200, 60).unwrap();
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
                let mut a = Terminal::new(200, 60).unwrap();
                a.process(prefix.as_bytes());
                if nested {
                    a.process(b"\x1b[?1049hNESTED\x1b[?47l\x1b[?1047l");
                }
                let mut b = Terminal::new(200, 60).unwrap();
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
        let mut a = Terminal::new(200, 60).unwrap();
        a.process(b"PRIMARY\r\n\x1b[?1049h\x1b[3;50r\x1b[?6h\x1b[?2004h\x1b[?1006h\x1b[?1003h\x1b[5 q\x1b[3g\x1b[4;12H\x1bH\x1b(0lqqk\x1b7\x1b[10;1H");
        let mut b = Terminal::new(200, 60).unwrap();
        b.process(&a.snapshot().unwrap());
        compare(&a, &b, "modes");
        let suffix = b"\x1b8x\tqq\x1b[49;1Hlast\nscroll\x1b[?1049l";
        a.process(suffix);
        b.process(suffix);
        compare(&a, &b, "continued modes");
    }
    fn compare(a: &Terminal, b: &Terminal, name: &str) {
        for line in 0..60 {
            for col in 0..200 {
                let x = &a.term.grid()[Line(line)][Column(col)];
                let y = &b.term.grid()[Line(line)][Column(col)];
                assert_eq!(
                    (x.c, x.fg, x.bg, x.flags),
                    (y.c, y.fg, y.bg, y.flags),
                    "{name} {line}:{col}"
                );
            }
        }
        assert_eq!(
            a.term.grid().cursor.point,
            b.term.grid().cursor.point,
            "{name}"
        );
        assert_eq!(a.term.mode(), b.term.mode(), "{name}");
        for index in 0..=258 {
            assert_eq!(
                a.term.colors()[index],
                b.term.colors()[index],
                "{name} palette {index}"
            );
        }
    }
    #[test]
    fn partial_csi_and_utf8_continue() {
        for (prefix, suffix) in [
            (b"hello\x1b[31".as_slice(), b"mX".as_slice()),
            (b"hello\xe2\x98", b"\x83"),
            (b"hello\x1b[\n31", b"mX"),
            (b"\x1b]4;1;rgb:ff/00/00\x1b", b"\\X"),
        ] {
            let mut a = Terminal::new(200, 60).unwrap();
            a.process(prefix);
            let mut b = Terminal::new(200, 60).unwrap();
            b.process(&a.snapshot().unwrap());
            a.process(suffix);
            b.process(suffix);
            compare(&a, &b, "partial");
        }
    }
}
