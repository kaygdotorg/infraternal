//! Last-good-size reconstruction and explicit fidelity after resize errors [13][40].
use super::*;

fn fixture() -> (Terminal, Ring) {
    let mut terminal = Terminal::new(80, 24).unwrap();
    let mut ring = Ring::new(4096);
    let bytes = b"\x1bcPRIMARY\x1b[?47hALT\x1b[?47l\x1b[?1003h\x1b[?1006h\x1b[38;2;";
    terminal.process(bytes);
    ring.append(bytes).unwrap();
    (terminal, ring)
}

#[test]
fn complete_ring_restores_screens_mouse_and_unfinished_syntax() {
    let (mut terminal, ring) = fixture();
    let (mut control, _) = fixture();
    // No-op size writes do not invalidate the geometry coverage certificate.
    terminal.resize(80, 24).unwrap();
    assert!(terminal.resize_with_ring(0, 24, Some(&ring)).is_err());
    assert_eq!(terminal.dimensions, (80, 24));
    assert_eq!(terminal.engine.state_difference(&control.engine), 0);
    assert!(terminal.snapshot().is_ok());
    for bytes in [b"1;2;3mZ".as_slice(), b"\x1b[?47h\x1b[2b\x1b[?47l"] {
        terminal.process(bytes);
        control.process(bytes);
        assert_eq!(terminal.engine.state_difference(&control.engine), 0);
    }
}

#[test]
fn ring_gap_requires_clean_approximate_recovery() {
    let (mut terminal, _) = fixture();
    let mut ring = Ring::new(4);
    ring.append(b"older retained output").unwrap();
    assert!(ring.start() > 0);
    assert!(terminal.resize_with_ring(0, 24, Some(&ring)).is_err());
    let mut control = Terminal::new(80, 24).unwrap();
    control.process(b"\x1bc");
    assert_eq!(terminal.engine.state_difference(&control.engine), 0);
    assert_eq!(
        terminal.snapshot().unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert_ne!(terminal.approximate_snapshot().len(), 0);
    terminal.process(b"later output");
    control.process(b"later output");
    assert_eq!(terminal.engine.state_difference(&control.engine), 0);
    assert!(
        terminal.snapshot().is_err(),
        "loss remains explicitly approximate"
    );
}

#[test]
fn earlier_geometry_changes_require_approximation_even_with_origin_coverage() {
    let (mut terminal, ring) = fixture();
    terminal.resize(40, 24).unwrap();
    assert_eq!(ring.start(), 0);
    assert!(terminal.resize_with_ring(0, 24, Some(&ring)).is_err());
    assert_eq!(terminal.dimensions, (40, 24));
    let mut control = Terminal::new(40, 24).unwrap();
    control.process(b"\x1bc");
    assert_eq!(terminal.engine.state_difference(&control.engine), 0);
    assert_eq!(
        terminal.snapshot().unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
}

#[test]
fn absent_ring_keeps_last_good_size_and_later_output_usable() {
    let (mut terminal, _) = fixture();
    assert!(terminal.resize(0, 24).is_err());
    terminal.process(b"continued output");
    terminal.resize(100, 30).unwrap();
    assert_eq!(terminal.dimensions, (100, 30));
    assert!(!terminal.recovery_pending);
    assert_eq!(
        terminal.snapshot().unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
}
