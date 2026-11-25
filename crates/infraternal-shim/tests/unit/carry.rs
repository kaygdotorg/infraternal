//! Checks that the carry shadow follows the engine's parser, byte for byte (#561).
use super::Carry;

/// Feeds `bytes` to a fresh shadow.
fn run(bytes: &[u8]) -> Carry {
    let mut carry = Carry::default();
    for &byte in bytes {
        let _ = carry.advance(byte);
    }
    carry
}

/// Text and finished sequences leave nothing to carry.
#[test]
fn plain_text_and_finished_sequences_end_at_ground() {
    assert!(run(b"hello \x1b[31mred\x1b[0m\x1b]0;title\x07 done").at_ground());
    assert!(run("héllo 界🙂".as_bytes()).at_ground());
}

/// Every kind of unfinished sequence, and a half-decoded character, is carried.
#[test]
fn unfinished_sequences_are_not_at_ground() {
    for input in [
        &b"\x1b"[..],
        b"\x1b[1;",
        b"\x1b]0;title",
        b"\x1bP1$r",
        b"\x1b_Gdata",
        b"\x1b(",
        &[0xe2, 0x82],
    ] {
        assert!(!run(input).at_ground(), "{input:?}");
    }
}

/// The reproducer behind #561: C1 bytes act inside a sequence.
#[test]
fn c1_bytes_end_or_restart_a_sequence_the_way_the_engine_does() {
    // 8-bit ST, and the other C1 controls, return to ground.
    for byte in [0x80, 0x84, 0x8f, 0x91, 0x97, 0x99, 0x9a, 0x9c] {
        assert!(run(&[0x1b, byte]).at_ground(), "ESC {byte:#x}");
        assert!(run(&[0x1b, b'[', b'1', byte]).at_ground(), "CSI {byte:#x}");
    }
    // The introducers start a new sequence, so the carry is not finished.
    for byte in [0x90, 0x98, 0x9b, 0x9d, 0x9e, 0x9f] {
        assert!(!run(&[0x1b, byte]).at_ground(), "ESC {byte:#x}");
    }
    // 0xA0 and up carry no meaning inside a CSI.
    assert!(!run(b"\x1b[1\xa0").at_ground());
}

/// A C1 introducer inside a sequence swaps it for the one it introduces.
#[test]
fn a_c1_introducer_converts_the_sequence_it_interrupts() {
    // CSI 0x9d starts an OSC; BEL then ends it.
    assert!(!run(b"\x1b[1\x9dtitle").at_ground());
    assert!(run(b"\x1b[1\x9dtitle\x07").at_ground());
    // 0x9b starts a CSI; a final byte ends it.
    assert!(run(b"\x1b]0;x\x1b\\\x1b[1\x9bm").at_ground());
}

/// OSC and DCS payload takes 8-bit bytes literally; CAN, SUB and 7-bit ST still end it.
#[test]
fn string_payload_keeps_its_high_bytes() {
    // OSC takes 0x20 and up as payload, even 8-bit ST.
    assert!(!run(b"\x1b]0;a\x9cb").at_ground());
    // DCS data and DCS ignore take 0x80 and up as payload.
    assert!(!run(b"\x1bP1p\x9c").at_ground());
    assert!(!run(b"\x1bP:\x9c\x9b").at_ground());
    // CAN and SUB still abort a string, and 7-bit ST still ends it.
    assert!(run(b"\x1b]0;a\x18").at_ground());
    assert!(run(b"\x1bP1p\x1a").at_ground());
    assert!(run(b"\x1b_x\x9cb\x1b\\").at_ground());
}

/// Strings are reported as strings, and only data strings keep their C0 bytes.
#[test]
fn strings_report_themselves_and_keep_their_c0_bytes() {
    assert!(run(b"\x1b]0;a").in_string());
    assert!(run(b"\x1bP1p").keeps_c0());
    assert!(run(b"\x1b_x").keeps_c0());
    assert!(!run(b"\x1b[1").in_string());
    assert!(!run(b"\x1b[1").keeps_c0());
}

/// Broken UTF-8 resolves the way the engine's decoder does.
#[test]
fn broken_utf8_is_replaced_the_way_the_engine_does() {
    // A truncated character ends at the next byte, which is then read again.
    assert!(run(b"\xe2\x82a").at_ground());
    assert!(
        !run(b"\xe2\x82\x1b").at_ground(),
        "ESC after a lead byte opens a sequence"
    );
    assert!(run(b"\xe2\x82\x1b\\").at_ground());
    // A stray continuation, an overlong lead and a C1 byte at ground do nothing.
    assert!(run(&[0x80, 0x9b, 0xc0, 0xc1, 0xf5, 0xff]).at_ground());
    // A C1 byte after a lead byte is just a continuation byte for it.
    assert!(!run(&[0xe2, 0x9b]).at_ground());
}

/// ESC inside a sequence starts over.
#[test]
fn escape_inside_a_sequence_restarts_it() {
    assert!(!run(b"\x1b[1\x1b").at_ground());
    assert!(run(b"\x1b[1\x1b[m").at_ground());
}

/// An ill-formed character is replaced once by the engine; the byte that cut
/// it short is read again and the abandoned bytes must leave the carry.
#[test]
fn a_byte_that_cuts_a_character_short_restarts_the_carry() {
    let mut carry = Carry::default();
    assert!(!carry.advance(0xeb), "a lead byte opens a character");
    assert!(carry.advance(0xed), "another lead byte abandons it");
    assert!(
        carry.advance(b'a'),
        "ED wants 80-9F next, so 'a' abandons it too"
    );
    assert!(carry.at_ground());
    assert!(!carry.advance(0xe2));
    assert!(!carry.advance(0x82));
    assert!(
        !carry.advance(0xac),
        "a complete character is not a restart"
    );
    // A stray byte at ground is replaced and consumed: nothing was abandoned.
    assert!(!carry.advance(0x9b));
    assert!(!carry.advance(0xe2));
    assert!(
        carry.advance(0x1b),
        "ESC after a lead byte restarts, then opens a sequence"
    );
    assert!(!carry.at_ground());
}

/// The mirror names the engine release it was checked against, and that must
/// be the release `scripts/build-vt` builds. Moving the engine without
/// re-checking the mirror fails here (see the module docs of `carry`).
#[test]
fn the_mirror_matches_the_pinned_engine_release() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/build-vt");
    let text = std::fs::read_to_string(script).unwrap();
    let pinned = text
        .lines()
        .find_map(|line| line.strip_prefix("version="))
        .expect("scripts/build-vt pins a version");
    assert_eq!(
        pinned,
        super::MIRRORED_ENGINE,
        "the engine moved: diff its parser and UTF-8 decoder, update carry.rs, then MIRRORED_ENGINE"
    );
}
