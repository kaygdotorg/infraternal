//! Fuzz complete payloads and fragmented/coalesced stream framing [12][40].
#![no_main]
#![forbid(unsafe_code)]
use infraternal_shim::frame::{Decoder, Frame, FrameRef};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    assert_eq!(
        FrameRef::decode(bytes).map(FrameRef::into_owned).ok(),
        Frame::decode(bytes).ok()
    );
    if let Ok(frame) = Frame::decode(bytes)
        && let Ok(wire) = frame.encode()
    {
        assert_eq!(Frame::decode(&wire[4..]).ok(), Some(frame));
    }
    for chunk in [1, 3, 17, 16384] {
        let mut decoder = Decoder::default();
        let mut expected = Vec::new();
        let mut expected_error = false;
        for part in bytes.chunks(chunk) {
            if decoder
                .feed_with(part, |frame| {
                    expected.push(frame.into_owned());
                    Ok(())
                })
                .is_err()
            {
                expected_error = true;
                break;
            }
        }
        let (actual, actual_error) = paused_frames(bytes, chunk);
        assert_eq!(actual, expected);
        assert_eq!(actual_error, expected_error);
    }
});

/// Every complete frame waits through two empty retries before admission. The
/// unconsumed socket suffix is then resumed, preserving malformed-prefix parity.
fn paused_frames(bytes: &[u8], chunk: usize) -> (Vec<Frame>, bool) {
    let mut decoder = Decoder::default();
    let mut frames = Vec::new();
    let mut failed = false;
    'parts: for part in bytes.chunks(chunk) {
        let mut rest = part;
        loop {
            let Ok(used) = decoder.feed_until(rest, |_| Ok(false)) else {
                failed = true;
                break 'parts;
            };
            assert!(used <= rest.len());
            rest = &rest[used..];
            for _ in 0..2 {
                let Ok(used) = decoder.feed_until(&[], |_| Ok(false)) else {
                    failed = true;
                    break 'parts;
                };
                assert_eq!(used, 0);
            }
            let mut admitted = 0;
            if decoder
                .feed_until(&[], |frame| {
                    frames.push(frame.into_owned());
                    admitted += 1;
                    Ok(true)
                })
                .is_err()
            {
                failed = true;
                break 'parts;
            }
            assert!(admitted <= 1);
            if rest.is_empty() {
                break;
            }
            // Either wire bytes or the one decoder-owned frame must progress.
            // This bounds retries by bytes plus frames, including coalesced data.
            assert!(used > 0 || admitted == 1);
        }
    }
    (frames, failed)
}
