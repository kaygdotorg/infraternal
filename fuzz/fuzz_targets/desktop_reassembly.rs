//! Fuzzes the desktop video reassembler with lost, repeated, reordered, foreign and late fragments [D232], #146.
//!
//! The input describes up to eight video frames (sequence step, keyframe
//! flag, size, fill byte) and then a delivery script: each script byte picks
//! one fragment of one frame and whether to deliver it as is, from another
//! session, or with one byte changed, and whether the clock first passes the
//! assembly deadline. The checks:
//!
//! - a delivered frame is one of the frames sent, byte for byte, unless a
//!   changed fragment of that frame was accepted first;
//! - delivered sequences only increase, the first delivered frame is a
//!   keyframe, and a delta frame is delivered only straight after its
//!   predecessor (otherwise the reassembler must wait for a keyframe);
//! - a foreign session is always refused, and memory held stays within one
//!   maximum-size frame plus its bitmap.
#![no_main]
#![forbid(unsafe_code)]
use infraternal_plugin_desktop::datagram::{FRAGMENT_BYTES, Reassembler, fragments};
use infraternal_plugin_desktop::media::{ASSEMBLY_TIMEOUT, Error, Video};
use infraternal_protocol::desktop::{MAX_VIDEO_BYTES, Message};
use libfuzzer_sys::fuzz_target;
use std::time::Instant;

/// The session the reassembler is bound to.
const SESSION: [u8; 16] = [7; 16];
/// Another session, whose fragments must always be refused.
const FOREIGN: [u8; 16] = [8; 16];

fuzz_target!(|data: &[u8]| {
    let [count, rest @ ..] = data else {
        return;
    };
    let count = usize::from(count % 8) + 1;
    let Some((specs, script)) = rest.split_at_checked(count * 4) else {
        return;
    };
    // Build the frames. Sizes reach a few fragments, and the last one is
    // allowed to be the maximum so the bound is exercised.
    let mut sent_frames = Vec::new();
    let mut sequence = 0u64;
    for spec in specs.as_chunks::<4>().0 {
        sequence += u64::from(spec[0] % 4) + 1;
        let len = if spec[1] == 0xFF {
            MAX_VIDEO_BYTES
        } else {
            usize::from(u16::from_be_bytes([spec[1], spec[2]])) % (6 * FRAGMENT_BYTES) + 1
        };
        sent_frames.push(Video {
            sequence,
            capture_ns: sequence * 1000,
            keyframe: spec[0] & 0x80 != 0,
            bytes: vec![spec[3]; len].into(),
        });
    }
    let mut pieces: Vec<Vec<(u32, Vec<u8>)>> = Vec::new();
    for video in &sent_frames {
        let mut list = Vec::new();
        let sent = fragments(&SESSION, video, |message| {
            if let Message::Fragment { offset, bytes, .. } = message {
                list.push((offset, bytes.to_vec()));
            }
            Ok(())
        });
        assert!(sent.is_ok());
        assert_eq!(list.len(), video.bytes.len().div_ceil(FRAGMENT_BYTES));
        pieces.push(list);
    }

    let start = Instant::now();
    let mut now = start;
    let mut reassembler = Reassembler::new(SESSION);
    let mut changed = vec![false; sent_frames.len()];
    let mut last_delivered: Option<u64> = None;
    for step in script.as_chunks::<2>().0 {
        let which = usize::from(step[0]) % sent_frames.len();
        let video = &sent_frames[which];
        let list = &pieces[which];
        let (offset, original) = &list[usize::from(step[1]) % list.len()];
        let mut bytes = original.clone();
        let mode = step[0] >> 5;
        if mode == 6 {
            bytes[0] ^= 1;
        }
        if mode == 7 {
            now += ASSEMBLY_TIMEOUT;
        }
        let session = if mode == 5 { &FOREIGN } else { &SESSION };
        let message = Message::Fragment {
            session_id: session,
            sequence: video.sequence,
            capture_ns: video.capture_ns,
            keyframe: video.keyframe,
            total: u32::try_from(video.bytes.len()).unwrap(),
            offset: *offset,
            bytes: &bytes,
        };
        let result = reassembler.push(message, now);
        if mode == 5 {
            assert!(matches!(result, Err(Error::Forbidden)));
            continue;
        }
        if mode == 6 && result.is_ok() {
            // The changed bytes may now be part of this frame's assembly.
            changed[which] = true;
        }
        assert!(
            reassembler.retained_bytes()
                <= MAX_VIDEO_BYTES + MAX_VIDEO_BYTES.div_ceil(FRAGMENT_BYTES * 8) + 64
        );
        if let Ok(Some(delivered)) = result {
            let source = sent_frames
                .iter()
                .position(|video| video.sequence == delivered.sequence)
                .unwrap();
            let video = &sent_frames[source];
            assert_eq!(delivered.keyframe, video.keyframe);
            assert_eq!(delivered.capture_ns, video.capture_ns);
            assert_eq!(delivered.bytes.len(), video.bytes.len());
            if !changed[source] {
                assert_eq!(
                    delivered.bytes, video.bytes,
                    "a delivered frame differs from the one sent"
                );
            }
            match last_delivered {
                None => assert!(
                    delivered.keyframe,
                    "the first delivered frame must be a keyframe"
                ),
                Some(last) => {
                    assert!(delivered.sequence > last, "sequences went backwards");
                    assert!(
                        delivered.keyframe || delivered.sequence == last + 1,
                        "a delta frame was delivered after a gap"
                    );
                }
            }
            last_delivered = Some(delivered.sequence);
            assert!(reassembler.deadline().is_none());
        }
        reassembler.expire(now);
        let _ = reassembler.take_repair();
    }
});
