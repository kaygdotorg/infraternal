//! Independent merge review: model byte ownership, replay and reply bounds [D307, #24].
use super::*;

#[test]
fn interleaved_replies_and_replays_match_partial_write_model() {
    let mut inputs = Inputs::default();
    let mut queue = VecDeque::new();
    let mut model = VecDeque::new();
    let writers = [0, 7, u32::MAX];
    let mut accepted = [0_u64; 3];
    let mut written = [0_u64; 3];
    for writer in writers {
        inputs.select(writer, (80, 24, 0, 0)).unwrap();
    }
    let mut seed = 0x8a12_424b_u64;
    for step in 0..20_000 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let slot = usize::try_from((seed >> 32) % 3).unwrap();
        match seed % 5 {
            0 => {
                let bytes = [u8::try_from(step % 251).unwrap(); 7];
                assert!(inputs.reply(false, &bytes, &mut queue));
                model.extend(bytes.into_iter().map(|byte| (None, byte)));
            }
            1..=3 => {
                // Overlap one already accepted byte, then append an unseen suffix.
                let overlap = usize::from(accepted[slot] > 0);
                let bytes = [u8::try_from(step % 251).unwrap(); 4];
                inputs
                    .accept(
                        writers[slot],
                        accepted[slot] - overlap as u64,
                        &bytes,
                        &mut queue,
                    )
                    .unwrap();
                model.extend(bytes[overlap..].iter().map(|byte| (Some(slot), *byte)));
                accepted[slot] += (bytes.len() - overlap) as u64;
                // Fully duplicated ranges must not add another ownership segment.
                inputs
                    .accept(writers[slot], accepted[slot] - 4, &bytes, &mut queue)
                    .unwrap();
            }
            _ => {}
        }
        // Include writes ending in the middle of both reply and typing segments.
        let drain = usize::try_from((seed >> 48) % 17).unwrap().min(queue.len());
        inputs.advance(drain).unwrap();
        for actual in queue.drain(..drain) {
            let (owner, expected) = model.pop_front().unwrap();
            assert_eq!(actual, expected, "step {step}");
            if let Some(owner) = owner {
                written[owner] += 1;
            }
        }
        assert_eq!(queue.len(), model.len());
        for (slot, writer) in writers.into_iter().enumerate() {
            let state = inputs.get(Some(writer)).unwrap();
            assert_eq!(
                (state.accepted, state.written),
                (accepted[slot], written[slot])
            );
        }
    }
    assert_eq!(
        queue.iter().copied().collect::<Vec<_>>(),
        model.iter().map(|(_, byte)| *byte).collect::<Vec<_>>()
    );
    inputs.advance(queue.len()).unwrap();
    for (slot, writer) in writers.into_iter().enumerate() {
        assert_eq!(inputs.get(Some(writer)).unwrap().written, accepted[slot]);
    }
    assert!(inputs.segments.is_empty());
}

#[test]
fn repeated_reply_registration_adds_exactly_one_identity() {
    for reply_first in [false, true] {
        let mut inputs = Inputs::default();
        let mut queue = VecDeque::new();
        if reply_first {
            assert!(inputs.reply(false, b"r", &mut queue));
        }
        for writer in 1..=512 {
            inputs.select(writer, (80, 24, 0, 0)).unwrap();
        }
        for _ in 0..1024 {
            assert!(inputs.reply(false, b"r", &mut queue));
            assert!(inputs.select(513, (80, 24, 0, 0)).is_err());
            assert_eq!(inputs.cursors.len(), 514);
        }
    }
}
