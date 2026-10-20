//! Ring regression and measurement harness, separated from production code [40].
use super::*;
#[cfg(test)]
mod tests {
    //! Exercises ring invariants against real data and frozen expectations.
    use super::*;
    #[test]
    fn wrap_and_exact_offsets() {
        let mut ring = Ring::new(4);
        ring.append(b"abc").unwrap();
        ring.append(b"def").unwrap();
        assert_eq!((ring.start(), ring.head()), (2, 6));
        assert_eq!(ring.read(2, 99), Some(b"cdef".to_vec()));
        assert_eq!(ring.read(6, 99), Some(vec![]));
        assert!(ring.read(1, 99).is_none());
        assert!(ring.read(7, 99).is_none());
        ring.append(b"0123456789").unwrap();
        assert_eq!(ring.read(12, 99), Some(b"6789".to_vec()));
    }

    #[cfg(feature = "process-per-user")]
    #[test]
    fn borrowed_ranges_obey_absolute_offsets_across_physical_wrap() {
        let mut ring = Ring::new(8);
        for byte in 0..43 {
            ring.append(&[byte]).unwrap();
        }
        assert!(
            !ring.bytes.as_slices().1.is_empty(),
            "exercise a physical wrap"
        );
        for seq in 34..=44 {
            for limit in 0..=12 {
                let expected = (35..=43).contains(&seq).then(|| {
                    (seq..43)
                        .take(limit)
                        .map(|n| u8::try_from(n).unwrap())
                        .collect::<Vec<_>>()
                });
                let actual = ring
                    .read_slices(seq, limit)
                    .map(|(first, second)| [first, second].concat());
                assert_eq!(actual, expected, "seq={seq} limit={limit}");
            }
        }
    }

    #[cfg(feature = "process-per-user")]
    #[test]
    fn shared_history_reservation_never_rounds_past_its_share() {
        let mut ring = Ring::new(67_108);
        for _ in 0..40 {
            ring.append(&[b'x'; 4096]).unwrap();
            assert!(ring.allocated_bytes() <= 67_108);
        }
        assert_eq!(ring.head() - ring.start(), 67_108);
        assert_eq!(ring.read(ring.start(), 4), Some(b"xxxx".to_vec()));
    }

    #[cfg(feature = "process-per-user")]
    #[test]
    fn empty_append_keeps_lazy_storage_unallocated() {
        let mut ring = Ring::new(65536);
        ring.append(&[]).unwrap();
        assert_eq!(ring.allocated_bytes(), 0);
        assert_eq!((ring.start(), ring.head()), (0, 0));
    }

    #[test]
    fn merge_review_head_and_retained_bytes_match_after_every_append() {
        for capacity in [0, 1, 3, 8, 31, 4097] {
            let mut ring = Ring::new(capacity);
            let mut stream = Vec::new();
            for count in [0, 1, 7, 4096, 0, 8193, 3, 97] {
                let bytes: Vec<_> = (0..count)
                    .map(|index| u8::try_from(index % 251).unwrap())
                    .collect();
                ring.append(&bytes).unwrap();
                stream.extend(bytes);
                let start = stream.len().saturating_sub(capacity);
                assert_eq!(ring.head(), stream.len() as u64);
                assert_eq!(ring.start(), start as u64);
                assert_eq!(
                    ring.read(start as u64, usize::MAX).unwrap(),
                    stream[start..]
                );
                assert_eq!(ring.read(ring.head(), 1), Some(Vec::new()));
                assert!(ring.read(ring.head() + 1, 1).is_none());
            }
        }
    }

    #[test]
    fn merge_review_head_overflow_does_not_publish_or_discard_bytes() {
        let mut ring = Ring::new(8);
        ring.append(b"kept").unwrap();
        ring.head = u64::MAX - 1;
        let before = ring.read(ring.start(), 8).unwrap();
        let offsets = (ring.start(), ring.head());
        assert!(ring.append(b"xx").is_err());
        assert_eq!((ring.start(), ring.head()), offsets);
        assert_eq!(ring.read(ring.start(), 8).unwrap(), before);
        ring.append(b"x").unwrap();
        assert_eq!(ring.head(), u64::MAX);
        assert_eq!(ring.read(ring.start(), 8).unwrap(), b"keptx");
    }
}
