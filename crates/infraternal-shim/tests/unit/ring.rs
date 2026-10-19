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
}
