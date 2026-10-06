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
}
