//! Validates the bounded output cursor used only by negotiated native standby writers [215], #129.
use std::io;

/// The cursor is a single integer, never terminal content or a plugin action.
pub const MAX_CURSOR_JSON: usize = 64;

/// Decode an exact cursor object after the caller checks negotiated stream authority.
/// # Errors
/// Refuses oversized, incomplete, duplicate, unknown or out-of-range fields.
pub fn decode(input: &[u8]) -> io::Result<u64> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cursor {
        out_seq: u64,
    }
    // Struct deserialization also accepts sequences. Only an object is part
    // of this contract; deny_unknown_fields alone does not enforce that shape.
    if input.len() > MAX_CURSOR_JSON || input.trim_ascii_start().first() != Some(&b'{') {
        return Err(io::ErrorKind::InvalidData.into());
    }
    serde_json::from_slice::<Cursor>(input)
        .map(|cursor| cursor.out_seq)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
mod tests {
    //! Holds the additive cursor shape to a constant parsing and allocation bound.
    use super::*;

    #[test]
    fn exact_unsigned_cursor_and_whole_object_are_required() {
        assert_eq!(decode(br#"{"out_seq":0}"#).unwrap(), 0);
        assert_eq!(
            decode(br#"{"out_seq":18446744073709551615}"#).unwrap(),
            u64::MAX
        );
        for invalid in [
            b"{}".as_slice(),
            br#"{"out_seq":-1}"#,
            br#"{"out_seq":1.0}"#,
            br#"{"out_seq":18446744073709551616}"#,
            br#"{"out_seq":1,"out_seq":2}"#,
            br#"{"out_seq":1,"writer":2}"#,
            br#"{"out_seq":1}{}"#,
            br#"{"out_seq":"1"}"#,
            b"[1]",
        ] {
            assert_eq!(
                decode(invalid).map_err(|error| error.kind()),
                Err(io::ErrorKind::InvalidData),
                "non-object or invalid cursor must be rejected: {invalid:?}"
            );
        }
        let mut oversized = br#"{"out_seq":1}"#.to_vec();
        oversized.resize(MAX_CURSOR_JSON + 1, b' ');
        assert!(decode(&oversized).is_err());
    }
}
