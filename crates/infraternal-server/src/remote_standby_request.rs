//! Strict bounded standby and activation requests, isolated for exact-body parser fuzzing [215], #129.
use std::io;

/// The transport-only request has a fixed byte bound and no permissive fields.
/// # Errors
/// Refuses inputs over 64 bytes, non-objects, duplicate or unknown fields,
/// malformed JSON and a non-boolean prime option.
pub fn wants_prime(input: &[u8]) -> io::Result<bool> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Options {
        #[serde(default)]
        prime: bool,
    }
    if input.len() > 64 || input.trim_ascii_start().first() != Some(&b'{') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    serde_json::from_slice::<Options>(input)
        .map(|options| options.prime)
        .map_err(|_| io::ErrorKind::InvalidInput.into())
}
/// Activation carries no caller-selected identity or terminal state.
/// # Errors
/// Refuses inputs over 64 bytes and anything other than one exact empty object.
pub fn activation(input: &[u8]) -> io::Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    if input.len() > 64 || input.trim_ascii_start().first() != Some(&b'{') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    serde_json::from_slice::<Empty>(input)
        .map(|_| ())
        .map_err(|_| io::ErrorKind::InvalidInput.into())
}

#[cfg(test)]
mod tests {
    //! Holds transport-only options to exact object shapes and fixed byte bounds.
    use super::*;
    #[test]
    fn requests_require_objects_and_exact_fields() {
        for input in [
            b"[]".as_slice(),
            b"[true]",
            b"[false]",
            b"null",
            b"true",
            b"\"{}\"",
            b"",
            b"{\"prime\":true,\"prime\":false}",
        ] {
            assert!(wants_prime(input).is_err(), "standby accepted {input:?}");
            assert!(activation(input).is_err(), "activation accepted {input:?}");
        }
        assert!(wants_prime(b" \n{\"prime\":true}").unwrap());
        assert!(!wants_prime(b"{}").unwrap());
        assert!(activation(b" \n{}").is_ok());
        assert!(activation(b"{\"prime\":true}").is_err());
        assert!(activation(&[b' '; 65]).is_err());
    }
}
