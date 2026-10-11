//! Validates signed release identities with the same stable/edge grammar as the signing Worker [226].

/// Derive a channel from a bounded version, never from unsigned release metadata.
#[must_use]
pub fn channel(version: &str) -> Option<&'static str> {
    if version.len() > 127 {
        return None;
    }
    if let Some(stamp) = version.strip_prefix("edge-") {
        let bytes = stamp.as_bytes();
        return (bytes.len() == 16
            && bytes[8] == b'T'
            && bytes[15] == b'Z'
            && bytes[..8]
                .iter()
                .chain(&bytes[9..15])
                .all(u8::is_ascii_digit))
        .then_some("edge");
    }
    let mut parts = version.split('.');
    let valid = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    });
    (valid && parts.next().is_none()).then_some("stable")
}
