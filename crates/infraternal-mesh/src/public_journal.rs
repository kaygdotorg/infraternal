//! Public file markers shared by the Linux mesh node and its status reader.

/// The journal beside the legacy, peer-free public snapshot.
pub const JOURNAL_FILE: &str = "mesh-public.journal";
/// The maximum appended bytes before a Linux mesh node compacts its public checkpoint.
pub const COMPACT_BYTES: usize = 128 * 1024;
/// The checkpoint and its bounded append area.
pub const MAX_BYTES: usize = 16 * 1024 * 1024 + COMPACT_BYTES;

/// The first bytes of a JSON whitespace trailer. Ordinary snapshot writers omit it.
const MARKER: &[u8] = b"\n\t\t \t\t\n";

/// The randomly selected journal generation.
pub type Token = [u8; 16];

/// Add the generation to the legacy snapshot without changing its JSON shape.
pub fn append_token(body: &mut Vec<u8>, token: Token) {
    body.extend_from_slice(MARKER);
    for byte in token {
        for bit in (0..8).rev() {
            body.push(if byte & (1 << bit) == 0 { b' ' } else { b'\t' });
        }
    }
}

/// Read the generation that selects a journal, if one was written.
#[must_use]
pub fn read_token(body: &[u8]) -> Option<Token> {
    let trailer = body.get(body.len().checked_sub(MARKER.len() + 128)?..)?;
    let bits = trailer.strip_prefix(MARKER)?;
    let mut token = Token::default();
    for (byte, group) in token.iter_mut().zip(bits.chunks_exact(8)) {
        for b in group {
            *byte = (*byte << 1)
                | match b {
                    b' ' => 0,
                    b'\t' => 1,
                    _ => return None,
                };
        }
    }
    Some(token)
}

/// Split the raw generation and its following newline from the file's records.
#[must_use]
pub fn split_header(body: &[u8]) -> Option<(Token, &[u8])> {
    let (token, frames) = body.split_at_checked(16)?;
    Some((token.try_into().ok()?, frames.strip_prefix(b"\n")?))
}

/// The public count at the start of a complete frame, separated from its checksum and JSON.
#[must_use]
pub fn split_count(frame: &[u8]) -> Option<(usize, &[u8])> {
    let (count, rest) = frame.split_at_checked(8)?;
    let count = usize::from_str_radix(std::str::from_utf8(count).ok()?, 16).ok()?;
    Some((count, rest.strip_prefix(b" ")?))
}

/// The most recent complete frame's public peer count, for offline status.
#[must_use]
pub fn peer_count(body: &[u8], expected: Token) -> Option<usize> {
    let (token, frames) = split_header(body)?;
    if token != expected {
        return None;
    }
    let end = frames.iter().rposition(|&byte| byte == b'\n')?;
    let complete = &frames[..end];
    let begin = complete
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |index| index + 1);
    split_count(&complete[begin..]).map(|(count, _)| count)
}
