//! Which characters share a hyperlink, compared across a restore (#594).
//!
//! The engine numbers each link a program opens without an id. The painter
//! writes that number as an id (`infraternal-implicit-N`), so a restored
//! viewer holds the link under an explicit id and starts its own numbering
//! afresh. The numbers may therefore differ between the original terminal and
//! the viewer; what must agree is the grouping: which cells share one link,
//! on which screen, with which URI. An id the program chose must agree exactly.
//!
//! One limit: a program that chooses an id in the painter's own spelling gets
//! the same bytes as a numbered link, so only its grouping is compared.

use std::collections::HashMap;

/// The start of every hyperlink opening the painter writes.
const OPENING: &[u8] = b"\x1b]8;id=";
/// The painter's spelling of a numbered link, before the number.
const NUMBERED: &[u8] = b"infraternal-implicit-";
/// What the viewer is given instead. The same length, so the frame budget and
/// the carry's offset do not move.
const RESTORED: &[u8] = b"infraternal-restored-";

/// A copy of `snapshot` to feed a viewer, with the numbered ids in its first
/// `repaint_len` bytes renamed. Without this, a link restored as number 0 and
/// the first link the viewer numbers itself would be painted alike, although
/// they are two links. The unfinished input after the repaint is untouched.
pub(super) fn mark_restored(snapshot: &[u8], repaint_len: usize) -> Vec<u8> {
    let mut marked = snapshot.to_vec();
    let id = OPENING.len()..OPENING.len() + NUMBERED.len();
    for at in 0..repaint_len.saturating_sub(id.end - 1) {
        let opening = &mut marked[at..at + id.end];
        if opening.starts_with(OPENING) && opening.ends_with(NUMBERED) {
            opening[id.clone()].copy_from_slice(RESTORED);
        }
    }
    marked
}

/// One link as a snapshot names it. Each screen numbers its links itself.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Link<'a> {
    alternate: bool,
    id: &'a [u8],
    uri: &'a [u8],
}

/// Walks the hyperlink openings of a snapshot, following the painter's
/// screen switches.
struct Openings<'a> {
    rest: &'a [u8],
    alternate: bool,
}

impl<'a> Openings<'a> {
    /// Starts on the primary screen, which the repaint's reset selects.
    fn new(snapshot: &'a [u8]) -> Self {
        Self {
            rest: snapshot,
            alternate: false,
        }
    }
}

impl<'a> Iterator for Openings<'a> {
    /// The bytes since the previous opening, and the link now opened.
    type Item = (&'a [u8], Link<'a>);

    /// The next complete opening. After the last one, `rest` holds the tail of
    /// the snapshot: closes and unfinished input are never openings.
    fn next(&mut self) -> Option<Self::Item> {
        for at in 0..self.rest.len() {
            let command = &self.rest[at..];
            if command.starts_with(b"\x1b[?47h") {
                self.alternate = true;
            } else if command.starts_with(b"\x1b[?47l") {
                self.alternate = false;
            } else if let Some(params) = command.strip_prefix(OPENING) {
                let separator = params.iter().position(|&byte| byte == b';')?;
                let after = &params[separator + 1..];
                let end = after.windows(2).position(|bytes| bytes == b"\x1b\\")?;
                let link = Link {
                    alternate: self.alternate,
                    id: &params[..separator],
                    uri: &after[..end],
                };
                let before = &self.rest[..at];
                self.rest = &after[end + 2..];
                return Some((before, link));
            }
        }
        None
    }
}

/// Whether `id` is `prefix` followed by a number.
fn numbered(id: &[u8], prefix: &[u8]) -> bool {
    id.strip_prefix(prefix)
        .is_some_and(|number| !number.is_empty() && number.iter().all(u8::is_ascii_digit))
}

/// Whether the snapshot of a restored viewer shows what the original's shows:
/// every byte equal except the ids of numbered links, which must pair one to
/// one. Pairing both ways catches two links merged into one and one link split
/// in two, even when they all point to the same URI.
pub(super) fn same_screen(original: &[u8], viewer: &[u8]) -> bool {
    let (mut original, mut viewer) = (Openings::new(original), Openings::new(viewer));
    let (mut forward, mut backward) = (HashMap::new(), HashMap::new());
    loop {
        match (original.next(), viewer.next()) {
            (Some((a_before, a)), Some((b_before, b))) => {
                let same_id = if numbered(a.id, NUMBERED) {
                    numbered(b.id, NUMBERED) || numbered(b.id, RESTORED)
                } else {
                    a.id == b.id
                };
                if a_before != b_before
                    || a.alternate != b.alternate
                    || a.uri != b.uri
                    || !same_id
                    || *forward.entry(a).or_insert(b) != b
                    || *backward.entry(b).or_insert(a) != a
                {
                    return false;
                }
            }
            (None, None) => return original.rest == viewer.rest,
            _ => return false,
        }
    }
}
