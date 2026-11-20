//! App icons travel apart from the window list, fetched on demand by content hash [D207,D208,D349], #146.
//!
//! Real 64 px app icons are 4–8 KiB of PNG, and one window-list page is capped
//! at 8 KiB, so icons cannot ride in the list. Instead:
//!
//! 1. The macOS helper renders each app's icon once (64 by 64 pixels, at most
//!    16 KiB of PNG) and sends it with the window list it was asked for. The
//!    infraternal agent passes the icons it already holds as `known_icons`, so
//!    the helper renders only new apps.
//! 2. The agent checks each PNG ([`valid_png`]), names it by its SHA-256
//!    ([`IconStore`]), keeps it in a small bounded memory store, and replaces
//!    the helper's icon list with an `icon` hash on each window row. The pages
//!    the server reads keep their 8 KiB cap.
//! 3. The browser asks for an icon it does not have by hash (`desktop.icon`).
//!    The server reads it from the host in 4 KiB pieces
//!    (`desktop.source.icon`), checks the hash and the PNG again, and replies
//!    with the whole image. The browser checks once more and caches it by hash.
//!
//! Icon bytes come from another machine, so every hop treats them as untrusted:
//! sizes are bounded before decoding, the PNG structure and checksums are
//! verified, and the content hash binds the bytes the browser shows to the
//! name the host listed.
use serde::{Deserialize, Serialize};
#[cfg(feature = "source")]
use serde_json::Value;

/// Width and height, in pixels, of every icon the helper renders.
pub const ICON_PIXELS: u32 = 64;
/// The largest PNG accepted for one icon, in bytes.
pub const MAX_ICON_PNG_BYTES: usize = 16 * 1024;
/// The bytes of PNG carried by one `desktop.source.icon` reply; with base64 and
/// JSON framing that stays well inside the 8 KiB action limit.
pub const ICON_CHUNK_BYTES: usize = 4 * 1024;
/// The most icon identities the agent tells the helper it already holds; the
/// helper reads at most this many.
pub const MAX_KNOWN_ICON_KEYS: usize = crate::protocol::MAX_KNOWN_ICONS;
/// The most icons the agent keeps (at most 1 MiB of PNG).
#[cfg(feature = "source")]
const MAX_STORED_ICONS: usize = 64;
/// The longest base64 text that can decode to an icon within the PNG limit.
#[cfg(feature = "source")]
const MAX_ICON_BASE64_BYTES: usize = MAX_ICON_PNG_BYTES.div_ceil(3) * 4;
/// The most chunks a PNG walk accepts; real icons have under ten.
const MAX_PNG_CHUNKS: usize = 64;

/// One app version's icon identity, as the helper and the agent name it.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IconKey {
    /// The app's bundle identifier from its macOS bundle.
    pub bundle_id: String,
    /// The bundle's short version and build version joined with `+` when both exist.
    pub app_version: String,
}

impl IconKey {
    /// True when both parts are non-empty, bounded and free of control characters.
    ///
    /// The bundle identifier's bound is the List validator's own
    /// (`protocol::MAX_ICON_KEY_TEXT`): the agent sends every stored key back
    /// in `known_icons`, so a key the store keeps but the validator refuses
    /// would make every later window list fail.
    #[must_use]
    pub fn valid(&self) -> bool {
        let part = |text: &str, max: usize| {
            !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
        };
        part(&self.bundle_id, crate::protocol::MAX_ICON_KEY_TEXT) && part(&self.app_version, 128)
    }
}

/// True when `hash` is a SHA-256 written as 64 lowercase hexadecimal digits.
#[must_use]
pub fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The SHA-256 of `bytes` as 64 lowercase hexadecimal digits: an icon's name.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> String {
    use sha2::Digest;
    use std::fmt::Write;
    let digest = sha2::Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// True when `bytes` is a well-formed PNG of exactly 64 by 64 pixels, no more
/// than 16 KiB.
///
/// It checks the signature, that the first chunk is a 13-byte `IHDR` naming
/// 64 × 64 with a legal bit depth, colour type, compression, filter and
/// interlace method, that every chunk fits and has a correct CRC, that there
/// is at least one `IDAT`, and that the image ends with an empty `IEND` and
/// nothing after it. It does not decompress the pixels: the browser's decoder
/// does that, and a PNG that passes here is bounded to 16 KiB in and at most
/// 32 KiB of pixels out (64 × 64, 16-bit RGBA).
#[must_use]
pub fn valid_png(bytes: &[u8]) -> bool {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() > MAX_ICON_PNG_BYTES || !bytes.starts_with(SIGNATURE) {
        return false;
    }
    let mut rest = &bytes[SIGNATURE.len()..];
    let mut seen_data = false;
    for index in 0..MAX_PNG_CHUNKS {
        let Some(Chunk {
            length,
            kind,
            data,
            crc,
            after,
        }) = next_chunk(rest)
        else {
            return false;
        };
        if crc32(&[kind.as_slice(), data].concat()) != crc {
            return false;
        }
        match (&kind, index) {
            (b"IHDR", 0) => {
                if length != 13 || !valid_header(data) {
                    return false;
                }
            }
            (_, 0) | (b"IHDR", _) => return false,
            (b"IDAT", _) => seen_data = true,
            (b"IEND", _) => return length == 0 && seen_data && after.is_empty(),
            _ => {}
        }
        rest = after;
    }
    false
}

/// One PNG chunk as laid out in the file.
struct Chunk<'a> {
    /// The data length the chunk header claims (already checked to fit).
    length: usize,
    /// The four-letter chunk type, such as `IHDR`.
    kind: [u8; 4],
    /// The chunk's data bytes.
    data: &'a [u8],
    /// The CRC stored after the data.
    crc: u32,
    /// Everything after this chunk.
    after: &'a [u8],
}

/// Splits one chunk off the front of `bytes`, or `None` if it does not fit or
/// its type is not four ASCII letters.
fn next_chunk(bytes: &[u8]) -> Option<Chunk<'_>> {
    let length = usize::try_from(u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?)).ok()?;
    let kind: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
    if !kind.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let end = 8usize.checked_add(length)?;
    let data = bytes.get(8..end)?;
    let crc = u32::from_be_bytes(bytes.get(end..end.checked_add(4)?)?.try_into().ok()?);
    Some(Chunk {
        length,
        kind,
        data,
        crc,
        after: &bytes[end + 4..],
    })
}

/// True when a 13-byte `IHDR` body names a 64 × 64 image with a legal format.
fn valid_header(data: &[u8]) -> bool {
    let [
        w0,
        w1,
        w2,
        w3,
        h0,
        h1,
        h2,
        h3,
        depth,
        colour,
        compression,
        filter,
        interlace,
    ] = data
    else {
        return false;
    };
    let width = u32::from_be_bytes([*w0, *w1, *w2, *w3]);
    let height = u32::from_be_bytes([*h0, *h1, *h2, *h3]);
    let format = match colour {
        0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
        3 => matches!(depth, 1 | 2 | 4 | 8),
        2 | 4 | 6 => matches!(depth, 8 | 16),
        _ => false,
    };
    width == ICON_PIXELS
        && height == ICON_PIXELS
        && format
        && *compression == 0
        && *filter == 0
        && *interlace <= 1
}

/// The CRC-32 PNG uses (ISO 3309, polynomial 0xEDB88320), bit by bit: icons are
/// a few KiB, read once each, so a table buys nothing.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// One icon the agent holds: which app version it belongs to, its name and its bytes.
#[cfg(feature = "source")]
struct StoredIcon {
    key: IconKey,
    hash: String,
    png: std::sync::Arc<[u8]>,
}

/// The agent's bounded memory of app icons, least recently used first.
///
/// At most 64 icons of at most 16 KiB each. It lives as long as the desktop
/// source, so a picker that polls every two seconds makes the helper render
/// each app's icon once, not on every poll.
#[cfg(feature = "source")]
#[derive(Default)]
pub(crate) struct IconStore {
    icons: std::collections::VecDeque<StoredIcon>,
}

#[cfg(feature = "source")]
impl IconStore {
    /// The most recently used icon identities, for the helper's `known_icons`.
    pub(crate) fn known(&self) -> Vec<IconKey> {
        self.icons
            .iter()
            .rev()
            .take(MAX_KNOWN_ICON_KEYS)
            .map(|icon| icon.key.clone())
            .collect()
    }

    /// Takes the helper's `app_icons` out of `inventory`, keeps each valid one,
    /// and tags every window row whose app has an icon with `"icon": <hash>`.
    ///
    /// A malformed, oversized or non-PNG entry is dropped on its own; the
    /// window rows are never lost because of an icon.
    pub(crate) fn absorb(&mut self, inventory: &mut Value) {
        let Some(object) = inventory.as_object_mut() else {
            return;
        };
        if let Some(Value::Array(entries)) = object.remove("app_icons") {
            for entry in entries.iter().take(MAX_STORED_ICONS) {
                if let Some((key, png)) = decode_entry(entry) {
                    self.insert(key, png);
                }
            }
        }
        let Some(Value::Array(windows)) = object.get_mut("windows") else {
            return;
        };
        for window in windows {
            let key = IconKey {
                bundle_id: window["bundle_id"].as_str().unwrap_or_default().to_owned(),
                app_version: window["app_version"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            };
            if let Some(index) = self.icons.iter().position(|icon| icon.key == key)
                && let Some(row) = window.as_object_mut()
            {
                row.insert(
                    "icon".to_owned(),
                    Value::String(self.icons[index].hash.clone()),
                );
                self.promote(index);
            }
        }
    }

    /// One piece of the icon named `hash`, starting at byte `offset`:
    /// `{"total": <bytes>, "data": <base64 of at most 4 KiB>}`, or `None` when
    /// the icon is unknown or `offset` is not a chunk start inside it.
    pub(crate) fn chunk(&mut self, hash: &str, offset: usize) -> Option<Value> {
        use base64::Engine;
        let index = self.icons.iter().position(|icon| icon.hash == hash)?;
        let png = self.icons[index].png.clone();
        self.promote(index);
        if offset >= png.len() || !offset.is_multiple_of(ICON_CHUNK_BYTES) {
            return None;
        }
        let end = png.len().min(offset + ICON_CHUNK_BYTES);
        Some(serde_json::json!({
            "total": png.len(),
            "data": base64::engine::general_purpose::STANDARD.encode(&png[offset..end]),
        }))
    }

    /// Stores one checked icon, replacing an older one for the same app
    /// version and evicting the least recently used beyond the cap.
    fn insert(&mut self, key: IconKey, png: Vec<u8>) {
        self.icons.retain(|icon| icon.key != key);
        let hash = content_hash(&png);
        self.icons.push_back(StoredIcon {
            key,
            hash,
            png: png.into(),
        });
        while self.icons.len() > MAX_STORED_ICONS {
            self.icons.pop_front();
        }
    }

    /// Moves the icon at `index` to the recently used end.
    fn promote(&mut self, index: usize) {
        if let Some(icon) = self.icons.remove(index) {
            self.icons.push_back(icon);
        }
    }
}

/// Reads one helper icon entry `{bundle_id, app_version, png_64}`, bounding the
/// base64 text before decoding it and checking the PNG after.
#[cfg(feature = "source")]
fn decode_entry(entry: &Value) -> Option<(IconKey, Vec<u8>)> {
    use base64::Engine;
    let key = IconKey {
        bundle_id: entry.get("bundle_id")?.as_str()?.to_owned(),
        app_version: entry.get("app_version")?.as_str()?.to_owned(),
    };
    let encoded = entry.get("png_64")?.as_str()?;
    if !key.valid() || encoded.len() > MAX_ICON_BASE64_BYTES {
        return None;
    }
    let png = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    valid_png(&png).then_some((key, png))
}

#[cfg(test)]
/// Checks the PNG gate, the content names and the agent's icon store.
pub(crate) mod tests {
    use super::*;

    /// Builds a valid PNG of `width` × `height` RGBA pixels with `padding` extra
    /// bytes in a private ancillary chunk, so tests can reach any size.
    pub(crate) fn png(width: u32, height: u32, padding: usize) -> Vec<u8> {
        fn chunk(out: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
            out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            out.extend_from_slice(&kind);
            out.extend_from_slice(data);
            out.extend_from_slice(&crc32(&[kind.as_slice(), data].concat()).to_be_bytes());
        }
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut header = Vec::new();
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&height.to_be_bytes());
        header.extend_from_slice(&[8, 6, 0, 0, 0]);
        chunk(&mut out, *b"IHDR", &header);
        if padding > 0 {
            chunk(&mut out, *b"prVt", &vec![0; padding]);
        }
        // Any bytes do for the gate: it never inflates IDAT.
        chunk(
            &mut out,
            *b"IDAT",
            &[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01],
        );
        chunk(&mut out, *b"IEND", &[]);
        out
    }

    /// A small 64 × 64 PNG passes; the wrong size, a bad CRC, trailing bytes,
    /// a missing IEND and anything over 16 KiB fail.
    #[test]
    fn only_bounded_well_formed_64px_pngs_pass() {
        let good = png(64, 64, 0);
        assert!(valid_png(&good));
        assert!(!valid_png(&png(32, 32, 0)));
        assert!(!valid_png(&png(64, 65, 0)));
        let mut bad_crc = good.clone();
        let last = bad_crc.len() - 1;
        bad_crc[last] ^= 1;
        assert!(!valid_png(&bad_crc));
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(!valid_png(&trailing));
        assert!(!valid_png(&good[..good.len() - 12]));
        let near = png(64, 64, MAX_ICON_PNG_BYTES - good.len() - 12);
        assert_eq!(near.len(), MAX_ICON_PNG_BYTES);
        assert!(valid_png(&near));
        assert!(!valid_png(&png(
            64,
            64,
            MAX_ICON_PNG_BYTES - good.len() - 11
        )));
        assert!(!valid_png(b"GIF89a"));
    }

    /// A chunk length that runs past the end is refused, not trusted.
    #[test]
    fn oversized_chunk_lengths_are_refused() {
        let mut lying = png(64, 64, 0);
        // The IDAT length field: signature (8) + IHDR (25).
        lying[33..37].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(!valid_png(&lying));
    }

    /// Hashes are 64 lowercase hex digits and nothing else.
    #[test]
    fn hashes_are_lowercase_sha256_hex() {
        let hash = content_hash(b"icon");
        assert!(valid_hash(&hash));
        assert!(!valid_hash(&hash.to_uppercase()));
        assert!(!valid_hash(&hash[1..]));
    }

    #[cfg(feature = "source")]
    /// The store takes icons out of the inventory, tags rows by hash, serves the
    /// bytes back in 4 KiB pieces and drops invalid icons on their own.
    #[test]
    fn the_store_tags_rows_and_serves_pieces() {
        use base64::Engine;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let icon = png(64, 64, 6000);
        let mut inventory = serde_json::json!({
            "windows": [
                {"window_id": 1, "bundle_id": "org.example.editor", "app_version": "1.0"},
                {"window_id": 2, "bundle_id": "org.example.other", "app_version": "1.0"},
            ],
            "app_icons": [
                {"bundle_id": "org.example.editor", "app_version": "1.0", "png_64": b64(&icon)},
                {"bundle_id": "org.example.other", "app_version": "1.0", "png_64": b64(&png(32, 32, 0))},
            ],
        });
        let mut store = IconStore::default();
        store.absorb(&mut inventory);
        assert!(inventory.get("app_icons").is_none());
        let hash = content_hash(&icon);
        assert_eq!(inventory["windows"][0]["icon"], hash.as_str());
        assert!(inventory["windows"][1].get("icon").is_none());
        assert_eq!(store.known().len(), 1);

        let mut joined = Vec::new();
        let mut offset = 0;
        while let Some(piece) = store.chunk(&hash, offset) {
            assert_eq!(piece["total"], icon.len());
            let data = base64::engine::general_purpose::STANDARD
                .decode(piece["data"].as_str().unwrap())
                .unwrap();
            assert!(data.len() <= ICON_CHUNK_BYTES);
            offset += data.len();
            joined.extend(data);
        }
        assert_eq!(joined, icon);
        assert!(store.chunk(&hash, 1).is_none(), "offsets start chunks");
        assert!(store.chunk(&content_hash(b"other"), 0).is_none());
    }

    #[cfg(feature = "source")]
    /// A later poll with no new icon still tags rows from what the store holds.
    #[test]
    fn rows_are_tagged_from_the_store_on_later_polls() {
        use base64::Engine;
        let icon = png(64, 64, 0);
        let mut store = IconStore::default();
        let mut first = serde_json::json!({
            "windows": [{"bundle_id": "org.example.editor", "app_version": "1.0"}],
            "app_icons": [{"bundle_id": "org.example.editor", "app_version": "1.0",
                "png_64": base64::engine::general_purpose::STANDARD.encode(&icon)}],
        });
        store.absorb(&mut first);
        let mut later = serde_json::json!({
            "windows": [{"bundle_id": "org.example.editor", "app_version": "1.0"}],
        });
        store.absorb(&mut later);
        assert_eq!(later["windows"][0]["icon"], content_hash(&icon).as_str());
    }
}
