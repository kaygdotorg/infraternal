//! Reads the versioned ELF compatibility note from an already opened replacement, never its pathname [217], #154.

use std::{fs::File, io, os::unix::fs::FileExt};

const NOTE: &[u8; 28] = b"\x0c\0\0\0\x04\0\0\0ACFIINFRATERNAL\0\x01\0\0\0";

/// Compatibility only: callers separately enforce root ownership and release policy.
/// # Errors
/// Refuses truncated or unbounded ELF metadata; unsupported formats return false.
pub fn capable(file: &File) -> io::Result<bool> {
    let mut header = [0; 64];
    file.read_exact_at(&mut header, 0)?;
    if &header[..7] != b"\x7fELF\x02\x01\x01" {
        return Ok(false);
    }
    let offset = u64::from_le_bytes(
        header[32..40]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?,
    );
    let stride = u16::from_le_bytes([header[54], header[55]]);
    let count = u16::from_le_bytes([header[56], header[57]]);
    if stride != 56 || count > 128 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    for index in 0..count {
        let mut program = [0; 56];
        let position = offset
            .checked_add(u64::from(index) * 56)
            .ok_or(io::ErrorKind::InvalidData)?;
        file.read_exact_at(&mut program, position)?;
        if program[..4] != 4u32.to_le_bytes() {
            continue;
        }
        let position = u64::from_le_bytes(
            program[8..16]
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
        );
        let length = u64::from_le_bytes(
            program[32..40]
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
        );
        if length > 65536 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut notes = vec![0; usize::try_from(length).map_err(|_| io::ErrorKind::InvalidData)?];
        file.read_exact_at(&mut notes, position)?;
        if has_note(&notes) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Walk exact aligned ELF note records; bytes in unrelated sections cannot qualify.
#[must_use]
pub fn has_note(mut bytes: &[u8]) -> bool {
    while bytes.len() >= 12 {
        if bytes.starts_with(NOTE) {
            return true;
        }
        let names = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let data = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let length =
            12u64 + u64::from(names).next_multiple_of(4) + u64::from(data).next_multiple_of(4);
        let Ok(length) = usize::try_from(length) else {
            return false;
        };
        let Some(rest) = bytes.get(length..) else {
            return false;
        };
        bytes = rest;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn marker_is_an_exact_versioned_note_not_a_byte_substring() {
        assert!(has_note(NOTE));
        for length in 0..NOTE.len() {
            assert!(!has_note(&NOTE[..length]));
        }
        for index in 0..NOTE.len() {
            let mut changed = *NOTE;
            changed[index] ^= 1;
            assert!(!has_note(&changed));
        }
        let mut prefixed = vec![0; 4];
        prefixed.extend_from_slice(NOTE);
        assert!(!has_note(&prefixed));
        assert!(!capable(&File::open("/usr/bin/bash").unwrap()).unwrap());
    }
}
