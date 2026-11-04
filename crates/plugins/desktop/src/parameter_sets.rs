//! Selects one viewer's original or restricted SPS from helper-owned standard SEI; picture NALs are never changed [D204,D266], #146.
//!
//! The helper puts two versions of the H.264 sequence parameter set (SPS) in each
//! keyframe: the one it sends by default, followed by a standard SEI message
//! (user data tagged `infraternal-sps1`) that carries the encoder's original SPS.
//! [`select`] picks one for a given viewer: the low-delay SPS as sent, or the
//! original one swapped in. Only these parameter NAL units are touched; the
//! picture data is passed through byte for byte, and a frame without the SEI
//! message is returned unchanged. A malformed SEI message makes the whole frame
//! refused rather than guessed at.
use bytes::Bytes;

/// The user-data identifier that marks the helper's SEI message.
const ID: &[u8; 16] = b"infraternal-sps1";

/// Which sequence parameter set a viewer wants. This preference is per viewer
/// and changes only on a repairing keyframe.
#[derive(Clone, Copy, Default, Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Parameters {
    /// The SPS exactly as the encoder produced it.
    Encoder,
    /// The helper's restricted SPS tuned for low decoding delay (the default).
    #[default]
    LowDelay,
}

/// Finds the next Annex-B start code at or after `from`. Returns where the start
/// code begins and where the NAL unit's data begins (3- or 4-byte start code).
fn prefix(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    (from..bytes.len().saturating_sub(2)).find_map(|i| {
        if bytes[i..].starts_with(&[0, 0, 0, 1]) {
            Some((i, i + 4))
        } else if bytes[i..].starts_with(&[0, 0, 1]) {
            Some((i, i + 3))
        } else {
            None
        }
    })
}

/// Looks at one NAL unit (without start code). If it is the helper's SEI
/// message, returns the original SPS inside it. `Ok(None)` means it is some
/// other NAL unit; `Err` means it carries the helper's tag but is malformed or
/// oversized.
// Only the helper's single user-data message is interpreted. Other SEI is opaque.
fn original(nal: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    if nal.first().is_none_or(|byte| byte & 31 != 6) {
        return Ok(None);
    }
    if nal.len() > 1500 {
        // The ASCII identifier needs no unescaping; inspect only the bounded header.
        let mut offset = 2;
        while offset < 16 && nal.get(offset) == Some(&255) {
            offset += 1;
        }
        return if nal.get(1) == Some(&5)
            && nal.get(offset + 1..offset + 1 + ID.len()) == Some(ID.as_slice())
        {
            Err(())
        } else {
            Ok(None)
        };
    }
    let mut rbsp = Vec::with_capacity(nal.len());
    let mut zeros = 0;
    let mut valid_escape = true;
    for (index, &byte) in nal[1..].iter().enumerate() {
        if zeros == 2 {
            if byte == 3 {
                valid_escape &= nal.get(index + 2).is_some_and(|next| *next <= 3);
                zeros = 0;
                continue;
            }
            valid_escape &= byte > 2;
        }
        rbsp.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    if rbsp.first() != Some(&5) {
        return Ok(None);
    }
    let mut size = 0usize;
    let mut offset = 1;
    loop {
        let Some(&byte) = rbsp.get(offset) else {
            return Ok(None);
        };
        size += usize::from(byte);
        offset += 1;
        if byte != 255 {
            break;
        }
    }
    if rbsp.get(offset..offset + ID.len()) != Some(ID.as_slice()) {
        return Ok(None);
    }
    // Recognized metadata must be exact and bounded; it cannot smuggle another NAL.
    if nal[0] != 6
        || !valid_escape
        || !(ID.len() + 5..=ID.len() + 1024).contains(&size)
        || rbsp.len() != offset + size + 1
        || rbsp.last() != Some(&0x80)
    {
        return Err(());
    }
    let sps = &rbsp[offset + ID.len()..offset + size];
    if sps[0] & 0x80 != 0 || sps[0] & 0x60 == 0 || sps[0] & 31 != 7 || prefix(sps, 0).is_some() {
        return Err(());
    }
    Ok(Some(sps.to_vec()))
}

/// Removes the helper's metadata from the access unit `bytes` and, for
/// [`Parameters::Encoder`], replaces the SPS just before it with the original.
/// For [`Parameters::LowDelay`] the SPS is kept and only the metadata is removed.
///
/// Strip only recognized helper metadata and restore its preceding SPS when requested.
/// Legacy access units and all non-keyframes keep the shared allocation.
/// # Errors
/// Refuses recognized metadata without an immediately preceding bounded SPS.
#[allow(clippy::result_unit_err)] // Metadata selection either preserves exact bytes or refuses the frame.
pub fn select(bytes: &Bytes, parameters: Parameters) -> Result<Bytes, ()> {
    let mut next = prefix(bytes, 0);
    let mut preceding = None;
    let mut retained = 0;
    let mut output: Option<Vec<u8>> = None;
    while let Some((start, payload)) = next {
        next = prefix(bytes, payload);
        let end = next.map_or(bytes.len(), |(start, _)| start);
        if let Some(sps) = original(&bytes[payload..end])? {
            let (sps_start, sps_payload, sps_end) = preceding.ok_or(())?;
            if sps_end != start || sps_end - sps_payload > 1024 || bytes[sps_payload] & 31 != 7 {
                return Err(());
            }
            let result = output.get_or_insert_with(|| Vec::with_capacity(bytes.len()));
            match parameters {
                Parameters::LowDelay => result.extend_from_slice(&bytes[retained..start]),
                Parameters::Encoder => {
                    result.extend_from_slice(&bytes[retained..sps_start]);
                    result.extend_from_slice(&bytes[sps_start..sps_payload]);
                    result.extend_from_slice(&sps);
                }
            }
            retained = end;
            preceding = None;
        } else {
            preceding = Some((start, payload, end));
        }
    }
    if let Some(mut output) = output {
        output.extend_from_slice(&bytes[retained..]);
        Ok(Bytes::from(output))
    } else {
        Ok(bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata(sps: &[u8]) -> Vec<u8> {
        let mut result = vec![
            0,
            0,
            0,
            1,
            6,
            5,
            u8::try_from(ID.len() + sps.len()).unwrap(),
        ];
        result.extend_from_slice(ID);
        result.extend_from_slice(sps);
        result.push(0x80);
        result
    }
    #[test]
    fn recognized_metadata_refuses_corrupted_nal_header_flags() {
        let sps = [0x27, 0x64, 0, 0x2a, 0x80];
        for header in [0x26, 0x46, 0x66, 0x86] {
            let mut marker = metadata(&sps);
            marker[4] = header;
            let mut input = vec![0, 0, 0, 1];
            input.extend(sps);
            input.extend(marker);
            let input = Bytes::from(input);
            for mode in [Parameters::Encoder, Parameters::LowDelay] {
                assert!(
                    select(&input, mode).is_err(),
                    "recognized header {header:02x}"
                );
            }
        }
    }
    #[test]
    fn variants_change_only_the_sps_and_strip_metadata() {
        let original = [
            0x27, 0x64, 0, 0x2a, 0xac, 0x56, 0x80, 0xf0, 0x13, 0x7e, 0x54,
        ];
        let restricted = [
            0x27, 0x64, 0, 0x2a, 0xac, 0x56, 0x80, 0xf0, 0x13, 0x7e, 0x58, 6, 0xd0, 0x44, 0x23,
            0x50,
        ];
        let pictures = [0, 0, 0, 1, 0x68, 0xff, 0, 0, 0, 1, 0x65, 0xff];
        let mut input = vec![0, 0, 0, 1];
        input.extend_from_slice(&restricted);
        input.extend(metadata(&original));
        input.extend(pictures);
        let input = Bytes::from(input);
        for (choice, sps) in [
            (Parameters::Encoder, original.as_slice()),
            (Parameters::LowDelay, restricted.as_slice()),
        ] {
            let mut expected = vec![0, 0, 0, 1];
            expected.extend(sps);
            expected.extend(pictures);
            let output = select(&input, choice).unwrap();
            assert_eq!(output, expected);
            let legacy = select(&output, choice).unwrap();
            assert_eq!(legacy.as_ptr(), output.as_ptr());
        }
    }
    #[test]
    fn complete_840_frame_fixtures_preserve_both_variants() {
        let original = include_bytes!("../tests/fixtures/mac-vt-annexb.h264");
        let restricted = include_bytes!("../tests/fixtures/mac-vt-vui.h264");
        let sps = [
            0x27, 0x64, 0, 0x2a, 0xac, 0x56, 0x80, 0xf0, 0x13, 0x7e, 0x54,
        ];
        let changed = [
            0x27, 0x64, 0, 0x2a, 0xac, 0x56, 0x80, 0xf0, 0x13, 0x7e, 0x58, 6, 0xd0, 0x44, 0x23,
            0x50,
        ];
        let mut packet = Vec::new();
        let mut offset = 0;
        let mut count = 0;
        while let Some(index) = restricted[offset..]
            .windows(changed.len())
            .position(|bytes| bytes == changed)
        {
            let end = offset + index + changed.len();
            packet.extend_from_slice(&restricted[offset..end]);
            packet.extend(metadata(&sps));
            offset = end;
            count += 1;
        }
        packet.extend_from_slice(&restricted[offset..]);
        assert_eq!(count, 7);
        let packet = Bytes::from(packet);
        assert_eq!(
            select(&packet, Parameters::LowDelay).unwrap().as_ref(),
            restricted
        );
        assert_eq!(
            select(&packet, Parameters::Encoder).unwrap().as_ref(),
            original
        );
    }
    #[test]
    fn bounded_parameter_metadata_mutation_corpus() {
        let mut seed = vec![0, 0, 0, 1, 0x27, 0x64, 0, 0x2a, 0xff];
        seed.extend(metadata(&[0x27, 0x64, 0, 0x2a, 0xff]));
        let mut state = 146u64;
        for _ in 0..24_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let mut bytes = seed.clone();
            let index = usize::try_from(state >> 32).unwrap() % bytes.len();
            bytes[index] ^= u8::try_from(state & 255).unwrap();
            let packet = Bytes::from(bytes);
            for mode in [Parameters::Encoder, Parameters::LowDelay] {
                if let Ok(selected) = select(&packet, mode) {
                    assert!(selected.len() <= packet.len());
                    assert_eq!(select(&selected, mode).unwrap(), selected);
                }
            }
        }
    }
    #[test]
    fn recognized_metadata_rejects_invalid_emulation_prevention() {
        let mut input = vec![0, 0, 0, 1, 0x27, 0x64, 0, 0x2a, 0xff];
        input.extend([0, 0, 0, 1, 6, 5, 22]);
        input.extend(ID);
        // A redundant escape before 4 is invalid even when the decoded length fits.
        input.extend([0x27, 0x64, 0, 0, 3, 4, 0x2a, 0x80]);
        assert!(select(&Bytes::from(input), Parameters::Encoder).is_err());
    }
    #[test]
    fn recognized_metadata_requires_bounded_adjacent_parameters() {
        let sps = [0x27, 0x64, 0, 0x2a, 0xff];
        let valid = metadata(&sps);
        assert!(select(&Bytes::from(valid.clone()), Parameters::Encoder).is_err());
        for len in 7 + ID.len()..valid.len() {
            let mut input = vec![0, 0, 0, 1];
            input.extend(sps);
            input.extend(&valid[..len]);
            assert!(select(&Bytes::from(input), Parameters::Encoder).is_err());
        }
    }
}
