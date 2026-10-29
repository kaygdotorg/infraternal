//! Bounded state exposure for image replacement; the parser algorithm stays pinned [D270].
#![forbid(unsafe_code)]
use crate::{Parser, State, params::Params};

const MAGIC: &[u8; 8] = b"VTCARRY1";
/// Fixed metadata plus a small reserve; the caller separately caps OSC bytes.
pub const FIXED_CAPACITY: usize = 384;

#[derive(Debug, PartialEq, Eq)]
pub enum CheckpointError {
    TooLarge,
    Allocation,
    Invalid,
}
impl core::fmt::Display for CheckpointError {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        output.write_str(match self {
            Self::TooLarge => "carry checkpoint exceeds its budget",
            Self::Allocation => "carry checkpoint allocation refused",
            Self::Invalid => "invalid carry checkpoint",
        })
    }
}
impl std::error::Error for CheckpointError {}

pub(crate) struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], CheckpointError> {
        let result = self.0.get(..length).ok_or(CheckpointError::Invalid)?;
        self.0 = &self.0[length..];
        Ok(result)
    }
    pub(crate) fn byte(&mut self) -> Result<u8, CheckpointError> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, CheckpointError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    fn u32(&mut self) -> Result<u32, CheckpointError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    fn u64(&mut self) -> Result<u64, CheckpointError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

impl<const N: usize> Parser<N> {
    /// Export every carry field, including ignored syntax and incomplete UTF-8.
    /// The caller's existing per-session bound is authoritative; this API does
    /// not relax it or retain an additional buffer in the parser.
    pub fn export_checkpoint(&self, max_osc_bytes: usize) -> Result<Vec<u8>, CheckpointError> {
        if self.osc_raw.len() > max_osc_bytes {
            return Err(CheckpointError::TooLarge);
        }
        let length = u32::try_from(self.osc_raw.len()).map_err(|_| CheckpointError::TooLarge)?;
        let capacity = FIXED_CAPACITY
            .checked_add(self.osc_raw.len())
            .ok_or(CheckpointError::TooLarge)?;
        let mut out = Vec::new();
        out.try_reserve_exact(capacity)
            .map_err(|_| CheckpointError::Allocation)?;
        out.extend_from_slice(MAGIC);
        out.push(self.state as u8);
        out.push(self.intermediate_idx as u8);
        out.extend_from_slice(&self.intermediates);
        out.extend_from_slice(&self.param.to_le_bytes());
        self.params.checkpoint_write(&mut out);
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&self.osc_raw);
        out.push(self.osc_num_params as u8);
        // Unused entries can retain offsets from a prior, longer OSC. Preserve
        // them without interpreting them as ranges in the current payload.
        for &(start, end) in &self.osc_params {
            out.extend_from_slice(&(start as u64).to_le_bytes());
            out.extend_from_slice(&(end as u64).to_le_bytes());
        }
        out.push(u8::from(self.ignoring));
        out.push(self.partial_utf8_len as u8);
        out.extend_from_slice(&self.partial_utf8);
        Ok(out)
    }

    /// Validate the complete bounded record before returning an owned parser.
    pub fn import_checkpoint(bytes: &[u8], max_osc_bytes: usize) -> Result<Self, CheckpointError> {
        if bytes.len()
            > FIXED_CAPACITY
                .checked_add(max_osc_bytes)
                .ok_or(CheckpointError::TooLarge)?
        {
            return Err(CheckpointError::TooLarge);
        }
        let mut input = Reader(bytes);
        if input.take(MAGIC.len())? != MAGIC {
            return Err(CheckpointError::Invalid);
        }
        let state = match input.byte()? {
            0 => State::CsiEntry,
            1 => State::CsiIgnore,
            2 => State::CsiIntermediate,
            3 => State::CsiParam,
            4 => State::DcsEntry,
            5 => State::DcsIgnore,
            6 => State::DcsIntermediate,
            7 => State::DcsParam,
            8 => State::DcsPassthrough,
            9 => State::Escape,
            10 => State::EscapeIntermediate,
            11 => State::OscString,
            12 => State::SosPmApcString,
            13 => State::Ground,
            _ => return Err(CheckpointError::Invalid),
        };
        let intermediate_idx = usize::from(input.byte()?);
        let mut intermediates = [0; crate::MAX_INTERMEDIATES];
        intermediates.copy_from_slice(input.take(crate::MAX_INTERMEDIATES)?);
        if intermediate_idx > intermediates.len() {
            return Err(CheckpointError::Invalid);
        }
        let param = input.u16()?;
        let params = Params::checkpoint_read(&mut input)?;
        let raw_length = usize::try_from(input.u32()?).map_err(|_| CheckpointError::TooLarge)?;
        if raw_length > max_osc_bytes {
            return Err(CheckpointError::TooLarge);
        }
        let raw = input.take(raw_length)?;
        let mut osc_raw = Vec::new();
        osc_raw
            .try_reserve_exact(raw.len())
            .map_err(|_| CheckpointError::Allocation)?;
        osc_raw.extend_from_slice(raw);
        let osc_num_params = usize::from(input.byte()?);
        if osc_num_params > crate::MAX_OSC_PARAMS {
            return Err(CheckpointError::Invalid);
        }
        let mut osc_params = [(0, 0); crate::MAX_OSC_PARAMS];
        for pair in &mut osc_params {
            *pair = (
                usize::try_from(input.u64()?).map_err(|_| CheckpointError::Invalid)?,
                usize::try_from(input.u64()?).map_err(|_| CheckpointError::Invalid)?,
            );
        }
        if osc_params[..osc_num_params]
            .iter()
            .any(|&(start, end)| start > end || end > osc_raw.len())
        {
            return Err(CheckpointError::Invalid);
        }
        let ignoring = match input.byte()? {
            0 => false,
            1 => true,
            _ => return Err(CheckpointError::Invalid),
        };
        let partial_utf8_len = usize::from(input.byte()?);
        let mut partial_utf8 = [0; 4];
        partial_utf8.copy_from_slice(input.take(4)?);
        if !input.0.is_empty() || partial_utf8_len > 3 {
            return Err(CheckpointError::Invalid);
        }
        if partial_utf8_len > 0 {
            // The parser's UTF-8 fast path assumes an incomplete valid prefix.
            // Restore that invariant rather than accepting arbitrary raw state.
            let valid = str::from_utf8(&partial_utf8[..partial_utf8_len])
                .is_err_and(|error| error.valid_up_to() == 0 && error.error_len().is_none());
            if state != State::Ground || !valid {
                return Err(CheckpointError::Invalid);
            }
        }
        Ok(Self {
            state,
            intermediates,
            intermediate_idx,
            params,
            param,
            osc_raw,
            osc_params,
            osc_num_params,
            ignoring,
            partial_utf8,
            partial_utf8_len,
        })
    }
}

#[cfg(test)]
mod tests {
    //! A replacement must resume the unfinished sequence, not start from ground.
    use super::*;
    #[derive(Default)]
    struct Observer(Vec<char>);
    impl crate::Perform for Observer {
        fn print(&mut self, point: char) {
            self.0.push(point);
        }
    }
    #[test]
    fn partial_sequence_survives_a_checkpoint() {
        let mut parser = Parser::new();
        let mut output = Observer::default();
        parser.advance(&mut output, b"before\x1b[38:2:1;");
        let state = parser.export_checkpoint(4096).unwrap();
        let mut replacement = Parser::<1024>::import_checkpoint(&state, 4096).unwrap();
        replacement.advance(&mut output, b"2;3mZ");
        assert_eq!(output.0.into_iter().collect::<String>(), "beforeZ");
    }

    #[test]
    fn malformed_unfinished_group_is_refused_before_dispatch() {
        let mut parser = Parser::new();
        let mut output = Observer::default();
        parser.advance(&mut output, b"\x1b[");
        for _ in 0..crate::params::MAX_PARAMS {
            parser.advance(&mut output, b"1:");
        }
        let mut state = parser.export_checkpoint(4096).unwrap();
        // This completed the parameter array while its last group remains
        // open. Dispatch must never expose a range beyond that array.
        let subparams = MAGIC.len() + 1 + 1 + crate::MAX_INTERMEDIATES + 2 + 2;
        state[subparams] = 255;
        assert!(Parser::<1024>::import_checkpoint(&state, 4096).is_err());
    }
}
