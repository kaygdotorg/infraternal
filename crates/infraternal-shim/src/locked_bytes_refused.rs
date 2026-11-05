//! Locked private pages where no audited implementation exists yet (#320, D244).
//!
//! The Linux module maps pages that are locked and excluded from core dumps.
//! macOS has no reviewed equivalent for the dump exclusion, so every
//! allocation is refused here: CA material is never held in ordinary memory,
//! and the server's CA paths fail closed instead of running weaker. The type
//! cannot be constructed, so its accessors are unreachable.
use std::{
    convert::Infallible,
    io,
    ops::{Deref, DerefMut},
};

/// Uninhabited off Linux: [`LockedBytes::new`] always refuses.
pub struct LockedBytes {
    never: Infallible,
}

impl LockedBytes {
    /// Always refuses private-buffer admission on this platform.
    /// # Errors
    /// Always `Unsupported`.
    pub fn new(_length: usize) -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Unreachable: no value of this type exists.
    pub fn truncate(&mut self, _length: usize) {
        match self.never {}
    }
}
impl Deref for LockedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self.never {}
    }
}
impl DerefMut for LockedBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self.never {}
    }
}
