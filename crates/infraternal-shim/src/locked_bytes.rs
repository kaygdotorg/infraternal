//! Audited page ownership for short-lived process-transfer buffers; pinning and dump exclusion never affect allocator neighbours [40][217], #154.
#![allow(unsafe_code)]

use nix::libc;
use std::{
    io,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

/// An anonymous, exclusively owned mapping, locked and excluded from core dumps.
/// No allocation can move or resize it; Drop clears it before releasing the pages.
pub struct LockedBytes {
    pointer: NonNull<u8>,
    length: usize,
    mapped: usize,
}
impl LockedBytes {
    /// Allocate bounded storage or refuse transfer if either protection fails.
    /// # Errors
    /// Refuses lengths over 4096 and failed page-size, mapping, lock or dump policy.
    pub fn new(length: usize) -> io::Result<Self> {
        if length > 4096 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: sysconf reads a process-independent scalar, with no pointers.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| io::ErrorKind::Unsupported)?;
        if page == 0 {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mapped = length
            .max(1)
            .div_ceil(page)
            .checked_mul(page)
            .ok_or(io::ErrorKind::InvalidInput)?;
        // SAFETY: anonymous private mapping, fd=-1, offset=0. The kernel owns
        // page initialization; successful pages are exclusively owned here.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let Some(pointer) = NonNull::new(raw.cast::<u8>()) else {
            // SAFETY: a successful mapping at address zero still needs release.
            unsafe {
                libc::munmap(raw, mapped);
            }
            return Err(io::ErrorKind::Other.into());
        };
        let buffer = Self {
            pointer,
            length,
            mapped,
        };
        // SAFETY: whole, aligned, live pages owned by buffer; no unrelated heap
        // data shares them. Both syscalls operate without dereferencing in Rust.
        if unsafe { libc::mlock(raw, mapped) } != 0
            || unsafe { libc::madvise(raw, mapped, libc::MADV_DONTDUMP) } != 0
        {
            return Err(io::Error::last_os_error()); // Drop also unlocks by unmapping.
        }
        Ok(buffer)
    }

    /// Shorten the readable initialized range without reallocating its pages.
    pub fn truncate(&mut self, length: usize) {
        self.length = self.length.min(length);
    }
}
impl Deref for LockedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: initialized anonymous pages remain mapped throughout self,
        // length never exceeds the owned mapping, and no mutable borrow aliases.
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.length) }
    }
}
impl DerefMut for LockedBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: exclusive self borrow provides exclusive access to the mapping.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.length) }
    }
}
impl Drop for LockedBytes {
    fn drop(&mut self) {
        // SAFETY: the entire mapping (including any truncated tail) is still
        // writable and exclusively owned. Volatile writes cannot be elided;
        // unmapping releases the lock without exposing a reusable uncleared page.
        unsafe {
            for index in 0..self.mapped {
                self.pointer.as_ptr().add(index).write_volatile(0);
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            libc::munmap(self.pointer.as_ptr().cast(), self.mapped);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_transfer_pages_are_locked_and_excluded_from_core_dumps() {
        let frame = LockedBytes::new(42).unwrap();
        let pointer = frame.as_ptr() as usize;
        let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut selected = false;
        for line in maps.lines() {
            if let Some((start, end)) = line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                selected = start <= pointer && pointer < end;
            }
            if selected && line.starts_with("VmFlags:") {
                assert!(
                    line.split_whitespace().any(|flag| flag == "lo"),
                    "seed frame must be mlocked"
                );
                assert!(
                    line.split_whitespace().any(|flag| flag == "dd"),
                    "seed frame must be MADV_DONTDUMP"
                );
                return;
            }
        }
        panic!("frame mapping missing from smaps");
    }
}
