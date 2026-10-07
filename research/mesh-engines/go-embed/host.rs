//! Minimal Rust host that links and calls the Go engine C ABI for a release-size measurement.
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::CString;
use std::os::raw::{c_char, c_int};

#[link(name = "wgbridge", kind = "static")]
unsafe extern "C" {
    fn WgCreateDevice(name: *mut c_char, mtu: c_int) -> usize;
    fn WgCloseDevice(handle: usize);
}

fn main() {
    let name = CString::new("wgsize0").unwrap();
    let handle = unsafe { WgCreateDevice(name.as_ptr() as *mut c_char, 1420) };
    // A nonzero handle proves that the linked engine created its TUN device in the rootless test namespace.
    assert_ne!(handle, 0, "the Go device must initialize through the Rust host");
    unsafe { WgCloseDevice(handle) };
}
