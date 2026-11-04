//! Refuses a Mac executable that would make dyld load code from outside the OS (#265).
//!
//! `mesh install` points a root `LaunchDaemon` at an executable. Its load
//! commands decide which files dyld opens before any of our code runs, so a
//! dylib or rpath under a user-writable directory would run that user's code
//! as root. The build wrapper (`.cargo/apple-cc.sh`) refuses such links, but a
//! binary built another way (another linker, a `cargo install` outside this
//! repository) never passed through it. This check runs on the file itself.
//!
//! The rule matches `.cargo/apple-image-check.sh`:
//! - every dylib load and every `LC_RPATH` names an absolute path under
//!   `/usr/lib/` or `/System/Library/`, with no `.` or `..` component (dyld
//!   resolves `/usr/lib/../../private/tmp/x` to a user-writable file);
//! - `LC_DYLD_ENVIRONMENT` is refused: it sets `DYLD_*` variables such as a
//!   library search path from inside the binary;
//! - `LC_LOAD_DYLINKER`, when present, is exactly `/usr/lib/dyld`.
//!
//! It parses only the Mach-O header and load commands, with every offset and
//! size checked against the bounds the header declares, so a malformed file is
//! refused rather than half-read. `/usr/bin/otool` is not used: it is an Xcode
//! command-line tools shim, absent on a Mac without them, which is exactly
//! where `mesh install` runs.

use std::{fs::File, io, os::unix::fs::FileExt, path::Path};

const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_DYLINKER: u32 = 0xe;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
const LC_DYLD_ENVIRONMENT: u32 = 0x27;
/// `mach_header_64` is 32 bytes; load commands follow it.
const HEADER_64: u64 = 32;
/// Far above any real binary (ours has about 4 KiB of load commands); bounds the read.
const MAX_LOAD_COMMANDS_BYTES: u32 = 1 << 20;
/// A universal binary with more slices than this is not one we build.
const MAX_FAT_SLICES: u32 = 8;

/// Check the executable at `path`.
///
/// # Errors
/// `PermissionDenied` when it loads code from outside the OS, `InvalidData`
/// when it is not a well-formed 64-bit Mach-O, and read failures.
pub fn check_file(path: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    check(&|offset, buffer| file.read_exact_at(buffer, offset))
}

/// Check an image given a positional reader; `read` fills the whole buffer or fails.
pub(crate) fn check(read: &dyn Fn(u64, &mut [u8]) -> io::Result<()>) -> io::Result<()> {
    let mut magic = [0_u8; 4];
    read(0, &mut magic).map_err(|_| invalid())?;
    match u32::from_be_bytes(magic) {
        FAT_MAGIC => check_fat(read, false),
        FAT_MAGIC_64 => check_fat(read, true),
        _ => check_thin(read, 0),
    }
}

/// Every slice of a universal binary must pass; dyld picks one at launch.
fn check_fat(read: &dyn Fn(u64, &mut [u8]) -> io::Result<()>, wide: bool) -> io::Result<()> {
    let mut header = [0_u8; 8];
    read(0, &mut header).map_err(|_| invalid())?;
    let slices = be32(&header, 4);
    if slices == 0 || slices > MAX_FAT_SLICES {
        return Err(invalid());
    }
    let entry: u64 = if wide { 32 } else { 20 };
    for index in 0..u64::from(slices) {
        let mut arch = [0_u8; 32];
        let arch = &mut arch[..usize::try_from(entry).map_err(|_| invalid())?];
        read(8 + index * entry, arch).map_err(|_| invalid())?;
        let offset = if wide {
            (u64::from(be32(arch, 8)) << 32) | u64::from(be32(arch, 12))
        } else {
            u64::from(be32(arch, 8))
        };
        check_thin(read, offset)?;
    }
    Ok(())
}

fn check_thin(read: &dyn Fn(u64, &mut [u8]) -> io::Result<()>, base: u64) -> io::Result<()> {
    let mut header = [0_u8; 32];
    read(base, &mut header).map_err(|_| invalid())?;
    // Only little-endian 64-bit images run on the Macs we support.
    if le32(&header, 0) != MH_MAGIC_64 {
        return Err(invalid());
    }
    let count = le32(&header, 16);
    let size = le32(&header, 20);
    if size > MAX_LOAD_COMMANDS_BYTES {
        return Err(invalid());
    }
    let mut commands = vec![0_u8; usize::try_from(size).map_err(|_| invalid())?];
    // A fat slice offset comes from the file, so the sum is checked.
    let start = base.checked_add(HEADER_64).ok_or_else(invalid)?;
    read(start, &mut commands).map_err(|_| invalid())?;
    let mut at = 0_usize;
    for _ in 0..count {
        let header = commands.get(at..at + 8).ok_or_else(invalid)?;
        let command = le32(header, 0);
        let length = usize::try_from(le32(header, 4)).map_err(|_| invalid())?;
        if length < 8 || length % 8 != 0 {
            return Err(invalid());
        }
        let body = commands.get(at..at + length).ok_or_else(invalid)?;
        check_command(command, body)?;
        at += length;
    }
    // The commands must fill exactly the size the header declares.
    if at != commands.len() {
        return Err(invalid());
    }
    Ok(())
}

fn check_command(command: u32, body: &[u8]) -> io::Result<()> {
    match command {
        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
        | LC_LOAD_UPWARD_DYLIB | LC_RPATH => {
            if os_path(string(body)?) {
                Ok(())
            } else {
                Err(outside())
            }
        }
        LC_LOAD_DYLINKER => {
            if string(body)? == b"/usr/lib/dyld" {
                Ok(())
            } else {
                Err(outside())
            }
        }
        LC_DYLD_ENVIRONMENT => Err(outside()),
        _ => Ok(()),
    }
}

/// The `lc_str` at byte 8 of a command: an offset into the command, then a NUL-terminated path.
fn string(body: &[u8]) -> io::Result<&[u8]> {
    let offset =
        usize::try_from(le32(body.get(8..12).ok_or_else(invalid)?, 0)).map_err(|_| invalid())?;
    let tail = body
        .get(offset..)
        .filter(|_| offset >= 12)
        .ok_or_else(invalid)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid)?;
    Ok(&tail[..end])
}

/// An absolute path under an OS-owned prefix that cannot step out of it.
fn os_path(path: &[u8]) -> bool {
    (path.starts_with(b"/usr/lib/") || path.starts_with(b"/System/Library/"))
        && path
            .split(|byte| *byte == b'/')
            .all(|component| component != b"." && component != b"..")
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0_u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0_u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_be_bytes(word)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "The executable is not a valid 64-bit Mach-O image.",
    )
}

fn outside() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "The executable loads code from outside macOS, so it cannot run as the Mesh service.",
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    /// One load command carrying a path, padded to a multiple of 8 bytes.
    fn path_command(command: u32, path: &str) -> Vec<u8> {
        // dylib_command: cmd, cmdsize, name.offset, timestamp, current, compat (24 bytes);
        // rpath_command and dylinker_command put the string right after offset (12 bytes).
        let fixed: usize = match command {
            LC_RPATH | LC_LOAD_DYLINKER | LC_DYLD_ENVIRONMENT => 12,
            _ => 24,
        };
        let mut length = fixed + path.len() + 1;
        length = length.div_ceil(8) * 8;
        let mut bytes = vec![0_u8; length];
        bytes[0..4].copy_from_slice(&command.to_le_bytes());
        bytes[4..8].copy_from_slice(&u32::try_from(length).expect("length").to_le_bytes());
        bytes[8..12].copy_from_slice(&u32::try_from(fixed).expect("offset").to_le_bytes());
        bytes[fixed..fixed + path.len()].copy_from_slice(path.as_bytes());
        bytes
    }

    fn image(commands: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = commands.concat();
        let mut bytes = vec![0_u8; 32];
        bytes[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes()); // MH_EXECUTE
        bytes[16..20].copy_from_slice(&u32::try_from(commands.len()).expect("n").to_le_bytes());
        bytes[20..24].copy_from_slice(&u32::try_from(body.len()).expect("size").to_le_bytes());
        bytes.extend(body);
        bytes
    }

    fn os_image() -> Vec<Vec<u8>> {
        vec![
            path_command(LC_LOAD_DYLINKER, "/usr/lib/dyld"),
            path_command(LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"),
            path_command(
                LC_LOAD_DYLIB,
                "/System/Library/Frameworks/Security.framework/Versions/A/Security",
            ),
        ]
    }

    fn checked(bytes: &[u8]) -> io::Result<()> {
        check(&|offset, buffer| {
            let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
            let source = bytes
                .get(start..start + buffer.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            buffer.copy_from_slice(source);
            Ok(())
        })
    }

    fn refused_with(mut commands: Vec<Vec<u8>>, extra: Vec<u8>) -> io::ErrorKind {
        commands.push(extra);
        checked(&image(&commands))
            .expect_err("the image must be refused")
            .kind()
    }

    #[test]
    fn an_image_that_loads_only_os_libraries_passes() {
        checked(&image(&os_image())).expect("OS-only image");
        let mut commands = os_image();
        commands.push(path_command(LC_RPATH, "/usr/lib/swift"));
        checked(&image(&commands)).expect("an OS rpath is fine");
    }

    #[test]
    fn a_dylib_or_rpath_outside_the_os_is_refused() {
        for extra in [
            path_command(LC_LOAD_DYLIB, "/opt/homebrew/lib/libiconv.2.dylib"),
            path_command(LC_LOAD_WEAK_DYLIB, "/private/tmp/libhelper.dylib"),
            path_command(LC_REEXPORT_DYLIB, "@rpath/libhelper.dylib"),
            path_command(LC_LAZY_LOAD_DYLIB, "/nix/store/x/lib/libz.dylib"),
            path_command(LC_LOAD_UPWARD_DYLIB, "libhelper.dylib"),
            path_command(LC_RPATH, "@loader_path/../lib"),
            path_command(LC_RPATH, "/opt/homebrew/lib"),
        ] {
            assert_eq!(
                refused_with(os_image(), extra),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    /// J162 F2: dyld resolves `..`, so an OS prefix alone proves nothing.
    #[test]
    fn a_path_that_steps_out_of_the_os_prefix_is_refused() {
        for path in [
            "/usr/lib/../../private/tmp/j162x/libhelper.dylib",
            "/System/Library/../../tmp/libhelper.dylib",
            "/usr/lib/./../../tmp/libhelper.dylib",
        ] {
            assert_eq!(
                refused_with(os_image(), path_command(LC_LOAD_DYLIB, path)),
                io::ErrorKind::PermissionDenied,
                "{path}"
            );
        }
        assert_eq!(
            refused_with(os_image(), path_command(LC_RPATH, "/usr/lib/../../tmp")),
            io::ErrorKind::PermissionDenied
        );
    }

    /// J162 F2: `-dyld_env` writes `DYLD_*` variables into the binary.
    #[test]
    fn a_dyld_environment_or_foreign_dylinker_is_refused() {
        assert_eq!(
            refused_with(
                os_image(),
                path_command(LC_DYLD_ENVIRONMENT, "DYLD_LIBRARY_PATH=/private/tmp/j162x")
            ),
            io::ErrorKind::PermissionDenied
        );
        let mut commands = os_image();
        commands[0] = path_command(LC_LOAD_DYLINKER, "/private/tmp/dyld");
        assert_eq!(
            checked(&image(&commands)).expect_err("foreign dyld").kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn a_malformed_image_is_refused() {
        let good = image(&os_image());
        // Not Mach-O, 32-bit, truncated, and a command that overruns the declared size.
        let mut not_macho = good.clone();
        not_macho[0..4].copy_from_slice(b"\x7fELF");
        let mut thirty_two = good.clone();
        thirty_two[0..4].copy_from_slice(&0xfeed_face_u32.to_le_bytes());
        let truncated = good[..good.len() - 8].to_vec();
        let mut overrun = good.clone();
        overrun[36..40].copy_from_slice(&4096_u32.to_le_bytes());
        let mut extra_count = good.clone();
        extra_count[16..20].copy_from_slice(&4_u32.to_le_bytes());
        let mut short_count = good.clone();
        short_count[16..20].copy_from_slice(&2_u32.to_le_bytes());
        let mut bad_offset = good.clone();
        bad_offset[40..44].copy_from_slice(&4_u32.to_le_bytes());
        for bytes in [
            not_macho,
            thirty_two,
            truncated,
            overrun,
            extra_count,
            short_count,
            bad_offset,
            Vec::new(),
        ] {
            assert_eq!(
                checked(&bytes).expect_err("malformed").kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn every_slice_of_a_universal_binary_is_checked() {
        let good = image(&os_image());
        let mut bad_commands = os_image();
        bad_commands.push(path_command(LC_LOAD_DYLIB, "/private/tmp/libhelper.dylib"));
        let bad = image(&bad_commands);
        let fat = |slices: &[&[u8]]| {
            let mut bytes = vec![0_u8; 4096];
            bytes[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
            bytes[4..8].copy_from_slice(&u32::try_from(slices.len()).expect("n").to_be_bytes());
            for (index, slice) in slices.iter().enumerate() {
                let offset = bytes.len();
                let entry = 8 + index * 20;
                bytes[entry + 8..entry + 12]
                    .copy_from_slice(&u32::try_from(offset).expect("offset").to_be_bytes());
                bytes[entry + 12..entry + 16]
                    .copy_from_slice(&u32::try_from(slice.len()).expect("size").to_be_bytes());
                bytes.extend_from_slice(slice);
            }
            bytes
        };
        checked(&fat(&[&good, &good])).expect("both slices OS-only");
        assert_eq!(
            checked(&fat(&[&good, &bad])).expect_err("bad slice").kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    /// The test binary itself is linked like the shipped one.
    #[cfg(target_os = "macos")]
    #[test]
    fn this_test_binary_passes() {
        check_file(&std::env::current_exe().expect("test binary")).expect("OS-only test binary");
    }
}
