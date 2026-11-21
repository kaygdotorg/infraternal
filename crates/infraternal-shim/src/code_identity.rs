//! Code-signing identity of this process and of a local socket peer (D203 C2, #146).
//!
//! A root infraternal agent on macOS starts the desktop helper as the console
//! user (`desktop_user`). Before it reads a byte from that helper, it asks the
//! kernel which code is on the other end of the socket and checks it with
//! [`PeerRequirement::verify`]:
//!
//! - The peer is named by its **audit token** (`LOCAL_PEERTOKEN`), never by
//!   pid, so a recycled pid cannot stand in for it.
//! - The running code must satisfy a code requirement: the fixed signing
//!   identifier `infraternal-desktop-helper`, signed by **the same signer as
//!   this daemon**. The signer is the daemon's Team ID when it has one (a
//!   Developer ID release). A development signature has no Team ID, so its
//!   leaf certificate's SHA-1 is used instead; that is the form the code
//!   requirement language takes for a certificate hash.
//! - A daemon with no certificate at all (ad hoc or unsigned) has no signer
//!   to compare against, so [`PeerRequirement::for_identifier`] fails and the
//!   caller refuses cross-user capture rather than trust any peer.
//!
//! Only the requirement string is kept. It is parsed again for each check, a
//! few times per app-window session, so no Security object is shared between
//! threads.
#![allow(unsafe_code)]

use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    data::CFData,
    dictionary::CFDictionary,
    string::{CFString, CFStringRef},
};
use security_framework::{
    certificate::SecCertificate,
    os::macos::code_signing::{Flags, GuestAttributes, SecCode, SecRequirement},
};
use std::{ffi::c_void, io, os::fd::AsFd};

/// `<Security/CSCommon.h>`: `kSecCSSigningInformation`, which adds the Team ID
/// and certificate chain to the signing information.
const SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// `<Security/SecCode.h>`: copy a code object's signing information. A
    /// dynamic `SecCodeRef` is accepted where the header names a static one.
    fn SecCodeCopySigningInformation(
        code: *const c_void,
        flags: u32,
        information: *mut *const c_void,
    ) -> i32;
    /// Key of the Team ID string in the signing information.
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    /// Key of the certificate chain array, leaf first.
    static kSecCodeInfoCertificates: CFStringRef;
}

unsafe extern "C" {
    /// `<CommonCrypto/CommonDigest.h>` (libSystem): SHA-1, the only hash the
    /// code requirement language accepts for `certificate leaf = H"…"`.
    fn CC_SHA1(data: *const c_void, length: u32, digest: *mut u8) -> *mut u8;
}

/// Who signed a piece of code, in the form a code requirement can name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signer {
    /// An Apple-issued certificate with this Team ID (Developer ID).
    Team(String),
    /// Any other certificate, named by the SHA-1 of its leaf certificate.
    Leaf([u8; 20]),
}

/// The signer of the running process.
///
/// # Errors
/// Fails when the process has no certificate (ad hoc or unsigned) or its
/// signing information cannot be read.
pub fn own_signer() -> io::Result<Signer> {
    let code = SecCode::for_self(Flags::NONE).map_err(io::Error::other)?;
    let mut raw: *const c_void = std::ptr::null();
    // SAFETY: `code` is a live SecCode for the duration of the call, and `raw`
    // is a valid out-pointer. On success the dictionary is returned retained
    // (create rule) and is released by the wrapper below.
    let status = unsafe {
        SecCodeCopySigningInformation(code.as_CFTypeRef(), SIGNING_INFORMATION, &raw mut raw)
    };
    if status != 0 || raw.is_null() {
        return Err(io::Error::other("this process's signature cannot be read"));
    }
    // SAFETY: a non-null dictionary owned by us under the create rule.
    let information: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(raw.cast()) };
    // SAFETY: Security exports these keys as immortal constant strings.
    let (team_key, certificates_key) = unsafe {
        (
            CFString::wrap_under_get_rule(kSecCodeInfoTeamIdentifier),
            CFString::wrap_under_get_rule(kSecCodeInfoCertificates),
        )
    };
    if let Some(team) = information
        .find(&team_key)
        .and_then(|value| value.downcast::<CFString>())
    {
        return signer_from_team(&team.to_string());
    }
    let leaf = information
        .find(&certificates_key)
        .and_then(|value| value.downcast::<CFArray>())
        .and_then(|chain| {
            chain.get(0).and_then(|first| {
                // SAFETY: the array holds CF objects and keeps this one alive
                // while we take our own reference (get rule).
                unsafe { CFType::wrap_under_get_rule(*first) }.downcast::<SecCertificate>()
            })
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "this process has no signing certificate",
            )
        })?;
    Ok(Signer::Leaf(sha1(&leaf.to_der())))
}

/// A Team ID is ten upper-case letters or digits. Anything else is refused
/// rather than placed in a requirement string.
fn signer_from_team(team: &str) -> io::Result<Signer> {
    if team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        Ok(Signer::Team(team.to_owned()))
    } else {
        Err(io::Error::other("this process's Team ID is malformed"))
    }
}

/// SHA-1 of `bytes` through libSystem.
fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut digest = [0_u8; 20];
    // A certificate is a few KiB; anything past u32 would be a corrupt chain,
    // and hashing a prefix of it only makes the requirement fail to match.
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    // SAFETY: `bytes` is readable for `length` bytes and `digest` holds the
    // 20 bytes CC_SHA1 writes.
    unsafe { CC_SHA1(bytes.as_ptr().cast(), length, digest.as_mut_ptr()) };
    digest
}

/// `bytes` as upper-case hex, the form the requirement language prints.
fn upper_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            let _ = write!(text, "{byte:02X}");
            text
        })
}

/// The code requirement text for `identifier` signed by `signer`.
///
/// `identifier` comes from our own code, but it is still checked for the
/// characters a signing identifier uses, so it can never end the quoted
/// string and add a clause.
///
/// # Errors
/// Refuses an identifier with other characters.
pub fn requirement(identifier: &str, signer: &Signer) -> io::Result<String> {
    if identifier.is_empty()
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(format!(
        "identifier \"{identifier}\" and {}",
        signed_by(signer)
    ))
}

/// The code requirement text for any code signed by `signer`, whatever its
/// identifier. `infraternal up` checks the capture app with it before it
/// publishes the bundle beside the root agent.
#[must_use]
pub fn signed_by(signer: &Signer) -> String {
    match signer {
        Signer::Team(team) => {
            format!("anchor apple generic and certificate leaf[subject.OU] = \"{team}\"")
        }
        Signer::Leaf(digest) => format!("certificate leaf = H\"{}\"", upper_hex(digest)),
    }
}

/// What a socket peer must be: code with one signing identifier, signed by
/// the same signer as this process.
#[derive(Clone, Debug)]
pub struct PeerRequirement(String);

impl PeerRequirement {
    /// The requirement for a peer signed as `identifier` by this process's
    /// own signer.
    ///
    /// # Errors
    /// Fails when this process is not signed with a certificate.
    pub fn for_identifier(identifier: &str) -> io::Result<Self> {
        let text = requirement(identifier, &own_signer()?)?;
        // Parse once now, so a requirement Security refuses fails at setup.
        text.parse::<SecRequirement>().map_err(io::Error::other)?;
        Ok(Self(text))
    }

    /// The requirement in the code requirement language, for logs and tests.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }

    /// Checks the code on the other end of the connected Unix `socket`.
    ///
    /// The kernel names the peer by audit token, and Security checks that
    /// code's dynamic validity and this requirement. The answer describes the
    /// process that connected (or accepted), whatever happens to its pid
    /// afterwards.
    ///
    /// # Errors
    /// `PermissionDenied` when the peer does not satisfy the requirement;
    /// other errors when its identity cannot be read.
    pub fn verify(&self, socket: &impl AsFd) -> io::Result<()> {
        let token = nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::LocalPeerToken)
            .map_err(io::Error::from)?;
        let mut bytes = [0_u8; 32];
        for (chunk, value) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(token.val) {
            chunk.copy_from_slice(&value.to_ne_bytes());
        }
        let data = CFData::from_buffer(&bytes);
        let mut attributes = GuestAttributes::new();
        attributes.set_audit_token(data.as_concrete_TypeRef());
        let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .map_err(io::Error::other)?;
        let requirement = self.0.parse::<SecRequirement>().map_err(io::Error::other)?;
        code.check_validity(Flags::NONE, &requirement).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the desktop helper is not signed by this infraternal agent's signer",
            )
        })
    }
}

#[cfg(test)]
/// Requirement text, hashing and the refusal of an unsigned signer.
mod tests {
    use super::*;

    /// The two requirement shapes, with the hash in upper-case hex.
    #[test]
    fn requirement_names_the_identifier_and_the_signer() {
        assert_eq!(
            requirement(
                "infraternal-desktop-helper",
                &Signer::Team("ABCDE12345".into())
            )
            .unwrap(),
            "identifier \"infraternal-desktop-helper\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\""
        );
        let mut digest = [0_u8; 20];
        digest[0] = 0x27;
        digest[19] = 0xcb;
        assert_eq!(
            requirement("infraternal-desktop-helper", &Signer::Leaf(digest)).unwrap(),
            format!(
                "identifier \"infraternal-desktop-helper\" and certificate leaf = H\"27{}CB\"",
                "00".repeat(18)
            )
        );
    }

    /// The signer-only form `infraternal up` checks the capture app with is
    /// the identifier form without its identifier clause.
    #[test]
    fn signed_by_names_only_the_signer() {
        let team = Signer::Team("ABCDE12345".into());
        assert_eq!(
            signed_by(&team),
            "anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\""
        );
        assert_eq!(
            requirement("infraternal-desktop-helper", &team).unwrap(),
            format!(
                "identifier \"infraternal-desktop-helper\" and {}",
                signed_by(&team)
            )
        );
        assert_eq!(
            signed_by(&Signer::Leaf([0xab; 20])),
            format!("certificate leaf = H\"{}\"", "AB".repeat(20))
        );
    }

    /// No identifier or Team ID can close the quoted string and add a clause.
    #[test]
    fn requirement_refuses_text_that_could_add_a_clause() {
        for identifier in ["", "a\" or anchor apple", "a b", "a\nb"] {
            assert!(
                requirement(identifier, &Signer::Leaf([0; 20])).is_err(),
                "{identifier:?}"
            );
        }
        for team in ["ABCDE1234", "ABCDE12345X", "abcde12345", "ABCDE\"1234"] {
            assert!(signer_from_team(team).is_err(), "{team:?}");
        }
        assert_eq!(
            signer_from_team("VP77RTCF3K").unwrap(),
            Signer::Team("VP77RTCF3K".into())
        );
    }

    /// The libSystem SHA-1 matches a known vector ("abc").
    #[test]
    fn sha1_matches_the_standard_vector() {
        assert_eq!(
            upper_hex(&sha1(b"abc")),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
    }

    /// A test binary is only linker-signed (ad hoc): there is no signer to
    /// match, so cross-user admission must be refused, not opened to anyone.
    #[test]
    fn an_ad_hoc_process_has_no_signer_to_trust() {
        assert!(PeerRequirement::for_identifier("infraternal-desktop-helper").is_err());
    }
}
