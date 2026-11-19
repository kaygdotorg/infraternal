//! Bind a fresh HTTP readiness response to the process answering the private
//! relocation control socket. The challenge is used only during relocation.

use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use std::{fmt::Write as _, sync::OnceLock};

/// The installer sends its challenge and expects the answer under this header.
pub const HEADER: &str = "x-infraternal-move-health";

/// Produce a process-bound answer for a fresh 128-bit, lowercase hex challenge.
#[must_use]
pub fn proof(challenge: &str) -> Option<String> {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();

    if challenge.len() != 32
        || !challenge
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let key = PKey::hmac(KEY.get_or_init(rand::random)).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).ok()?;
    let digest = signer.sign_oneshot_to_vec(challenge.as_bytes()).ok()?;
    let mut answer = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut answer, "{byte:02x}").ok()?;
    }
    Some(answer)
}
