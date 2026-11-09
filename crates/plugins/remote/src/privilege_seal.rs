//! Opens a password the browser sealed for this infraternal agent, once (D274, D376, #399).
//!
//! When a host admin upgrades a host to the root infraternal agent, the browser
//! seals the person's sudo, doas or root password so the server only ever
//! forwards bytes it cannot read. This module is the infraternal agent's half:
//!
//! 1. [`SealKey::new`] makes a fresh X25519 key for one attempt. Its public half
//!    goes to the browser through the server.
//! 2. The browser seals the password to it (format below) and the server
//!    forwards the bytes.
//! 3. [`SealKey::open`] consumes the key and returns the password in a buffer
//!    that wipes itself when dropped.
//!
//! **Each key opens at most one sealed password.** `ring` only offers
//! *ephemeral* X25519 private keys, and agreeing consumes them, so a second
//! open of the same key cannot even be written. The key is never on disk.
//!
//! # Format, version 1
//!
//! ```text
//! sealed = 0x01 ‖ e_pub (32) ‖ nonce (12) ‖ AES-256-GCM(ciphertext ‖ tag 16)
//! dh     = X25519(e, seal_key)                 // the browser's e is one-use too
//! key    = HKDF-SHA256(ikm = dh,
//!                      salt = e_pub ‖ seal_pub,
//!                      info = "infraternal privilege seal v1" ‖ host (16) ‖ attempt (16) ‖ method)
//! aad    = "ifpriv1" ‖ host (16) ‖ attempt (16) ‖ method
//! ```
//!
//! Binding the host, the attempt and the method into both the key and the
//! additional data means a sealed password can't be replayed to another host,
//! another attempt or another way in. The browser side implements the same
//! format with `WebCrypto`; a known-answer vector in this module's tests pins it
//! for both.
//!
//! What this protects against, plainly: the password never sits readable in
//! the server's memory, database, logs or backups. A server that is actively
//! malicious could hand the browser a key of its own, but such a server
//! already commands this infraternal agent, so sealing does not claim to stop
//! it.
use ring::{aead, agreement, hkdf, rand::SystemRandom};
use zeroize::Zeroizing;

/// The only format version this infraternal agent opens.
pub const VERSION: u8 = 1;
/// Fixed bytes before the ciphertext: version, the browser's public key, the nonce.
const HEADER: usize = 1 + 32 + 12;
/// AES-GCM's tag length.
const TAG: usize = 16;
/// Longest password accepted. sudo, doas and su read far less; the cap keeps a
/// hostile request from making this infraternal agent allocate much.
pub const MAX_SECRET: usize = 1024;
/// Prefix of the HKDF info string; the version is part of it on purpose.
const INFO: &[u8] = b"infraternal privilege seal v1";
/// Prefix of the AEAD additional data.
const AAD: &[u8] = b"ifpriv1";

/// The way in a sealed password is for. Part of the key derivation, so a
/// password sealed for `sudo` can't be fed to `su`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// The person's own password, for sudo.
    Sudo,
    /// The person's own password, for doas.
    Doas,
    /// The root password, for su.
    Su,
}

impl Method {
    /// The exact bytes bound into the seal; the browser uses the same words.
    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Sudo => b"sudo",
            Self::Doas => b"doas",
            Self::Su => b"su",
        }
    }
}

/// What a sealed password is bound to. Both sides must agree on all three.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The host's id, as the server knows it.
    pub host: [u8; 16],
    /// This attempt's id; a new key and a new id for every try.
    pub attempt: [u8; 16],
    /// The way in.
    pub method: Method,
}

/// Why a sealed password could not be opened. Deliberately coarse: the reason
/// is logged and shown without ever echoing any of the sealed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The bytes are not a version-1 seal of an acceptable size.
    Malformed,
    /// The key agreement or the authentication tag failed: the bytes were
    /// changed, were sealed to another key, or are bound to something else.
    Refused,
}

/// A one-use X25519 key that opens exactly one sealed password.
pub struct SealKey {
    private: agreement::EphemeralPrivateKey,
    public: [u8; 32],
}

impl SealKey {
    /// Make a fresh key from the system's random source.
    ///
    /// # Errors
    /// Fails only when the system random source fails.
    pub fn new() -> Result<Self, ring::error::Unspecified> {
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())?;
        let mut public = [0; 32];
        public.copy_from_slice(private.compute_public_key()?.as_ref());
        Ok(Self { private, public })
    }

    /// The public half, which the browser seals to.
    #[must_use]
    pub const fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Open `sealed` for `binding`, consuming this key whatever the result.
    ///
    /// # Errors
    /// [`OpenError::Malformed`] for the wrong version or size,
    /// [`OpenError::Refused`] when the bytes don't authenticate.
    pub fn open(self, binding: &Binding, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        let peer = split(sealed)?.peer;
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer);
        let seal_public = self.public;
        agreement::agree_ephemeral(self.private, &peer, |dh| {
            let mut shared = Zeroizing::new([0; 32]);
            shared.copy_from_slice(dh);
            open_with_shared(&shared, &seal_public, binding, sealed)
        })
        .map_err(|_| OpenError::Refused)?
    }
}

/// The three parts of a seal after its version byte.
struct Parts<'a> {
    /// The browser's one-use X25519 public key.
    peer: &'a [u8],
    /// The AES-GCM nonce.
    nonce: [u8; 12],
    /// The ciphertext with its tag.
    ciphertext: &'a [u8],
}

/// Split a seal into its [`Parts`], checking only the version and the size.
fn split(sealed: &[u8]) -> Result<Parts<'_>, OpenError> {
    if sealed.len() < HEADER + TAG + 1
        || sealed.len() > HEADER + TAG + MAX_SECRET
        || sealed[0] != VERSION
    {
        return Err(OpenError::Malformed);
    }
    let mut nonce = [0; 12];
    nonce.copy_from_slice(&sealed[33..HEADER]);
    Ok(Parts {
        peer: &sealed[1..33],
        nonce,
        ciphertext: &sealed[HEADER..],
    })
}

/// The symmetric half of opening, once the X25519 agreement is done. Split out
/// so the format can be pinned with a known-answer vector: `ring` can't load
/// a fixed private key, so the vector starts from the shared secret.
fn open_with_shared(
    shared: &[u8; 32],
    seal_public: &[u8; 32],
    binding: &Binding,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let Parts {
        peer,
        nonce,
        ciphertext,
    } = split(sealed)?;
    let key = derive(shared, peer, seal_public, binding)?;
    let aad = additional(binding);
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let plain = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad[..]),
            &mut buffer,
        )
        .map_err(|_| OpenError::Refused)?
        .len();
    buffer.truncate(plain);
    Ok(buffer)
}

/// The AES-256-GCM key for one seal (see the module docs for the inputs).
fn derive(
    shared: &[u8; 32],
    peer: &[u8],
    seal_public: &[u8; 32],
    binding: &Binding,
) -> Result<aead::LessSafeKey, OpenError> {
    let mut salt = [0; 64];
    salt[..32].copy_from_slice(peer);
    salt[32..].copy_from_slice(seal_public);
    let info = [
        INFO,
        &binding.host[..],
        &binding.attempt[..],
        binding.method.label(),
    ];
    // The pseudorandom key must outlive the expansion that borrows it.
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(shared);
    let okm = prk
        .expand(&info, &aead::AES_256_GCM)
        .map_err(|_| OpenError::Refused)?;
    Ok(aead::LessSafeKey::new(aead::UnboundKey::from(okm)))
}

/// The additional data both sides authenticate (see the module docs).
fn additional(binding: &Binding) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD.len() + 32 + 4);
    aad.extend_from_slice(AAD);
    aad.extend_from_slice(&binding.host);
    aad.extend_from_slice(&binding.attempt);
    aad.extend_from_slice(binding.method.label());
    aad
}

#[cfg(test)]
mod tests {
    //! The seal opens once, for exactly its binding, and matches the pinned vector.
    use super::*;

    /// Seal `secret` to `seal_public` the way the browser does, with `ring`'s
    /// own one-use key standing in for `WebCrypto`'s.
    fn seal(seal_public: &[u8; 32], binding: &Binding, secret: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        let e = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        let e_pub = e.compute_public_key().unwrap();
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, seal_public);
        let mut sealed = vec![VERSION];
        sealed.extend_from_slice(e_pub.as_ref());
        let nonce = [7; 12];
        sealed.extend_from_slice(&nonce);
        agreement::agree_ephemeral(e, &peer, |dh| {
            let mut shared = [0; 32];
            shared.copy_from_slice(dh);
            let key = derive(&shared, &sealed[1..33], seal_public, binding).unwrap();
            let mut body = secret.to_vec();
            key.seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&additional(binding)[..]),
                &mut body,
            )
            .unwrap();
            sealed.extend_from_slice(&body);
        })
        .unwrap();
        sealed
    }

    /// The binding every test seals for, unless it tests another.
    const BINDING: Binding = Binding {
        host: [0x11; 16],
        attempt: [0x22; 16],
        method: Method::Sudo,
    };

    /// A password sealed to a fresh key opens to the same bytes.
    #[test]
    fn a_sealed_password_opens_once_to_the_same_bytes() {
        let key = SealKey::new().unwrap();
        let sealed = seal(&key.public(), &BINDING, b"correct horse");
        assert_eq!(&key.open(&BINDING, &sealed).unwrap()[..], b"correct horse");
    }

    /// Changing the host, the attempt or the method refuses the seal, so a
    /// sealed password can't be replayed anywhere else.
    #[test]
    fn a_seal_is_refused_for_any_other_binding() {
        for other in [
            Binding {
                host: [0x12; 16],
                ..BINDING
            },
            Binding {
                attempt: [0x23; 16],
                ..BINDING
            },
            Binding {
                method: Method::Su,
                ..BINDING
            },
            Binding {
                method: Method::Doas,
                ..BINDING
            },
        ] {
            let key = SealKey::new().unwrap();
            let sealed = seal(&key.public(), &BINDING, b"pw");
            assert_eq!(
                key.open(&other, &sealed).unwrap_err(),
                OpenError::Refused,
                "{other:?}"
            );
        }
    }

    /// A seal for another key, a flipped byte anywhere, a wrong version or an
    /// oversized secret is refused.
    #[test]
    fn tampered_foreign_and_oversized_seals_are_refused() {
        let other = SealKey::new().unwrap();
        let key = SealKey::new().unwrap();
        assert_eq!(
            key.open(&BINDING, &seal(&other.public(), &BINDING, b"pw"))
                .unwrap_err(),
            OpenError::Refused
        );
        let base = {
            let probe = SealKey::new().unwrap();
            (probe.public(), seal(&probe.public(), &BINDING, b"pw"))
        };
        for index in 1..base.1.len() {
            let mut bent = base.1.clone();
            bent[index] ^= 1;
            // A fresh key each time: the original private key is gone after one open.
            let fresh = SealKey::new().unwrap();
            assert!(fresh.open(&BINDING, &bent).is_err(), "byte {index}");
        }
        let mut version = base.1.clone();
        version[0] = 2;
        assert_eq!(
            SealKey::new()
                .unwrap()
                .open(&BINDING, &version)
                .unwrap_err(),
            OpenError::Malformed
        );
        let key = SealKey::new().unwrap();
        let big = seal(&key.public(), &BINDING, &[b'x'; MAX_SECRET + 1]);
        assert_eq!(key.open(&BINDING, &big).unwrap_err(), OpenError::Malformed);
        assert_eq!(
            SealKey::new()
                .unwrap()
                .open(&BINDING, &[1; 20])
                .unwrap_err(),
            OpenError::Malformed
        );
    }

    /// The pinned vector (made with an independent implementation, Python
    /// `cryptography`): from a fixed shared secret and keys, the seal opens to
    /// "hunter2". The browser's `WebCrypto` sealer is tested against the same.
    pub(super) const KAT: (&str, &str, &str) = (
        // shared secret
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        // seal public key
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        // sealed bytes
        "01404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000102030405060708090a0bf5902befea40b538a9e2d87a95a8e0ffec2b38ada517b5",
    );

    /// Decode lowercase hex in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The format is pinned: the vector opens to "hunter2".
    #[test]
    fn the_pinned_vector_opens() {
        let shared: [u8; 32] = hex(KAT.0).try_into().unwrap();
        let public: [u8; 32] = hex(KAT.1).try_into().unwrap();
        let opened = open_with_shared(&shared, &public, &BINDING, &hex(KAT.2)).unwrap();
        assert_eq!(&opened[..], b"hunter2");
    }
}
