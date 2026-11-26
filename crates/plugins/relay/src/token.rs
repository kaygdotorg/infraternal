//! The pair tokens that name a relayed pair's link on one relay (D401 Q8).
//!
//! Both ends of a pair compute the same token from a secret only they share; the
//! relay matches two requests for it without learning who asked (see `wire`).

use crate::wire::Token;

/// Label that separates relay pair tokens from every other use of the pair's secret.
const TOKEN_LABEL: &[u8] = b"infraternal relay pair token v1\0";

/// The token one pair asks `relay` for, from the pair's shared secret.
///
/// `shared` is the X25519 result of one end's static mesh key and the other
/// end's public mesh key, so both ends compute the same value and nobody else
/// can, the relay included. The token is the first 16 bytes of
/// HMAC-SHA256(`shared`, label ‖ relay name): one-way, so the token a relay
/// sees reveals nothing about `shared`, and bound to the relay's certificate
/// name, so two relays carrying the same pair see unrelated tokens.
#[must_use]
pub fn pair_token(shared: &[u8; 32], relay: &str) -> Token {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, shared);
    let mut context = ring::hmac::Context::with_key(&key);
    context.update(TOKEN_LABEL);
    context.update(relay.as_bytes());
    let tag = context.sign();
    let mut token = [0; 16];
    token.copy_from_slice(&tag.as_ref()[..16]);
    Token(token)
}

#[cfg(test)]
mod tests {
    //! The derivation is shared, per relay and per pair, and pinned by a vector.
    use super::*;

    /// A pair token is the same for one secret and relay, differs otherwise, and matches a fixed vector.
    #[test]
    fn pair_tokens_are_shared_per_pair_and_differ_per_relay_and_pair() {
        let shared = [3; 32];
        let token = pair_token(&shared, "relay.example.org");
        assert_eq!(token, pair_token(&shared, "relay.example.org"));
        assert_ne!(token, pair_token(&shared, "other.example.org"));
        assert_ne!(token, pair_token(&[4; 32], "relay.example.org"));
        // A fixed vector, so the derivation cannot drift between two releases
        // without this test (both ends of a pair may run different builds).
        assert_eq!(
            token.0,
            [
                0xc7, 0x2a, 0x24, 0xaa, 0x6d, 0x1c, 0x70, 0x83, 0x78, 0x0f, 0xd7, 0xbe, 0xcc, 0x7a,
                0x75, 0x3e
            ]
        );
    }
}
