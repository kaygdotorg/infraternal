//! Relay link control messages and the DATAGRAM header, shared by the relay and its clients [313].
//!
//! A relay connection carries one client-opened bidirectional control stream
//! and QUIC DATAGRAM frames. Control messages are fixed-size per kind, so the
//! reader knows every length from the first byte and never buffers more than
//! [`MAX_MESSAGE`] bytes. A DATAGRAM is a 4-byte link id followed by one
//! `WireGuard` ciphertext packet; the relay forwards the frame unchanged, so the
//! same id names the link at both ends and forwarding never copies bytes.
//!
//! Hosts are named by the UUID in their verified certificate (the
//! `urn:infraternal:host:<uuid>` SAN that enrollment issues). Names a client
//! sends are only requests: the relay links two hosts only when each asked for
//! the other, so one enrolled host cannot reach a pair that did not ask for it.

use std::fmt;

/// Largest control message (a `Linked` notice); readers never need more.
pub const MAX_MESSAGE: usize = 21;
/// Bytes in front of the ciphertext in every relayed DATAGRAM.
pub const HEADER: usize = 4;

const LINK: u8 = 0x01;
const UNLINK: u8 = 0x02;
const LINKED: u8 = 0x81;
const UNLINKED: u8 = 0x82;

/// A host's enrollment UUID, taken from its verified certificate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostId(pub [u8; 16]);

impl HostId {
    /// Parse the URI SAN that host enrollment writes into every host leaf.
    /// Only the lowercase or uppercase hyphenated form is accepted.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        Self::parse(uri.strip_prefix("urn:infraternal:host:")?)
    }

    /// Parse the hyphenated 36-character UUID form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 36 {
            return None;
        }
        let mut out = [0_u8; 16];
        let mut nibbles = 0;
        for (index, &byte) in bytes.iter().enumerate() {
            if matches!(index, 8 | 13 | 18 | 23) {
                if byte != b'-' {
                    return None;
                }
                continue;
            }
            let value = char::from(byte).to_digit(16)?;
            let value = u8::try_from(value).ok()?;
            out[nibbles / 2] |= if nibbles % 2 == 0 { value << 4 } else { value };
            nibbles += 1;
        }
        Some(Self(out))
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for HostId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// Relay-assigned link id; zero is never assigned, so it can mark "no link".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkId(pub u32);

/// Client to relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// Ask to exchange datagrams with this host.
    Link(HostId),
    /// Withdraw a request or tear down the link with this host.
    Unlink(HostId),
}

/// Relay to client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// Both hosts asked; datagrams with this id now reach the peer.
    Linked { peer: HostId, id: LinkId },
    /// The link ended (the peer withdrew or left); the request stays pending.
    Unlinked { peer: HostId },
}

/// Body length that follows a request kind byte, or `None` for an unknown kind.
#[must_use]
pub fn request_len(kind: u8) -> Option<usize> {
    matches!(kind, LINK | UNLINK).then_some(16)
}

/// Body length that follows a notice kind byte, or `None` for an unknown kind.
#[must_use]
pub fn notice_len(kind: u8) -> Option<usize> {
    match kind {
        LINKED => Some(20),
        UNLINKED => Some(16),
        _ => None,
    }
}

impl Request {
    /// Encode as kind byte plus body.
    #[must_use]
    pub fn encode(self) -> [u8; 17] {
        let (kind, host) = match self {
            Self::Link(host) => (LINK, host),
            Self::Unlink(host) => (UNLINK, host),
        };
        let mut out = [0; 17];
        out[0] = kind;
        out[1..].copy_from_slice(&host.0);
        out
    }

    /// Decode a body whose kind and length came from [`request_len`].
    #[must_use]
    pub fn decode(kind: u8, body: &[u8]) -> Option<Self> {
        let host = HostId(body.try_into().ok()?);
        match kind {
            LINK => Some(Self::Link(host)),
            UNLINK => Some(Self::Unlink(host)),
            _ => None,
        }
    }
}

impl Notice {
    /// Encode as kind byte plus body; returns the buffer and its used length.
    #[must_use]
    pub fn encode(self) -> ([u8; MAX_MESSAGE], usize) {
        let mut out = [0; MAX_MESSAGE];
        match self {
            Self::Linked { peer, id } => {
                out[0] = LINKED;
                out[1..17].copy_from_slice(&peer.0);
                out[17..21].copy_from_slice(&id.0.to_be_bytes());
                (out, 21)
            }
            Self::Unlinked { peer } => {
                out[0] = UNLINKED;
                out[1..17].copy_from_slice(&peer.0);
                (out, 17)
            }
        }
    }

    /// Decode a body whose kind and length came from [`notice_len`].
    /// A `Linked` notice with id zero is refused.
    #[must_use]
    pub fn decode(kind: u8, body: &[u8]) -> Option<Self> {
        match (kind, body.len()) {
            (LINKED, 20) => {
                let id = u32::from_be_bytes(body[16..20].try_into().ok()?);
                let peer = HostId(body[..16].try_into().ok()?);
                (id != 0).then_some(Self::Linked {
                    peer,
                    id: LinkId(id),
                })
            }
            (UNLINKED, 16) => Some(Self::Unlinked {
                peer: HostId(body.try_into().ok()?),
            }),
            _ => None,
        }
    }
}

/// Split a relayed DATAGRAM into its link id and ciphertext.
#[must_use]
pub fn split(datagram: &[u8]) -> Option<(LinkId, &[u8])> {
    let id = u32::from_be_bytes(datagram.get(..HEADER)?.try_into().ok()?);
    (id != 0 && datagram.len() > HEADER).then(|| (LinkId(id), &datagram[HEADER..]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Round trips and refusals for every control kind and the DATAGRAM header.
    use super::*;

    #[test]
    fn host_ids_round_trip_through_the_enrollment_uri() {
        let text = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        let host = HostId::from_uri(&format!("urn:infraternal:host:{text}")).unwrap();
        assert_eq!(host.to_string(), text);
        assert_eq!(HostId::parse(&text.to_uppercase()), Some(host));
        for bad in [
            "",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1fg",
            "0f1e2d3c-4b5a-6978-8796_a5b4c3d2e1f0",
            "+f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
        ] {
            assert_eq!(HostId::parse(bad), None, "{bad}");
        }
        assert_eq!(HostId::from_uri(&format!("urn:other:host:{text}")), None);
    }

    #[test]
    fn requests_and_notices_round_trip() {
        let host = HostId([7; 16]);
        for request in [Request::Link(host), Request::Unlink(host)] {
            let bytes = request.encode();
            assert_eq!(request_len(bytes[0]), Some(bytes.len() - 1));
            assert_eq!(Request::decode(bytes[0], &bytes[1..]), Some(request));
        }
        for notice in [
            Notice::Linked {
                peer: host,
                id: LinkId(0x0102_0304),
            },
            Notice::Unlinked { peer: host },
        ] {
            let (bytes, len) = notice.encode();
            assert_eq!(notice_len(bytes[0]), Some(len - 1));
            assert_eq!(Notice::decode(bytes[0], &bytes[1..len]), Some(notice));
        }
    }

    #[test]
    fn unknown_kinds_short_bodies_and_zero_ids_are_refused() {
        for kind in 0..=u8::MAX {
            if !matches!(kind, LINK | UNLINK) {
                assert_eq!(request_len(kind), None);
                assert_eq!(Request::decode(kind, &[0; 16]), None);
            }
            if !matches!(kind, LINKED | UNLINKED) {
                assert_eq!(notice_len(kind), None);
            }
        }
        assert_eq!(Request::decode(LINK, &[0; 15]), None);
        assert_eq!(Notice::decode(LINKED, &[0; 20]), None);
        assert_eq!(Notice::decode(LINKED, &[0; 19]), None);
        assert_eq!(Notice::decode(UNLINKED, &[0; 20]), None);
    }

    #[test]
    fn datagram_needs_a_nonzero_id_and_ciphertext() {
        assert_eq!(split(&[0, 0, 0, 9, 1, 2]), Some((LinkId(9), &[1, 2][..])));
        assert_eq!(split(&[0, 0, 0, 9]), None);
        assert_eq!(split(&[0, 0, 0, 0, 1]), None);
        assert_eq!(split(&[0, 0, 9]), None);
    }
}
