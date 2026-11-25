//! Defines the bounded app-level handshake that admits D168 identities over
//! the public WebSocket listener [168], #291, and makes the server prove its
//! current leg-B leaf on that path (#559).
//!
//! The messages and the signed transcripts live in `infraternal-link`
//! (#580) and are re-exported here; this module keeps what needs OpenSSL:
//! the TLS exporter, signing and verifying, and the server-leaf check.
//!
//! # The handshake
//!
//! After the WebSocket upgrade the server always sends an
//! [`AgentLinkChallenge`] (a 32-byte nonce). Then:
//!
//! - the agent answers an [`AgentLinkProofV2`]. It adds a fresh agent
//!   nonce and the agent's view of the TLS session ([`tls_channel_binding`],
//!   RFC 9266 `tls-exporter`), signed over [`agent_proof_bytes_v2`]. The
//!   server answers [`AgentLinkReadyV2`]: its current leg-B leaf and a
//!   signature by that leaf's key over [`server_proof_bytes_v2`]. The
//!   agent checks the leaf exactly as on a direct leg-B dial (chain to the
//!   enrolled CA, server purpose, server name, validity; see
//!   [`verify_server_leaf`]) and then applies the
//!   [`crate::server_leaf_floor::ServerLeafFloor`], so a copied, older leaf
//!   is refused here too.
//!
//! There is no older handshake. The first design (#291) had the agent sign
//! only the challenge and the server answer a bare `ready`, which proved
//! nothing about the server beyond the outer HTTPS certificate. It was
//! removed (#559, J1198): a server refuses any other proof message and an
//! agent refuses any other answer, with the same errors as any malformed
//! message, so the refusal tells a prober nothing about what once existed.
//!
//! # What the TLS binding adds, and where
//!
//! When the server terminates TLS itself, it knows the exporter of the
//! connection the proof arrived on and requires the agent's value to match.
//! A relay in the middle has two TLS sessions with two different exporters,
//! so its forwarded proof is refused, whatever certificate it presents
//! (even a copy of the real HTTPS key). The server then signs the binding into
//! `ready-v2` (`channel_bound: true`), so the agent sees the same proof.
//!
//! Behind a TLS-terminating reverse proxy the server never sees the agent's
//! TLS session. It signs "unbound" instead, and the agent accepts that only
//! when its enrollment trusts the system roots, which is the reverse-proxy
//! mode. With a pinned HTTPS certificate the server terminates TLS, so an
//! unbound answer is refused.
//!
//! # Invariants
//!
//! - Every signed message starts with its own domain string, so neither
//!   side's signature is valid as the other's or as a TLS handshake signature.
//! - Transcript fields are fixed-length, except the binding, which is
//!   preceded by a presence byte. No two different inputs produce the same
//!   bytes.
//! - The server signs only after it has verified the agent's proof, and its
//!   signature covers the agent's fresh nonce. A recorded `ready-v2` is
//!   therefore useless on any other connection.

/// The wire models, constants and transcript builders, under their old paths.
pub use infraternal_link::agent_link::{
    AgentLinkChallenge, AgentLinkProofV2, AgentLinkReadyV2, BINDING_LEN, CHANNEL_BINDING_LABEL,
    NONCE_LEN, PROOF_V2, READY_V2, agent_proof_bytes_v2, message_type, server_proof_bytes_v2,
};
use openssl::{
    hash::MessageDigest,
    pkey::{HasPublic, Id, PKeyRef, Private},
    sign::{Signer, Verifier},
    ssl::{SslRef, SslVersion},
    stack::Stack,
    x509::{
        X509, X509PurposeId, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyParam,
    },
};
use std::io;
use uuid::Uuid;

/// The RFC 9266 `tls-exporter` channel binding of `ssl`: 32 bytes exported
/// under the label `EXPORTER-Channel-Binding` with an empty context.
///
/// Both ends of one TLS session compute the same value. Two sessions (the
/// two halves of a relay) have different values. Only TLS 1.3 sessions get
/// one: TLS 1.2's exporter is unsafe for binding without the extended master
/// secret, which this code cannot confirm. Returns `None` otherwise.
#[must_use]
pub fn tls_channel_binding(ssl: &SslRef) -> Option<[u8; BINDING_LEN]> {
    if ssl.version2() != Some(SslVersion::TLS1_3) {
        return None;
    }
    let mut binding = [0; BINDING_LEN];
    ssl.export_keying_material(&mut binding, CHANNEL_BINDING_LABEL, Some(&[]))
        .ok()?;
    Some(binding)
}

/// Sign `message` with an Ed25519 or P-256 key, the two key types infraternal
/// issues. Any other key type is refused.
/// # Errors
/// An unsupported key type or a signing failure.
pub fn sign(key: &PKeyRef<Private>, message: &[u8]) -> io::Result<Vec<u8>> {
    let mut signer = match key.id() {
        Id::ED25519 => Signer::new_without_digest(key),
        Id::EC if is_p256(key) => Signer::new(MessageDigest::sha256(), key),
        _ => return Err(server_unproved()),
    }
    .map_err(|_| server_unproved())?;
    signer
        .sign_oneshot_to_vec(message)
        .map_err(|_| server_unproved())
}

/// Whether `signature` is `key`'s Ed25519 or P-256 signature of `message`.
/// Any other key type is never valid.
#[must_use]
pub fn verify<T: HasPublic>(key: &PKeyRef<T>, message: &[u8], signature: &[u8]) -> bool {
    let verifier = match key.id() {
        Id::ED25519 => Verifier::new_without_digest(key),
        Id::EC if is_p256(key) => Verifier::new(MessageDigest::sha256(), key),
        _ => return false,
    };
    verifier.is_ok_and(|mut verifier| verifier.verify_oneshot(signature, message).unwrap_or(false))
}

/// Whether an EC key is on P-256, the only curve infraternal uses.
fn is_p256<T: HasPublic>(key: &PKeyRef<T>) -> bool {
    key.ec_key()
        .is_ok_and(|key| key.group().curve_name() == Some(openssl::nid::Nid::X9_62_PRIME256V1))
}

/// Check `leaf` the way a direct leg-B dial checks the server: it chains to
/// one of the enrolled `roots` (at most one intermediate level, as the TLS
/// connector allows), is valid now, carries the TLS server purpose and names
/// `name` (a DNS name or an IP address).
///
/// This adds no ordering: call the
/// [`crate::server_leaf_floor::ServerLeafFloor`] after it.
/// # Errors
/// `InvalidData` for any failed check (see [`server_unproved`]).
pub fn verify_server_leaf(roots: &[X509], leaf: &X509, name: &str) -> io::Result<()> {
    if roots.is_empty() || roots.len() > 16 {
        return Err(server_unproved());
    }
    let mut trust = X509StoreBuilder::new().map_err(|_| server_unproved())?;
    for root in roots {
        trust
            .add_cert(root.clone())
            .map_err(|_| server_unproved())?;
    }
    let mut params = X509VerifyParam::new().map_err(|_| server_unproved())?;
    params
        .set_purpose(X509PurposeId::SSL_SERVER)
        .map_err(|_| server_unproved())?;
    params.set_depth(2);
    if let Ok(ip) = name.parse() {
        params.set_ip(ip).map_err(|_| server_unproved())?;
    } else {
        params.set_host(name).map_err(|_| server_unproved())?;
    }
    trust.set_param(&params).map_err(|_| server_unproved())?;
    let chain = Stack::new().map_err(|_| server_unproved())?;
    let verified = X509StoreContext::new()
        .map_err(|_| server_unproved())?
        .init(&trust.build(), leaf, &chain, |context| {
            context.verify_cert()
        })
        .map_err(|_| server_unproved())?;
    if verified {
        Ok(())
    } else {
        Err(server_unproved())
    }
}

/// What the infraternal agent needs to judge an [`AgentLinkReadyV2`].
pub struct ServerProofPolicy<'a> {
    /// The enrolled CA roots (the same ones the leg-B dial trusts).
    pub roots: &'a [X509],
    /// The server name the leaf must carry.
    pub server_name: &'a str,
    /// Refuse a server that did not check the TLS binding. Set it whenever the
    /// HTTPS certificate is pinned: then the server terminates TLS itself.
    pub require_binding: bool,
}

/// Everything about this connection's handshake that the server's signature
/// must cover, as the agent knows it.
pub struct AgentTranscript<'a> {
    /// The enrolled host id.
    pub host_id: Uuid,
    /// The server's challenge nonce.
    pub server_nonce: &'a [u8; NONCE_LEN],
    /// The agent's own nonce from its proof.
    pub client_nonce: &'a [u8; NONCE_LEN],
    /// The certificate DER the agent proved with.
    pub agent_certificate_der: &'a [u8],
    /// The binding of the TLS session the agent sees, if it has one.
    pub binding: Option<&'a [u8; BINDING_LEN]>,
}

/// Verify a decoded `ready-v2` on the infraternal agent: the leaf passes
/// [`verify_server_leaf`], the binding rule of `policy` holds, and the
/// signature covers this exact `transcript`. Returns the leaf, which the
/// caller must still pass to its `ServerLeafFloor` before trusting the link.
/// # Errors
/// [`server_unproved`] for a bad leaf or signature; [`not_bound`] when the
/// server did not (or could not) check this TLS session's binding but the
/// policy requires it.
pub fn verify_ready_v2(
    policy: &ServerProofPolicy<'_>,
    transcript: &AgentTranscript<'_>,
    leaf_der: &[u8],
    channel_bound: bool,
    signature: &[u8],
) -> io::Result<X509> {
    if leaf_der.len() > 4096 || signature.len() > 512 {
        return Err(server_unproved());
    }
    let leaf = X509::from_der(leaf_der).map_err(|_| server_unproved())?;
    if leaf.to_der().map_err(|_| server_unproved())? != leaf_der {
        return Err(server_unproved());
    }
    verify_server_leaf(policy.roots, &leaf, policy.server_name)?;
    let binding = if channel_bound {
        // The server says it checked a binding: it must be ours.
        Some(transcript.binding.ok_or_else(not_bound)?)
    } else if policy.require_binding {
        return Err(not_bound());
    } else {
        None
    };
    let agent_certificate = sha256(transcript.agent_certificate_der)?;
    let leaf_hash = sha256(leaf_der)?;
    let message = server_proof_bytes_v2(
        transcript.host_id,
        transcript.server_nonce,
        transcript.client_nonce,
        &agent_certificate,
        &leaf_hash,
        binding,
    );
    let key = leaf.public_key().map_err(|_| server_unproved())?;
    if !verify(&key, &message, signature) {
        return Err(server_unproved());
    }
    Ok(leaf)
}

/// SHA-256 of `bytes`.
/// # Errors
/// Only if OpenSSL's digest fails.
pub fn sha256(bytes: &[u8]) -> io::Result<[u8; 32]> {
    openssl::hash::hash(MessageDigest::sha256(), bytes)
        .map_err(|_| server_unproved())?
        .as_ref()
        .try_into()
        .map_err(|_| server_unproved())
}

/// The refusal when the server did not prove a valid, current leg-B leaf.
///
/// `InvalidData`, never `PermissionDenied`: that kind means "the server
/// refused this host's identity" and starts certificate recovery, which a
/// server that failed to prove itself must not trigger (the same rule as
/// [`crate::server_leaf_floor`]).
#[must_use]
pub fn server_unproved() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "remote infraternal server did not prove its current certificate",
    )
}

/// The refusal when the link is not bound to the TLS session the agent sees
/// although it must be: something between the agent and the server
/// terminates TLS (a relay, or a proxy in front of a pinned certificate).
/// `InvalidData` for the same reason as [`server_unproved`].
#[must_use]
pub fn not_bound() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "remote infraternal server link is not bound to this TLS session",
    )
}

#[cfg(test)]
mod tests {
    //! Transcript shape, the agent-side check of `ready-v2`, and a real TLS
    //! session's channel binding.
    use super::*;

    use crate::remote_tls::{
        Identity,
        tests::{leaf, root},
    };

    /// One server-side `ready-v2` and the agent-side values to check it with.
    struct Case {
        ca: Identity,
        server: Identity,
        agent_der: Vec<u8>,
        host: Uuid,
        server_nonce: [u8; 32],
        client_nonce: [u8; 32],
        binding: [u8; 32],
    }

    impl Case {
        /// A fresh CA, server leaf and agent certificate, with fixed nonces.
        fn new() -> Self {
            let ca = root();
            let server = leaf(&ca, true);
            let agent = leaf(&ca, false);
            Self {
                agent_der: agent.certificate.to_der().unwrap(),
                ca,
                server,
                host: Uuid::from_u128(7),
                server_nonce: [1; 32],
                client_nonce: [2; 32],
                binding: [3; 32],
            }
        }

        /// What an honest server signs, with `binding` when it checked one.
        fn sign(&self, signer: &Identity, binding: Option<&[u8; 32]>) -> Vec<u8> {
            let message = server_proof_bytes_v2(
                self.host,
                &self.server_nonce,
                &self.client_nonce,
                &sha256(&self.agent_der).unwrap(),
                &sha256(&self.server.certificate.to_der().unwrap()).unwrap(),
                binding,
            );
            sign(&signer.key, &message).unwrap()
        }

        /// The agent's view of this handshake, bound to `self.binding`.
        fn transcript(&self) -> AgentTranscript<'_> {
            AgentTranscript {
                host_id: self.host,
                server_nonce: &self.server_nonce,
                client_nonce: &self.client_nonce,
                agent_certificate_der: &self.agent_der,
                binding: Some(&self.binding),
            }
        }

        /// Run [`verify_ready_v2`] on the server leaf with this policy.
        fn check(
            &self,
            transcript: &AgentTranscript<'_>,
            require_binding: bool,
            channel_bound: bool,
            signature: &[u8],
        ) -> io::Result<X509> {
            let roots = [self.ca.certificate.clone()];
            verify_ready_v2(
                &ServerProofPolicy {
                    roots: &roots,
                    server_name: "localhost",
                    require_binding,
                },
                transcript,
                &self.server.certificate.to_der().unwrap(),
                channel_bound,
                signature,
            )
        }
    }

    /// The four signed v2 messages never collide: agent and server domains
    /// differ from each other, and a missing binding is not a
    /// zero binding.
    #[test]
    fn v2_transcripts_are_domain_separated_and_unambiguous() {
        let host = Uuid::from_u128(1);
        let agent = agent_proof_bytes_v2(host, &[1; 32], &[2; 32], Some(&[0; 32]));
        let agent_unbound = agent_proof_bytes_v2(host, &[1; 32], &[2; 32], None);
        let server = server_proof_bytes_v2(host, &[1; 32], &[2; 32], &[4; 32], &[5; 32], None);
        assert!(agent.starts_with(b"infraternal-agent-link-v2\0agent\0"));
        assert!(server.starts_with(b"infraternal-agent-link-v2\0server\0"));
        assert_ne!(agent, agent_unbound);
        assert_ne!(agent[..agent_unbound.len()], agent_unbound[..]);
        assert_ne!(
            agent_proof_bytes_v2(host, &[2; 32], &[1; 32], None),
            agent_unbound,
            "the two nonces must not be interchangeable"
        );
    }

    /// An honest bound answer passes and returns the leaf; any change to what
    /// the signature covers is refused as "server unproved".
    #[test]
    fn ready_v2_signature_covers_the_whole_transcript() {
        let case = Case::new();
        let signature = case.sign(&case.server, Some(&case.binding));
        let accepted = case
            .check(&case.transcript(), true, true, &signature)
            .unwrap();
        assert_eq!(
            accepted.to_der().unwrap(),
            case.server.certificate.to_der().unwrap()
        );
        let other_nonce = [9; 32];
        let other_binding = [8; 32];
        let other_agent = leaf(&case.ca, false).certificate.to_der().unwrap();
        let changed = [
            AgentTranscript {
                host_id: Uuid::from_u128(8),
                ..case.transcript()
            },
            AgentTranscript {
                server_nonce: &other_nonce,
                ..case.transcript()
            },
            AgentTranscript {
                client_nonce: &other_nonce,
                ..case.transcript()
            },
            AgentTranscript {
                agent_certificate_der: &other_agent,
                ..case.transcript()
            },
            AgentTranscript {
                binding: Some(&other_binding),
                ..case.transcript()
            },
        ];
        for transcript in &changed {
            let error = case.check(transcript, true, true, &signature).unwrap_err();
            assert_eq!(error.to_string(), server_unproved().to_string());
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    /// A pinned-HTTPS agent refuses an unbound answer; a reverse-proxy agent
    /// accepts it. A "bound" answer to an agent without a binding is refused.
    #[test]
    fn binding_policy_refuses_unbound_answers_when_pinned() {
        let case = Case::new();
        let unbound = case.sign(&case.server, None);
        let refused = case
            .check(&case.transcript(), true, false, &unbound)
            .unwrap_err();
        assert_eq!(refused.to_string(), not_bound().to_string());
        case.check(&case.transcript(), false, false, &unbound)
            .expect("reverse-proxy policy accepts a signed unbound answer");
        let bound = case.sign(&case.server, Some(&case.binding));
        let no_binding = AgentTranscript {
            binding: None,
            ..case.transcript()
        };
        let refused = case.check(&no_binding, false, true, &bound).unwrap_err();
        assert_eq!(refused.to_string(), not_bound().to_string());
        // A server cannot turn a bound signature into an unbound answer.
        assert!(
            case.check(&case.transcript(), false, false, &bound)
                .is_err()
        );
    }

    /// The leaf must be the server's own: a signature by another key, a leaf
    /// from another CA, a client-purpose leaf or another name are refused.
    #[test]
    fn ready_v2_refuses_a_leaf_that_is_not_the_servers() {
        let case = Case::new();
        let stranger = leaf(&case.ca, true);
        let forged = case.sign(&stranger, Some(&case.binding));
        assert!(case.check(&case.transcript(), true, true, &forged).is_err());
        let other_ca = root();
        let roots = [other_ca.certificate.clone()];
        assert!(verify_server_leaf(&roots, &case.server.certificate, "localhost").is_err());
        let roots = [case.ca.certificate.clone()];
        verify_server_leaf(&roots, &case.server.certificate, "localhost").unwrap();
        assert!(verify_server_leaf(&roots, &case.server.certificate, "example.test").is_err());
        let client = leaf(&case.ca, false);
        assert!(verify_server_leaf(&roots, &client.certificate, "localhost").is_err());
        assert!(verify_server_leaf(&[], &case.server.certificate, "localhost").is_err());
    }

    /// Both ends of one real TLS 1.3 session export the same binding, and a
    /// second session exports a different one: the property a relay breaks.
    #[tokio::test]
    async fn both_ends_of_one_tls_session_share_its_binding() {
        use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
        let ca = root();
        let server = leaf(&ca, true);
        let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
        acceptor.set_certificate(&server.certificate).unwrap();
        acceptor.set_private_key(&server.key).unwrap();
        let acceptor = acceptor.build();
        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        let connector = connector.build();
        let mut bindings = Vec::new();
        for _ in 0..2 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let accepting = acceptor.clone();
            let server_side = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let ssl = openssl::ssl::Ssl::new(accepting.context()).unwrap();
                let mut stream = tokio_openssl::SslStream::new(ssl, socket).unwrap();
                std::pin::Pin::new(&mut stream).accept().await.unwrap();
                tls_channel_binding(stream.ssl()).unwrap()
            });
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let ssl = connector
                .configure()
                .unwrap()
                .into_ssl("localhost")
                .unwrap();
            let mut stream = tokio_openssl::SslStream::new(ssl, socket).unwrap();
            std::pin::Pin::new(&mut stream).connect().await.unwrap();
            let client_side = tls_channel_binding(stream.ssl()).unwrap();
            assert_eq!(client_side, server_side.await.unwrap());
            bindings.push(client_side);
        }
        assert_ne!(bindings[0], bindings[1]);
    }

    /// Cost of what v2 adds per handshake, in a release build:
    /// `cargo test --release -p infraternal-plugin-remote --features transport
    /// --lib -- --ignored agent_link_v2_crypto_cost --nocapture`.
    /// The exporter is paid once per HTTPS connection by every TLS client of
    /// a `config.tls` server; the rest only by infraternal agent links.
    #[tokio::test]
    #[ignore = "measurement, run by hand in release mode"]
    async fn agent_link_v2_crypto_cost() {
        use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
        use std::time::Instant;
        const ROUNDS: u32 = 2000;
        const HANDSHAKES: u32 = 300;
        let case = Case::new();
        let ca = &case.ca;
        let server = &case.server;
        let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
        acceptor.set_certificate(&server.certificate).unwrap();
        acceptor.set_private_key(&server.key).unwrap();
        let acceptor = acceptor.build();
        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        let connector = connector.build();
        // Full TLS 1.3 handshakes over loopback, for scale: the exporter is
        // paid once per such handshake.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_side = tokio::spawn(async move {
            let mut last = None;
            for _ in 0..HANDSHAKES {
                let (socket, _) = listener.accept().await.unwrap();
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut stream = tokio_openssl::SslStream::new(ssl, socket).unwrap();
                std::pin::Pin::new(&mut stream).accept().await.unwrap();
                last = Some(stream);
            }
            last.unwrap()
        });
        let started = Instant::now();
        let mut stream = None;
        for _ in 0..HANDSHAKES {
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let ssl = connector
                .configure()
                .unwrap()
                .into_ssl("localhost")
                .unwrap();
            let mut client = tokio_openssl::SslStream::new(ssl, socket).unwrap();
            std::pin::Pin::new(&mut client).connect().await.unwrap();
            stream = Some(client);
        }
        let handshake = started.elapsed().as_nanos() / u128::from(HANDSHAKES);
        let stream = stream.unwrap();
        let _server_stream = server_side.await.unwrap();
        let per = |started: Instant| started.elapsed().as_nanos() / u128::from(ROUNDS);
        let started = Instant::now();
        for _ in 0..ROUNDS {
            std::hint::black_box(tls_channel_binding(stream.ssl()));
        }
        let exporter = per(started);
        let started = Instant::now();
        let mut signature = Vec::new();
        for _ in 0..ROUNDS {
            signature = case.sign(server, Some(&case.binding));
        }
        let server_sign = per(started);
        let roots = [ca.certificate.clone()];
        let leaf_der = server.certificate.to_der().unwrap();
        let started = Instant::now();
        for _ in 0..ROUNDS {
            verify_ready_v2(
                &ServerProofPolicy {
                    roots: &roots,
                    server_name: "localhost",
                    require_binding: true,
                },
                &case.transcript(),
                &leaf_der,
                true,
                &signature,
            )
            .unwrap();
        }
        let agent_verify = per(started);
        println!(
            "agent_link_v2_cost_ns tls13_loopback_handshake={handshake} exporter={exporter} server_sign_with_hashes={server_sign} agent_verify_leaf_and_signature={agent_verify} rounds={ROUNDS} handshakes={HANDSHAKES}"
        );
    }
}
