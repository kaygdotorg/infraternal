//! Locks the mesh negotiation policy while excluding unused engine implementations [D289, #413].
#![allow(clippy::unwrap_used)]

/// Shares the existing in-memory authority; no host account or key files are used.
#[allow(dead_code)]
#[path = "common/mesh_runtime.rs"]
mod runtime;

use infraternal_plugin_ssh::mesh_server::config;
use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// The mesh keeps its complete existing transport offer, in preference order.
#[test]
fn mesh_transport_offer_is_unchanged() {
    let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let config = config(key);
    assert_eq!(
        config
            .preferred
            .kex
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        [
            "mlkem768x25519-sha256",
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group17-sha512",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group15-sha512",
            "diffie-hellman-group14-sha256",
            "ext-info-c",
            "ext-info-s",
            "kex-strict-c-v00@openssh.com",
            "kex-strict-s-v00@openssh.com",
        ]
    );
    assert_eq!(
        config
            .preferred
            .cipher
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        [
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr"
        ]
    );
    assert_eq!(
        config
            .preferred
            .mac
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        [
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-256"
        ]
    );
    assert_eq!(
        config
            .preferred
            .compression
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>(),
        ["none"]
    );
    // Extension markers do not have key-exchange implementations.
    for name in config.preferred.kex.iter().take(9) {
        assert!(russh::kex::Name::try_from(name.as_ref()).is_ok());
    }
}

/// Unoffered NIST ECDH must not retain its implementations through the factory.
#[test]
fn unoffered_nist_ecdh_is_not_registered() {
    for name in [
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
    ] {
        assert!(
            russh::kex::Name::try_from(name).is_err(),
            "{name} is still registered"
        );
    }
}

/// Unoffered AES variants must not keep transport implementations linked in.
#[test]
fn unoffered_aes_ciphers_are_not_registered() {
    for name in [
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "aes128-gcm@openssh.com",
    ] {
        assert!(
            russh::cipher::Name::try_from(name).is_err(),
            "{name} is still registered"
        );
    }
    for name in russh::Preferred::DEFAULT.cipher.iter() {
        assert!(russh::cipher::Name::try_from(name.as_ref()).is_ok());
    }
}

/// Deprecated transport algorithms are absent; internal clear/AEAD support remains.
#[test]
fn unoffered_legacy_transport_is_not_registered() {
    for name in [
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "none",
    ] {
        assert!(
            russh::kex::Name::try_from(name).is_err(),
            "{name} is still registered"
        );
    }
    for name in ["hmac-sha1", "hmac-sha1-etm@openssh.com"] {
        assert!(
            russh::mac::Name::try_from(name).is_err(),
            "{name} is still registered"
        );
    }
    assert!(russh::mac::Name::try_from("none").is_ok());
    assert!(russh::cipher::Name::try_from("clear").is_ok());
}

/// Removing ECDH must retain every existing NIST ECDSA signer and verifier.
#[test]
fn ecdsa_keys_still_sign_and_verify() {
    for curve in [
        EcdsaCurve::NistP256,
        EcdsaCurve::NistP384,
        EcdsaCurve::NistP521,
    ] {
        let key = PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            Algorithm::Ecdsa { curve },
        )
        .unwrap();
        let signature = key
            .sign("mesh-fixture", HashAlg::Sha256, b"challenge")
            .unwrap();
        assert!(
            key.public_key()
                .verify("mesh-fixture", b"challenge", &signature)
                .is_ok()
        );
        assert!(
            key.public_key()
                .verify("mesh-fixture", b"different", &signature)
                .is_err()
        );
    }
}

/// Decode one public algorithm name-list from a bounded fixture packet.
fn name_list(packet: &mut &[u8]) -> String {
    let length = u32::from_be_bytes(packet[..4].try_into().unwrap()) as usize;
    let value = std::str::from_utf8(&packet[4..4 + length])
        .unwrap()
        .to_owned();
    *packet = &packet[4 + length..];
    value
}

/// A client sees the same complete KEXINIT offer, including host certificates.
#[tokio::test]
async fn wire_offer_keeps_the_mesh_transport_and_host_certificate() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let ca = runtime::key();
        let host = runtime::key();
        let mut builder = russh::keys::ssh_key::certificate::Builder::new(
            vec![1; 32], host.public_key(), 0, u64::MAX,
        ).unwrap();
        builder.cert_type(russh::keys::ssh_key::certificate::CertType::Host).unwrap();
        builder.valid_principal("mesh-host").unwrap();
        let cert = builder.sign(&ca).unwrap();
        let authority = runtime::Authority::new(&ca, &cert);
        let mut settings = config(host);
        settings.certificates = vec![cert];
        let (mut client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(infraternal_plugin_ssh::mesh_server::serve(
            authority, "127.0.0.1".parse().unwrap(), 9, Arc::new(settings), server,
        ));
        client.write_all(b"SSH-2.0-fixture\r\n").await.unwrap();
        let mut reader = BufReader::new(client);
        let mut banner = String::new();
        reader.read_line(&mut banner).await.unwrap();
        assert!(banner.starts_with("SSH-2.0-"));
        let length = reader.read_u32().await.unwrap() as usize;
        assert!((18..65536).contains(&length));
        let padding = reader.read_u8().await.unwrap() as usize;
        let mut packet = vec![0; length - 1];
        reader.read_exact(&mut packet).await.unwrap();
        assert_eq!(packet[0], 20, "first packet must be KEXINIT");
        let mut payload = &packet[17..packet.len() - padding];
        let actual = (0..10).map(|_| name_list(&mut payload)).collect::<Vec<_>>();
        let ciphers = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr";
        let macs = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256";
        assert_eq!(actual, [
            "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group18-sha512,diffie-hellman-group17-sha512,diffie-hellman-group16-sha512,diffie-hellman-group15-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
            "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519",
            ciphers, ciphers, macs, macs, "none", "none", "", "",
        ]);
        println!("mesh SSH KEXINIT name-lists: {actual:?}");
        // This fixture stops before authentication and owns the entire connection task.
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }).await.unwrap();
}
