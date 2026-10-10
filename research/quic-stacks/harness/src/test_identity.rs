//! Role: Creates short-lived in-memory credentials shared by the QUIC candidates.
//! SPDX-License-Identifier: AGPL-3.0-only

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::io::{Read, Write};

const MAX_IDENTITY_PART_BYTES: usize = 16 * 1024;

/// Ephemeral client/server identity and its private test trust anchor.
pub struct TestIdentity {
    pub ca_der: Vec<u8>,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl TestIdentity {
    /// Sends ephemeral benchmark credentials through a private child-process pipe.
    pub fn write_to(&self, mut writer: impl Write) -> Result<(), Box<dyn std::error::Error>> {
        for part in [&self.ca_der, &self.cert_der, &self.key_der] {
            if part.len() > MAX_IDENTITY_PART_BYTES {
                return Err("benchmark identity component exceeded the pipe limit".into());
            }
            writer.write_all(&(part.len() as u32).to_le_bytes())?;
            writer.write_all(part)?;
        }
        writer.flush()?;
        Ok(())
    }

    /// Reads the in-memory identity sent by the parent benchmark process.
    pub fn read_from(mut reader: impl Read) -> Result<Self, Box<dyn std::error::Error>> {
        let mut parts = Vec::with_capacity(3);
        for _ in 0..3 {
            let mut length = [0u8; 4];
            reader.read_exact(&mut length)?;
            let length = u32::from_le_bytes(length) as usize;
            if length == 0 || length > MAX_IDENTITY_PART_BYTES {
                return Err("benchmark identity component length was invalid".into());
            }
            let mut part = vec![0u8; length];
            reader.read_exact(&mut part)?;
            parts.push(part);
        }
        let mut parts = parts.into_iter();
        Ok(Self {
            ca_der: parts.next().expect("three identity parts were read"),
            cert_der: parts.next().expect("three identity parts were read"),
            key_der: parts.next().expect("three identity parts were read"),
        })
    }
}

/// Generates a locally trusted identity without writing key material to disk.
pub fn generate() -> Result<TestIdentity, Box<dyn std::error::Error>> {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "quic benchmark test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned(), "*.quicbench.test".to_owned()])?;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let cert = leaf_params.signed_by(&key, &ca_issuer)?;

    Ok(TestIdentity {
        ca_der: ca_cert.der().to_vec(),
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    })
}
