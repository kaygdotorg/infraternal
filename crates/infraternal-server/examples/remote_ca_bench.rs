//! Measures candidate internal CA primitives with existing vendored OpenSSL, without storing keys or selecting a foundation (#78).

use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    x509::{
        X509, X509NameBuilder, X509Req,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use std::{error::Error, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn certificate(
    key: &PKey<Private>,
    request: Option<&X509Req>,
    issuer: Option<&X509>,
    serial: u32,
) -> Result<X509> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text(
        "CN",
        if request.is_some() {
            "infraternal host"
        } else {
            "infraternal CA"
        },
    )?;
    let name = name.build();
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(issuer.map_or(&*name, |issuer| issuer.subject_name()))?;
    let serial = BigNum::from_u32(serial)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    let not_before = Asn1Time::from_unix(1_791_331_200)?;
    let not_after = Asn1Time::from_unix(1_791_936_000)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    if let Some(request) = request {
        let public = request.public_key()?;
        if public.id() != Id::ED25519 || !request.verify(&public)? {
            return Err("CSR verification failed".into());
        }
        builder.set_pubkey(&public)?;
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        builder.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
        let san = SubjectAlternativeName::new()
            .uri("urn:infraternal:host:00000000-0000-4000-8000-000000000001")
            .build(&builder.x509v3_context(issuer.map(std::ops::Deref::deref), None))?;
        builder.append_extension(san)?;
    } else {
        builder.set_pubkey(key)?;
        builder.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
    }
    builder.sign(
        key,
        if key.id() == Id::ED25519 {
            MessageDigest::null()
        } else {
            MessageDigest::sha256()
        },
    )?;
    Ok(builder.build())
}

fn rss_kib() -> Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    Ok(status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .ok_or("missing RSS")?
        .split_whitespace()
        .next()
        .ok_or("missing RSS value")?
        .parse()?)
}

fn cpu_ticks() -> Result<u64> {
    let status = std::fs::read_to_string("/proc/self/stat")?;
    // The tail begins at stat field 3; user/system CPU are fields 14/15.
    let fields: Vec<_> = status
        .rsplit_once(')')
        .ok_or("missing stat fields")?
        .1
        .split_whitespace()
        .collect();
    Ok(fields[11].parse::<u64>()? + fields[12].parse::<u64>()?)
}

fn main() -> Result<()> {
    let candidate = std::env::args().nth(1).ok_or("specify ed25519 or p256")?;
    let baseline = rss_kib()?;
    let key = match candidate.as_str() {
        "ed25519" => PKey::generate_ed25519()?,
        "p256" => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            PKey::from_ec_key(EcKey::generate(&group)?)?
        }
        _ => return Err("unknown candidate".into()),
    };
    let issuer = certificate(&key, None, None, 1)?;
    let host = PKey::generate_ed25519()?;
    let mut request = X509Req::builder()?;
    request.set_pubkey(&host)?;
    request.set_subject_name(issuer.subject_name())?;
    request.sign(&host, MessageDigest::null())?;
    let request = X509Req::from_der(&request.build().to_der()?)?;
    let mut samples = Vec::with_capacity(2000);
    let cpu_start = cpu_ticks()?;
    let start = Instant::now();
    for serial in 2..2002 {
        let start = Instant::now();
        let leaf = certificate(&key, Some(&request), Some(&issuer), serial)?;
        if !leaf.verify(&key)? {
            return Err("leaf verification failed".into());
        }
        samples.push(start.elapsed().as_micros());
    }
    let elapsed = start.elapsed();
    let cpu = cpu_ticks()? - cpu_start;
    samples.sort_unstable();
    let before_500 = rss_kib()?;
    let mut retained = Vec::with_capacity(500);
    let mut der_bytes = 0;
    for serial in 2002..2502 {
        let leaf = certificate(&key, Some(&request), Some(&issuer), serial)?;
        der_bytes += leaf.to_der()?.len();
        retained.push(leaf);
    }
    println!(
        "candidate={candidate} openssl={} samples=2000 csr_verify_issue_leaf_verify_p50_us={} p99_us={} wall_ms={} cpu_ticks={} clock_ticks_per_second={} baseline_rss_kib={baseline} before_500_rss_kib={before_500} retained_500_rss_kib={} retained_500_der_bytes={der_bytes}",
        openssl::version::version(),
        samples[1000],
        samples[1980],
        elapsed.as_millis(),
        cpu,
        nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)?.ok_or("missing clock tick rate")?,
        rss_kib()?
    );
    Ok(())
}
