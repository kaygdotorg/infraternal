//! Tracks migrations, marks release payloads [225], and isolates per-run staging trust (#188 D1).
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Directory tracking also rebuilds SQLx when a new migration is added.
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-env-changed=INFRATERNAL_RELEASE_BUILD");
    let release = env::var("INFRATERNAL_RELEASE_BUILD").is_ok_and(|value| value == "1");
    println!(
        "cargo:rustc-env=INFRATERNAL_RELEASE_BUILD={}",
        if release { "1" } else { "0" }
    );
    println!("cargo:rerun-if-env-changed=INFRATERNAL_STAGING_PUBLIC_KEY");
    if env::var_os("CARGO_FEATURE_STAGING_TRUST").is_none() {
        return Ok(());
    }
    let path = PathBuf::from(
        env::var_os("INFRATERNAL_STAGING_PUBLIC_KEY")
            .ok_or("staging-trust requires a per-run public key file")?,
    );
    assert!(
        path.is_absolute(),
        "staging public key path must be absolute"
    );
    println!("cargo:rerun-if-changed={}", path.display());
    let public = fs::read_to_string(&path)?;
    let fields: Vec<_> = public.split_whitespace().collect();
    assert!(
        public.lines().count() == 1
            && (2..=3).contains(&fields.len())
            && fields[0] == "ssh-ed25519"
            && fields[1].len() == 68
            && fields[1]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte)),
        "staging key must be one Ed25519 public key"
    );
    let production = fs::read_to_string("../../release/allowed_signers")?;
    println!("cargo:rerun-if-changed=../../release/allowed_signers");
    // This marker is part of the live trust string, so stripping cannot erase
    // the production gate's evidence while retaining the test authority.
    let trust = format!(
        "{production}\nrelease@infraternal.com namespaces=\"infraternal-release\" ssh-ed25519 {} infraternal-staging-trust-v1\n",
        fields[1]
    );
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo output directory missing")?);
    fs::write(output.join("staging-trust"), trust)?;
    Ok(())
}
