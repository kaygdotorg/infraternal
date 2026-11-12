//! Real-host proof driver for the root upgrade's host half (D376, #399); never shipped.
//!
//! This plays the server's part against the real `privilege.*` actions, with
//! no server: it asks for a seal key, seals the password with the same
//! format the browser uses, has this account become root with it, and then
//! runs one install-shaped step through the relay. Run it as the account
//! being upgraded, on a throwaway host:
//!
//! ```text
//! privilege-elevate-proof <way> < password-file
//! ```
//!
//! `<way>` is `sudo-nopasswd`, `sudo`, `doas` or `su`. The password is read
//! from stdin (a 0600 file), never from argv. The binary is also the relay:
//! the elevation snippet copies it, checks its digest and runs it with
//! `__privilege-relay`, so `main` hands that case to the relay first.
//!
//! Output is one line per fact (`outcome=…`, `relay_uid=…`, `exit=…`),
//! for the evidence log. The password is never printed.
use base64::Engine as _;
use infraternal_agent::{privilege_agent, privilege_relay_host};
use infraternal_plugin_remote::privilege_relay::{Decoder, Frame};
use ring::{aead, agreement, hkdf, rand::SystemRandom};
use sha2::Digest as _;
use std::{error::Error, io::Read as _, process::ExitCode};

/// Any failure of the driver; it only ever reports one and exits.
type Failed = Box<dyn Error>;

/// `ring` is built without `std`, so its error is mapped by hand.
fn crypto(_: ring::error::Unspecified) -> Failed {
    "the seal could not be made".into()
}

/// Seal `secret` for `host`/`attempt`/`method` to `public`, exactly as the
/// browser does (see `privilege_seal`'s format).
fn seal(
    public: &[u8; 32],
    host: [u8; 16],
    attempt: [u8; 16],
    method: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, Failed> {
    let rng = SystemRandom::new();
    let e = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).map_err(crypto)?;
    let e_pub = e.compute_public_key().map_err(crypto)?;
    let mut nonce = [0; 12];
    ring::rand::SecureRandom::fill(&rng, &mut nonce).map_err(crypto)?;
    let mut sealed = vec![1];
    sealed.extend_from_slice(e_pub.as_ref());
    sealed.extend_from_slice(&nonce);
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, public);
    let mut body = secret.to_vec();
    agreement::agree_ephemeral(e, &peer, |dh| {
        let mut salt = e_pub.as_ref().to_vec();
        salt.extend_from_slice(public);
        let info: [&[u8]; 4] = [
            &b"infraternal privilege seal v1"[..],
            &host[..],
            &attempt[..],
            method,
        ];
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(dh);
        let okm = prk.expand(&info, &aead::AES_256_GCM)?;
        let key = aead::LessSafeKey::new(aead::UnboundKey::from(okm));
        let mut aad = b"ifpriv1".to_vec();
        aad.extend_from_slice(&host);
        aad.extend_from_slice(&attempt);
        aad.extend_from_slice(method);
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad[..]),
            &mut body,
        )
    })
    .map_err(crypto)?
    .map_err(crypto)?;
    sealed.extend_from_slice(&body);
    Ok(sealed)
}

/// Hands a relay start to the relay, otherwise runs the proof for the way named in argv.
fn main() -> ExitCode {
    if let Some(code) = privilege_relay_host::run_if_requested() {
        return code;
    }
    match run() {
        Ok(code) => code,
        Err(error) => {
            println!("driver_error={error}");
            ExitCode::from(3)
        }
    }
}

/// Call one `privilege.*` action and parse its JSON reply.
async fn call(
    action: &str,
    request: &serde_json::Value,
    sessions: &std::path::Path,
) -> Result<serde_json::Value, Failed> {
    let reply = privilege_agent::execute(action, request.to_string().as_bytes(), sessions).await?;
    Ok(serde_json::from_slice(&reply.json)?)
}

/// The proof itself: probe, seal, elevate, one step through the relay, end.
fn run() -> Result<ExitCode, Failed> {
    let way = std::env::args().nth(1).unwrap_or_default();
    let mut password = Vec::new();
    if way != "sudo-nopasswd" {
        std::io::stdin().read_to_end(&mut password)?;
        while password.last().is_some_and(|byte| *byte == b'\n') {
            password.pop();
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(prove(&way, password))
}

/// The async part of the proof.
async fn prove(way: &str, mut password: Vec<u8>) -> Result<ExitCode, Failed> {
    let sessions = std::env::temp_dir().join(format!("j410-proof-{}", std::process::id()));
    std::fs::create_dir_all(&sessions)?;
    std::fs::set_permissions(
        &sessions,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let probe = call("privilege.probe", &serde_json::json!({}), &sessions).await?;
    println!("probe={probe}");
    let attempt = uuid::Uuid::new_v4();
    let host = uuid::Uuid::new_v4();
    let ids = serde_json::json!({"attempt": attempt.simple().to_string()});
    let digest = hex(&sha2::Sha256::digest(std::fs::read(
        std::env::current_exe()?,
    )?));
    let sealed = if way == "sudo-nopasswd" {
        None
    } else {
        let reply = call("privilege.key", &ids, &sessions).await?;
        let key = reply["key"].as_str().ok_or("no key")?;
        let public: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(key)?
            .try_into()
            .map_err(|_| "key size")?;
        let sealed = seal(
            &public,
            *host.as_bytes(),
            *attempt.as_bytes(),
            way.as_bytes(),
            &password,
        )?;
        Some(base64::engine::general_purpose::STANDARD.encode(sealed))
    };
    zeroize::Zeroize::zeroize(&mut password);
    let request = serde_json::json!({
        "attempt": attempt.simple().to_string(),
        "host": host.simple().to_string(),
        "way": way,
        "sealed": sealed,
        "digest": digest,
    });
    let reply = match call("privilege.elevate", &request, &sessions).await {
        Ok(reply) => reply.to_string(),
        Err(error) => format!("error {error}"),
    };
    println!("elevate={reply}");
    if !reply.contains("started") {
        let _ = std::fs::remove_dir_all(&sessions);
        return Ok(ExitCode::from(1));
    }
    // One install-shaped step: who are we, can we read root-only state,
    // and does stdin reach the script.
    let script = "printf 'relay_uid=%s\\n' \"$(id -u)\"; \
        printf 'shadow_readable=%s\\n' \"$(test -r /etc/shadow && echo yes || echo no)\"; \
        printf 'selinux=%s\\n' \"$(getenforce 2>/dev/null || echo none)\"; \
        read line; printf 'stdin=%s\\n' \"$line\"; exit 3";
    let mut send = Vec::new();
    // The relay runs no step before it knows how to put the host back
    // (J415 R4). This proof installs nothing, so its rollback only logs.
    Frame::Rollback {
        transaction: uuid::Uuid::nil().into_bytes(),
        script: "logger -t infraternal-privilege-proof rollback-ran".into(),
    }
    .encode(&mut send);
    Frame::Open {
        channel: 1,
        script: script.into(),
    }
    .encode(&mut send);
    Frame::Stdin {
        channel: 1,
        bytes: b"through-the-relay\n".to_vec(),
    }
    .encode(&mut send);
    Frame::StdinEnd { channel: 1 }.encode(&mut send);
    let mut decoder = Decoder::default();
    let mut done = false;
    for _ in 0..30 {
        let request = serde_json::json!({
            "attempt": attempt.simple().to_string(),
            "send": base64::engine::general_purpose::STANDARD.encode(&send),
        });
        send.clear();
        let reply = call("privilege.pump", &request, &sessions).await?;
        let received = reply["recv"].as_str().ok_or("no recv")?;
        decoder.push(&base64::engine::general_purpose::STANDARD.decode(received)?);
        while let Some(frame) = decoder.frame().map_err(|_| "bad frame")? {
            match frame {
                Frame::Ready => println!("relay=ready"),
                Frame::Stdout { bytes, .. } => print!("{}", String::from_utf8_lossy(&bytes)),
                Frame::Exit { code, .. } => {
                    println!("exit={code:?}");
                    done = true;
                }
                other => println!("unexpected={other:?}"),
            }
        }
        if done || reply["closed"] == true {
            break;
        }
    }
    let _ = call("privilege.end", &ids, &sessions).await;
    let _ = std::fs::remove_dir_all(&sessions);
    Ok(if done {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}
