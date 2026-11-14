//! A native infraternal viewer: the browser's leg-A path without the browser.
//!
//! It signs up the owner the way the browser does (setup token, WebAuthn
//! registration with a software ES256 passkey and PRF key wraps), then talks to
//! the real server over the real WebSocket with the shipping codec
//! (`infraternal-protocol`): Hello, Welcome, `ssh.session.open`, AttachTerm, Resize,
//! Input, Output, Credit. Credit follows the web client's policy: a 1 MiB
//! window, returned as output is consumed.
//!
//! What it leaves out, on purpose: decoding in a worker and painting. Those
//! are the browser's cost; tmux and Zellij are measured to the same point
//! (bytes delivered to the terminal), see `pty`.
//!
//! Secrets: the setup token is read from a file, the session cookie is written
//! to a 0600 file; neither is printed or passed in argv.
use crate::args::{Args, die};
use crate::term::{Screen, TermIo};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hkdf::Hkdf;
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;
use tungstenite::client::IntoClientRequest;
use tungstenite::{Message, WebSocket};

/// Initial output allowance, matching the attached browser viewer.
const INITIAL_CREDIT: u32 = 1024 * 1024;

/// Generate a fixed-size random value or stop if the system RNG fails.
fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap_or_else(|_| die("no randomness"));
    b
}

/// One HTTP/1.1 POST of JSON; returns (status, Set-Cookie pairs, body).
fn post(server: &str, path: &str, origin: &str, cookie: Option<&str>, body: &Value) -> (u16, Vec<String>, Value) {
    let body = body.to_string();
    let mut s = TcpStream::connect(server).unwrap_or_else(|e| die(&format!("connect {server}: {e}")));
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {server}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(&body);
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| die("bad HTTP response"));
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut payload = raw[split + 4..].to_vec();
    let status = head.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut cookies = Vec::new();
    let mut chunked = false;
    for line in head.lines().skip(1) {
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.eq_ignore_ascii_case("set-cookie") {
            cookies.push(v.trim().split(';').next().unwrap_or("").to_owned());
        }
        if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    if chunked {
        let mut out = Vec::new();
        let mut rest = &payload[..];
        while let Some(p) = rest.windows(2).position(|w| w == b"\r\n") {
            let len = usize::from_str_radix(String::from_utf8_lossy(&rest[..p]).trim(), 16).unwrap_or(0);
            if len == 0 {
                break;
            }
            out.extend_from_slice(&rest[p + 2..p + 2 + len]);
            rest = &rest[p + 4 + len..];
        }
        payload = out;
    }
    let value = serde_json::from_slice(&payload).unwrap_or(Value::Null);
    (status, cookies, value)
}

// aes-gcm 0.10's nonce type is built through the older generic-array API.
#[allow(deprecated)]
/// Encrypt a data-encryption key using the same key-wrap envelope as setup.
fn wrap(ikm: &[u8], dek: &[u8], user: &str, kind: &str) -> Value {
    let salt: [u8; 32] = random();
    let nonce: [u8; 12] = random();
    let aad = format!("infraternal/keywrap/v1|{user}|{kind}").into_bytes();
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), ikm).expand(&aad, &mut key).unwrap();
    let ct = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: dek, aad: &aad })
        .unwrap();
    json!({"salt": B64.encode(salt), "nonce": B64.encode(nonce), "ciphertext": B64.encode(ct)})
}

/// Minimal CBOR writer for the fixed attestation shapes WebAuthn needs.
fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
}
/// Append a positive or negative CBOR integer to `out`.
fn cbor_int(v: i64, out: &mut Vec<u8>) {
    if v >= 0 { cbor_head(0, v as u64, out) } else { cbor_head(1, (-1 - v) as u64, out) }
}
/// Append a CBOR byte string to `out`.
fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len() as u64, out);
    out.extend_from_slice(b);
}
/// Append a UTF-8 CBOR text string to `out`.
fn cbor_text(t: &str, out: &mut Vec<u8>) {
    cbor_head(3, t.len() as u64, out);
    out.extend_from_slice(t.as_bytes());
}

/// `ix-register`: create the owner account with a software passkey.
pub fn register(args: &Args) {
    let server = args.str("server");
    let origin = args.str("origin");
    let rp_id = origin.split("://").nth(1).unwrap_or("").split(':').next().unwrap_or("").to_owned();
    let token = std::fs::read_to_string(args.str("setup-token-file")).unwrap_or_else(|_| die("setup token file"));
    let (status, cookies, start) = post(&server, "/auth/setup-start", &origin, None, &json!({"token": token.trim(), "name": "owner"}));
    if status != 200 {
        die(&format!("setup-start returned {status}"));
    }
    let user = start["user_id"].as_str().unwrap_or_else(|| die("no user_id")).to_owned();
    let pk = &start["options"]["publicKey"];
    let key = SigningKey::from_slice(&random::<32>()).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let cred_id: [u8; 32] = random();
    let prf_secret: [u8; 32] = random();
    // PRF: HMAC-SHA256 over SHA-256("WebAuthn PRF\0" || salt), as an authenticator's hmac-secret.
    let salt = B64.decode(pk["extensions"]["prf"]["eval"]["first"].as_str().unwrap_or_else(|| die("no PRF salt"))).unwrap();
    let mut input = b"WebAuthn PRF\0".to_vec();
    input.extend_from_slice(&salt);
    let prf = {
        use hkdf::hmac::{Hmac, Mac};
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&prf_secret).unwrap();
        mac.update(&Sha256::digest(&input));
        mac.finalize().into_bytes().to_vec()
    };
    let mut cose = Vec::new();
    cbor_head(5, 5, &mut cose);
    for (k, v) in [(1i64, 2i64), (3, -7), (-1, 1)] {
        cbor_int(k, &mut cose);
        cbor_int(v, &mut cose);
    }
    cbor_int(-2, &mut cose);
    cbor_bytes(point.x().unwrap(), &mut cose);
    cbor_int(-3, &mut cose);
    cbor_bytes(point.y().unwrap(), &mut cose);
    let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
    auth_data.push(0x45); // user present, user verified, attested credential data
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]);
    auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&cred_id);
    auth_data.extend_from_slice(&cose);
    let mut att = Vec::new();
    cbor_head(5, 3, &mut att);
    cbor_text("fmt", &mut att);
    cbor_text("none", &mut att);
    cbor_text("attStmt", &mut att);
    cbor_head(5, 0, &mut att);
    cbor_text("authData", &mut att);
    cbor_bytes(&auth_data, &mut att);
    let client_data = json!({"type": "webauthn.create", "challenge": pk["challenge"], "origin": origin, "crossOrigin": false}).to_string();
    let proof = json!({
        "id": B64.encode(cred_id), "rawId": B64.encode(cred_id), "type": "public-key",
        "response": {"clientDataJSON": B64.encode(client_data.as_bytes()), "attestationObject": B64.encode(&att), "transports": ["internal"]},
        "extensions": {"credProps": {"rk": true}},
    });
    let dek: [u8; 32] = random();
    let recovery_entropy: [u8; 32] = random();
    let recovery = |kind: &str| {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(None, &recovery_entropy).expand(format!("infraternal/recovery/{kind}/v2").as_bytes(), &mut out).unwrap();
        out
    };
    let binding = cookies.first().cloned().unwrap_or_else(|| die("no ceremony cookie"));
    let (status, cookies, _) = post(
        &server,
        "/auth/registration-finish",
        &origin,
        Some(&binding),
        &json!({
            "ceremony": start["ceremony"], "proof": proof,
            "passkey_wrap": wrap(&prf, &dek, &user, "passkey"),
            "recovery_verifier": B64.encode(recovery("auth")),
            "recovery_wrap": wrap(&recovery("wrap"), &dek, &user, "recovery"),
        }),
    );
    if status != 200 {
        die(&format!("registration-finish returned {status}"));
    }
    let session = cookies.into_iter().filter(|c| c.split_once('=').is_some_and(|(_, v)| !v.is_empty())).collect::<Vec<_>>().join("; ");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(args.str("cookie-out"))
        .unwrap_or_else(|e| die(&format!("cookie file: {e}")));
    f.write_all(session.as_bytes()).unwrap();
    println!("{}", json!({"registered": true}));
}

/// Authenticated WebSocket client used for the native viewer measurement.
pub struct Ix {
    ws: WebSocket<TcpStream>,
    stream: u32,
    in_seq: u64,
    call_id: u32,
    buf: Vec<u8>,
    /// Output that arrived before the attach Ack, handed out by `recv` first.
    pending: std::collections::VecDeque<Vec<u8>>,
    /// Server probes answered on this connection (idle cost of an attached viewer).
    pub pings: u64,
}

impl Ix {
    /// Connect using the supplied origin and cookie, then complete the hello exchange.
    pub fn connect(args: &Args) -> Self {
        let server = args.str("server");
        let origin = args.str("origin");
        let cookie = std::fs::read_to_string(args.str("cookie-file")).unwrap_or_else(|_| die("cookie file"));
        let tcp = TcpStream::connect(&server).unwrap_or_else(|e| die(&format!("connect: {e}")));
        tcp.set_nodelay(true).unwrap();
        let mut req = format!("ws://{server}/v1/ws").into_client_request().unwrap();
        req.headers_mut().insert("Origin", origin.parse().unwrap());
        req.headers_mut().insert("Cookie", cookie.trim().parse().unwrap());
        let (ws, _) = tungstenite::client(req, tcp).unwrap_or_else(|e| die(&format!("websocket: {e}")));
        let mut ix = Self { ws, stream: 1, in_seq: 0, call_id: 0, buf: Vec::with_capacity(256), pending: Default::default(), pings: 0 };
        ix.expect(|f| matches!(f, Frame::Hello { .. }), "server Hello");
        ix.frame(0, &Frame::Hello { version: 1, caps: 0, client_info: "h2h" });
        ix.expect(|f| matches!(f, Frame::Welcome { .. }), "Welcome");
        ix
    }

    /// Encode and send one protocol frame on the selected stream.
    fn frame(&mut self, stream: u32, frame: &Frame<'_>) {
        encode_muxed_frame_into(stream, frame, &mut self.buf).unwrap();
        self.ws.send(Message::Binary(self.buf.clone().into())).unwrap_or_else(|e| die(&format!("ws send: {e}")));
    }

    /// Next binary message, answering protocol pings; `None` on timeout.
    fn next(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        // The server probes an attached viewer often; answering those must not
        // extend the caller's timeout.
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            self.ws.get_ref().set_read_timeout(Some(left.max(Duration::from_millis(1)))).unwrap();
            match self.ws.read() {
                Ok(Message::Binary(b)) => {
                    if std::env::var_os("H2H_DEBUG").is_some() {
                        match decode_muxed_frame(&b).map(|d| d.frame) {
                            Ok(Frame::Output { out_seq, bytes }) => eprintln!("{} output {out_seq} +{}", crate::clock::now_ns() / 1000, bytes.len()),
                            other => eprintln!("{} frame {:?}", crate::clock::now_ns() / 1000, other.map(|f| format!("{f:?}").chars().take(80).collect::<String>())),
                        }
                    }
                    let ping = match decode_muxed_frame(&b) {
                        Ok(d) => match d.frame {
                            Frame::Ping { nonce, sent_us } => Some((d.stream_id, nonce, sent_us)),
                            _ => None,
                        },
                        Err(_) => die("undecodable frame"),
                    };
                    match ping {
                        Some((s, nonce, sent_us)) => {
                            self.pings += 1;
                            self.frame(s, &Frame::Pong { nonce, sent_us });
                        }
                        None => return Some(b.to_vec()),
                    }
                }
                Ok(Message::Close(c)) => die(&format!("server closed: {c:?}")),
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
                {
                    return None;
                }
                Err(e) => die(&format!("ws read: {e}")),
            }
        }
    }

    /// Return the next matching frame, failing with `what` if the exchange stalls.
    fn expect(&mut self, want: impl Fn(&Frame<'_>) -> bool, what: &str) -> Vec<u8> {
        for _ in 0..1000 {
            if let Some(b) = self.next(Duration::from_secs(20)) {
                if want(&decode_muxed_frame(&b).unwrap().frame) {
                    return b;
                }
            } else {
                break;
            }
        }
        die(&format!("no {what}"))
    }

    /// Invoke one server action and decode its JSON result.
    pub fn call(&mut self, action: &str, input: &Value) -> Value {
        self.call_id += 1;
        let id = self.call_id;
        let input = input.to_string();
        self.frame(0, &Frame::Call { call_id: id, action_id: action, input_json: input.as_bytes() });
        let b = self.expect(|f| matches!(f, Frame::Result { call_id, .. } if *call_id == id), "Result");
        match decode_muxed_frame(&b).unwrap().frame {
            Frame::Result { ok: true, json, .. } => serde_json::from_slice(json).unwrap_or(Value::Null),
            Frame::Result { json, .. } => die(&format!("{action} failed: {}", String::from_utf8_lossy(json))),
            _ => unreachable!(),
        }
    }

    /// Attach to a session and retain any output delivered before its acknowledgement.
    pub fn attach(&mut self, session: &str) {
        let mut id = [0u8; 16];
        for (i, b) in id.iter_mut().enumerate() {
            *b = u8::from_str_radix(&session[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| die("bad session id"));
        }
        self.frame(self.stream, &Frame::AttachTerm { session_id: &id, last_out_seq: 0, last_in_seq: 0 });
        self.frame(self.stream, &Frame::Credit { bytes: INITIAL_CREDIT });
        self.frame(self.stream, &Frame::Resize { cols: 120, rows: 40, px_w: 0, px_h: 0 });
        // The Ack names the server's input offset; typing continues from it.
        loop {
            let b = self.next(Duration::from_secs(20)).unwrap_or_else(|| die("no attach Ack"));
            let d = decode_muxed_frame(&b).unwrap();
            if d.stream_id != self.stream {
                continue;
            }
            match d.frame {
                Frame::Ack { in_seq_acked } => {
                    self.in_seq = in_seq_acked;
                    return;
                }
                Frame::Output { bytes, .. } | Frame::Snapshot { bytes, .. } => {
                    self.pending.push_back(bytes.to_vec());
                    self.frame(self.stream, &Frame::Credit { bytes: bytes.len() as u32 });
                }
                Frame::Close { code, reason } => die(&format!("attach refused {code}: {reason}")),
                _ => {}
            }
        }
    }
}

impl TermIo for Ix {
    fn send(&mut self, bytes: &[u8]) {
        let seq = self.in_seq;
        self.in_seq += bytes.len() as u64;
        self.frame(self.stream, &Frame::Input { in_seq: seq, bytes });
    }

    fn recv(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        if let Some(early) = self.pending.pop_front() {
            return Some(early);
        }
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let b = self.next(left)?;
            let d = decode_muxed_frame(&b).unwrap();
            if d.stream_id != self.stream {
                continue;
            }
            match d.frame {
                Frame::Output { bytes, .. } | Frame::Snapshot { bytes, .. } => {
                    let out = bytes.to_vec();
                    // Consumed at once: return the credit, as the web client does after parsing.
                    self.frame(self.stream, &Frame::Credit { bytes: out.len() as u32 });
                    return Some(out);
                }
                Frame::Close { code, reason } => die(&format!("stream closed {code}: {reason}")),
                _ => {}
            }
        }
    }

    fn probes(&self) -> u64 {
        self.pings
    }

    fn close(mut self: Box<Self>) {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
    }
}

/// `ix-open`: open N sessions and print their ids (JSON list).
pub fn open(args: &Args) {
    let count: usize = args.num("count", 1);
    let mut ix = Ix::connect(args);
    let ids: Vec<Value> = (0..count)
        // The web client's own action: a session on the server's host, sized by the attach's Resize.
        .map(|_| {
            let id = ix.call("ssh.session.open", &json!({}))["session_id"].as_str().unwrap_or_default().replace('-', "");
            Value::String(id)
        })
        .collect();
    println!("{}", Value::Array(ids));
    Box::new(ix).close();
}

/// Attach a viewer to `--session` and wrap it for the shared procedures.
pub fn screen(args: &Args) -> Screen {
    let mut ix = Ix::connect(args);
    ix.attach(&args.str("session"));
    Screen::new(Box::new(ix))
}
