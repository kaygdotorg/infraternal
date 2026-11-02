//! In-memory authority and runtime doubles for real-engine SSH boundary tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_ssh::{
    mesh_admission::{CertificateClaims, CurrentAccess, Refusal},
    mesh_certificate::{self, CertificateAccess, Identity},
    mesh_login::{
        Attachment, AuthorizedLogin, Control, Exit, LoginAuthority, LoginGuard, SessionKind,
        Terminal,
    },
};
use russh::keys::{
    Algorithm, Certificate, HashAlg, PrivateKey,
    ssh_key::{Fingerprint, certificate::Builder},
};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{RwLock, RwLockReadGuard, mpsc, oneshot},
};

pub fn key() -> PrivateKey {
    PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
pub fn certificate(
    ca: &PrivateKey,
    user: &PrivateKey,
    start: u64,
    end: u64,
    person: &str,
) -> Certificate {
    certificate_options(ca, user, start, end, person, true)
}
pub fn certificate_options(
    ca: &PrivateKey,
    user: &PrivateKey,
    start: u64,
    end: u64,
    person: &str,
    pty: bool,
) -> Certificate {
    certificate_at_source(ca, user, start, end, person, pty, "127.0.0.1")
}
pub fn certificate_at_source(
    ca: &PrivateKey,
    user: &PrivateKey,
    start: u64,
    end: u64,
    person: &str,
    pty: bool,
    source: &str,
) -> Certificate {
    let mut builder = Builder::new(vec![1; 32], user.public_key(), start, end).unwrap();
    builder.valid_principal(person).unwrap();
    builder
        .critical_option("source-address", format!("{source}/32"))
        .unwrap();
    if pty {
        builder.extension("permit-pty", "").unwrap();
    }
    builder.sign(ca).unwrap()
}

pub struct Rules {
    pub source: IpAddr,
    pub ca: Fingerprint,
    pub digest: [u8; 32],
    pub person: String,
    pub current: bool,
    pub network: bool,
    pub login: bool,
}
pub struct Opened {
    pub person: String,
    pub account: String,
    pub kind: SessionKind,
    pub terminal: Option<Terminal>,
}
pub struct Authority {
    pub rules: RwLock<Rules>,
    pub opened: Mutex<Vec<Opened>>,
    pub controls: Arc<Mutex<Vec<Control>>>,
}
impl Authority {
    pub fn new(ca: &PrivateKey, cert: &Certificate) -> Arc<Self> {
        Self::from_public(ca.public_key(), cert)
    }
    pub fn from_public(ca: &russh::keys::PublicKey, cert: &Certificate) -> Arc<Self> {
        Arc::new(Self {
            rules: RwLock::new(Rules {
                ca: ca.fingerprint(HashAlg::Sha256),
                source: "127.0.0.1".parse().unwrap(),
                digest: mesh_certificate::digest(cert).unwrap(),
                person: "person-1".into(),
                current: true,
                network: true,
                login: true,
            }),
            opened: Mutex::new(Vec::new()),
            controls: Arc::new(Mutex::new(Vec::new())),
        })
    }
}
pub struct Guard<'a> {
    rules: RwLockReadGuard<'a, Rules>,
    authority: &'a Authority,
}
impl CurrentAccess for Guard<'_> {
    fn source_node(&self, address: IpAddr) -> Option<u64> {
        (address == self.rules.source).then_some(7)
    }
    fn certificate_current(&self, certificate: &CertificateClaims<'_>) -> bool {
        self.rules.current
            && certificate.fingerprint == self.rules.digest
            && certificate.person == self.rules.person
            && certificate.source_node == 7
    }
    fn network_access(&self, source: u64, target: u64, port: u16) -> bool {
        self.rules.network && (source, target, port) == (7, 9, 22)
    }
    fn login_access(&self, person: &str, target: u64, account: &str) -> bool {
        self.rules.login && person == self.rules.person && target == 9 && account == "operator"
    }
}
impl CertificateAccess for Guard<'_> {
    fn trusted_ca(&self) -> &Fingerprint {
        &self.rules.ca
    }
    fn identity(&self, digest: &[u8; 32]) -> Option<Identity> {
        (*digest == self.rules.digest).then(|| Identity {
            person: self.rules.person.clone(),
            source_node: 7,
            source_address: self.rules.source,
        })
    }
}
impl LoginAuthority for Authority {
    type Guard<'a> = Guard<'a>;
    async fn current(&self) -> Result<Guard<'_>, Refusal> {
        Ok(Guard {
            rules: self.rules.read().await,
            authority: self,
        })
    }
}
// Test runtime registration completes in memory; its worker owns asynchronous I/O.
#[allow(clippy::unused_async_trait_impl)]
impl LoginGuard for Guard<'_> {
    type Files = MemoryFiles;
    async fn open_session(
        &self,
        login: &AuthorizedLogin<'_>,
        kind: SessionKind,
        terminal: Option<Terminal>,
    ) -> Result<Attachment, Refusal> {
        self.authority.opened.lock().unwrap().push(Opened {
            person: login.identity().person.clone(),
            account: login.account().into(),
            kind: kind.clone(),
            terminal,
        });
        let shell = matches!(kind, SessionKind::Shell);
        let (attachment, runtime) = tokio::io::duplex(1024);
        let (output, input) = tokio::io::split(attachment);
        let (control, mut controls) = mpsc::channel(8);
        let recorded = Arc::clone(&self.authority.controls);
        let (exit, completion) = oneshot::channel();
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(runtime);
            if shell {
                writer.write_all(b"ready\n").await.unwrap();
            }
            let mut bytes = [0; 1024];
            loop {
                tokio::select! {
                    result = reader.read(&mut bytes) => {
                        match result { Ok(0) | Err(_) => break, Ok(count) => if writer.write_all(&bytes[..count]).await.is_err() { break; } }
                    }
                    message = controls.recv() => {
                        if let Some(message) = message { recorded.lock().unwrap().push(message); } else { break; }
                    }
                }
            }
            drop(writer);
            let _ = exit.send(Exit::Status(0));
        });
        Ok(Attachment {
            input: Box::pin(input),
            output: Box::pin(output),
            errors: None,
            control,
            exit: completion,
        })
    }
    async fn open_files(&self, login: &AuthorizedLogin<'_>) -> Result<MemoryFiles, Refusal> {
        if login.identity().person != self.rules.person {
            return Err(Refusal::LoginAccess);
        }
        Ok(MemoryFiles::default())
    }
}

#[derive(Default)]
pub struct MemoryFiles {
    contents: Vec<u8>,
}
// The file provider completes in memory, without target-host filesystem access.
#[allow(clippy::unused_async_trait_impl)]
impl russh_sftp::server::Handler for MemoryFiles {
    type Error = russh_sftp::protocol::StatusCode;
    fn unimplemented(&self) -> Self::Error {
        Self::Error::OpUnsupported
    }
    async fn open(
        &mut self,
        id: u32,
        filename: String,
        _: russh_sftp::protocol::OpenFlags,
        _: russh_sftp::protocol::FileAttributes,
    ) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        if filename != "/sample" {
            return Err(Self::Error::PermissionDenied);
        }
        Ok(russh_sftp::protocol::Handle {
            id,
            handle: "sample".into(),
        })
    }
    async fn close(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        if handle != "sample" {
            return Err(Self::Error::Failure);
        }
        Ok(status(id))
    }
    async fn realpath(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Name, Self::Error> {
        if path != "." && path != "/" {
            return Err(Self::Error::NoSuchFile);
        }
        Ok(russh_sftp::protocol::Name {
            id,
            files: vec![russh_sftp::protocol::File::dummy("/")],
        })
    }
    async fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        if path != "/sample" {
            return Err(Self::Error::NoSuchFile);
        }
        let mut attrs = russh_sftp::protocol::FileAttributes::dummy();
        attrs.set_dir(false);
        attrs.set_regular(true);
        attrs.size = Some(self.contents.len() as u64);
        Ok(russh_sftp::protocol::Attrs { id, attrs })
    }
    async fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        self.stat(id, path).await
    }
    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<russh_sftp::protocol::Data, Self::Error> {
        if handle != "sample" {
            return Err(Self::Error::Failure);
        }
        let offset = usize::try_from(offset).map_err(|_| Self::Error::Failure)?;
        if offset >= self.contents.len() {
            return Err(Self::Error::Eof);
        }
        let end = offset
            .saturating_add(len.min(32768) as usize)
            .min(self.contents.len());
        Ok(russh_sftp::protocol::Data {
            id,
            data: self.contents[offset..end].to_vec(),
        })
    }
    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        if handle != "sample" {
            return Err(Self::Error::Failure);
        }
        let offset = usize::try_from(offset).map_err(|_| Self::Error::Failure)?;
        let end = offset
            .checked_add(data.len())
            .filter(|end| *end <= 1024 * 1024)
            .ok_or(Self::Error::Failure)?;
        self.contents.resize(self.contents.len().max(end), 0);
        self.contents[offset..end].copy_from_slice(&data);
        Ok(status(id))
    }
}
fn status(id: u32) -> russh_sftp::protocol::Status {
    russh_sftp::protocol::Status {
        id,
        status_code: russh_sftp::protocol::StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::new(),
    }
}
