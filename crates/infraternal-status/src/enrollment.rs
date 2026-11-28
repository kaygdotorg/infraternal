//! Reads the displayable server origin from a private enrollment identity.

use crate::Scope;
use nix::{
    fcntl::{OFlag, open, openat},
    sys::stat::Mode,
    unistd::Uid,
};
use std::{
    fs::File,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
};
use zeroize::Zeroizing;

/// Only the server fields survive parsing. The identity also holds private keys.
#[derive(serde::Deserialize)]
struct Server {
    /// HTTPS origin recorded by current enrollments.
    public_origin: Option<String>,
    /// TLS name used by enrollments before the public origin was recorded.
    server_name: String,
}

/// Read only a private, scope-owned identity, and return its canonical HTTPS origin.
///
/// The bounded input is wiped on drop and serde skips fields outside the projection.
/// Open the file relative to the checked directory so replacing that directory
/// during a status call cannot substitute another identity.
pub(super) fn server(data: &Path, scope: Scope) -> io::Result<Option<String>> {
    const MAX_IDENTITY_BYTES: usize = 8192;
    if !data.is_absolute() {
        return Ok(None);
    }
    let owner = match scope {
        Scope::System => 0,
        Scope::User => Uid::effective().as_raw(),
    };
    let directory = File::from(open(
        data,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = directory.metadata()?;
    if metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let identity = File::from(openat(
        &directory,
        "identity.json",
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = identity.metadata()?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_IDENTITY_BYTES + 1));
    identity
        .take((MAX_IDENTITY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_IDENTITY_BYTES {
        return Ok(None);
    }
    let Ok(server) = serde_json::from_slice::<Server>(&bytes) else {
        return Ok(None);
    };
    let candidate = server
        .public_origin
        .unwrap_or_else(|| format!("https://{}", server.server_name));
    let Ok(origin) = url::Url::parse(&candidate) else {
        return Ok(None);
    };
    if origin.scheme() == "https"
        && origin.host_str().is_some()
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none()
    {
        Ok(Some(origin.origin().ascii_serialization()))
    } else {
        Ok(None)
    }
}
