//! Says which certificate, key or CA file stopped the server's TLS startup, and why (#595).
//!
//! The server used to answer every such refusal with the same sentence, so an
//! operator could not tell a wrong file mode from a certificate that does not
//! name the public origin. A [`TlsProblem`] pairs the thing that was checked
//! ([`TlsPart`]) with the rule it broke ([`TlsFault`]).
//!
//! Startup messages never carry a path, key, certificate or request data
//! ([`crate::ServerError`]), so a part is named by its command-line option or by
//! its fixed file name inside the CA directory, and a fault only ever adds a
//! permission mode, a size limit or OpenSSL's fixed verification reason.

use std::{fmt, io, path::Path};

/// The file, directory or check that TLS startup was looking at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsPart {
    /// The HTTPS certificate named by `--tls-cert`.
    Certificate,
    /// The HTTPS private key named by `--tls-key`.
    PrivateKey,
    /// The `--tls-cert` and `--tls-key` pair taken together.
    CertificateAndKey,
    /// The CA directory: `--remote-ca-dir`, or the standard data directory.
    CaDirectory,
    /// The `pending` marker of a CA directory that is not set up yet.
    PendingMarker,
    /// The retained public issuer, `issuer.pem` in the CA directory.
    Issuer,
    /// The current CA generation, `active` in the CA directory.
    ActiveCa,
    /// The server's own certificate for host connections, kept in the CA directory.
    HostCertificate,
    /// The CA administration that unlocks host connections.
    CaAdministration,
}

impl fmt::Display for TlsPart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Certificate => "the --tls-cert file",
            Self::PrivateKey => "the --tls-key file",
            Self::CertificateAndKey => "the --tls-cert and --tls-key files",
            Self::CaDirectory => "the CA directory (--remote-ca-dir)",
            Self::PendingMarker => "the file `pending` in the CA directory",
            Self::Issuer => "the file `issuer.pem` in the CA directory",
            Self::ActiveCa => "the current CA in the CA directory (`active`)",
            Self::HostCertificate => "the server's certificate for host connections",
            Self::CaAdministration => "the CA administration",
        })
    }
}

/// The rule the checked [`TlsPart`] broke.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsFault {
    /// Nothing exists at the given location.
    Missing,
    /// The server's account may not open or inspect it.
    Forbidden,
    /// The last path component is a symbolic link, which these files refuse.
    SymbolicLink,
    /// It could not be opened, inspected or read for another reason.
    Unreadable,
    /// It is a directory, pipe or device instead of a regular file.
    NotFile,
    /// It is not a directory.
    NotDirectory,
    /// It belongs to an account other than the one running the server.
    ForeignOwner,
    /// Group or other users have access; holds the permission bits found.
    SharedAccess {
        /// The permission bits (`0o777` part of the mode) of the refused entry.
        mode: u32,
    },
    /// It is longer than the limit in bytes.
    TooLarge {
        /// The largest size the server reads.
        limit: usize,
    },
    /// It does not hold a PEM certificate.
    NotCertificate,
    /// It does not hold a PEM private key that could be loaded.
    NotPrivateKey,
    /// The private key does not belong to the certificate.
    KeyMismatch,
    /// The issuer is not a self-signed certificate with the expected key algorithm.
    NotIssuer,
    /// The certificate failed verification against the retained issuer; holds
    /// OpenSSL's fixed reason text (for example a name mismatch or expiry).
    Rejected {
        /// OpenSSL's constant description of the verification failure.
        reason: &'static str,
    },
    /// A required value is absent from the configuration.
    NotConfigured,
    /// An internal check or write failed; no further detail is safe to show.
    Failed,
}

impl TlsFault {
    /// Classify a failed open or inspection of a configured file.
    pub(crate) fn from_io(error: &io::Error) -> Self {
        #[cfg(unix)]
        if error.raw_os_error() == Some(nix::libc::ELOOP) {
            return Self::SymbolicLink;
        }
        match error.kind() {
            io::ErrorKind::NotFound => Self::Missing,
            io::ErrorKind::PermissionDenied => Self::Forbidden,
            _ => Self::Unreadable,
        }
    }
}

impl fmt::Display for TlsFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("does not exist"),
            Self::Forbidden => formatter.write_str("cannot be opened by the server's account"),
            Self::SymbolicLink => formatter
                .write_str("is a symbolic link; give the server the file itself or a copy of it"),
            Self::Unreadable => formatter.write_str("cannot be read"),
            Self::NotFile => formatter.write_str("is not a regular file"),
            Self::NotDirectory => formatter.write_str("is not a directory"),
            Self::ForeignOwner => {
                formatter.write_str("must be owned by the account that runs the server")
            }
            Self::SharedAccess { mode } => write!(
                formatter,
                "has mode {mode:04o}; group and other users must have no access (chmod go-rwx)"
            ),
            Self::TooLarge { limit } => write!(formatter, "is larger than {limit} bytes"),
            Self::NotCertificate => formatter.write_str("does not hold a PEM certificate"),
            Self::NotPrivateKey => {
                formatter.write_str("does not hold a PEM private key that can be loaded")
            }
            Self::KeyMismatch => {
                formatter.write_str("do not match: the key belongs to another certificate")
            }
            Self::NotIssuer => formatter
                .write_str("is not a self-signed issuer certificate with the expected key type"),
            Self::Rejected { reason } => {
                write!(formatter, "failed certificate verification ({reason})")
            }
            Self::NotConfigured => formatter.write_str("is required and not configured"),
            Self::Failed => formatter.write_str("could not be checked or prepared"),
        }
    }
}

/// One refused TLS startup check, shown after "TLS configuration failed".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsProblem {
    /// What was being checked.
    pub part: TlsPart,
    /// The rule it broke.
    pub fault: TlsFault,
}

impl fmt::Display for TlsProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.part, self.fault)
    }
}

impl TlsPart {
    /// Report that this part broke `fault`, as the server's startup error.
    #[cfg(feature = "remote")]
    pub(crate) fn error(self, fault: TlsFault) -> crate::ServerError {
        crate::ServerError::TlsConfiguration(TlsProblem { part: self, fault })
    }

    /// Report a failure whose detail must not be shown, for use in `map_err`.
    #[cfg(feature = "remote")]
    pub(crate) fn failed<E>(self) -> impl Fn(E) -> crate::ServerError {
        move |_| self.error(TlsFault::Failed)
    }
}

/// Find out why the standalone HTTPS listener could not load its two files.
///
/// The TLS library reports one opaque error for both, so this reads them again,
/// only after that failure, and names the first one that cannot be used. This
/// listener follows symbolic links and accepts any file mode, so those rules are
/// not repeated here.
pub(crate) fn explain_load(certificate: &Path, private_key: &Path) -> TlsProblem {
    let problem = |part, fault| TlsProblem { part, fault };
    let certificate = match std::fs::read(certificate) {
        Ok(bytes) => bytes,
        Err(error) => return problem(TlsPart::Certificate, TlsFault::from_io(&error)),
    };
    let Ok(certificate) = openssl::x509::X509::from_pem(&certificate) else {
        return problem(TlsPart::Certificate, TlsFault::NotCertificate);
    };
    let key = match std::fs::read(private_key) {
        Ok(bytes) => zeroize::Zeroizing::new(bytes),
        Err(error) => return problem(TlsPart::PrivateKey, TlsFault::from_io(&error)),
    };
    // An empty passphrase makes an encrypted key fail here instead of making
    // OpenSSL ask for one on the terminal.
    let Ok(key) = openssl::pkey::PKey::private_key_from_pem_passphrase(&key, b"") else {
        return problem(TlsPart::PrivateKey, TlsFault::NotPrivateKey);
    };
    if certificate
        .public_key()
        .is_ok_and(|public| public.public_eq(&key))
    {
        problem(TlsPart::CertificateAndKey, TlsFault::Failed)
    } else {
        problem(TlsPart::CertificateAndKey, TlsFault::KeyMismatch)
    }
}
