//! Maps each published service to its owner-approved DNS and certificate shape [D316, #281].
//! Exact flat-service certificate names appear in public Certificate Transparency logs.

use std::io;

/// Certificate layout used for this exposure's route names.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NameShape {
    /// Use `service.machine.suffix` under a wildcard that stays on this machine.
    #[default]
    PerMachineWildcard,
    /// Use `service.suffix` and issue an exact certificate on the serving machine.
    FlatService,
}

/// Whether ACME should request a machine wildcard or one exact flat service name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateName {
    /// Private key is generated and retained by the machine named in the pattern.
    Wildcard(String),
    /// Exact name is issued on the node serving this route.
    Exact(String),
}

/// DNS host and certificate identity for one published service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureNames {
    /// Exact Host header this router accepts.
    pub hostname: String,
    /// DNS name requested from the ACME resolver.
    pub certificate: CertificateName,
}

/// Return the default naming mode, kept as a function so the selected default is one edit.
#[must_use]
pub const fn default_name_shape() -> NameShape {
    NameShape::PerMachineWildcard
}

/// Resolve one service hostname and certificate name under the configured public-host suffix.
///
/// # Errors
/// Returns an invalid-input error when any DNS label or the final name violates DNS limits.
pub fn exposure_names(
    _shape: NameShape,
    _machine: &str,
    _service: &str,
    _suffix: &str,
) -> io::Result<ExposureNames> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "proxy naming is not implemented",
    ))
}
