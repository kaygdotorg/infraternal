//! Host machine binding diagnostics and the saved public enrolment identity.

/// Public enrolment fingerprint checked by this host's state store.
pub use infraternal_mesh_node::enrolment::Enrolment;

/// Why a Mesh enrollment cannot be bound to this installation (Linux machine ID, Mac hardware).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
pub enum MachineBindingError {
    /// The current installation has no persistent machine ID.
    MissingId,
    /// The saved fingerprint belongs to a different Linux installation.
    ForeignMachine,
    /// The old record has no fingerprint to establish where it was created.
    UnboundRecord,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl std::fmt::Display for MachineBindingError {
    /// Format the refusal and matching recovery as a diagnostic for service logs.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} {}", self.summary(), self.recovery())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// Preserve the typed refusal across the service and CLI error boundary.
impl std::error::Error for MachineBindingError {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl MachineBindingError {
    /// Explain why the binding was refused without exposing either machine ID.
    #[must_use]
    pub fn summary(&self) -> &'static str {
        match self {
            #[cfg(target_os = "linux")]
            Self::MissingId => "This Linux installation has no persistent machine ID.",
            #[cfg(target_os = "macos")]
            Self::MissingId => "This Mac's hardware identity could not be read.",
            #[cfg(target_os = "linux")]
            Self::ForeignMachine => {
                "Saved Mesh state belongs to a different machine or an earlier Linux installation."
            }
            #[cfg(target_os = "macos")]
            Self::ForeignMachine => {
                "Saved Mesh state belongs to a different machine or an earlier macOS installation."
            }
            Self::UnboundRecord => "Saved Mesh state has no machine binding.",
        }
    }

    /// Give the operator the matching recovery action.
    #[must_use]
    pub fn recovery(&self) -> &'static str {
        match self {
            #[cfg(target_os = "linux")]
            Self::MissingId => "Configure a persistent /etc/machine-id, then try again.",
            #[cfg(target_os = "macos")]
            Self::MissingId => "Check that this Mac reports its hardware UUID, then try again.",
            Self::ForeignMachine | Self::UnboundRecord => {
                "Use Add host to re-enroll this installation with a fresh state directory."
            }
        }
    }
}
