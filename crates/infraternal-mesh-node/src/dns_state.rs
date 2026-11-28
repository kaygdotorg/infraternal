//! Public status of the platform resolver that serves mesh names.

/// What `mesh status` reports about the host resolver integration.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DnsState {
    /// `resolved`, `networkmanager`, `hosts`, `resolver-files`, `unprivileged`, `unavailable`
    /// or `off` (nothing attempted yet).
    pub mode: &'static str,
    /// One plain sentence a person can act on.
    pub detail: String,
    /// The suffixes routed to the mesh resolver.
    pub suffixes: Vec<String>,
    /// Whether the suffixes are also search domains.
    pub search: bool,
}
