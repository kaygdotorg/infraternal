//! Keeps persistence behind a host-supplied account layout source, independent of the selected database engine [198,243].
use infraternal_plugin_api::Operation;
use serde_json::Value;
use tokio::sync::watch;
/// Safe refusal categories carry no database details, credentials, or foreign session existence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The request envelope, JSON, text, or input size is invalid.
    InvalidRequest,
    /// An intent has unsupported fields or would violate layout bounds.
    InvalidIntent,
    /// A supplied or resulting document violates the canvas schema.
    InvalidDocument,
    /// The base revision is negative or ahead of the saved layout.
    InvalidRevision,
    /// A newer account look superseded this whole-look edit.
    LookSuperseded,
    /// A referenced session is unavailable to this account, whether missing or owned elsewhere.
    ReferenceUnavailable,
    /// A retry reused an operation identity with different contents.
    ReceiptConflict,
    /// The account has reached its retained operation limit.
    ReceiptLimit,
    /// Storage could not complete the operation; internal diagnostics stay on the server.
    StorageUnavailable,
}
impl Refusal {
    /// Stable machine-readable reason and friendly public explanation for a refused request.
    #[must_use]
    pub const fn public(self) -> (&'static str, &'static str) {
        match self {
            Self::InvalidRequest => ("invalid_request", "The layout request is invalid."),
            Self::InvalidIntent => (
                "invalid_intent",
                "The layout edit has invalid fields or exceeds layout bounds.",
            ),
            Self::InvalidDocument => (
                "invalid_document",
                "The layout document has invalid fields or exceeds layout bounds.",
            ),
            Self::InvalidRevision => (
                "invalid_revision",
                "The layout edit refers to an unavailable revision.",
            ),
            Self::LookSuperseded => (
                "look_superseded",
                "A newer appearance was saved. Reload the saved appearance before editing it.",
            ),
            Self::ReferenceUnavailable => (
                "reference_unavailable",
                "A terminal in this layout is unavailable to your account.",
            ),
            Self::ReceiptConflict => (
                "operation_conflict",
                "This layout operation identity was already used for a different edit.",
            ),
            Self::ReceiptLimit => (
                "operation_limit",
                "This account has reached its saved layout operation limit.",
            ),
            Self::StorageUnavailable => (
                "storage_unavailable",
                "The server could not access the saved layout.",
            ),
        }
    }
}
/// The host binds every call to the authenticated account; a source never receives credentials.
pub trait LayoutStore: Send + Sync {
    fn changes(&self) -> watch::Receiver<()>;
    /// Applies or initializes this account layout and returns only safe refusal details.
    fn call<'a>(
        &'a self,
        initialize: bool,
        account: &'a str,
        input: &'a [u8],
    ) -> Operation<'a, Result<i64, Refusal>>;
    fn events<'a>(
        &'a self,
        account: &'a str,
        after: Option<i64>,
    ) -> Operation<'a, Result<Vec<Value>, ()>>;
}
