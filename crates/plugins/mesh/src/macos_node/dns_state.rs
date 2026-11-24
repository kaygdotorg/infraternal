//! The Mac node's report of how mesh names reach the host resolver, for `mesh status`.
//!
//! Kept beside, not inside, `macos_node.rs` so the node file stays under the repository's
//! size gate. The resolver integration runs on the worker thread, so this reads its files.

use super::Node;

impl Node {
    /// What the host resolver integration did, for `mesh status`; `null` without `mesh-dns`.
    #[must_use]
    pub fn dns_state(&self) -> serde_json::Value {
        #[cfg(feature = "mesh-dns")]
        {
            serde_json::json!(crate::dns_integration::macos_installed_state())
        }
        #[cfg(not(feature = "mesh-dns"))]
        {
            serde_json::Value::Null
        }
    }
}
