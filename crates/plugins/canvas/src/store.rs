//! Keeps persistence behind a host-supplied account layout source, independent of the selected database engine [198,243].
use infraternal_plugin_api::Operation;
use serde_json::Value;
use tokio::sync::watch;
/// The host binds every call to the authenticated account; a source never receives credentials.
pub trait LayoutStore: Send + Sync {
    fn changes(&self) -> watch::Receiver<()>;
    fn call<'a>(
        &'a self,
        initialize: bool,
        account: &'a str,
        input: &'a [u8],
    ) -> Operation<'a, Result<i64, ()>>;
    fn events<'a>(
        &'a self,
        account: &'a str,
        after: Option<i64>,
    ) -> Operation<'a, Result<Vec<Value>, ()>>;
}
