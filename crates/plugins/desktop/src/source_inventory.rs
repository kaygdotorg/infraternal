//! Bounds source inventory pages by the frozen action limit and ties cursors to one current helper snapshot [D16,D232].
//!
//! The helper reports all windows at once, which can exceed the maximum action
//! size. A [`Snapshot`] splits that list into pages that each fit. A cursor is
//! `<snapshot id>:<offset>`, so a cursor from an older snapshot, or one that
//! skips ahead or repeats, is rejected by [`Snapshot::accepts`].
use infraternal_plugin_api::{MAX_ACTION_BYTES, PluginError};
use serde_json::{Value, json};
use uuid::Uuid;
/// One inventory report from the helper, served page by page.
pub(super) struct Snapshot {
    /// Random id embedded in every cursor, tying cursors to this snapshot.
    id: Uuid,
    /// Everything in the report except the window list; repeated on each page.
    metadata: Value,
    windows: Vec<Value>,
    /// Index of the first window not yet sent.
    next: usize,
}
impl Snapshot {
    /// Splits the helper's inventory JSON into metadata and its `windows` array.
    /// Returns [`PluginError::Rejected`] if it is not an object with a `windows`
    /// array.
    pub fn new(mut value: Value) -> Result<Self, PluginError> {
        let object = value.as_object_mut().ok_or(PluginError::Rejected)?;
        let windows = object
            .remove("windows")
            .and_then(|v| v.as_array().cloned())
            .ok_or(PluginError::Rejected)?;
        Ok(Self {
            id: Uuid::new_v4(),
            metadata: value,
            windows,
            next: 0,
        })
    }
    /// True only for the cursor the previous page handed out, i.e. the one that
    /// continues exactly where this snapshot stopped.
    pub fn accepts(&self, cursor: &str) -> bool {
        cursor == self.cursor(self.next)
    }
    /// The cursor string that resumes at window `offset`.
    fn cursor(&self, offset: usize) -> String {
        format!("{}:{offset}", self.id)
    }
    /// Builds the next page, `{"inventory": ..., "cursor": ...}`, with as many
    /// windows as fit within the maximum action size, and advances. `cursor` is
    /// null on the last page. Fails with [`PluginError::MessageTooLarge`] if not
    /// even one window fits (or the metadata alone is too big).
    pub fn page(&mut self) -> Result<Value, PluginError> {
        let begin = self.next;
        let mut accepted = None;
        for end in begin..=self.windows.len() {
            let mut inventory = self.metadata.clone();
            inventory["windows"] = Value::Array(self.windows[begin..end].to_vec());
            let cursor = (end < self.windows.len()).then(|| self.cursor(end));
            let page = json!({"inventory":inventory,"cursor":cursor});
            if serde_json::to_vec(&page)
                .map_err(|_| PluginError::Rejected)?
                .len()
                > MAX_ACTION_BYTES
            {
                break;
            }
            accepted = Some((end, page));
        }
        let (end, page) = accepted.ok_or(PluginError::MessageTooLarge)?;
        if end == begin && end < self.windows.len() {
            return Err(PluginError::MessageTooLarge);
        }
        self.next = end;
        Ok(page)
    }
}
