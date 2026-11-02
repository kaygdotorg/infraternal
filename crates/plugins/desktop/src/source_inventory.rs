//! Bounds source inventory pages by the frozen action limit and ties cursors to one current helper snapshot [D16,D232].
use infraternal_plugin_api::{MAX_ACTION_BYTES, PluginError};
use serde_json::{Value, json};
use uuid::Uuid;
pub(super) struct Snapshot {
    id: Uuid,
    metadata: Value,
    windows: Vec<Value>,
    next: usize,
}
impl Snapshot {
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
    pub fn accepts(&self, cursor: &str) -> bool {
        cursor == self.cursor(self.next)
    }
    fn cursor(&self, offset: usize) -> String {
        format!("{}:{offset}", self.id)
    }
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
