//! Bounds topic discovery before dispatching opaque subscription filters to their owning plugin [11,198].
use serde::Deserialize;
use std::borrow::Cow;

/// The only field routing reads from a subscription filter.
#[derive(Deserialize)]
struct Topic<'a> {
    #[serde(borrow)]
    topic: Cow<'a, str>,
}

/// Reads just the `topic` of a subscription filter, to find which plugin owns it.
///
/// `filter_json` is the raw JSON object of the filter. Returns `None` if it is longer than
/// `max_len` bytes or is not JSON with a string `topic`; nothing else in the filter is looked at.
///
/// Discover only the routing key; the receiving plugin validates the complete filter.
/// Ordinary topic names borrow from the existing frame. Escaped JSON remains valid.
/// The host supplies its compiled providers' frame bound before any JSON allocation.
#[must_use]
pub fn subscription_topic(filter_json: &[u8], max_len: usize) -> Option<Cow<'_, str>> {
    if filter_json.len() > max_len {
        return None;
    }
    serde_json::from_slice::<Topic<'_>>(filter_json)
        .ok()
        .map(|filter| filter.topic)
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
