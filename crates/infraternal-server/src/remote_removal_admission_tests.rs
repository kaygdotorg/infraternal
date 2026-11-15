//! The removal service's own permits run out as "busy", not as "not allowed" (#519).
use super::admit;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// With every permit held, the next request must be `Throttled` (the HTTP layer answers 429, and the browser says
/// "too many host removals"); a freed permit admits again. `Denied` would show the unrelated "refresh the host list".
#[test]
fn exhausted_permits_are_throttled_not_denied() {
    let permits = Arc::new(Semaphore::new(2));
    let held = [admit(&permits).unwrap(), admit(&permits).unwrap()];
    assert!(
        matches!(admit(&permits), Err(crate::auth::Error::Throttled)),
        "a full service must answer Throttled"
    );
    drop(held);
    assert!(admit(&permits).is_ok());
}
