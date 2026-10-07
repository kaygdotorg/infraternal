//! Reports fixed notification bookkeeping at existing socket caps; excludes shared runtime/allocator costs.
use super::{MAX_CONNECTIONS, MAX_USER_CONNECTIONS, RecoverySnapshot};

#[test]
#[ignore = "notification state sizing diagnostic, not allocator-inclusive RSS certification"]
fn recovery_notification_state_at_socket_capacity() {
    let receiver = std::mem::size_of::<tokio::sync::watch::Receiver<()>>();
    let snapshot = std::mem::size_of::<RecoverySnapshot>();
    let subscribed = std::mem::size_of::<bool>();
    let per_socket = receiver + snapshot + subscribed;
    println!(
        "Recovery notification fixed fields: receiver={receiver} snapshot={snapshot} subscribed={subscribed}; {per_socket} bytes/socket x {MAX_USER_CONNECTIONS} user cap = {} bytes; x {MAX_CONNECTIONS} global cap = {} bytes",
        per_socket * MAX_USER_CONNECTIONS,
        per_socket * MAX_CONNECTIONS
    );
    println!(
        "Shared watch channel: one per Auth; per-socket fields do not allocate on each recovery update; excludes stack alignment, Tokio channel allocation and transient JSON."
    );
}
