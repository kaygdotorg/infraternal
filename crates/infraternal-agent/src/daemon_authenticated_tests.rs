//! Keeps the authenticated UID fence in session-only builds before state creation or channel IO (D240, D255).

use super::*;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use std::os::fd::AsRawFd;

#[tokio::test]
async fn authenticated_uid_refusal_precedes_state_and_io() {
    let root = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache/codex-scratch/addhost-instant")
        },
        PathBuf::from,
    );
    let state = root.join(format!("refused-{}", uuid::Uuid::new_v4()));
    let (_peer, descriptor) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .unwrap();
    let channel = Socket::inherited(descriptor.as_raw_fd()).unwrap();
    let result = run_authenticated(
        &channel,
        Some(state.clone()),
        nix::unistd::Uid::effective().as_raw() ^ 1,
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert!(!state.exists());
}
