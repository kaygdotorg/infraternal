//! Startup discovery must recover every authenticated live socket, with bounded work rather than a host count cap [D214], #151.
use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

#[tokio::test(flavor = "current_thread")]
async fn discovery_recovers_more_than_128_authenticated_sockets() {
    let directory = Directory::new();
    let state = super::state(Some(directory.0.clone())).unwrap();
    let mut servers = tokio::task::JoinSet::new();
    for value in 1_u128..=200 {
        let id = value.to_le_bytes();
        let path = state
            .join("sessions")
            .join(format!("{}.sock", uuid::Uuid::from_bytes(id).simple()));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        servers.spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            super::super::send(
                &mut peer,
                &infraternal_shim::frame::Frame::Hello {
                    version: 1,
                    caps: 0,
                    session: id,
                    pid: std::process::id(),
                    cols: 80,
                    rows: 24,
                    created: 0,
                    head: 0,
                    start: 0,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                super::super::Reader::default()
                    .read(&mut peer)
                    .await
                    .unwrap(),
                infraternal_shim::frame::Frame::Attach(0)
            );
        });
    }
    assert_eq!(super::super::discover(&state).await.unwrap().len(), 200);
    while let Some(result) = servers.join_next().await {
        result.unwrap();
    }
}
