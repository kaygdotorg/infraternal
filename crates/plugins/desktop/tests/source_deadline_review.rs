//! Reviews silent same-user helper control deadlines and joined retirement [D203,D232], #146.
#![cfg(all(feature = "source", target_os = "linux"))]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_api::{AgentPlugin, ComponentPlugin};
use infraternal_plugin_desktop::source::SourceBridge;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};

#[tokio::test]
async fn silent_inventory_helper_releases_control_admission_after_deadline() {
    let target = PathBuf::from("target");
    let remove_target_afterward = !target.exists();
    fs::create_dir_all(&target).unwrap();
    let runtime = target.join(format!("sd-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&runtime).unwrap();
    let executable = runtime.join("silent.py");
    fs::write(
        &executable,
        r#"#!/usr/bin/env python3
# Role: acknowledges receipt out of band and keeps the response direction silent.
import os, socket, sys
os.umask(0o077)
listener = socket.socket(socket.AF_UNIX)
listener.bind(os.path.join(sys.argv[1], "desktop.sock"))
listener.listen(1)
connection, _ = listener.accept()
listener.close()
request = connection.recv(65536)
base = sys.argv[sys.argv.index("--companion-runtime") + 1]
with open(os.path.join(base, "received"), "w") as marker:
    marker.write(str(request[5]))
while connection.recv(65536):
    pass
"#,
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
    let mut bridge = SourceBridge::new(runtime.clone(), fs::canonicalize(&executable).unwrap(), 1);
    bridge.set_enabled(true).await.unwrap();
    let operation = bridge.call_async("desktop.source.windows", b"{}").unwrap();
    let mut worker = tokio::spawn(operation);
    tokio::time::timeout(Duration::from_secs(3), async {
        while !runtime.join("received").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fs::read_to_string(runtime.join("received")).unwrap(), "1");
    // Start the observation after real request receipt, excluding process startup.
    // This is a functional deadline check, not a performance measurement.
    let completed = tokio::time::timeout(Duration::from_secs(4), &mut worker).await;
    let bounded = matches!(completed, Ok(Ok(Err(_))));
    let active = bridge.status().active_work;
    bridge.set_enabled(false).await.unwrap();
    if !worker.is_finished() {
        let _ = worker.await;
    }
    fs::remove_dir_all(runtime).unwrap();
    if remove_target_afterward {
        let _ = fs::remove_dir(target);
    }
    assert!(
        bounded && active == 0,
        "silent inventory retained its control operation and helper until explicit disable (active_work={active})"
    );
}
