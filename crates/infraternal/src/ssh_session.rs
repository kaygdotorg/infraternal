//! Launches the D255 shim-owned shell and bridges SSH pipes through the existing terminal dispatcher.

use infraternal_agent::{
    daemon,
    sessions::{self, Manager},
};
use infraternal_plugin_api::channel::Channel;
use std::{io, path::PathBuf, process::ExitCode};

/// Internal authenticated SSH command; all protocol output goes to its pipe.
/// No public shell, arbitrary command or login identity is accepted from argv.
pub fn run(state: PathBuf) -> ExitCode {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .and_then(|runtime| runtime.block_on(bridge(state)));
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
async fn bridge(state: PathBuf) -> io::Result<()> {
    let state = sessions::state(Some(state))?;
    let uid = nix::unistd::Uid::effective().as_raw();
    let exe = std::env::current_exe()?;
    let session = sessions::launch(&exe, &state, Manager::detect().await, uid, 80, 24).await?;
    let channel = infraternal_plugin_ssh::stdio::Stdio::inherited()?;
    channel
        .write(format!("SESSION {}\n", uuid::Uuid::from_bytes(session.id)).as_bytes())
        .await?;
    // The daemon discovers this exact shim through its ordinary authenticated
    // rendezvous. Neither this bridge nor SSH starts a shell outside the shim.
    drop(session);
    daemon::run_authenticated(&channel, Some(state), uid).await
}
