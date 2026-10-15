//! Standalone reliability host: one startup thread owns SIGCHLD and real PTYs [D81/D270].
use infraternal_shim::{Config, run_host_accounted};
use std::{
    fs::{DirBuilder, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
};

extern "C" fn child_notification(_: nix::libc::c_int) {}

fn main() -> io::Result<()> {
    if std::env::var("PPU_RELIABILITY_CHILD_HANDLER").as_deref() == Ok("1") {
        let action = nix::sys::signal::SigAction::new(
            nix::sys::signal::SigHandler::Handler(child_notification),
            nix::sys::signal::SaFlags::SA_NOCLDWAIT,
            nix::sys::signal::SigSet::empty(),
        );
        // SAFETY: single-threaded fixture startup; the static handler neither
        // allocates nor accesses runtime state. This also exercises removal of
        // inherited auto-reaping flags, independently of SIG_IGN.
        #[allow(unsafe_code)]
        unsafe { nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGCHLD, &action) }
            .map_err(io::Error::from)?;
    }
    let root = std::env::var_os("PPU_RELIABILITY_STATE")
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let root = PathBuf::from(root);
    let accounting = if std::env::var("PPU_RELIABILITY_TRACE").as_deref() == Ok("1") {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        Some(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("stages.log"))?,
        )
    } else {
        None
    };
    let configs = (1_u128..=2)
        .map(|id| {
            let mut config = Config::new(id.to_le_bytes(), nix::unistd::Uid::effective().as_raw());
            config.state = Some(root.clone());
            config.ring_capacity = 65536;
            config
        })
        .collect();
    run_host_accounted(configs, accounting)
}
