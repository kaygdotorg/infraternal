//! Standalone reliability host: one startup thread owns SIGCHLD and real PTYs [D81/D270].
use infraternal_shim::{Config, run_host};
use std::{io, path::PathBuf};

fn main() -> io::Result<()> {
    let root = std::env::var_os("PPU_RELIABILITY_STATE")
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let configs = (1_u128..=2)
        .map(|id| {
            let mut config = Config::new(id.to_le_bytes(), nix::unistd::Uid::effective().as_raw());
            config.state = Some(PathBuf::from(&root));
            config.ring_capacity = 65536;
            config
        })
        .collect();
    run_host(configs)
}
