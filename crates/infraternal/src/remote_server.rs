//! Activates normal CLI remote listeners from retained public trust, never from an argv signing key or implicit CA generation [168], #78.

use clap::Args;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Default, Args)]
pub(crate) struct Options {
    /// Advertised server IP and port for dial-out QUIC and TCP/TLS hosts.
    #[arg(long, global = true)]
    pub remote_listen: Option<SocketAddr>,
    /// Private directory containing retained public issuer.pem (XDG default).
    #[arg(long, global = true, requires = "remote_listen")]
    pub remote_ca_dir: Option<PathBuf>,
}

pub(crate) async fn serve(
    config: infraternal_server::ServerConfig,
    options: Options,
) -> Result<(), infraternal_server::ServerError> {
    #[cfg(feature = "remote")]
    {
        if let Some(listen) = options.remote_listen {
            let startup = infraternal_server::RemoteStartup {
                listen,
                ca_dir: options.remote_ca_dir,
            };
            let remote = startup.cold_start(&config)?;
            infraternal_server::serve_with_remote(config, remote).await
        } else {
            infraternal_server::serve(config).await
        }
    }
    #[cfg(not(feature = "remote"))]
    {
        if options.remote_listen.is_some() {
            return Err(infraternal_server::ServerError::InvalidConfiguration);
        }
        infraternal_server::serve(config).await
    }
}

#[cfg(test)]
#[path = "remote_server_tests.rs"]
mod tests;
