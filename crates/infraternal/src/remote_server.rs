//! Activates normal CLI remote listeners from retained public trust, never from an argv signing key or implicit CA generation [168], #78.

use clap::Args;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Default, Args)]
pub(crate) struct Options {
    /// Advertised server IP and port for dial-out QUIC and TCP/TLS hosts.
    #[arg(long, global = true)]
    #[cfg_attr(feature = "remote", arg(long_help = infraternal_plugin_remote::SERVE.help()))]
    pub remote_listen: Option<SocketAddr>,
    /// Private directory containing retained public issuer.pem (XDG default).
    #[arg(long, global = true, requires = "remote_listen")]
    pub remote_ca_dir: Option<PathBuf>,
}

impl Options {
    /// Use the plugin action identifier for configured remote serving.
    pub(crate) fn action_id(&self) -> &'static str {
        if self.remote_listen.is_none() {
            return "server.serve";
        }
        #[cfg(feature = "remote")]
        {
            infraternal_plugin_remote::SERVE.id
        }
        #[cfg(not(feature = "remote"))]
        {
            "remote.server.serve"
        }
    }
}

pub(crate) enum Outcome {
    Stopped,
    #[cfg(feature = "remote")]
    Restart(crate::restart::Replacement),
}

pub(crate) async fn serve(
    config: infraternal_server::ServerConfig,
    options: Options,
) -> Result<Outcome, infraternal_server::ServerError> {
    #[cfg(feature = "remote")]
    {
        let remote = options
            .remote_listen
            .map(|listen| {
                infraternal_server::RemoteStartup {
                    listen,
                    ca_dir: options.remote_ca_dir,
                }
                .cold_start(&config)
            })
            .transpose()?;
        {
            if let Some(authority) = remote
                .as_ref()
                .and_then(|remote| remote.ca_administration.as_ref())
            {
                // Invalid inheritance never prevents serving retained public
                // trust: it simply leaves the cold source locked [168][217].
                let _ = infraternal_server::ca_handoff::accept_stdin(&authority.memory_source());
            } else {
                let cold = infraternal_server::ca_memory::MemoryCaSource::unprovisioned(None);
                let _ = infraternal_server::ca_handoff::accept_stdin(&cold);
            }
        }
        let source = remote
            .as_ref()
            .map(|remote| remote.enrollment.source.clone());
        let mut control = crate::restart::Control::start(&config.data_dir)
            .map_err(infraternal_server::ServerError::Listener)?;
        let serving = async move {
            if let Some(remote) = remote {
                infraternal_server::serve_with_remote(config, remote).await
            } else {
                infraternal_server::serve(config).await
            }
        };
        tokio::select! {
            result = serving => result.map(|()| Outcome::Stopped),
            binary = control.requested() => {
                let binary = binary.map_err(infraternal_server::ServerError::Listener)?;
                Ok(Outcome::Restart(crate::restart::Replacement::new(binary, source.as_deref())))
            }
        }
    }
    #[cfg(not(feature = "remote"))]
    {
        if options.remote_listen.is_some() {
            return Err(infraternal_server::ServerError::InvalidConfiguration);
        }
        infraternal_server::serve(config)
            .await
            .map(|()| Outcome::Stopped)
    }
}

#[cfg(test)]
#[path = "remote_server_tests.rs"]
mod tests;
