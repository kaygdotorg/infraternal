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

/// Serve the remote server with this configuration and options.
pub(crate) async fn serve(
    config: infraternal_server::ServerConfig,
    options: Options,
) -> Result<Outcome, infraternal_server::ServerError> {
    #[cfg(feature = "remote")]
    {
        infraternal_server::ca_memory::initialize_private_key_memory()?;
        // Detach private stdin before cold_start can return an error or perform
        // any configuration I/O; install only after retained trust is available.
        let inherited = infraternal_server::ca_handoff::receive_stdin();
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
        let warm = if let (Ok(inherited), Some(authority)) = (
            inherited,
            remote
                .as_ref()
                .and_then(|remote| remote.ca_administration.as_ref()),
        ) {
            inherited.install(&authority.memory_source()).is_ok()
        } else {
            false
        };
        // Correlate the successor's actual retained-trust installation result
        // with the predecessor's request record using the unchanged service PID.
        tracing::info!(
            service_pid = std::process::id(),
            outcome = if warm { "warm" } else { "cold" },
            "server_ca_startup"
        );
        let source = remote
            .as_ref()
            .map(|remote| remote.enrollment.source.clone());
        let clock_health = remote.as_ref().map_or_else(
            || std::sync::Arc::new(infraternal_server::clock_health::ClockHealth::default()),
            |remote| remote.clock_health.clone(),
        );
        let control = crate::restart::Control::start_with_clock(&config.data_dir, clock_health);
        let serving = async move {
            if let Some(remote) = remote {
                infraternal_server::serve_with_remote(config, remote).await
            } else {
                infraternal_server::serve(config).await
            }
        };
        let mut control = match control {
            Ok(control) => control,
            Err(error) => {
                // The private convenience endpoint is not a dependency of the
                // HTTP server or retained public CA verification.
                tracing::warn!(error_kind = ?error.kind(), "server restart control unavailable; continuing without its socket");
                return serving.await.map(|()| Outcome::Stopped);
            }
        };
        tokio::pin!(serving);
        loop {
            tokio::select! {
                result = &mut serving => return result.map(|()| Outcome::Stopped),
                replacement = control.requested(source.as_deref()) => {
                    match replacement {
                        Ok(replacement) => return Ok(Outcome::Restart(replacement)),
                        Err(error) => {
                            tracing::warn!(error_kind = ?error.kind(), "server restart control failed; continuing to serve");
                            // Keep serving; back off if accept repeatedly fails.
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
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

/// Exercises the failed-control path without treating the test harness as a server executable.
#[cfg(all(test, feature = "remote"))]
async fn serve_behind_control<F>(
    data_dir: PathBuf,
    serving: F,
) -> Result<Outcome, infraternal_server::ServerError>
where
    F: std::future::Future<Output = Result<(), infraternal_server::ServerError>> + Send,
{
    match crate::restart::Control::start(&data_dir) {
        Ok(_) => panic!("test fixture requires an unavailable restart control endpoint"),
        Err(error) => {
            tracing::warn!(error_kind = ?error.kind(), "server restart control unavailable; continuing without its socket");
            serving.await.map(|()| Outcome::Stopped)
        }
    }
}

#[cfg(test)]
#[path = "remote_server_tests.rs"]
mod tests;
