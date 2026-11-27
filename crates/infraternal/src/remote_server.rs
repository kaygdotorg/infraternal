//! Activates normal CLI remote listeners from retained public trust, never from an argv signing key or implicit CA generation [168], #78.

use clap::Args;
use std::{net::SocketAddr, path::PathBuf};

/// Server command-line options for remote serving: leg B and the relay role (D402).
#[derive(Debug, Default, Args)]
pub(crate) struct Options {
    /// Advertised server IP and port for dial-out QUIC and TCP/TLS hosts.
    #[arg(long, global = true)]
    #[cfg_attr(feature = "remote", arg(long_help = infraternal_plugin_remote::SERVE.help()))]
    pub remote_listen: Option<SocketAddr>,
    /// Private directory containing retained public issuer.pem (XDG default).
    #[arg(long, global = true, requires = "remote_listen")]
    pub remote_ca_dir: Option<PathBuf>,
    /// UDP port on which the server's own node runs the mesh relay (D402). Off when absent.
    #[arg(long, global = true, requires = "remote_listen")]
    pub relay_port: Option<u16>,
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

/// How the remote server loop exited: cleanly stopped or replacing itself in place.
pub(crate) enum Outcome {
    Stopped,
    #[cfg(feature = "remote")]
    Restart(Box<crate::restart::Replacement>),
}

/// Serve the remote server with this configuration and options.
pub(crate) async fn serve(
    config: infraternal_server::ServerConfig,
    options: Options,
) -> Result<Outcome, infraternal_server::ServerError> {
    #[cfg(feature = "remote")]
    {
        // The relay role runs on the server's own node, with a leaf this server keeps (D402).
        #[cfg(feature = "plugin-mesh")]
        if let Some(port) = options.relay_port {
            infraternal_server::relay_role::enable(port);
        }
        infraternal_server::ca_memory::initialize_private_key_memory()?;
        // Detach private stdin before cold_start can return an error or perform
        // any configuration I/O; install only after retained trust is available.
        let inherited = infraternal_server::ca_handoff::receive_stdin();
        // An update switch in flight is settled before anything opens the database:
        // the previous release puts back its D295 copy here (#211 S4).
        #[cfg(feature = "release")]
        if infraternal_server::update_apply::startup(&config.data_dir).is_err() {
            return Err(infraternal_server::ServerError::UpdateTrial);
        }
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
        // Updates must keep the CA if it is unlocked at switch time, whether it came
        // through the handoff or a passkey unlocked it later (D217, #211 S4).
        #[cfg(feature = "release")]
        if let Some(source) = source.clone() {
            infraternal_server::update_apply::set_ca_probe(Box::new(move || {
                source
                    .subscribe_locked()
                    .is_some_and(|locked| !*locked.borrow())
            }));
        }
        let clock_health = remote.as_ref().map_or_else(
            || std::sync::Arc::new(infraternal_server::clock_health::ClockHealth::default()),
            |remote| remote.clock_health.clone(),
        );
        let control = crate::restart::Control::start_with_clock(&config.data_dir, clock_health);
        // The auto-update's switches mirror Mesh state from this folder (#211 S4, #489).
        #[cfg(feature = "release")]
        let data_dir = config.data_dir.clone();
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
        // The auto-updater's switches use this same loop and handoff (#211 S4).
        #[cfg(feature = "release")]
        let mut switches = infraternal_server::update_apply::switch_requests();
        loop {
            #[cfg(feature = "release")]
            let switch = switches.recv();
            #[cfg(not(feature = "release"))]
            let switch = std::future::pending::<Option<()>>();
            tokio::select! {
                result = &mut serving => {
                    // A new release on trial that cannot serve (a failed migration, for
                    // example) undoes itself warm instead of exiting cold (#211 S4).
                    #[cfg(feature = "release")]
                    if result.is_err()
                        && let Some(replacement) = crate::restart::failed_start(source.as_ref(), &data_dir)
                    {
                        return Ok(Outcome::Restart(Box::new(replacement)));
                    }
                    return result.map(|()| Outcome::Stopped);
                }
                Some(request) = switch => {
                    #[cfg(feature = "release")]
                    if let Some(replacement) = crate::restart::switch(request, source.as_ref(), &data_dir) {
                        return Ok(Outcome::Restart(Box::new(replacement)));
                    }
                    #[cfg(not(feature = "release"))]
                    let () = request;
                }
                replacement = control.requested(source.as_ref()) => {
                    match replacement {
                        Ok(replacement) => return Ok(Outcome::Restart(Box::new(replacement))),
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
        #[cfg(target_os = "linux")]
        if let Ok(socket) = crate::server_control::Socket::bind(&config.data_dir) {
            let data = config.data_dir.clone();
            let serving = infraternal_server::serve(config);
            tokio::pin!(serving);
            return tokio::select! {
                result = &mut serving => result,
                _ = crate::server_control::serve_database(socket, &data) => serving.await,
            }
            .map(|()| Outcome::Stopped);
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
