//! Runs the real desktop source supervisor for isolated measurements, exchanging only public enrollment material over stdio [D208,D232,#146].
use infraternal_agent::{remote_client, remote_tls::Identity};
use infraternal_plugin_api::PluginRegistry;
use infraternal_plugin_desktop::source::SourceBridge;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    x509::{X509, X509NameBuilder, X509Req},
};
use serde::Deserialize;
use std::{
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// The fixture supplies certificates, never a private key or a browser credential.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    certificate_der: Vec<u8>,
    ca_der: Vec<u8>,
    endpoint: std::net::SocketAddr,
    server_name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_DESKTOP_BENCH_DIR").ok_or("measurement directory missing")?,
    );
    let helper = PathBuf::from(
        std::env::var_os("INFRATERNAL_DESKTOP_BENCH_HELPER").ok_or("measurement helper missing")?,
    );
    let key = PKey::generate_ed25519()?;
    let mut request = X509Req::builder()?;
    request.set_subject_name(&X509NameBuilder::new()?.build())?;
    request.set_pubkey(&key)?;
    request.sign(&key, MessageDigest::null())?;
    let uid = nix::unistd::Uid::effective().as_raw();
    println!(
        "{}",
        serde_json::json!({"csr_der":request.build().to_der()?, "pid":std::process::id(), "uid":uid})
    );
    io::stdout().flush()?;
    // One bounded public response; the generated private key stays in this process.
    let mut reply = String::new();
    io::stdin().lock().take(65_537).read_line(&mut reply)?;
    if reply.len() > 65_536 || !reply.ends_with('\n') {
        return Err("invalid enrollment response".into());
    }
    let enrollment: Enrollment = serde_json::from_str(&reply)?;
    let identity = remote_client::RemoteIdentity {
        identity: Identity {
            certificate: X509::from_der(&enrollment.certificate_der)?,
            key,
        },
        roots: vec![X509::from_der(&enrollment.ca_der)?],
        endpoint: enrollment.endpoint,
        server_name: enrollment.server_name,
        execution_uid: uid,
    };
    let mut registry = PluginRegistry::default();
    #[cfg(feature = "plugin-host-facts")]
    registry
        .register(Box::new(
            infraternal_plugin_host_facts::HostFactsPlugin::new(
                infraternal_plugin_host_facts::AgentMode::Remote,
            ),
        ))
        .map_err(|_| "host facts registration refused")?;
    registry
        .register(Box::new(SourceBridge::new(
            root.join("capture"),
            helper,
            infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS,
        )))
        .map_err(|_| "source registration refused")?;
    registry
        .begin_call("desktop.up", b"{}")
        .map_err(|_| "source admission refused")?
        .await
        .map_err(|_| "source startup refused")?;
    let registry = Arc::new(Mutex::new(registry));
    let running =
        remote_client::run_with_registry(&identity, Some(root.join("runtime")), registry.clone());
    let outcome = tokio::select! {
        result = running => result,
        result = tokio::signal::ctrl_c() => result,
    };
    let shutdown = registry
        .lock()
        .map_err(|_| "source state unavailable")?
        .begin_call("desktop.down", b"{}")
        .map_err(|_| "source shutdown refused")?;
    shutdown.await.map_err(|_| "source cleanup incomplete")?;
    outcome?;
    Ok(())
}
