//! The relay role of the server's own node, slice 1 (D402 Q3, Q4).
//!
//! The relay is a role of the one binary, not part of the server process: the server's
//! embedded infraternal agent runs it, like any node could. What the server adds is what only
//! it has, the deployment CA. Here it keeps a dedicated **relay leaf** for its public name
//! fresh (`server_leaf`'s relay rotation: 7 days, renewed at half-life while the CA is
//! unlocked, durable in the CA's `active` directory so a locked cold start still has it) and
//! hands it to the mesh coordinator, which sends it to its own node in `mesh.relays`
//! (`infraternal_plugin_mesh::relay_list`). Once the node reports the port it bound, every
//! other node's relay list names this relay.
//!
//! Opt-in for slice 1: the operator passes `--relay-port` (UDP; D391 proposes 443). Without it
//! no relay runs, so a server whose UDP port is used by something else changes nothing.

use crate::{ca_administration::CaAdministrationConfig, server_leaf};
use infraternal_plugin_mesh::relay_list::{ServeIdentity, ServeSource, set_serve_source};
use openssl::x509::X509;
use std::sync::{Arc, OnceLock, RwLock};

/// The UDP port `--relay-port` asked for; unset means the relay role is off.
static PORT: OnceLock<u16> = OnceLock::new();

/// Ask for the relay role on UDP `port` (from the command line). Call before the server runs.
pub fn enable(port: u16) {
    let _ = PORT.set(port);
}

/// The relay leaf the node is handed now, as the PEM text the node parses.
struct Current {
    name: String,
    leaf: Option<String>,
    roots: Vec<String>,
}

/// Start the relay leaf rotation and give the coordinator its serve source, when the role
/// was enabled and this server keeps its leaves in a bootstrapped CA directory. Returns the
/// rotation task for the caller to run for the listeners' lifetime.
pub(crate) fn start(
    administration: &CaAdministrationConfig,
    roots: &[X509],
) -> Option<impl std::future::Future<Output = ()> + Send + 'static> {
    let port = *PORT.get()?;
    let (directory, name) = administration.server_leaf()?;
    let retained = server_leaf::load_relay(&directory).unwrap_or_else(|_| {
        tracing::warn!("relay: the retained relay leaf is unreadable; issuing a new one");
        None
    });
    let relay = retained
        .as_ref()
        .map_or_else(uuid::Uuid::new_v4, |(_, relay)| *relay);
    let roots = roots
        .iter()
        .filter_map(|root| root.to_pem().ok())
        .filter_map(|pem| String::from_utf8(pem).ok())
        .collect::<Vec<_>>();
    let current = Arc::new(RwLock::new(Current {
        name: name.clone(),
        leaf: retained
            .as_ref()
            .and_then(|(identity, _)| leaf_pem(identity)),
        roots,
    }));
    let (changes, receiver) = tokio::sync::watch::channel(0_u64);
    set_serve_source(ServeSource {
        identity: {
            let current = current.clone();
            Arc::new(move || {
                let current = current
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                Some(ServeIdentity {
                    name: current.name.clone(),
                    leaf: current.leaf.clone()?,
                    roots: current.roots.clone(),
                })
            })
        },
        changes: receiver,
        port,
    });
    let rotation = server_leaf::Rotation {
        source: administration.memory_source(),
        directory,
        name,
        relay: Some(relay),
    };
    let first = retained.map(|(identity, _)| identity.certificate);
    Some(server_leaf::run(rotation, first, move |identity| {
        let pem = leaf_pem(identity).ok_or_else(|| std::io::Error::other("relay leaf PEM"))?;
        current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .leaf = Some(pem);
        changes.send_modify(|generation| *generation += 1);
        Ok(())
    }))
}

/// The leaf certificate PEM followed by its PKCS#8 key PEM, the layout the node parses.
fn leaf_pem(identity: &infraternal_agent::remote_tls::Identity) -> Option<String> {
    let bytes = server_leaf::encode(identity).ok()?;
    String::from_utf8(bytes.to_vec()).ok()
}
