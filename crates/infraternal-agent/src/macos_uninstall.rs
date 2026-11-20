//! Hands authenticated removal of the owned Mac installation to an independent child.

use infraternal_plugin_api::{ActionReply, AgentPlugin, PluginDescriptor, PluginError};
use infraternal_plugin_mesh::{macos_service, node::Enrolment};
use infraternal_plugin_remote::{NODE_DESCRIPTOR, UNINSTALL, uninstall_request::decode_request};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// One removal child at a time for a launchd-managed host.
pub(super) struct Uninstall {
    host: String,
    pending: Arc<AtomicBool>,
}

impl Uninstall {
    /// Register only while running the binary installed for this enrollment.
    pub(super) fn for_enrolment(enrolment: &Enrolment) -> Option<Self> {
        let host = enrolment.host();
        if !nix::unistd::Uid::effective().is_root()
            || std::env::current_exe().ok()?.as_path()
                != std::path::Path::new(macos_service::MACHINE_BINARY)
        {
            return None;
        }
        macos_service::validate_installation(host).ok()?;
        Some(Self {
            host: host.to_owned(),
            pending: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Spawn the child and return only the byte that arms it after the reply.
    fn prepare(&self) -> Result<infraternal_plugin_api::AfterReply, PluginError> {
        if self.pending.swap(true, Ordering::AcqRel) {
            return Err(PluginError::Rejected);
        }
        let result = self.spawn_child();
        if result.is_err() {
            self.pending.store(false, Ordering::Release);
        }
        result
    }

    /// Give the helper a pipe that closes unread if the transport drops the reply.
    fn spawn_child(&self) -> Result<infraternal_plugin_api::AfterReply, PluginError> {
        let mut child =
            macos_service::prepare_removal(&self.host).map_err(|_| PluginError::Rejected)?;
        let mut arm = child.stdin.take().ok_or(PluginError::Rejected)?;
        let pending = Arc::clone(&self.pending);
        std::thread::Builder::new()
            .name("macos-uninstall".to_owned())
            .spawn(move || {
                // Only waits for the helper; nobody is waiting on it (#554).
                let _ = infraternal_shim::qos::set_current_thread(infraternal_shim::qos::Qos::Utility);
                let _ = child.wait();
                pending.store(false, Ordering::Release);
            })
            .map_err(|_| PluginError::Rejected)?;
        Ok(Box::new(move || {
            // One byte to a fresh, empty pipe cannot wait on the helper.
            let _ = arm.write_all(&[1]);
        }))
    }
}

impl AgentPlugin for Uninstall {
    /// Only the authenticated server channel routes the private uninstall action.
    fn descriptor(&self) -> &'static PluginDescriptor {
        &NODE_DESCRIPTOR
    }

    /// Refuse dispatch paths that cannot acknowledge the removal before it starts.
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
        Err(PluginError::Rejected)
    }

    /// Review or arm only a request for this live enrollment.
    fn call_with_reply(&mut self, action: &str, input: &[u8]) -> Result<ActionReply, PluginError> {
        let request = decode_request(input)?;
        if action != UNINSTALL.id || request.host != self.host {
            return Err(PluginError::Rejected);
        }
        if request.dry_run {
            macos_service::validate_installation(&self.host).map_err(|_| PluginError::Rejected)?;
            return Ok(ActionReply {
                json: br#"{"state":"ready","owned":true,"left":[]}"#.to_vec(),
                after_write: None,
            });
        }
        Ok(ActionReply {
            json: br#"{"state":"accepted","cleanup":"pending","left":[]}"#.to_vec(),
            after_write: Some(self.prepare()?),
        })
    }
}
