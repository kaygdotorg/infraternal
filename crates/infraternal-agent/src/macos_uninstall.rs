//! Hands authenticated removal of the owned Mac installation to an independent child.
//!
//! Two installs answer the server's uninstall: the root `LaunchDaemon` (root mode) and the
//! person's `LaunchAgent` (user mode, #146). Each checks that it runs the binary its install
//! published and that the install's receipt names the requested host, then starts a removal
//! child in its own process group. The child waits for one byte that is written only after
//! the reply went out, so a dropped reply removes nothing, and it outlives the agent it stops.

use infraternal_plugin_api::{ActionReply, AgentPlugin, PluginDescriptor, PluginError};
use infraternal_plugin_mesh::{macos_service, node::Enrolment};
use infraternal_plugin_remote::{NODE_DESCRIPTOR, UNINSTALL, uninstall_request::decode_request};
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// One removal child at a time for a launchd-managed host.
pub(super) struct Uninstall {
    host: String,
    /// Which install this agent belongs to.
    kind: Kind,
    pending: Arc<AtomicBool>,
}

/// The install an agent removes when the server asks.
enum Kind {
    /// The root `LaunchDaemon` under `/Library` (root mode).
    Root,
    /// The person's `LaunchAgent` under their `~/Library` (user mode, #146): the home comes
    /// from the password database for the agent's uid, never from `$HOME`.
    User {
        /// The person's home folder.
        home: PathBuf,
    },
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
            kind: Kind::Root,
            pending: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Register for a user-mode agent (#146, J1087) only while it runs the binary its install
    /// published and that install's receipt names this enrollment's host.
    pub(super) fn for_user_mode(enrolment: &Enrolment) -> Option<Self> {
        let uid = nix::unistd::Uid::effective();
        if uid.is_root() {
            return None;
        }
        let home = nix::unistd::User::from_uid(uid).ok()??.dir;
        let this = Self {
            host: enrolment.host().to_owned(),
            kind: Kind::User { home },
            pending: Arc::new(AtomicBool::new(false)),
        };
        this.validate().ok()?;
        Some(this)
    }

    /// Check the install is still the one this agent belongs to.
    fn validate(&self) -> std::io::Result<()> {
        match &self.kind {
            Kind::Root => macos_service::validate_installation(&self.host).map(|_| ()),
            Kind::User { home } => {
                use infraternal_plugin_mesh::macos_user_mode as user;
                if std::env::current_exe()? != user::user_install_binary(home) {
                    return Err(std::io::ErrorKind::PermissionDenied.into());
                }
                let mut receipt = String::new();
                std::fs::File::open(user::user_install_receipt(home))?
                    .take(64)
                    .read_to_string(&mut receipt)?;
                if user::receipt_names_host(&receipt, &self.host) {
                    Ok(())
                } else {
                    Err(std::io::ErrorKind::PermissionDenied.into())
                }
            }
        }
    }

    /// Start the removal child for this install, waiting on its stdin for the armed byte.
    fn removal_child(&self) -> std::io::Result<Child> {
        match &self.kind {
            Kind::Root => macos_service::prepare_removal(&self.host),
            Kind::User { home } => {
                use infraternal_plugin_mesh::macos_user_mode as user;
                self.validate()?;
                // A new process group, so the launchd bootout that stops this agent during
                // removal does not also stop the child doing the removal.
                Command::new(user::user_install_binary(home))
                    .arg(user::USER_REMOVE_HANDOFF)
                    .arg(&self.host)
                    .env_clear()
                    .current_dir("/")
                    .process_group(0)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
            }
        }
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
        let mut child = self.removal_child().map_err(|_| PluginError::Rejected)?;
        let mut arm = child.stdin.take().ok_or(PluginError::Rejected)?;
        let pending = Arc::clone(&self.pending);
        std::thread::Builder::new()
            .name("macos-uninstall".to_owned())
            .spawn(move || {
                // Only waits for the helper; nobody is waiting on it (#554).
                let _ =
                    infraternal_shim::qos::set_current_thread(infraternal_shim::qos::Qos::Utility);
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
            self.validate().map_err(|_| PluginError::Rejected)?;
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
