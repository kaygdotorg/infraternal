//! Shares one descriptor between server socket work and node component lifecycle [15,16,28,198,201].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod action;

pub use action::{
    ActionAvailability, ActionContract, ActionDefinition, ActionEffect, ActionExample,
    ActionPermission, ActionRegistry, ActionTarget, CliHandler, DryRun as CliDryRun, JsonSchema,
    JsonSchemaType, PluginDefinition, RegisteredAction, RegistryError, SafetyNotes,
};

pub mod admission;
pub mod channel;
pub mod host_name;
pub mod node_channel;
pub mod present;
pub mod release_version;
/// One pipeline-stamped identity shared by reported versions and lockstep downloads [225,226].
pub const VERSION: &str = env!("INFRATERNAL_VERSION");
/// Static header avoids a per-download formatting allocation [226].
pub const RELEASE_USER_AGENT: &str = concat!("infraternal/", env!("INFRATERNAL_VERSION"));
#[cfg(any(test, feature = "native-wire"))]
pub mod datagrams;
pub mod path;
pub mod routing;
pub mod server_path;
#[cfg(feature = "socket-host")]
pub mod storage;
pub mod streams;

#[cfg(feature = "socket-host")]
use bytes::Bytes;
use serde::Serialize;
use std::collections::HashSet;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
#[cfg(feature = "socket-host")]
use tokio::sync::mpsc;

/// The interface version compiled into every descriptor.
pub const API_VERSION: u16 = 1;
/// Fresh destructive confirmation window shared by host and plugins [28].
pub const FRESH_SECONDS: i64 = 300;
/// A plugin operation remains cancellable by the host's session watchdog.
pub type Operation<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// Permission and confirmation semantics exposed to every adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Effect {
    Read,
    Write,
    Destructive,
}
/// One public action definition; schemas refer to the frozen contract types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ActionDef {
    pub id: &'static str,
    pub summary: &'static str,
    pub instructions: &'static [&'static str],
    pub input: SchemaRef,
    pub output: SchemaRef,
    pub permission: Permission,
    pub effect: Effect,
    pub target: Target,
    pub dry_run: DryRun,
    pub opens: Option<&'static str>,
}
/// Read visibility may follow any management action without introducing a view-only role [187].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Permission {
    One(&'static str),
    Any(&'static [&'static str]),
}
/// A server feature and a node component share an id but cannot create each other.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RoleDef {
    pub id: &'static str,
    pub requires: &'static [&'static str],
    pub default_enabled: bool,
}
/// Pure metadata: inspecting a disabled plugin starts no work.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct PluginDescriptor {
    pub id: &'static str,
    pub api: u16,
    pub actions: &'static [ActionDef],
    pub topics: &'static [&'static str],
    pub settings: Option<SchemaRef>,
    pub events: &'static [EventDef],
    pub streams: &'static [StreamDef],
    pub defaults: &'static [SettingDefault],
    pub dependencies: &'static [Dependency],
    pub can_enable_components: &'static [&'static str],
    pub roles: &'static [RoleDef],
    pub max_frame_len: usize,
    #[serde(skip)]
    pub unavailable: &'static [u8],
    #[serde(skip)]
    pub unavailable_event: &'static [u8],
}
/// The host retains bearer material; plugins receive only its database hash.
pub trait SocketHost: Send + Sync {
    fn user_id(&self) -> &str;
    /// Public node actions may share a namespace with a server feature.
    fn node_action_declared(&self, _id: &str) -> bool {
        false
    }
    fn token_hash(&self) -> &str;
    /// Public authenticated lifetime for binding pending layout requests. Test hosts may omit it.
    fn session_incarnation(&self) -> Option<&str> {
        None
    }
    /// Each viewer retains this socket's own live authority, never another login
    /// belonging to the same user. Unimplemented adapters fail closed.
    #[cfg(feature = "native-streams")]
    fn authority(&self) -> Arc<dyn streams::Authority> {
        Arc::new(streams::Denied)
    }
    /// Withdraw the socket projection before aborting its workers.
    #[cfg(feature = "native-streams")]
    fn retire(&self) {}
    /// Resolve only hosts accessible to this authenticated user. A disabled or
    /// unsupported adapter opens no listener and returns no host lease.
    #[cfg(any(test, feature = "native-streams"))]
    fn node<'a>(&'a self, _id: &'a str) -> Operation<'a, Option<Arc<dyn streams::NodeHost>>> {
        Box::pin(async { None })
    }
    /// # Errors
    /// Refuses when socket authority ends or the supplied operation fails.
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>>;
    fn fresh(&self, now: i64) -> Operation<'_, bool>;
    fn live(&self) -> Operation<'_, bool>;
    /// The host checks owner and fresh session authority at a feature switch.
    fn may_configure(&self) -> Operation<'_, bool>;
}
/// Fixed slots include queued subscriptions; admission is bounded independently of workers.
pub const MAX_SUBSCRIPTIONS: usize = 32;
pub type SubscriptionRegistry = Arc<[AtomicU64; MAX_SUBSCRIPTIONS]>;
/// A superseded request or reply cannot inherit a replacement's generation.
#[must_use]
pub fn subscription_current(registry: &SubscriptionRegistry, sub_id: u32, generation: u32) -> bool {
    let stamp = (u64::from(generation) << 32) | u64::from(sub_id);
    generation != 0
        && registry
            .iter()
            .any(|entry| entry.load(Ordering::Acquire) == stamp)
}
/// Withdraw before replacement admission, including refusal of a replacement.
pub fn subscription_withdraw(registry: &SubscriptionRegistry, sub_id: u32) {
    for entry in registry.iter() {
        let stamp = entry.load(Ordering::Acquire);
        if stamp != 0 && stamp & u64::from(u32::MAX) == u64::from(sub_id) {
            entry.store(0, Ordering::Release);
            break;
        }
    }
}
/// The transport treats event JSON as opaque, retaining plugin lifecycle identity.
#[cfg(feature = "socket-host")]
pub struct PluginReply {
    pub plugin_id: &'static str,
    pub epoch: u64,
    pub wire: Bytes,
    /// Optional per-packet authority survives queueing and guards the actual write.
    #[cfg(feature = "native-streams")]
    pub authority: Option<Arc<dyn streams::Authority>>,
}
#[cfg(feature = "socket-host")]
impl PluginReply {
    /// Construct an ordinary reply independently of dependency feature unification.
    #[must_use]
    pub fn new(plugin_id: &'static str, epoch: u64, wire: Bytes) -> Self {
        Self {
            plugin_id,
            epoch,
            wire,
            #[cfg(feature = "native-streams")]
            authority: None,
        }
    }
}
/// The host stamps lifecycle identity; plugin code cannot replace it on the hosted queue.
#[cfg(feature = "socket-host")]
#[derive(Clone)]
pub struct ReplySender {
    tx: mpsc::Sender<PluginReply>,
    plugin_id: &'static str,
    epoch: u64,
    #[cfg(feature = "native-streams")]
    authority: Option<Arc<dyn streams::Authority>>,
}
#[cfg(feature = "socket-host")]
impl ReplySender {
    /// Bind a host-owned queue to one immutable plugin generation.
    #[must_use]
    pub fn new(tx: mpsc::Sender<PluginReply>, plugin_id: &'static str, epoch: u64) -> Self {
        Self {
            tx,
            plugin_id,
            epoch,
            #[cfg(feature = "native-streams")]
            authority: None,
        }
    }
    /// Bind bulk delivery to its originating session and viewer lease.
    #[must_use]
    #[cfg(feature = "native-streams")]
    pub fn with_authority(&self, authority: Arc<dyn streams::Authority>) -> Self {
        Self {
            tx: self.tx.clone(),
            plugin_id: self.plugin_id,
            epoch: self.epoch,
            authority: Some(authority),
        }
    }
    /// Send opaque encoded bytes with the host's lifecycle identity.
    ///
    /// # Errors
    /// Refuses when the browser reply queue has closed.
    pub async fn send(&self, wire: Bytes) -> Result<(), mpsc::error::SendError<PluginReply>> {
        self.tx
            .send(PluginReply {
                plugin_id: self.plugin_id,
                epoch: self.epoch,
                wire,
                #[cfg(feature = "native-streams")]
                authority: self.authority.clone(),
            })
            .await
    }
    /// Retain at most one bulk packet until the transport releases its bytes.
    /// Cancellation drops the completion lease; socket queues stay bounded.
    /// # Errors
    /// Refuses a closed queue or a retired packet lease.
    #[allow(clippy::result_unit_err)] // A packet lease has only live/retired states, like WireLane.
    #[cfg(feature = "native-streams")]
    pub async fn send_and_wait(&self, wire: Bytes) -> Result<(), ()> {
        struct Lease {
            bytes: Bytes,
            done: Option<tokio::sync::oneshot::Sender<()>>,
        }
        impl AsRef<[u8]> for Lease {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for Lease {
            fn drop(&mut self) {
                if let Some(done) = self.done.take() {
                    let _ = done.send(());
                }
            }
        }
        let (done, completed) = tokio::sync::oneshot::channel();
        self.send(Bytes::from_owner(Lease {
            bytes: wire,
            done: Some(done),
        }))
        .await
        .map_err(|_| ())?;
        completed.await.map_err(|_| ())
    }
}
/// Compiled implementations own their work and expose only declared entry points.
#[cfg(feature = "socket-host")]
pub trait Plugin: Send + Sync {
    /// Change admission and withdraw retained resources synchronously before
    /// the host awaits shutdown. Enabling must remain lazy: no task, timer or
    /// listener starts here. Disabling is idempotent and cannot revive work.
    #[cfg(any(test, feature = "global-work"))]
    fn configure(&self, _enabled: bool) {}
    /// Join plugin-owned work after admission and socket workers are withdrawn.
    /// The synchronous hook must already have signalled retirement, so cancelling
    /// this waiter cannot leave work admitted under a disabled feature.
    #[cfg(any(test, feature = "global-work"))]
    fn stopped(&self) -> Operation<'_, ()> {
        Box::pin(async {})
    }
    fn descriptor(&self) -> &'static PluginDescriptor;
    /// Publish committed host authority changes through existing plugin workers.
    /// The host calls this only after durable commit; it creates no idle work.
    fn authority_changed(&self) -> Option<Operation<'_, ()>> {
        None
    }
    /// Optional event-driven work for an admitted node. The runtime owns cancellation.
    fn node_connected(
        &self,
        _channel: Arc<dyn node_channel::NodeChannel>,
    ) -> Option<Operation<'static, ()>> {
        None
    }
    fn run(
        &self,
        host: Arc<dyn SocketHost>,
        requests: mpsc::Receiver<Bytes>,
        replies: ReplySender,
        registry: SubscriptionRegistry,
    ) -> Operation<'static, ()>;
}
/// Check destructive authority at the transaction's commit boundary using SQLite's clock [28].
/// The host and plugins share this query so freshness cannot diverge by adapter.
///
/// # Errors
/// Returns database errors without exposing them to a caller's wire response.
#[cfg(feature = "socket-host")]
pub async fn fresh_session_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token_hash: &str,
    user: &str,
    now: i64,
    fresh_seconds: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>MAX(?,unixepoch()) AND fresh>MAX(?,unixepoch())-? AND fresh<=MAX(?,unixepoch()))")
        .bind(token_hash).bind(user).bind(now).bind(now).bind(fresh_seconds).bind(now).fetch_one(&mut **tx).await
}

/// A contract type name or inline settings schema, serialized as the existing string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SchemaRef(pub &'static str);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Target {
    Global,
    Node,
    Host,
    Session,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum DryRun {
    Unsupported,
    Supported,
    Required,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct EventDef {
    pub id: &'static str,
    pub schema: SchemaRef,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct StreamDef {
    pub id: &'static str,
    pub schema: SchemaRef,
    pub resumable: bool,
    /// Native binary lanes are additive; absent metadata preserves existing JSON.
    #[cfg(any(test, feature = "native-streams"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire: Option<streams::WireStreamDef>,
}
impl StreamDef {
    /// Declare an existing JSON stream independently of native feature unification.
    #[must_use]
    pub const fn json(id: &'static str, schema: SchemaRef, resumable: bool) -> Self {
        Self {
            id,
            schema,
            resumable,
            #[cfg(any(test, feature = "native-streams"))]
            wire: None,
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub enum DefaultValue {
    Null,
    Bool(bool),
    Unsigned(u64),
    Text(&'static str),
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct SettingDefault {
    pub id: &'static str,
    pub value: DefaultValue,
}

/// A confirmed server is a prerequisite, never an implicit node component [201].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Dependency {
    ExistingServer,
    Component(&'static str),
}

impl PluginDescriptor {
    /// Check declaration invariants before exposing a plugin through any adapter.
    /// # Errors
    /// Refuses incompatible versions, duplicate actions, missing instructions,
    /// destructive calls without a required dry run, or implicit server creation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.api != API_VERSION || self.id.is_empty() {
            return Err("The plugin definition is unavailable.");
        }
        if self.can_enable_components.contains(&"server")
            || self.dependencies.contains(&Dependency::Component("server"))
        {
            return Err("A node component cannot create a server.");
        }
        for (index, action) in self.actions.iter().enumerate() {
            if !action.id.starts_with(self.id)
                || action.id.as_bytes().get(self.id.len()) != Some(&b'.')
                || self.actions[..index]
                    .iter()
                    .any(|other| other.id == action.id)
                || action.summary.is_empty()
                || action.instructions.is_empty()
                || action.instructions.iter().any(|step| step.is_empty())
                || action.input.0.is_empty()
                || action.output.0.is_empty()
                || match action.permission {
                    Permission::One(permission) => permission.is_empty(),
                    Permission::Any(permissions) => {
                        permissions.is_empty()
                            || permissions.iter().any(|permission| permission.is_empty())
                    }
                }
                || action.effect == Effect::Destructive && action.dry_run != DryRun::Required
            {
                return Err("The plugin action definition is unavailable.");
            }
        }
        for (index, stream) in self.streams.iter().enumerate() {
            if stream.id.is_empty()
                || stream.schema.0.is_empty()
                || self.streams[..index]
                    .iter()
                    .any(|other| other.id == stream.id)
            {
                return Err("The plugin stream definition is unavailable.");
            }
            #[cfg(any(test, feature = "native-streams"))]
            if let Some(wire) = stream.wire {
                wire.validate()?;
                if self.streams[..index]
                    .iter()
                    .filter_map(|other| other.wire)
                    .any(|other| {
                        other.capability == wire.capability
                            || wire.browser_capability.is_some()
                                && other.browser_capability == wire.browser_capability
                            || other.opening_tag == wire.opening_tag
                            || wire.datagram_tag.is_some()
                                && wire.datagram_tag == other.datagram_tag
                    })
                {
                    return Err("The plugin stream ownership is ambiguous.");
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PluginState {
    On,
    Stopping,
    Off,
}
impl PluginState {
    /// Shared plain state labels for human adapters [202].
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::On => "On",
            Self::Stopping => "Stopping",
            Self::Off => "Off",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PluginStatus {
    pub state: PluginState,
    pub active_work: usize,
}

/// Node lifecycle is distinct from server socket work; both use the same descriptor [201].
/// Trusted core authorizes control calls before invoking a node's plugin.
/// Disable returns only after owned work, sockets and timers have retired [198].
pub trait ComponentPlugin: Send + Sync {
    fn descriptor(&self) -> &'static PluginDescriptor;
    fn status(&self) -> PluginStatus;
    fn set_enabled(&self, enabled: bool) -> PluginOperation<'_, ()>;
}

/// Control failures contain fixed public text, never transport data or login material.
pub type PluginOperation<'a, T> = Operation<'a, Result<T, &'static str>>;

impl ActionDef {
    /// Render the declared steps for operator help without a second copy of the instructions.
    #[must_use]
    pub fn help(&self) -> String {
        use std::fmt::Write;
        let mut help = self.summary.to_owned();
        for (index, step) in self.instructions.iter().enumerate() {
            // Formatting into an owned String cannot fail; only static metadata is included.
            let _ = write!(help, "\n{}. {step}", index + 1);
        }
        help
    }
}

#[cfg(test)]
mod component_tests {
    use super::*;
    const ACTION: ActionDef = ActionDef {
        id: "fixture.read",
        summary: "Read status",
        instructions: &["Read the current status."],
        input: SchemaRef("fixture.empty"),
        output: SchemaRef("fixture.status"),
        target: Target::Node,
        effect: Effect::Read,
        permission: Permission::One("fixture.read"),
        dry_run: DryRun::Unsupported,
        opens: None,
    };
    const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
        id: "fixture",
        api: API_VERSION,
        actions: &[ACTION],
        events: &[],
        streams: &[],
        settings: None,
        defaults: &[],
        dependencies: &[Dependency::ExistingServer],
        can_enable_components: &["ssh"],
        topics: &[],
        roles: &[],
        max_frame_len: 0,
        unavailable: &[],
        unavailable_event: &[],
    };
    #[test]
    fn component_declarations_cannot_create_servers() {
        assert!(DESCRIPTOR.validate().is_ok());
        let invalid = PluginDescriptor {
            can_enable_components: &["server"],
            ..DESCRIPTOR
        };
        assert!(invalid.validate().is_err());
        let invalid = PluginDescriptor {
            dependencies: &[Dependency::Component("server")],
            ..DESCRIPTOR
        };
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn destructive_actions_require_a_dry_run_and_every_action_has_instructions() {
        const DESTRUCTIVE: [ActionDef; 1] = [ActionDef {
            effect: Effect::Destructive,
            ..ACTION
        }];
        const MISSING: [ActionDef; 1] = [ActionDef {
            instructions: &[],
            ..ACTION
        }];
        const REQUIRED: [ActionDef; 1] = [ActionDef {
            effect: Effect::Destructive,
            dry_run: DryRun::Required,
            ..ACTION
        }];
        assert!(
            PluginDescriptor {
                actions: &DESTRUCTIVE,
                ..DESCRIPTOR
            }
            .validate()
            .is_err()
        );
        assert!(
            PluginDescriptor {
                actions: &MISSING,
                ..DESCRIPTOR
            }
            .validate()
            .is_err()
        );
        assert!(
            PluginDescriptor {
                actions: &REQUIRED,
                ..DESCRIPTOR
            }
            .validate()
            .is_ok()
        );
    }
}

/// Maximum encoded node-side plugin action body.
pub const MAX_ACTION_BYTES: usize = 8 * 1024;

/// A nonblocking continuation released only after its successful result frame is written.
/// Dropping it on cancellation must leave the deferred effect unstarted.
pub type AfterReply = Box<dyn FnOnce() + Send + 'static>;

/// Bounded JSON plus an optional handoff that needs its reply transmitted first.
pub struct ActionReply {
    pub json: Vec<u8>,
    pub after_write: Option<AfterReply>,
}

/// A plugin implementation that can be routed without feature-specific agent code.
pub trait AgentPlugin: Send {
    /// Propose an applied server address; disabled components return none.
    fn preferred_server(&self) -> Option<std::net::IpAddr> {
        None
    }
    /// Receive the host's actual authenticated transport status.
    fn set_server_link(&mut self, _link: &server_path::ServerLink) {}
    /// Static action and settings metadata.
    fn descriptor(&self) -> &'static PluginDescriptor;
    /// Machine-only control actions are omitted from human API/MCP/CLI discovery.
    /// They still share the same action definitions and bounded dispatcher.
    fn control_actions(&self) -> &'static [ActionDef] {
        &[]
    }
    /// Drain declared public lifecycle notifications after an action; never private state.
    fn take_events(&mut self) -> Vec<(&'static str, Vec<u8>)> {
        Vec::new()
    }
    /// Opt into generic component CLI commands generated from public actions.
    fn has_cli(&self) -> bool {
        false
    }
    /// A write may present a declared read action's current status afterwards.
    fn human_status_action(&self, _action_id: &str) -> Option<&'static str> {
        None
    }
    /// Present public output inside the plugin, keeping feature fields out of core adapters.
    /// The answer, the aligned detail and the machine form come from one place so they cannot disagree.
    /// # Errors
    /// Rejects malformed public JSON.
    fn present(
        &self,
        _action_id: &str,
        output: &[u8],
        _width: usize,
    ) -> Result<present::Presented, PluginError> {
        let value: serde_json::Value =
            serde_json::from_slice(output).map_err(|_| PluginError::Rejected)?;
        Ok(present::Presented {
            tone: present::Tone::Good,
            message: String::new(),
            body: serde_json::to_string_pretty(&value).map_err(|_| PluginError::Rejected)? + "\n",
            next: Vec::new(),
            data: value,
        })
    }
    /// Validate and execute one declared action.
    /// # Errors
    /// Returns a bounded plugin error for a rejected action, unknown action, or oversized body.
    fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError>;
    /// Optional owned asynchronous action. Returning a static future releases
    /// registry admission before native I/O; existing synchronous plugins keep
    /// their behavior and deferred-after-write contract.
    #[cfg(any(test, feature = "native-streams"))]
    fn call_async(
        &mut self,
        _action_id: &str,
        _input: &[u8],
    ) -> Option<Operation<'static, Result<ActionReply, PluginError>>> {
        None
    }
    /// Compiled native dispatch is separate from runtime preparation. A disabled
    /// provider advertises its declaration but refuses effects in its own state.
    #[cfg(any(test, feature = "native-streams"))]
    fn wire_provider(&self) -> Option<Arc<dyn streams::WireProvider>> {
        None
    }
    /// Host-owned negotiated native capabilities, updated once per admitted
    /// connection. Zero withdraws availability on mux-only transport or loss.
    #[cfg(any(test, feature = "native-streams"))]
    fn transport_capabilities(&mut self, _capabilities: u64) {}
    /// Prepare an effect that can interrupt the current transport after its reply.
    /// # Errors
    /// Returns the same bounded dispatch failures as `call`.
    fn call_with_reply(
        &mut self,
        action_id: &str,
        input: &[u8],
    ) -> Result<ActionReply, PluginError> {
        self.call(action_id, input).map(|json| ActionReply {
            json,
            after_write: None,
        })
    }
    /// Apply a compiled resource policy to a core transport action.
    /// # Errors
    /// Returns a fixed public refusal without implementation details.
    fn admit(
        &self,
        _action_id: &str,
        _context: admission::NodeContext,
    ) -> Result<(), admission::OpenRefusal> {
        Ok(())
    }
    /// Refresh host-owned facts only when a control action requests them.
    fn update_context(&mut self, _context: admission::NodeContext) {}
}

/// A bounded registry that dispatches actions only to declared plugin handlers.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Box<dyn AgentPlugin>>,
    action_ids: HashSet<&'static str>,
    plugin_ids: HashSet<&'static str>,
}

impl PluginRegistry {
    /// Publish current negotiated transport availability without packet-owned
    /// routing or per-frame provider callbacks.
    #[cfg(any(test, feature = "native-streams"))]
    pub fn transport_capabilities(&mut self, capabilities: u64) {
        for plugin in &mut self.plugins {
            plugin.transport_capabilities(capabilities);
        }
    }
    /// Collect immutable native handlers without retaining the mutable registry.
    /// # Errors
    /// Refuses undeclared providers and ambiguous capabilities/opening tags.
    #[cfg(any(test, feature = "native-streams"))]
    pub fn wire_providers(&self) -> Result<Vec<streams::WireProviderEntry>, PluginError> {
        let mut entries: Vec<streams::WireProviderEntry> = Vec::new();
        for plugin in &self.plugins {
            let Some(provider) = plugin.wire_provider() else {
                continue;
            };
            let descriptor = plugin.descriptor();
            descriptor
                .validate()
                .map_err(|_| PluginError::InvalidDescriptor)?;
            let mut declared = false;
            for definition in descriptor
                .streams
                .iter()
                .filter_map(|stream| stream.wire.as_ref())
            {
                if entries.iter().any(|entry| {
                    entry.definition.capability == definition.capability
                        || definition.browser_capability.is_some()
                            && entry.definition.browser_capability == definition.browser_capability
                        || entry.definition.opening_tag == definition.opening_tag
                        || definition.datagram_tag.is_some()
                            && definition.datagram_tag == entry.definition.datagram_tag
                }) {
                    return Err(PluginError::InvalidDescriptor);
                }
                entries.push(streams::WireProviderEntry {
                    definition,
                    provider: provider.clone(),
                });
                declared = true;
            }
            if !declared {
                return Err(PluginError::InvalidDescriptor);
            }
        }
        Ok(entries)
    }

    /// Prepare a bounded owned operation, leaving the registry free for other
    /// control traffic while the provider waits on native I/O.
    /// # Errors
    /// Refuses undeclared actions and oversized inputs before provider dispatch.
    #[cfg(any(test, feature = "native-streams"))]
    pub fn begin_call(
        &mut self,
        action_id: &str,
        input: &[u8],
    ) -> Result<Operation<'static, Result<ActionReply, PluginError>>, PluginError> {
        if input.len() > MAX_ACTION_BYTES {
            return Err(PluginError::MessageTooLarge);
        }
        let plugin = self
            .plugins
            .iter_mut()
            .find(|plugin| {
                plugin
                    .descriptor()
                    .actions
                    .iter()
                    .chain(plugin.control_actions())
                    .any(|action| action.id == action_id)
            })
            .ok_or(PluginError::UnknownAction)?;
        let operation = if let Some(operation) = plugin.call_async(action_id, input) {
            operation
        } else {
            let reply = plugin.call_with_reply(action_id, input)?;
            Box::pin(async move { Ok(reply) })
        };
        Ok(Box::pin(async move {
            let reply = operation.await?;
            if reply.json.len() > MAX_ACTION_BYTES {
                return Err(PluginError::MessageTooLarge);
            }
            Ok(reply)
        }))
    }
    /// Consult resource policies without selecting a feature in core dispatch.
    /// # Errors
    /// Returns the first policy refusal.
    pub fn admit(
        &self,
        action_id: &str,
        context: admission::NodeContext,
    ) -> Result<(), admission::OpenRefusal> {
        for plugin in &self.plugins {
            plugin.admit(action_id, context)?;
        }
        Ok(())
    }

    /// Publish trusted counts before an on-request fact read.
    pub fn update_context(&mut self, context: admission::NodeContext) {
        for plugin in &mut self.plugins {
            plugin.update_context(context);
        }
    }

    /// Resolve component proposals without choosing between conflicting routes.
    /// # Errors
    /// Refuses contradictory server addresses rather than depending on registration order.
    pub fn preferred_server(&self) -> Result<Option<std::net::IpAddr>, PluginError> {
        let mut selected = None;
        for candidate in self
            .plugins
            .iter()
            .filter_map(|plugin| plugin.preferred_server())
        {
            if selected.is_some_and(|address| address != candidate) {
                return Err(PluginError::Rejected);
            }
            selected = Some(candidate);
        }
        Ok(selected)
    }
    /// Publish transport status without exposing identity material to plugins.
    pub fn set_server_link(&mut self, link: &server_path::ServerLink) {
        for plugin in &mut self.plugins {
            plugin.set_server_link(link);
        }
    }
    /// Registers one plugin whose descriptor is internally consistent.
    /// # Errors
    /// Rejects unsupported API versions, duplicate ids, or actions outside the plugin namespace.
    pub fn register(&mut self, plugin: Box<dyn AgentPlugin>) -> Result<(), PluginError> {
        let descriptor = plugin.descriptor();
        let controls = PluginDescriptor {
            actions: plugin.control_actions(),
            ..*descriptor
        };
        let mut seen = HashSet::new();
        if descriptor.validate().is_err()
            || controls.validate().is_err()
            || descriptor.api != API_VERSION
            || self.plugin_ids.contains(descriptor.id)
            || descriptor
                .actions
                .iter()
                .chain(plugin.control_actions())
                .any(|action| {
                    !seen.insert(action.id)
                        || !action.id.starts_with(&format!("{}.", descriptor.id))
                        || self.action_ids.contains(action.id)
                })
        {
            return Err(PluginError::InvalidDescriptor);
        }
        self.plugin_ids.insert(descriptor.id);
        self.action_ids.extend(
            descriptor
                .actions
                .iter()
                .chain(plugin.control_actions())
                .map(|action| action.id),
        );
        self.plugins.push(plugin);
        Ok(())
    }

    /// Drain only declared bounded events, rejecting a plugin's invalid notification.
    /// # Errors
    /// Rejects undeclared identifiers, invalid JSON or oversized envelopes.
    pub fn events(&mut self) -> Result<Vec<Vec<u8>>, PluginError> {
        let mut events = Vec::new();
        for plugin in &mut self.plugins {
            let descriptor = plugin.descriptor();
            for (id, body) in plugin.take_events() {
                if body.len() > 1024 || !descriptor.events.iter().any(|event| event.id == id) {
                    return Err(PluginError::Rejected);
                }
                let value: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|_| PluginError::Rejected)?;
                let envelope=serde_json::to_vec(&serde_json::json!({"type":"plugin.event","plugin":descriptor.id,"id":id,"value":value})).map_err(|_|PluginError::Rejected)?;
                if envelope.len() > 1024 {
                    return Err(PluginError::MessageTooLarge);
                }
                events.push(envelope);
            }
        }
        Ok(events)
    }
    /// Pure CLI declarations; constructing commands never invokes an action.
    #[must_use]
    pub fn cli_descriptors(&self) -> Vec<&'static PluginDescriptor> {
        self.plugins
            .iter()
            .filter(|plugin| plugin.has_cli())
            .map(|plugin| plugin.descriptor())
            .collect()
    }
    /// Resolve an optional public read after a successful operator write.
    /// # Errors
    /// Refuses unknown, machine-only, or non-read follow-up actions.
    pub fn human_status_action(
        &self,
        action_id: &str,
    ) -> Result<Option<&'static str>, PluginError> {
        let plugin = self.public_plugin(action_id)?;
        let Some(id) = plugin.human_status_action(action_id) else {
            return Ok(None);
        };
        if !plugin
            .descriptor()
            .actions
            .iter()
            .any(|action| action.id == id && action.effect == Effect::Read)
        {
            return Err(PluginError::Rejected);
        }
        Ok(Some(id))
    }
    /// Present a bounded public reply with the implementation's pure presenter.
    /// # Errors
    /// Refuses private control actions, oversized replies and malformed presentation data.
    pub fn present(
        &self,
        action_id: &str,
        output: &[u8],
        width: usize,
    ) -> Result<present::Presented, PluginError> {
        if output.len() > MAX_ACTION_BYTES {
            return Err(PluginError::MessageTooLarge);
        }
        self.public_plugin(action_id)?
            .present(action_id, output, width)
    }
    fn public_plugin(&self, action_id: &str) -> Result<&dyn AgentPlugin, PluginError> {
        self.plugins
            .iter()
            .find(|plugin| {
                plugin
                    .descriptor()
                    .actions
                    .iter()
                    .any(|action| action.id == action_id)
            })
            .map(std::convert::AsRef::as_ref)
            .ok_or(PluginError::UnknownAction)
    }
    /// Dispatch only public node actions from a local operator surface.
    /// # Errors
    /// Machine control actions remain available only through the admitted channel adapter.
    pub fn call_public(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        if !self.plugins.iter().any(|plugin| {
            plugin
                .descriptor()
                .actions
                .iter()
                .any(|action| action.id == action_id)
        }) {
            return Err(PluginError::UnknownAction);
        }
        self.call(action_id, input)
    }

    /// Executes one declared action while bounding both directions of its JSON body.
    /// # Errors
    /// Returns a bounded error for an unknown action, oversized message, or plugin rejection.
    pub fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        let reply = self.call_with_reply(action_id, input)?;
        if reply.after_write.is_some() {
            return Err(PluginError::Rejected);
        }
        Ok(reply.json)
    }

    /// Dispatch with a continuation owned by the transport writer until transmission.
    /// # Errors
    /// Refuses undeclared actions, oversized bodies and rejected plugin calls.
    pub fn call_with_reply(
        &mut self,
        action_id: &str,
        input: &[u8],
    ) -> Result<ActionReply, PluginError> {
        if input.len() > MAX_ACTION_BYTES {
            return Err(PluginError::MessageTooLarge);
        }
        let plugin = self.plugins.iter_mut().find(|plugin| {
            plugin
                .descriptor()
                .actions
                .iter()
                .chain(plugin.control_actions())
                .any(|action| action.id == action_id)
        });
        let Some(plugin) = plugin else {
            return Err(PluginError::UnknownAction);
        };
        let output = plugin.call_with_reply(action_id, input)?;
        if output.json.len() > MAX_ACTION_BYTES {
            return Err(PluginError::MessageTooLarge);
        }
        Ok(output)
    }
}

/// Fixed-size plugin call failures safe to return over the control protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginError {
    /// No registered plugin declared the requested action.
    UnknownAction,
    /// A descriptor conflicts with the current API or registry.
    InvalidDescriptor,
    /// Input or output exceeds the API bound.
    MessageTooLarge,
    /// The plugin rejected a validly routed action.
    Rejected,
}

#[cfg(test)]
mod tests;

/// Whether commands for components that are not built yet are compiled in (feature `placeholders`).
/// Default builds leave them out: they are hidden anyway (D299), and their text costs binary size (D243).
pub const PLACEHOLDERS: bool = cfg!(feature = "placeholders");

/// The placeholder actions `build` makes, or none in a default build. The closure is never
/// called then, so its strings and schemas are not linked into the binary.
#[must_use]
pub fn placeholders<I: IntoIterator<Item = ActionDefinition>>(
    build: impl FnOnce() -> I,
) -> Vec<ActionDefinition> {
    if PLACEHOLDERS {
        build().into_iter().collect()
    } else {
        Vec::new()
    }
}

/// Adapt hosted action metadata into the shared CLI registry without duplicating routes.
///
/// Hosted actions require the server's authenticated transport. The CLI currently
/// has no device-session adapter, so these paths report unavailable rather than
/// bypassing permissions or changing a fresh process's non-durable plugin state.
impl PluginDescriptor {
    /// Register the descriptor with its original hosted schemas and authority.
    #[must_use]
    pub fn cli_plugin(&self, target: ActionTarget) -> PluginDefinition {
        PluginDefinition::new(
            self.id,
            format!("{} plugin actions.", self.id),
            self.actions.iter().map(|source| {
                let permission = match source.permission {
                    Permission::One(permission) => permission.to_owned(),
                    Permission::Any(permissions) => permissions.first().copied().unwrap_or("").to_owned(),
                };
                let effect = match source.effect {
                    Effect::Read => ActionEffect::Read,
                    Effect::Write => ActionEffect::Write,
                    Effect::Destructive => ActionEffect::Destructive,
                };
                let destructive = effect == ActionEffect::Destructive;
                let mut action = ActionDefinition::new(
                    source.id.split('.'),
                    source.summary,
                    format!("Use this action through an authenticated {} plugin session.", self.id),
                    source.instructions.iter().copied(),
                    JsonSchema::object(
                        [("input_file".to_owned(), JsonSchema::string(format!(
                            "File containing the action JSON body described by {}.", source.input.0
                        )))],
                        std::iter::empty(),
                    ),
                    JsonSchema::command_result(),
                    ActionContract::new(target, effect, permission, if destructive {
                        CliDryRun::Required
                    } else {
                        CliDryRun::Unsupported
                    }),
                ).not_available_yet().with_safety(SafetyNotes {
                    destructive,
                    dry_run_first: destructive,
                    notes: vec!["An authenticated CLI device-session adapter is not available yet; use the server UI. The hosted descriptor below defines the exact wire schemas and permission alternatives.".to_owned()],
                });
                if let Permission::Any(permissions) = source.permission {
                    action.contract.permission = ActionPermission::Any {
                        any: permissions.iter().map(|permission| (*permission).to_owned()).collect(),
                    };
                }
                action.hosted = Some(*source);
                action
            }),
        )
    }
}
