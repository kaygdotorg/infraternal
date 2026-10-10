//! Shares one descriptor between server socket work and node component lifecycle [15,16,28,198,201].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod admission;
pub mod channel;
pub mod routing;

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
#[derive(Clone, Copy, Debug, Serialize)]
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
#[derive(Clone, Copy, Debug, Serialize)]
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
    fn token_hash(&self) -> &str;
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
pub struct PluginReply {
    pub plugin_id: &'static str,
    pub epoch: u64,
    pub wire: Bytes,
}
/// The host stamps lifecycle identity; plugin code cannot replace it on the hosted queue.
#[derive(Clone)]
pub struct ReplySender {
    tx: mpsc::Sender<PluginReply>,
    plugin_id: &'static str,
    epoch: u64,
}
impl ReplySender {
    /// Bind a host-owned queue to one immutable plugin generation.
    #[must_use]
    pub fn new(tx: mpsc::Sender<PluginReply>, plugin_id: &'static str, epoch: u64) -> Self {
        Self {
            tx,
            plugin_id,
            epoch,
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
            })
            .await
    }
}
/// Compiled implementations own their work and expose only declared entry points.
pub trait Plugin: Send + Sync {
    fn descriptor(&self) -> &'static PluginDescriptor;
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
#[derive(Clone, Copy, Debug, Serialize)]
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

/// A plugin implementation that can be routed without feature-specific agent code.
pub trait AgentPlugin: Send {
    /// Static action and settings metadata.
    fn descriptor(&self) -> &'static PluginDescriptor;
    /// Validate and execute one declared action.
    /// # Errors
    /// Returns a bounded plugin error for a rejected action, unknown action, or oversized body.
    fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError>;
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
    /// Registers one plugin whose descriptor is internally consistent.
    /// # Errors
    /// Rejects unsupported API versions, duplicate ids, or actions outside the plugin namespace.
    pub fn register(&mut self, plugin: Box<dyn AgentPlugin>) -> Result<(), PluginError> {
        let descriptor = plugin.descriptor();
        if descriptor.api != API_VERSION
            || self.plugin_ids.contains(descriptor.id)
            || descriptor.actions.iter().any(|action| {
                !action.id.starts_with(&format!("{}.", descriptor.id))
                    || self.action_ids.contains(action.id)
            })
        {
            return Err(PluginError::InvalidDescriptor);
        }
        self.plugin_ids.insert(descriptor.id);
        self.action_ids
            .extend(descriptor.actions.iter().map(|action| action.id));
        self.plugins.push(plugin);
        Ok(())
    }

    /// Executes one declared action while bounding both directions of its JSON body.
    /// # Errors
    /// Returns a bounded error for an unknown action, oversized message, or plugin rejection.
    pub fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        if input.len() > MAX_ACTION_BYTES {
            return Err(PluginError::MessageTooLarge);
        }
        let plugin = self.plugins.iter_mut().find(|plugin| {
            plugin
                .descriptor()
                .actions
                .iter()
                .any(|action| action.id == action_id)
        });
        let Some(plugin) = plugin else {
            return Err(PluginError::UnknownAction);
        };
        let output = plugin.call(action_id, input)?;
        if output.len() > MAX_ACTION_BYTES {
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
