//! Descriptors and bounded socket interfaces for compiled plugins [15,16,28,198,201].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

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
#[derive(Clone, Copy, Serialize)]
pub struct ActionDef {
    pub id: &'static str,
    pub summary: &'static str,
    pub instructions: &'static [&'static str],
    pub input: &'static str,
    pub output: &'static str,
    pub permission: Permission,
    pub effect: Effect,
}
/// Read visibility may follow any management action without introducing a view-only role [187].
#[derive(Clone, Copy, Serialize)]
pub enum Permission {
    One(&'static str),
    Any(&'static [&'static str]),
}
/// A server feature and a node component share an id but cannot create each other.
#[derive(Serialize)]
pub struct RoleDef {
    pub id: &'static str,
    pub requires: &'static [&'static str],
    pub default_enabled: bool,
}
/// Pure metadata: inspecting a disabled plugin starts no work.
#[derive(Serialize)]
pub struct PluginDescriptor {
    pub id: &'static str,
    pub api: u16,
    pub actions: &'static [ActionDef],
    pub topics: &'static [&'static str],
    pub settings: &'static str,
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
}

/// A bounded registry that dispatches actions only to declared plugin handlers.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Box<dyn AgentPlugin>>,
    action_ids: HashSet<&'static str>,
    plugin_ids: HashSet<&'static str>,
}

impl PluginRegistry {
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
