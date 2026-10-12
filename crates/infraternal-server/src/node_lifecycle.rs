//! Owns plugin workers for authenticated nodes under the same cancellation boundary as socket workers [198].
use super::{Entry, PluginError, PluginRuntime, Task};
use infraternal_plugin_api::node_channel::NodeChannel;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, atomic::Ordering},
};
#[derive(Default)]
pub(super) struct Nodes {
    channels: HashMap<String, Arc<dyn NodeChannel>>,
    work: HashMap<(String, &'static str), Arc<Task>>,
}
impl PluginRuntime {
    /// Attach only an admitted host capability; replacing a channel joins its previous workers.
    /// # Errors
    /// Refuses poisoned worker ownership and retires the partially attached channel.
    pub async fn attach_node(&self, channel: Arc<dyn NodeChannel>) -> Result<(), PluginError> {
        let _switch = self.inner.switches.lock().await;
        let mut nodes = self.inner.nodes.lock().await;
        let id = channel.id().to_owned();
        stop(&mut nodes, &id).await;
        nodes.channels.insert(id.clone(), channel.clone());
        for entry in &self.inner.entries {
            if let Err(error) = start(&mut nodes, entry, channel.clone()) {
                stop(&mut nodes, &id).await;
                nodes.channels.remove(&id);
                return Err(error);
            }
        }
        Ok(())
    }
    /// Retiring an old admission cannot detach a newer channel for the same host.
    #[cfg(any(feature = "remote", test))]
    pub(crate) async fn detach_node_if(&self, channel: &Arc<dyn NodeChannel>) {
        let _switch = self.inner.switches.lock().await;
        let mut nodes = self.inner.nodes.lock().await;
        if nodes
            .channels
            .get(channel.id())
            .is_some_and(|current| Arc::ptr_eq(current, channel))
        {
            nodes.channels.remove(channel.id());
            stop(&mut nodes, channel.id()).await;
        }
    }
    pub(super) async fn start_nodes(&self, entry: &Arc<Entry>) -> Result<(), PluginError> {
        let mut nodes = self.inner.nodes.lock().await;
        let channels: Vec<_> = nodes.channels.values().cloned().collect();
        for channel in channels {
            start(&mut nodes, entry, channel)?;
        }
        Ok(())
    }
}
fn start(
    nodes: &mut Nodes,
    entry: &Arc<Entry>,
    channel: Arc<dyn NodeChannel>,
) -> Result<(), PluginError> {
    if !entry.enabled.load(Ordering::Acquire) {
        return Ok(());
    }
    let id = channel.id().to_owned();
    let Some(work) = entry.plugin.node_connected(channel) else {
        return Ok(());
    };
    let mut tasks = entry
        .tasks
        .lock()
        .map_err(|_| PluginError::RoleUnavailable)?;
    tasks.retain(|task| {
        task.handle
            .lock()
            .is_ok_and(|handle| handle.as_ref().is_some_and(|handle| !handle.is_finished()))
    });
    let task = Arc::new(Task {
        handle: Mutex::new(Some(tokio::spawn(work))),
    });
    tasks.push(task.clone());
    nodes.work.insert((id, entry.plugin.descriptor().id), task);
    Ok(())
}
async fn stop(nodes: &mut Nodes, id: &str) {
    let keys: Vec<_> = nodes
        .work
        .keys()
        .filter(|(node, _)| node == id)
        .cloned()
        .collect();
    let mut handles = Vec::new();
    for key in keys {
        if let Some(task) = nodes.work.remove(&key)
            && let Ok(mut handle) = task.handle.lock()
            && let Some(handle) = handle.take()
        {
            handle.abort();
            handles.push(handle);
        }
    }
    for handle in handles {
        let _ = handle.await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use infraternal_plugin_api::{
        Operation, Plugin, PluginDescriptor, ReplySender, SocketHost, SubscriptionRegistry,
    };
    use std::sync::atomic::AtomicUsize;
    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    struct Counting {
        active: Arc<AtomicUsize>,
        started: Arc<tokio::sync::Notify>,
    }
    const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
        id: "fixture",
        api: infraternal_plugin_api::API_VERSION,
        actions: &[],
        topics: &[],
        settings: None,
        events: &[],
        streams: &[],
        defaults: &[],
        dependencies: &[],
        can_enable_components: &[],
        roles: &[infraternal_plugin_api::RoleDef {
            id: "server",
            requires: &["server"],
            default_enabled: true,
        }],
        max_frame_len: 8192,
        unavailable: b"{}",
        unavailable_event: b"{}",
    };
    impl Plugin for Counting {
        fn descriptor(&self) -> &'static PluginDescriptor {
            &DESCRIPTOR
        }
        fn node_connected(&self, _: Arc<dyn NodeChannel>) -> Option<Operation<'static, ()>> {
            let active = self.active.clone();
            let started = self.started.clone();
            Some(Box::pin(async move {
                active.fetch_add(1, Ordering::SeqCst);
                let _guard = Guard(active);
                started.notify_one();
                std::future::pending::<()>().await;
            }))
        }
        fn run(
            &self,
            _: Arc<dyn SocketHost>,
            _: tokio::sync::mpsc::Receiver<bytes::Bytes>,
            _: ReplySender,
            _: SubscriptionRegistry,
        ) -> Operation<'static, ()> {
            Box::pin(async {})
        }
    }
    struct Channel;
    impl NodeChannel for Channel {
        fn id(&self) -> &'static str {
            "host"
        }
        fn observed_ip(&self) -> std::net::IpAddr {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        }
        fn is_server(&self) -> bool {
            false
        }
        fn changes(&self) -> tokio::sync::watch::Receiver<()> {
            tokio::sync::watch::channel(()).1
        }
        fn call(
            &self,
            _: &str,
            _: Vec<u8>,
        ) -> infraternal_plugin_api::PluginOperation<'_, Vec<u8>> {
            Box::pin(async { Err("unused fixture call") })
        }
    }
    async fn started(notify: &tokio::sync::Notify) {
        tokio::time::timeout(std::time::Duration::from_secs(5), notify.notified())
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn disabling_replacement_and_retirement_join_the_correct_node_worker() {
        let active = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(tokio::sync::Notify::new());
        let runtime = PluginRuntime::new(
            vec![Arc::new(Counting {
                active: active.clone(),
                started: notify.clone(),
            })],
            "server",
        );
        assert_eq!(active.load(Ordering::SeqCst), 0);
        let old: Arc<dyn NodeChannel> = Arc::new(Channel);
        runtime.attach_node(old.clone()).await.unwrap();
        started(&notify).await;
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.active_workers("fixture"), 1);
        runtime.set_enabled("fixture", false).await.unwrap();
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.active_workers("fixture"), 0);
        runtime.set_enabled("fixture", true).await.unwrap();
        started(&notify).await;
        assert_eq!(active.load(Ordering::SeqCst), 1);
        let new: Arc<dyn NodeChannel> = Arc::new(Channel);
        runtime.attach_node(new.clone()).await.unwrap();
        started(&notify).await;
        assert_eq!(active.load(Ordering::SeqCst), 1);
        runtime.detach_node_if(&old).await;
        assert_eq!(active.load(Ordering::SeqCst), 1);
        runtime.detach_node_if(&new).await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.active_workers("fixture"), 0);
    }
}
