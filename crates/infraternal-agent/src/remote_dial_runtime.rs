//! Owns Quinn's existing Tokio drivers for one outgoing attempt, so TCP fallback cancels losing UDP drain timers [64][130], #78.

use quinn::{AsyncTimer, AsyncUdpSocket, Runtime};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
};

/// Cancellation belongs to the dial attempt, rather than to detached Quinn tasks.
/// A fresh endpoint on reconnect prevents cancellation from affecting a winner.
pub(super) struct DialRuntime(Arc<Drivers>);
impl DialRuntime {
    pub(super) fn new() -> Self {
        Self(Arc::new(Drivers(Mutex::new(Vec::new()))))
    }
    pub(super) fn runtime(&self) -> Arc<dyn Runtime> {
        self.0.clone()
    }
}
impl Drop for DialRuntime {
    fn drop(&mut self) {
        // A prior panic cannot invalidate owned cancellation handles. Recover
        // the vector so unwinding still cancels every detached UDP driver.
        for task in self
            .0
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
    }
}

#[derive(Debug)]
struct Drivers(Mutex<Vec<tokio::task::JoinHandle<()>>>);
impl Runtime for Drivers {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn AsyncTimer>> {
        quinn::TokioRuntime.new_timer(instant)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        // Each endpoint makes one outgoing connection. Retire completed handles
        // before retaining the next driver; the session cannot grow this list.
        let mut tasks = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.is_finished());
        tasks.push(tokio::spawn(future));
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}
