//! Content-free, opt-in stage receipts for app-window measurements [D208,D232,#146].
//!
//! Monotonic timestamps share one process-local origin. Its wall-clock bracket
//! permits clock alignment with a stated uncertainty; different hosts' raw
//! monotonic values are never subtracted. Disabled measurements read no clock,
//! allocate no packet state and start no task or timer.
use std::{
    sync::OnceLock,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

struct Clock {
    origin: Instant,
    pid: u32,
}
static CLOCK: OnceLock<Option<Clock>> = OnceLock::new();

fn clock() -> Option<&'static Clock> {
    CLOCK
        .get_or_init(|| {
            std::env::var_os("INFRATERNAL_DESKTOP_MEASURE")?;
            let pid = std::process::id();
            let before = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_nanos();
            let origin = Instant::now();
            let after = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_nanos();
            eprintln!(
                "METRIC app_window_clock pid={pid} wall_before_ns={before} wall_after_ns={after}"
            );
            Some(Clock { origin, pid })
        })
        .as_ref()
}

#[cfg(feature = "server")]
pub(crate) fn enabled() -> bool {
    clock().is_some()
}

pub(crate) fn record(stage: &'static str, capture_ns: u64, sequence: u64, bytes: usize) {
    if let Some(clock) = clock() {
        let at = clock.origin.elapsed().as_nanos();
        eprintln!(
            "METRIC app_window_stage pid={} stage={stage} at_ns={at} capture_ns={capture_ns} sequence={sequence} bytes={bytes}",
            clock.pid
        );
    }
}

#[cfg(any(feature = "source", feature = "server"))]
pub(crate) fn frame(stage: &'static str, frame: &crate::media::Video) {
    record(stage, frame.capture_ns, frame.sequence, frame.bytes.len());
}

pub(crate) fn control(stage: &'static str, kind: crate::protocol::Kind) {
    if let Some(clock) = clock() {
        let at = clock.origin.elapsed().as_nanos();
        eprintln!(
            "METRIC app_window_control pid={} stage={stage} at_ns={at} kind={}",
            clock.pid, kind as u8
        );
    }
}

/// Decorate the existing per-viewer authority only during measurement. The
/// operation still crosses its original authority checks, and these timestamps
/// bracket the actual socket operation rather than release of a queued packet.
#[cfg(feature = "server")]
pub(crate) fn delivery(
    inner: std::sync::Arc<dyn infraternal_plugin_api::streams::Authority>,
    frame: &crate::media::Video,
) -> std::sync::Arc<dyn infraternal_plugin_api::streams::Authority> {
    use infraternal_plugin_api::{Operation, streams::Authority};
    struct Delivery {
        inner: std::sync::Arc<dyn Authority>,
        capture_ns: u64,
        sequence: u64,
        bytes: usize,
    }
    impl Authority for Delivery {
        fn permits(&self) -> bool {
            self.inner.permits()
        }
        fn cancelled(&self) -> Operation<'_, ()> {
            self.inner.cancelled()
        }
        fn authorized<'a>(
            &'a self,
            operation: Operation<'a, Result<(), ()>>,
        ) -> Operation<'a, Result<(), ()>> {
            self.inner.authorized(Box::pin(async move {
                record(
                    "browser_socket_begin",
                    self.capture_ns,
                    self.sequence,
                    self.bytes,
                );
                let result = operation.await;
                record(
                    if result.is_ok() {
                        "browser_socket_end"
                    } else {
                        "browser_socket_refused"
                    },
                    self.capture_ns,
                    self.sequence,
                    self.bytes,
                );
                result
            }))
        }
    }
    std::sync::Arc::new(Delivery {
        inner,
        capture_ns: frame.capture_ns,
        sequence: frame.sequence,
        bytes: frame.bytes.len(),
    })
}

/// The native companion prefixes every encoded unit with its capture timestamp.
/// Use that identity across the helper's threads without copying video bytes.
#[cfg(all(feature = "desktop", any(target_os = "macos", test)))]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn helper_frame(stage: &'static str, body: &[u8]) {
    let capture_ns = body
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(0, u64::from_be_bytes);
    record(stage, capture_ns, 0, body.len());
}
