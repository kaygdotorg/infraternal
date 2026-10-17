//! Shares scheduler and drop code for bounded SSH setup and helper tasks (D243, D255).

/// Erase each cold future type so helpers reuse one scheduler implementation.
/// The caller keeps its cancellation handle; terminal frames do not cross this boundary.
pub(crate) fn spawn(
    work: impl std::future::Future<Output = ()> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    let work: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> = Box::pin(work);
    tokio::spawn(work)
}
