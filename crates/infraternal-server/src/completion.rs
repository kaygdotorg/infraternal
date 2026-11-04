//! Retain owned database work and its admission bounds through waiter cancellation (#240, D243).

/// Discard the result after cancellation, reusing the existing unit-output task (D243).
fn detach<F>(query: std::pin::Pin<Box<F>>, runtime: Option<tokio::runtime::Handle>)
where
    F: std::future::Future + Send + 'static + ?Sized,
{
    let detached: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> =
        Box::pin(async move {
            let _ = query.await;
        });
    if let Some(runtime) = runtime {
        runtime.spawn(detached);
    } else {
        tokio::spawn(detached);
    }
}

/// Keep owned work alive when its waiter is cancelled; ordinary completion stays inline.
pub(crate) struct DetachOnDrop<F: std::future::Future + Send + 'static + ?Sized>
where
    F::Output: Send,
{
    operation: Option<std::pin::Pin<Box<F>>>,
    runtime: Option<tokio::runtime::Handle>,
}

impl<F: std::future::Future + Send + 'static + ?Sized> DetachOnDrop<F>
where
    F::Output: Send,
{
    /// Wraps `operation`. It runs inline while polled; if the wrapper is dropped before
    /// it finishes, the operation is handed to a runtime task instead of being cancelled.
    pub(crate) fn new(operation: std::pin::Pin<Box<F>>) -> Self {
        Self {
            operation: Some(operation),
            runtime: None,
        }
    }

    /// Retain the scheduling context when a public waiter can be dropped on another thread.
    pub(crate) fn on_runtime(mut self, runtime: tokio::runtime::Handle) -> Self {
        self.runtime = Some(runtime);
        self
    }
}

impl<F: std::future::Future + Send + 'static + ?Sized> std::future::Future for DetachOnDrop<F>
where
    F::Output: Send,
{
    type Output = F::Output;

    /// Polls the wrapped operation. Once it has produced its output, polling again stays `Pending` forever.
    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let Some(query) = this.operation.as_mut() else {
            return std::task::Poll::Pending;
        };
        match std::future::Future::poll(query.as_mut(), context) {
            std::task::Poll::Ready(result) => {
                this.operation.take();
                std::task::Poll::Ready(result)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<F: std::future::Future + Send + 'static + ?Sized> Drop for DetachOnDrop<F>
where
    F::Output: Send,
{
    /// Hands unfinished work to [`detach`] so cancelling a waiter never aborts the database work or frees its admission permits.
    fn drop(&mut self) {
        if let Some(query) = self.operation.take() {
            // Ownership, including any admission permits, stays with the operation
            // until it completes. Dropping its waiter must not release that bound.
            detach(query, self.runtime.take());
        }
    }
}
