//! Retain owned database work and its admission bounds through waiter cancellation (#240, D243).

/// Discard the result after cancellation, reusing the existing unit-output task (D243).
fn detach<F>(query: std::pin::Pin<Box<F>>)
where
    F: std::future::Future + Send + 'static + ?Sized,
{
    let detached: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> =
        Box::pin(async move {
            let _ = query.await;
        });
    tokio::spawn(detached);
}

/// Keep owned work alive when its waiter is cancelled; ordinary completion stays inline.
pub(crate) struct DetachOnDrop<F: std::future::Future + Send + 'static + ?Sized>(
    Option<std::pin::Pin<Box<F>>>,
)
where
    F::Output: Send;

impl<F: std::future::Future + Send + 'static + ?Sized> DetachOnDrop<F>
where
    F::Output: Send,
{
    pub(crate) fn new(operation: std::pin::Pin<Box<F>>) -> Self {
        Self(Some(operation))
    }
}

impl<F: std::future::Future + Send + 'static + ?Sized> std::future::Future for DetachOnDrop<F>
where
    F::Output: Send,
{
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let Some(query) = this.0.as_mut() else {
            return std::task::Poll::Pending;
        };
        match std::future::Future::poll(query.as_mut(), context) {
            std::task::Poll::Ready(result) => {
                this.0.take();
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
    fn drop(&mut self) {
        if let Some(query) = self.0.take() {
            // Ownership, including any admission permits, stays with the operation
            // until it completes. Dropping its waiter must not release that bound.
            detach(query);
        }
    }
}
