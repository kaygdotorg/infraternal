//! Proves queued probes do not expire before the endpoint can emit their encrypted datagrams [215,263], #201.
use super::*;
use crate::{
    remote_path_socket::PathSocket,
    remote_tls::tests::{leaf, root},
};
use quinn::{
    AsyncUdpSocket, Runtime as _, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    io::IoSliceMut,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::Duration,
};

#[derive(Debug)]
struct HeldSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    until: Arc<Mutex<tokio::time::Instant>>,
}
#[derive(Debug)]
struct HeldPoller {
    inner: Pin<Box<dyn UdpPoller>>,
    until: Arc<Mutex<tokio::time::Instant>>,
    delay: Pin<Box<tokio::time::Sleep>>,
}
impl UdpPoller for HeldPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let until = *self.until.lock().unwrap();
        self.delay.as_mut().reset(until);
        if std::future::Future::poll(self.delay.as_mut(), cx).is_pending() {
            return Poll::Pending;
        }
        self.inner.as_mut().poll_writable(cx)
    }
}
impl AsyncUdpSocket for HeldSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HeldPoller {
            inner: self.inner.clone().create_io_poller(),
            until: self.until.clone(),
            delay: Box::pin(tokio::time::sleep(Duration::ZERO)),
        })
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if tokio::time::Instant::now() < *self.until.lock().unwrap() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}

#[tokio::test]
async fn a_queued_probe_cannot_expire_before_the_socket_emits_it() {
    let ca = root();
    let server = quinn::Endpoint::server(
        server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let physical = server.local_addr().unwrap();
    let logical = std::net::SocketAddr::new("127.0.0.2".parse().unwrap(), physical.port());
    let until = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let socket = Arc::new(HeldSocket {
        inner: quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap(),
        until: until.clone(),
    });
    let path = PathSocket::new(socket, logical);
    path.use_mesh(physical);
    let mut client = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        path.clone(),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    client.set_default_client_config(client_config(&leaf(&ca, false), &[ca.certificate]).unwrap());
    let (dial, accept) = tokio::join!(client.connect(logical, "localhost").unwrap(), async {
        server.accept().await.unwrap().await
    });
    let dial = dial.unwrap();
    let accept = accept.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    *until.lock().unwrap() = tokio::time::Instant::now() + Duration::from_millis(200);
    let result = tokio::time::timeout(
        Duration::from_millis(400),
        path_interrupted(
            &dial,
            &path,
            Duration::from_millis(100),
            Duration::from_millis(50),
        ),
    )
    .await;
    client.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
    drop(accept);
    assert!(
        result.is_err(),
        "a healthy path was declared dead while its probe was queued: {result:?}"
    );
}
