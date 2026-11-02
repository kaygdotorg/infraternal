//! Check that truncated file requests stop before reaching the file provider.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use russh_sftp::{
    protocol::{FileAttributes, Handle, OpenFlags, StatusCode},
    server::{self, Handler},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Files(Arc<AtomicUsize>);
#[allow(clippy::unused_async_trait_impl)]
impl Handler for Files {
    type Error = StatusCode;
    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }
    async fn open(
        &mut self,
        id: u32,
        _: String,
        _: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Handle {
            id,
            handle: "sample".into(),
        })
    }
}

async fn exchange(client: &mut tokio::io::DuplexStream, payload: &[u8]) -> Vec<u8> {
    client
        .write_u32(u32::try_from(payload.len()).unwrap())
        .await
        .unwrap();
    client.write_all(payload).await.unwrap();
    let length = client.read_u32().await.unwrap();
    let mut reply = vec![0; length as usize];
    client.read_exact(&mut reply).await.unwrap();
    reply
}

#[tokio::test]
async fn open_without_attribute_flags_is_refused_before_file_provider() {
    let opened = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&opened);
    let (service, mut client) = tokio::io::duplex(1024);
    let worker = tokio::spawn(server::serve_with_config(
        service,
        Files(opened),
        server::Config::default(),
    ));
    assert_eq!(exchange(&mut client, &[1, 0, 0, 0, 3]).await[0], 2);
    // SSH_FXP_OPEN contains id, filename, open flags AND an ATTRS flags word.
    // A complete valid control must reach the provider exactly once.
    let mut payload = vec![3];
    payload.extend_from_slice(&7_u32.to_be_bytes());
    payload.extend_from_slice(&7_u32.to_be_bytes());
    payload.extend_from_slice(b"/sample");
    payload.extend_from_slice(
        &(OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE)
            .bits()
            .to_be_bytes(),
    );
    payload.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(exchange(&mut client, &payload).await[0], 102);
    assert_eq!(observed.swap(0, Ordering::SeqCst), 1);
    // Every proper prefix is framed at its actual length. The frame itself is
    // complete, while the OPEN payload is truncated at each byte boundary.
    let mut accepted = Vec::new();
    for cut in 0..payload.len() {
        let reply = exchange(&mut client, &payload[..cut]).await;
        if observed.swap(0, Ordering::SeqCst) != 0 {
            accepted.push((cut, reply[0]));
        }
    }
    drop(client);
    worker.await.unwrap().unwrap();
    assert!(
        accepted.is_empty(),
        "truncated OPEN reached the file provider (prefix length, reply type): {accepted:?}"
    );
}

#[tokio::test]
async fn flagged_attributes_must_be_complete_before_open() {
    let opened = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&opened);
    let (service, mut client) = tokio::io::duplex(1024);
    let worker = tokio::spawn(server::serve_with_config(
        service,
        Files(opened),
        server::Config::default(),
    ));
    assert_eq!(exchange(&mut client, &[1, 0, 0, 0, 3]).await[0], 2);
    for (flags, fields) in [(1_u32, 8_usize), (2, 8), (4, 4), (8, 8), (15, 28)] {
        let mut request = vec![3];
        request.extend_from_slice(&7_u32.to_be_bytes());
        request.extend_from_slice(&7_u32.to_be_bytes());
        request.extend_from_slice(b"/sample");
        request.extend_from_slice(&OpenFlags::READ.bits().to_be_bytes());
        request.extend_from_slice(&flags.to_be_bytes());
        request.resize(request.len() + fields, 0);
        assert_eq!(exchange(&mut client, &request).await[0], 102);
        assert_eq!(observed.swap(0, Ordering::SeqCst), 1);
        for cut in 24..request.len() {
            let reply = exchange(&mut client, &request[..cut]).await;
            assert_eq!(
                observed.swap(0, Ordering::SeqCst),
                0,
                "flags {flags}, prefix {cut}, reply {}",
                reply[0]
            );
        }
    }
    drop(client);
    worker.await.unwrap().unwrap();
}

#[tokio::test]
async fn extended_attributes_must_be_complete_before_open() {
    let opened = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&opened);
    let (service, mut client) = tokio::io::duplex(1024);
    let worker = tokio::spawn(server::serve_with_config(
        service,
        Files(opened),
        server::Config::default(),
    ));
    assert_eq!(exchange(&mut client, &[1, 0, 0, 0, 3]).await[0], 2);
    for ordinary in [0_u32, 15] {
        let mut request = vec![3];
        request.extend_from_slice(&7_u32.to_be_bytes());
        request.extend_from_slice(&7_u32.to_be_bytes());
        request.extend_from_slice(b"/sample");
        request.extend_from_slice(&OpenFlags::READ.bits().to_be_bytes());
        request.extend_from_slice(&(0x8000_0000 | ordinary).to_be_bytes());
        if ordinary != 0 {
            request.resize(request.len() + 28, 0);
        }
        let extension_start = request.len();
        request.extend_from_slice(&1_u32.to_be_bytes());
        request.extend_from_slice(&3_u32.to_be_bytes());
        request.extend_from_slice(b"tag");
        request.extend_from_slice(&2_u32.to_be_bytes());
        // Extension data is opaque bytes, not a filename or UTF-8 text.
        request.extend_from_slice(&[0xff, 0]);
        for cut in extension_start..request.len() {
            let reply = exchange(&mut client, &request[..cut]).await;
            assert_eq!(
                observed.swap(0, Ordering::SeqCst),
                0,
                "extended attributes prefix {cut} reached provider, reply {}",
                reply[0]
            );
        }
        assert_eq!(exchange(&mut client, &request).await[0], 102);
        assert_eq!(observed.swap(0, Ordering::SeqCst), 1);
        request.truncate(extension_start);
        request.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(exchange(&mut client, &request).await[0], 102);
        assert_eq!(observed.swap(0, Ordering::SeqCst), 1);
    }
    drop(client);
    worker.await.unwrap().unwrap();
}
