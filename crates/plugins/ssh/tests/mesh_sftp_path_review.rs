//! Verify malformed path bytes cannot select a different file-provider path.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use russh_sftp::{
    protocol::{FileAttributes, Handle, OpenFlags, StatusCode},
    server::{self, Handler},
};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Files(Arc<Mutex<Vec<String>>>);
#[allow(clippy::unused_async_trait_impl)]
impl Handler for Files {
    type Error = StatusCode;
    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }
    async fn open(
        &mut self,
        id: u32,
        path: String,
        _: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.0.lock().unwrap().push(path);
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
async fn invalid_path_encoding_is_refused_instead_of_selecting_a_replacement_path() {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&paths);
    let (service, mut client) = tokio::io::duplex(1024);
    let worker = tokio::spawn(server::serve_with_config(
        service,
        Files(paths),
        server::Config::default(),
    ));
    assert_eq!(exchange(&mut client, &[1, 0, 0, 0, 3]).await[0], 2);
    let request = |path: &[u8]| {
        let mut bytes = vec![3];
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(path.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(path);
        bytes.extend_from_slice(&OpenFlags::READ.bits().to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes
    };
    for path in [
        b"/\xff".as_slice(),
        b"/\xc0\xaf",
        b"/\xed\xa0\x80",
        b"/\xf4\x90\x80\x80",
        b"/\xe2\x82",
    ] {
        let reply = exchange(&mut client, &request(path)).await;
        assert!(
            observed.lock().unwrap().is_empty(),
            "invalid path reached the provider"
        );
        assert_eq!(reply[0], 101, "expected an error status");
        assert_eq!(
            u32::from_be_bytes(reply[5..9].try_into().unwrap()),
            StatusCode::BadMessage as u32
        );
    }
    // A valid Unicode path after the refusals must arrive byte-for-byte; strict
    // decoding must neither normalize paths nor retire a usable file channel.
    let valid = "/é/😀";
    assert_eq!(
        exchange(&mut client, &request(valid.as_bytes())).await[0],
        102
    );
    drop(client);
    worker.await.unwrap().unwrap();
    assert_eq!(*observed.lock().unwrap(), vec![valid.to_owned()]);
}
