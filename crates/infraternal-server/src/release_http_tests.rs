//! Exercises byte ceilings, HTTP refusal, cancellation cleanup and HTTPS-only transport [224,225].
#![allow(clippy::unwrap_used)]
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn bounded_body_status_and_existing_destination_are_refused() {
    let root = std::path::PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()),
    )
    .join(format!("release-http-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    for (index, status, body, maximum, accepted) in [
        (0, "200 OK", "payload", 7, true),
        (1, "200 OK", "payload", 6, false),
        (2, "404 Not Found", "", 7, false),
        (3, "302 Found", "", 7, false),
        (4, "200 OK", "payload", 7, false),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}/payload", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let size = socket.read(&mut request).await.unwrap();
            assert!(request[..size].starts_with(b"GET /payload HTTP/1.1"));
            socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        let destination = root.join(index.to_string());
        if index == 4 {
            std::fs::write(&destination, b"retained").unwrap();
        }
        let result = download(&address, &destination, maximum).await;
        if let Err(error) = &result {
            assert_ne!(error.reason(), "");
        }
        assert_eq!(result.is_ok(), accepted);
        if accepted {
            assert_eq!(std::fs::read(&destination).unwrap(), body.as_bytes());
        }
        if index == 4 {
            assert_eq!(std::fs::read(&destination).unwrap(), b"retained");
        }
        server.await.unwrap();
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn https_cannot_silently_accept_a_plaintext_bucket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("https://{}/payload", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let size = socket.read(&mut request).await.unwrap();
        assert!(!request[..size].starts_with(b"GET"));
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload")
            .await
            .unwrap();
    });
    let destination = std::path::PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()),
    )
    .join(format!("https-refusal-{}", uuid::Uuid::new_v4()));
    assert!(matches!(
        download(&address, &destination, 7).await,
        Err(DownloadError::Network)
    ));
    assert!(!destination.exists());
    server.await.unwrap();
}

#[tokio::test]
async fn unsupported_scheme_credentials_query_and_fragment_never_connect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap();
    let destination = std::path::PathBuf::from("unused-release-destination");
    for address in [
        format!("ftp://{host}/payload"),
        format!("https://user@{host}/payload"),
        format!("https://{host}/payload?unexpected"),
        format!("https://{host}/payload#unexpected"),
    ] {
        assert!(matches!(
            download(&address, &destination, 7).await,
            Err(DownloadError::Network)
        ));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}
