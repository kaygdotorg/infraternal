//! Exercises byte ceilings, HTTP refusal, cancellation cleanup and HTTPS-only transport [224,225].
#![allow(clippy::unwrap_used)]
use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A body that keeps delivering data survives more than the old 90-second clock.
#[tokio::test]
async fn progressing_body_outlives_the_total_download_clock() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}/payload", listener.local_addr().unwrap());
    let (release, mut released) = tokio::sync::mpsc::channel::<()>(1);
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n")
            .await
            .unwrap();
        for _ in 0..12 {
            released.recv().await.unwrap();
            socket.write_all(b"x").await.unwrap();
        }
    });
    let destination = std::env::temp_dir().join(format!("j276-http-{}", uuid::Uuid::new_v4()));
    let path = destination.clone();
    let running = tokio::spawn(async move { download(&address, &path, 12).await });
    tokio::time::pause();
    let guard = std::time::Instant::now() + Duration::from_secs(600);
    for count in 1..=12 {
        release.send(()).await.unwrap();
        while !std::fs::metadata(&destination).is_ok_and(|m| m.len() == count) {
            assert!(!running.is_finished(), "download ended before byte {count}");
            assert!(std::time::Instant::now() < guard, "HTTP fixture wedged");
            tokio::task::yield_now().await;
        }
        if count != 12 {
            tokio::time::advance(Duration::from_secs(10)).await;
        }
    }
    tokio::time::resume();
    assert!(running.await.unwrap().is_ok());
    server.await.unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"xxxxxxxxxxxx");
    std::fs::remove_file(destination).unwrap();
}

/// Headers and empty frames cannot keep a body that stopped moving alive.
#[tokio::test]
async fn stalled_body_expires_after_thirty_seconds_without_data() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}/payload", listener.local_addr().unwrap());
    let (ready, received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .await
            .unwrap();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let destination = std::env::temp_dir().join(format!("j276-stall-{}", uuid::Uuid::new_v4()));
    let path = destination.clone();
    let running = tokio::spawn(async move { download(&address, &path, 2).await });
    received.await.unwrap();
    tokio::time::pause();
    while !std::fs::metadata(&destination).is_ok_and(|m| m.len() == 1) {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(31)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert!(
        running.is_finished(),
        "stalled body retained the old whole-download clock"
    );
    tokio::time::resume();
    assert!(matches!(
        running.await.unwrap(),
        Err(DownloadError::Network)
    ));
    server.abort();
    let _ = server.await;
    std::fs::remove_file(destination).unwrap();
}

#[tokio::test]
/// The downloader refuses an oversized body, a bad status and an existing destination.
async fn bounded_body_status_and_existing_destination_are_refused() {
    // The downloader bounds every write and fsync at 30 s, so its destination must
    // not sit on the slow build disk, whose fsync stalls exceed that (#509).
    let root = std::env::temp_dir().join(format!("release-http-{}", uuid::Uuid::new_v4()));
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
/// An `https://` source never falls back to plaintext when the bucket speaks plain HTTP.
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
    let destination = std::env::temp_dir().join(format!("https-refusal-{}", uuid::Uuid::new_v4()));
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
