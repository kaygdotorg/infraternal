//! Checks the registration request used by the head-to-head terminal fixture.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    thread,
    time::Duration,
};

/// Reads one local HTTP request body so the fixture can inspect its JSON fields.
fn read_request_body(stream: &mut TcpStream) -> Vec<u8> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("request line");
    let mut content_length = None;
    loop {
        line.clear();
        reader.read_line(&mut line).expect("request headers");
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
        }
    }
    let mut body = vec![0; content_length.expect("content length")];
    reader.read_exact(&mut body).expect("request body");
    body
}

/// Sends `--name` through `ix-register` as the registered rootless login.
#[test]
fn ix_register_uses_the_requested_login_name() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("local setup listener");
    let address = listener.local_addr().expect("listener address");
    let capture = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("setup request");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let body = read_request_body(&mut stream);
        stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .expect("stop after capturing setup-start");
        body
    });

    let token_path = std::env::temp_dir().join(format!(
        "h2h-ix-register-name-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos()
    ));
    std::fs::write(&token_path, "fixture-token").expect("setup token file");
    let origin = format!("https://localhost:{}", address.port());
    let output = Command::new(env!("CARGO_BIN_EXE_h2h"))
        .args([
            "ix-register",
            "--server",
            &address.to_string(),
            "--origin",
            &origin,
            "--setup-token-file",
            token_path.to_str().expect("UTF-8 temp path"),
            "--name",
            "claude",
        ])
        .output()
        .expect("run ix-register");
    std::fs::remove_file(token_path).expect("remove setup token file");

    assert_eq!(
        output.status.code(),
        Some(2),
        "the fixture stops after setup-start"
    );
    let body = capture.join().expect("captured setup request");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("setup-start JSON");
    assert_eq!(payload["name"], "claude");
}
