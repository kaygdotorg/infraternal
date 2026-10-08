//! Role: Measures server-only resident memory for idle QUIC connections and active streams.
//! SPDX-License-Identifier: AGPL-3.0-only

use crate::test_identity::{self, TestIdentity};
use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    process::{Command, Stdio},
};

struct MemoryRows {
    baseline: u64,
    idle: u64,
    active: u64,
}

/// Starts an isolated server child, measures it at 1,000 idle connections and streams.
pub fn action() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(2).collect::<Vec<_>>();
    if args.len() != 2 || !matches!(args[0].as_str(), "quinn" | "openssl") {
        return Err("usage: bench-memory <quinn|openssl> <connection-count>".into());
    }
    let count = args[1].parse::<usize>()?;
    if count == 0 {
        return Err("connection count must be positive".into());
    }
    println!(
        "stack,connections,baseline_rss_bytes,idle_rss_bytes,active_rss_bytes,idle_bytes_per_connection,stream_bytes_per_connection"
    );
    let stack = args[0].as_str();
    let identity = test_identity::generate()?;
    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .arg("memory-server")
        .arg(stack)
        .arg(count.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let result = run_parent(stack, count, &identity, &mut child);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let rows = result?;
    if !status.success() {
        return Err(format!("memory server exited with {status}").into());
    }
    let idle_per_connection = rows.idle.saturating_sub(rows.baseline) / count as u64;
    let stream_per_connection = rows.active.saturating_sub(rows.idle) / count as u64;
    println!(
        "{},{},{},{},{},{},{}",
        if stack == "quinn" {
            "quinn-rustls-ring"
        } else {
            "openssl-native-3.6.3"
        },
        count,
        rows.baseline,
        rows.idle,
        rows.active,
        idle_per_connection,
        stream_per_connection
    );
    Ok(())
}

fn run_parent(
    stack: &str,
    count: usize,
    identity: &TestIdentity,
    child: &mut std::process::Child,
) -> Result<MemoryRows, Box<dyn Error>> {
    let mut child_input = child
        .stdin
        .take()
        .ok_or("memory server stdin pipe was not created")?;
    identity.write_to(&mut child_input)?;
    let stdout = child
        .stdout
        .take()
        .ok_or("memory server stdout pipe was not created")?;
    let mut child_output = BufReader::new(stdout);
    let ready = read_stage(&mut child_output, "ready")?;
    let server_addr = ready
        .0
        .parse::<SocketAddr>()
        .map_err(|_| "memory server reported an invalid socket address")?;
    let baseline = ready.1;

    match stack {
        "quinn" => {
            let mut clients = QuinnClients::connect(identity, server_addr, count)?;
            let idle = read_stage(&mut child_output, "idle")?.1;
            clients.open_streams()?;
            child_input.write_all(b"streams\n")?;
            child_input.flush()?;
            let active = read_stage(&mut child_output, "active")?.1;
            child_input.write_all(b"stop\n")?;
            child_input.flush()?;
            Ok(MemoryRows {
                baseline,
                idle,
                active,
            })
        }
        "openssl" => {
            let mut clients = OpenSslClients::connect(identity, server_addr, count)?;
            let idle = read_stage(&mut child_output, "idle")?.1;
            clients.open_streams()?;
            child_input.write_all(b"streams\n")?;
            child_input.flush()?;
            let active = wait_for_openssl_active(&mut clients, child_output)?;
            child_input.write_all(b"stop\n")?;
            child_input.flush()?;
            Ok(MemoryRows {
                baseline,
                idle,
                active,
            })
        }
        _ => unreachable!("stack validated before spawning child"),
    }
}

fn read_stage(reader: &mut impl BufRead, expected: &str) -> Result<(String, u64), Box<dyn Error>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(format!("memory server closed before the {expected} stage").into());
    }
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields[0] != expected {
        return Err(format!("unexpected memory server response: {}", line.trim()).into());
    }
    Ok((fields[1].to_owned(), fields[2].parse()?))
}

/// Receives ephemeral credentials and serves the requested memory stages.
pub fn server_action() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(2).collect::<Vec<_>>();
    if args.len() != 2 || !matches!(args[0].as_str(), "quinn" | "openssl") {
        return Err("usage: memory-server <quinn|openssl> <connection-count>".into());
    }
    let count = args[1].parse::<usize>()?;
    let stdin = std::io::stdin();
    let mut control = stdin.lock();
    let identity = TestIdentity::read_from(&mut control)?;
    match args[0].as_str() {
        "quinn" => server_quinn(&identity, count, &mut control),
        "openssl" => server_openssl(&identity, count, &mut control),
        _ => unreachable!("stack validated before reading credentials"),
    }
}

fn wait_for_control(reader: &mut impl BufRead, expected: &str) -> Result<(), Box<dyn Error>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(format!("benchmark controller closed before {expected}").into());
    }
    if line.trim() != expected {
        return Err(format!(
            "expected controller command {expected}, received {}",
            line.trim()
        )
        .into());
    }
    Ok(())
}

fn resident_bytes() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .ok_or("VmRSS missing from /proc/self/status")?;
    let kib = line
        .split_whitespace()
        .nth(1)
        .ok_or("VmRSS value missing")?
        .parse::<u64>()?;
    Ok(kib * 1024)
}

struct QuinnClients {
    runtime: tokio::runtime::Runtime,
    _endpoint: quinn::Endpoint,
    connections: Vec<quinn::Connection>,
    streams: Vec<(quinn::SendStream, quinn::RecvStream)>,
}

impl QuinnClients {
    fn connect(
        identity: &TestIdentity,
        server_addr: SocketAddr,
        count: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let (_, client_config) = crate::quinn_stack::make_configs(identity)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (endpoint, connections) = runtime.block_on(async move {
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
            endpoint.set_default_client_config(client_config);
            let mut connections = Vec::with_capacity(count);
            for _ in 0..count {
                connections.push(endpoint.connect(server_addr, "localhost")?.await?);
            }
            Ok::<_, Box<dyn Error>>((endpoint, connections))
        })?;
        Ok(Self {
            runtime,
            _endpoint: endpoint,
            connections,
            streams: Vec::with_capacity(count),
        })
    }

    fn open_streams(&mut self) -> Result<(), Box<dyn Error>> {
        self.runtime.block_on(async {
            for connection in &self.connections {
                let (mut send, recv) = connection.open_bi().await?;
                send.write_all(&[1]).await?;
                self.streams.push((send, recv));
            }
            Ok::<_, Box<dyn Error>>(())
        })
    }
}

struct OpenSslClients {
    _context: crate::openssl_native::Context,
    connections: Vec<(std::net::UdpSocket, crate::openssl_native::Ssl)>,
    streams: Vec<crate::openssl_native::Ssl>,
}

impl OpenSslClients {
    fn connect(
        identity: &TestIdentity,
        server_addr: SocketAddr,
        count: usize,
    ) -> Result<Self, Box<dyn Error>> {
        use crate::openssl_native as native;
        use openssl_sys as ossl;
        use std::os::fd::AsRawFd;

        let context = native::make_context(false, identity)?;
        let mut connections = Vec::with_capacity(count);
        for _ in 0..count {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
            socket.connect(server_addr)?;
            let ssl = native::nonnull(
                unsafe { ossl::SSL_new(context.0) },
                "SSL_new(memory client)",
            )?;
            let ssl = native::Ssl(ssl);
            native::check_ssl(
                unsafe { native::SSL_set_fd(ssl.0, socket.as_raw_fd()) },
                "SSL_set_fd(memory client)",
            )?;
            native::check_ssl(
                unsafe { ossl::SSL_set_blocking_mode(ssl.0, 1) },
                "SSL_set_blocking_mode(memory client)",
            )?;
            native::check_ssl(
                unsafe {
                    ossl::SSL_set_default_stream_mode(ssl.0, native::SSL_DEFAULT_STREAM_MODE_NONE)
                },
                "SSL_set_default_stream_mode(memory client)",
            )?;
            native::set_hostname(ssl.0, "localhost")?;
            native::check_zero(
                unsafe {
                    ossl::SSL_set_alpn_protos(
                        ssl.0,
                        native::ALPN.as_ptr(),
                        native::ALPN.len() as u32,
                    )
                },
                "SSL_set_alpn_protos(memory client)",
            )?;
            native::check_handshake(
                ssl.0,
                unsafe { ossl::SSL_connect(ssl.0) },
                "SSL_connect(memory client)",
            )?;
            connections.push((socket, ssl));
        }
        Ok(Self {
            _context: context,
            connections,
            streams: Vec::with_capacity(count),
        })
    }

    fn open_streams(&mut self) -> Result<(), Box<dyn Error>> {
        use crate::openssl_native as native;
        use openssl_sys as ossl;

        for (_, connection) in &self.connections {
            let stream = unsafe { ossl::SSL_new_stream(connection.0, 0) };
            let stream = native::Ssl(native::nonnull(stream, "SSL_new_stream(memory client)")?);
            native::write_all(&stream, &[1], "SSL_write_ex(memory stream)")?;
            // Client QUIC domains use an application-driven event loop in this
            // harness; drive each connection after queuing its stream data.
            native::check_ssl(
                unsafe { native::SSL_handle_events(connection.0) },
                "SSL_handle_events(memory client)",
            )?;
            self.streams.push(stream);
        }
        Ok(())
    }

    fn drive_events(&mut self) -> Result<(), Box<dyn Error>> {
        for (_, connection) in &self.connections {
            crate::openssl_native::check_ssl(
                unsafe { crate::openssl_native::SSL_handle_events(connection.0) },
                "SSL_handle_events(memory client)",
            )?;
        }
        Ok(())
    }
}

/// Drives client QUIC events while the server accepts all incoming streams.
fn wait_for_openssl_active(
    clients: &mut OpenSslClients,
    mut child_output: BufReader<std::process::ChildStdout>,
) -> Result<u64, Box<dyn Error>> {
    let (active_sender, active_receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let active = read_stage(&mut child_output, "active").map_err(|error| error.to_string());
        let _ = active_sender.send(active);
    });
    loop {
        match active_receiver.try_recv() {
            Ok(active) => {
                reader
                    .join()
                    .map_err(|_| "OpenSSL memory stage reader panicked")?;
                return active.map(|(_, rss)| rss).map_err(|error| error.into());
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                reader
                    .join()
                    .map_err(|_| "OpenSSL memory stage reader panicked")?;
                return Err("OpenSSL memory stage reader stopped unexpectedly".into());
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        clients.drive_events()?;
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn server_quinn(
    identity: &TestIdentity,
    count: usize,
    control: &mut impl BufRead,
) -> Result<(), Box<dyn Error>> {
    use quinn::Endpoint;

    let (server_config, _) = crate::quinn_stack::make_configs(identity)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
        println!("ready {} {}", endpoint.local_addr()?, resident_bytes()?);
        std::io::stdout().flush()?;
        let mut connections = Vec::with_capacity(count);
        for _ in 0..count {
            let incoming = endpoint.accept().await.ok_or("server endpoint closed")?;
            connections.push(incoming.await?);
        }
        println!("idle 0 {}", resident_bytes()?);
        std::io::stdout().flush()?;
        wait_for_control(control, "streams")?;
        let mut streams = Vec::with_capacity(count);
        for connection in &connections {
            let (send, mut recv) = connection.accept_bi().await?;
            let mut token = [0u8; 1];
            recv.read_exact(&mut token).await?;
            streams.push((send, recv));
        }
        println!("active 0 {}", resident_bytes()?);
        std::io::stdout().flush()?;
        wait_for_control(control, "stop")?;
        drop(streams);
        drop(connections);
        endpoint.close(0u32.into(), b"memory sample complete");
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}

fn server_openssl(
    identity: &TestIdentity,
    count: usize,
    control: &mut impl BufRead,
) -> Result<(), Box<dyn Error>> {
    use crate::openssl_native as native;
    use openssl_sys as ossl;
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let address = socket.local_addr()?;
    let context = native::make_context(true, identity)?;
    let listener = native::make_listener(&context, &socket)?;
    println!("ready {address} {}", resident_bytes()?);
    std::io::stdout().flush()?;
    let mut connections = Vec::with_capacity(count);
    for _ in 0..count {
        let connection = unsafe { native::SSL_accept_connection(listener.0, 0) };
        let connection = native::Ssl(native::nonnull(
            connection,
            "SSL_accept_connection(memory)",
        )?);
        native::check_ssl(
            unsafe { ossl::SSL_set_blocking_mode(connection.0, 1) },
            "SSL_set_blocking_mode(memory server)",
        )?;
        native::check_handshake(
            connection.0,
            unsafe { ossl::SSL_accept(connection.0) },
            "SSL_accept(memory server)",
        )?;
        native::check_ssl(
            unsafe {
                native::SSL_set_incoming_stream_policy(
                    connection.0,
                    native::SSL_INCOMING_STREAM_POLICY_ACCEPT,
                    0,
                )
            },
            "SSL_set_incoming_stream_policy(memory server)",
        )?;
        connections.push(connection);
    }
    println!("idle 0 {}", resident_bytes()?);
    std::io::stdout().flush()?;
    wait_for_control(control, "streams")?;
    let mut streams = Vec::with_capacity(count);
    for (index, connection) in connections.iter().enumerate() {
        let stream = loop {
            let stream = unsafe {
                ossl::SSL_accept_stream(connection.0, native::SSL_ACCEPT_STREAM_NO_BLOCK)
            };
            if !stream.is_null() {
                break stream;
            }
            // Drive the connection event loop until this client's stream is visible.
            native::check_ssl(
                unsafe { native::SSL_handle_events(connection.0) },
                "SSL_handle_events(memory server)",
            )?;
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        let stream = native::Ssl(native::nonnull(
            stream,
            &format!("SSL_accept_stream(memory connection {index})"),
        )?);
        native::read_exact(&stream, 1, "SSL_read_ex(memory stream)")?;
        streams.push(stream);
    }
    println!("active 0 {}", resident_bytes()?);
    std::io::stdout().flush()?;
    wait_for_control(control, "stop")?;
    drop(streams);
    drop(connections);
    drop(listener);
    drop(context);
    drop(socket);
    Ok(())
}
