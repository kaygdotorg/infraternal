//! Measure local relay metadata at 200 simultaneous streams without allocating PTYs or attributing shell memory to transport [D214], #151.
use super::*;
use tokio::sync::mpsc;

fn private_kib() -> u64 {
    std::fs::read_to_string("/proc/self/smaps_rollup")
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("Private_Dirty:") || line.starts_with("Private_Clean:"))
        .map(|line| {
            line.split_ascii_whitespace()
                .nth(1)
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .sum()
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "weighted release measurement of 200 idle relay tasks"]
async fn terminal_stream_memory_at_200() {
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap_or_else(|| "../../target".into()),
    );
    let state = sessions::state(Some(root.join(format!("s{}", std::process::id())))).unwrap();
    let (ready, mut readiness) = mpsc::channel(201);
    let (output, mut receive) = mpsc::channel(201);
    let mut servers = JoinSet::new();
    let mut tasks = JoinSet::new();
    let mut commands = Vec::new();
    let mut paths = Vec::new();
    for value in 1_u128..=201 {
        let id = value.to_le_bytes();
        let path = state
            .join("sessions")
            .join(format!("{}.sock", uuid::Uuid::from_bytes(id).simple()));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let ready = ready.clone();
        servers.spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            sessions::send(
                &mut peer,
                &Shim::Hello {
                    version: 1,
                    caps: SEQUENCED_INPUT | infraternal_shim::frame::MULTI_WRITER,
                    session: id,
                    pid: std::process::id(),
                    cols: 80,
                    rows: 24,
                    created: 0,
                    head: 0,
                    start: 0,
                },
            )
            .await
            .unwrap();
            let mut reader = Reader::default();
            assert_eq!(
                reader.read(&mut peer).await.unwrap(),
                Shim::Attach(SEQUENCED_INPUT | infraternal_shim::frame::MULTI_WRITER)
            );
            assert_eq!(
                reader.read(&mut peer).await.unwrap(),
                Shim::SelectWriter(u32::try_from(value).unwrap())
            );
            assert_eq!(
                reader.read(&mut peer).await.unwrap(),
                Shim::InputStateRequest
            );
            sessions::send(&mut peer, &Shim::InputState(0, 0))
                .await
                .unwrap();
            assert_eq!(reader.read(&mut peer).await.unwrap(), Shim::ReadFrom(0));
            ready.send(()).await.unwrap();
            let _ = reader.read(&mut peer).await;
        });
        paths.push((path, id));
    }
    let (path, id) = paths.remove(0);
    let (sender, receiver) = session_commands::channel();
    let warm = terminal(path, id, 1, 0, 0, receiver, output.clone());
    println!("relay_future_bytes={}", std::mem::size_of_val(&warm));
    commands.push(sender);
    tasks.spawn(warm);
    tokio::time::timeout(std::time::Duration::from_secs(5), readiness.recv())
        .await
        .unwrap()
        .unwrap();
    receive.recv().await.unwrap();
    let before = private_kib();
    for (index, (path, id)) in paths.into_iter().enumerate() {
        let (sender, receiver) = session_commands::channel();
        commands.push(sender);
        tasks.spawn(terminal(
            path,
            id,
            u32::try_from(index + 2).unwrap(),
            0,
            0,
            receiver,
            output.clone(),
        ));
    }
    for _ in 0..200 {
        tokio::time::timeout(std::time::Duration::from_secs(5), readiness.recv())
            .await
            .unwrap()
            .unwrap();
        receive.recv().await.unwrap();
    }
    let after = private_kib();
    println!(
        "streams=200 private_before_kib={before} private_after_kib={after} delta_kib={} bytes_per_stream={} load={}",
        after.saturating_sub(before),
        after.saturating_sub(before) * 1024 / 200,
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    tasks.abort_all();
    servers.abort_all();
    while tasks.join_next().await.is_some() {}
    while servers.join_next().await.is_some() {}
    std::fs::remove_dir_all(state).unwrap();
}
