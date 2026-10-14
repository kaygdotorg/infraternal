//! Per-user desktop helper entrypoint; no daemon or server is created [D203,D201].
#[cfg(target_os = "macos")]
fn main() -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    const TIMEOUT: &str = "SCREENCAPTUREKIT_COMPLETION_TIMEOUT_SECS";
    if std::env::args_os().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: infraternal-desktop-helper <private-runtime-directory> [--json]\n\n{}",
            infraternal_plugin_desktop::manifest::UP.help()
        );
        return Ok(());
    }
    // Bound the pinned wrapper's callback waits before starting Tokio or AppKit.
    // Re-exec preserves the helper PID and avoids mutating a multithreaded process environment.
    if std::env::var(TIMEOUT).as_deref() != Ok("3") {
        let error = std::process::Command::new(std::env::current_exe()?)
            .args(std::env::args_os().skip(1))
            .env(TIMEOUT, "3")
            .exec();
        return Err(error);
    }
    run()
}
#[cfg(target_os = "macos")]
#[tokio::main]
async fn run() -> std::io::Result<()> {
    use infraternal_plugin_desktop::{helper, native::Native, socket::Endpoint};
    use std::{
        io,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    let json = std::env::args_os().any(|arg| arg == "--json");
    let once = std::env::args_os().any(|arg| arg == "--once");
    let mut args = std::env::args_os().skip(1);
    let mut runtime = None;
    let mut companion_runtime = None;
    while let Some(argument) = args.next() {
        if argument == "--json" || argument == "--once" {
            continue;
        }
        if argument == "--companion-runtime" {
            if companion_runtime.is_some() {
                return Err(io::Error::other("Duplicate desktop companion directory."));
            }
            companion_runtime = Some(PathBuf::from(args.next().ok_or_else(|| {
                io::Error::other("A private desktop companion directory is required.")
            })?));
        } else if runtime.replace(PathBuf::from(argument)).is_some() {
            return Err(io::Error::other("Unexpected desktop helper argument."));
        }
    }
    let runtime = runtime.ok_or_else(|| {
        io::Error::other("Usage: infraternal-desktop-helper <private-runtime-directory>")
    })?;
    let endpoint = Endpoint::bind(&runtime)?;
    let companion_runtime = companion_runtime.as_deref().unwrap_or(&runtime);
    infraternal_plugin_desktop::socket::validate_runtime(companion_runtime)?;
    let native_path = extract_companion(companion_runtime)?;
    endpoint.listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(endpoint.listener.try_clone()?)?;
    let stopping = Arc::new(AtomicBool::new(false));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut native = Some(Native::spawn(&native_path)?);
    if json {
        println!(
            "{}",
            serde_json::json!({"state":"on","socket":endpoint.path()})
        );
    } else {
        println!(
            "Desktop helper\n  State   Ready\n  Socket  {}\n\nNext\n  List app windows with the local desktop client.",
            endpoint.path().display()
        );
    }
    let result: io::Result<()> = async {
        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => Some(accepted?),
                _ = terminate.recv() => None,
                _ = interrupt.recv() => None,
            };
            let Some((socket,_)) = accepted else { break };
            let socket = socket.into_std()?;
            socket.set_nonblocking(false)?;
            let shutdown = socket.try_clone()?;
            let encoder_path = native_path.clone();
            let mut companion = native.take().ok_or_else(|| io::Error::other("Desktop companion unavailable."))?; let stop = Arc::clone(&stopping);
            let mut task = tokio::task::spawn_blocking(move || { let result = helper::session(socket,&mut companion,&encoder_path,&stop); (companion,result) });
            tokio::select! {
                result = &mut task => { if let Ok((companion,result)) = result { native = Some(companion); if let Err(error) = result && error.kind() != io::ErrorKind::UnexpectedEof { eprintln!("Desktop stream stopped: {error}"); } } },
                _ = terminate.recv() => { stopping.store(true,Ordering::Release); let _ = shutdown.shutdown(std::net::Shutdown::Both); let _ = task.await; break },
                _ = interrupt.recv() => { stopping.store(true,Ordering::Release); let _ = shutdown.shutdown(std::net::Shutdown::Both); let _ = task.await; break },
            }
            if once { break; }
        }
        Ok(())
    }.await;
    // Keep the inert companion at a stable path so macOS permission grants
    // address the same executable on later starts. Disabling leaves no process.
    result
}
#[cfg(target_os = "macos")]
fn extract_companion(runtime: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    use std::{
        fs,
        io::{self, Read},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let native_path = runtime.join("desktop-native");
    // Extract only into the authenticated private directory, never overwrite a file or symlink.
    let embedded = include_bytes!(env!("INFRATERNAL_DESKTOP_NATIVE"));
    match fs::symlink_metadata(&native_path) {
        Ok(_) => {
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&native_path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o500
                || metadata.len() != u64::try_from(embedded.len()).unwrap_or(u64::MAX)
            {
                return Err(io::Error::other(
                    "Desktop companion differs from this helper; remove the stopped helper's companion before updating.",
                ));
            }
            let mut actual = Vec::new();
            file.take(metadata.len().saturating_add(1))
                .read_to_end(&mut actual)?;
            if actual != embedded.as_slice() {
                return Err(io::Error::other(
                    "Desktop companion differs from this helper; remove the stopped helper's companion before updating.",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Publish a complete immutable file atomically: simultaneous owned
            // source helpers must never observe a partially extracted binary.
            let temporary = runtime.join(format!("desktop-native-{}.pending", std::process::id()));
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o500)
                .open(&temporary)?;
            std::io::Write::write_all(&mut file, embedded)?;
            file.sync_all()?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o500))?;
            let publication = fs::hard_link(&temporary, &native_path);
            fs::remove_file(&temporary)?;
            match publication {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    return extract_companion(runtime);
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    }
    Ok(native_path)
}
#[cfg(not(target_os = "macos"))]
fn main() {
    if std::env::args_os().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: infraternal-desktop-helper <private-runtime-directory> [--json]\n\n{}",
            infraternal_plugin_desktop::manifest::UP.help()
        );
        return;
    }
    if std::env::args_os().any(|arg| arg == "--json") {
        println!(
            "{}",
            serde_json::json!({"state":"unavailable","error":"Desktop capture requires a logged-in macOS session."})
        );
    } else {
        eprintln!(
            "Desktop capture\n  State   Unavailable\n  Next    Run the desktop helper in a logged-in macOS session."
        );
    }
    std::process::exit(2);
}
