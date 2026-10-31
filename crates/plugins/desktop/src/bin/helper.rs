//! Per-user desktop helper entrypoint; no daemon or server is created [D203,D201].
#[cfg(target_os = "macos")]
use std::io::Write as _;

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
    if std::env::args_os().any(|arg| arg == "--check-permissions") {
        let path = configured_companion()?.ok_or_else(|| {
            std::io::Error::other(
                "Set INFRATERNAL_DESKTOP_COMPANION to the executable inside the signed capture app bundle.",
            )
        })?;
        let output = infraternal_plugin_desktop::native::check_permissions(&path)?;
        std::io::stdout().write_all(&output)?;
        return Ok(());
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
    let native_path = configured_companion()?.ok_or_else(|| {
        io::Error::other(
            "Set INFRATERNAL_DESKTOP_COMPANION to the executable inside the signed capture app bundle.",
        )
    })?;
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
                result = &mut task => {
                    if let Ok((companion, session_result)) = result {
                        if let Err(error) = session_result && error.kind() != io::ErrorKind::UnexpectedEof {
                            eprintln!("Desktop stream stopped: {error}");
                        }
                        if companion.is_stopped() {
                            drop(companion);
                            native = Some(restart_companion(native_path.clone()).await?);
                        } else {
                            native = Some(companion);
                        }
                    } else {
                        native = Some(restart_companion(native_path.clone()).await?);
                    }
                },
                _ = terminate.recv() => { stopping.store(true,Ordering::Release); let _ = shutdown.shutdown(std::net::Shutdown::Both); let _ = task.await; break },
                _ = interrupt.recv() => { stopping.store(true,Ordering::Release); let _ = shutdown.shutdown(std::net::Shutdown::Both); let _ = task.await; break },
            }
            if once { break; }
        }
        Ok(())
    }.await;
    // Capture instances are retired after each stream; LaunchServices keeps
    // their TCC identity attached to the installed bundle across later starts.
    result
}

#[cfg(target_os = "macos")]
async fn restart_companion(
    path: std::path::PathBuf,
) -> std::io::Result<infraternal_plugin_desktop::native::Native> {
    tokio::task::spawn_blocking(move || infraternal_plugin_desktop::native::Native::spawn(&path))
        .await
        .map_err(|_| std::io::Error::other("Desktop companion restart failed."))?
}
/// A locally configured signed companion keeps its installed bundle identity.
/// Remote action bodies cannot select this path; the supervising user owns it.
#[cfg(target_os = "macos")]
fn configured_companion() -> std::io::Result<Option<std::path::PathBuf>> {
    std::env::var_os("INFRATERNAL_DESKTOP_COMPANION")
        .map(std::path::PathBuf::from)
        .map(|path| validate_companion(&path).map(|()| path))
        .transpose()
}

#[cfg(any(target_os = "macos", test))]
fn validate_companion(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    infraternal_plugin_desktop::native::companion_app_bundle(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o100 == 0
    {
        return Err(std::io::Error::other(
            "Desktop companion must be an absolute, owned executable without shared write access.",
        ));
    }
    Ok(())
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

/// Exercises the local executable boundary without invoking platform privacy APIs.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod companion_tests {
    use super::validate_companion;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn signed_companion_path_requires_owned_executable_and_refuses_links_and_shared_writes() {
        let base =
            PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()));
        fs::create_dir_all(&base).unwrap();
        let root = fs::canonicalize(base)
            .unwrap()
            .join(format!("companion-path-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let _cleanup = Cleanup(root.clone());
        let contents = root.join("InfraternalCaptureHelper.app").join("Contents");
        let executable = contents.join("MacOS/InfraternalCaptureHelper");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(contents.join("Info.plist"), "bundle fixture").unwrap();
        fs::write(&executable, b"fixture executable").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_companion(&executable).is_ok());
        let loose = root.join("companion");
        fs::write(&loose, b"loose executable").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_companion(&loose).is_err());
        let link = root.join("link");
        symlink(&executable, &link).unwrap();
        assert!(validate_companion(&link).is_err());
        assert!(validate_companion(&root).is_err());
        assert!(validate_companion(std::path::Path::new("relative-companion")).is_err());
        for mode in [0o600, 0o720, 0o702] {
            fs::set_permissions(&executable, fs::Permissions::from_mode(mode)).unwrap();
            assert!(validate_companion(&executable).is_err(), "mode {mode:o}");
        }
        assert!(validate_companion(&root.join("missing")).is_err());
    }
}
