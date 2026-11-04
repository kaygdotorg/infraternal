//! Local test client saves helper Annex-B access units without a server or browser [D203,D208].
//!
//! Usage: `infraternal-desktop-client <socket> list|status|capture [start.json
//! output.h264 seconds] [--json]`.
//!
//! It connects to a running desktop helper's Unix socket, sends one command and
//! prints the reply as a short text report (or raw JSON with `--json`).
//! `capture` also reads a start request from a JSON file, then writes the
//! received video access units to the output file for the given number of
//! seconds (default 5, at most 120). It exists for testing the helper by hand.
use infraternal_plugin_desktop::protocol::{self, Kind};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{fs::OpenOptionsExt, net::UnixStream},
    path::PathBuf,
    time::Duration,
};
/// Parses the command line, sends one command to the helper, prints the reply,
/// and for `capture` saves the stream. Returns an error (non-zero exit) on bad
/// usage, I/O failure, or when the helper answers with an error.
fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: infraternal-desktop-client <socket> list|status|capture [start.json output.h264 seconds] [--json]"
        );
        for action in [
            infraternal_plugin_desktop::manifest::LIST,
            infraternal_plugin_desktop::manifest::CAPTURE,
            infraternal_plugin_desktop::manifest::SESSION_STATUS,
        ] {
            println!("\n{}", action.help());
        }
        return Ok(());
    }
    if args.len() < 2 {
        return Err(io::Error::other(
            "Usage: infraternal-desktop-client <socket> list|status|capture [start.json output.h264 seconds] [--json]",
        ));
    }
    let mut socket = UnixStream::connect(PathBuf::from(&args[0]))?;
    socket.set_read_timeout(Some(Duration::from_secs(130)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let json = args.iter().any(|arg| arg == "--json");
    let command = args[1].to_str().unwrap_or("");
    let kind = match command {
        "list" => Kind::List,
        "status" => Kind::Status,
        "capture" => Kind::Start,
        _ => return Err(io::Error::other("Choose list, status or capture.")),
    };
    let body = if kind == Kind::Start {
        let path = args
            .get(2)
            .ok_or_else(|| io::Error::other("A capture request file is required."))?;
        let file = fs::File::open(path)?;
        let mut body = Vec::new();
        file.take(protocol::MAX_CONTROL as u64 + 1)
            .read_to_end(&mut body)?;
        body
    } else {
        b"{}".to_vec()
    };
    protocol::validate_command(kind, &body)?;
    protocol::write(&mut socket, kind, &body)?;
    let (reply, metadata) = protocol::read(&mut socket)?;
    let value: serde_json::Value = serde_json::from_slice(&metadata)?;
    if reply == Kind::Error {
        if json {
            println!("{value}");
        } else {
            println!(
                "Desktop capture\n  State   Unavailable\n  Reason  {}",
                clean(value["error"].as_str().unwrap_or("Desktop request failed."))
            );
        }
        return Err(io::Error::other("Desktop helper rejected the request."));
    }
    render(&value, kind, json);
    if kind != Kind::Start {
        return Ok(());
    }
    save_stream(socket, &args, json)
}

/// Makes helper-supplied text safe to print: drops control characters (which
/// could drive the terminal) and bidirectional overrides (which could reorder
/// the displayed text), and keeps at most 256 characters.
fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() && !matches!(u32::from(*c),0x202a..=0x202e | 0x2066..=0x2069))
        .take(256)
        .collect()
}
/// Prints the helper's reply: the raw JSON when `json` is set, otherwise a
/// window and display table for `List`, or a short state summary for other
/// commands.
fn render(value: &serde_json::Value, kind: Kind, json: bool) {
    if json {
        println!("{value}");
    } else if kind == Kind::List {
        println!(
            "App windows\n  {:>8}  {:>7}  {:<24}  Title",
            "Window", "PID", "App"
        );
        for window in value["windows"].as_array().into_iter().flatten() {
            println!(
                "  {:>8}  {:>7}  {:<24}  {}",
                window["window_id"],
                window["owner_pid"],
                clean(window["app_name"].as_str().unwrap_or("Unknown app")),
                clean(window["title"].as_str().unwrap_or("Untitled"))
            );
        }
        println!(
            "\nWhole screen\n  {:>8}  {:>14}  {:>5}  Name",
            "Display", "Pixel size", "Scale"
        );
        for display in value["displays"].as_array().into_iter().flatten() {
            println!(
                "  {:>8}  {:>14}  {:>5}  Whole screen",
                display["display_id"],
                format!("{}×{}", display["pixel_width"], display["pixel_height"]),
                display["backing_scale"]
            );
        }
        println!("\nNext\n  Use a fresh window ID + PID or display ID in the capture request.");
    } else {
        println!(
            "Desktop capture\n  State   {}",
            if value["state"] == "on" { "On" } else { "Off" }
        );
        if value["state"] == "on" {
            println!(
                "  Output  {}×{} pixels\n  Mode    {}",
                value["width"],
                value["height"],
                clean(value["reason"].as_str().unwrap_or("Unavailable"))
            );
            if !value["window_id"].is_null() {
                println!(
                    "  Window  {} (PID {})",
                    value["window_id"], value["owner_pid"]
                );
            }
        }
        println!("\nNext\n  List app windows, then capture a fresh target identity.");
    }
}

/// Writes the helper's video to the file named by `args[3]` for `args[4]`
/// seconds (default 5, capped at 120), then asks it to stop and waits for the
/// final state message.
///
/// The output file is created new with mode 0600 and never overwritten. A
/// background thread appends each video payload (minus its 9-byte header) as it
/// arrives; the result is the number of frames saved.
fn save_stream(mut socket: UnixStream, args: &[std::ffi::OsString], json: bool) -> io::Result<()> {
    let output = args
        .get(3)
        .ok_or_else(|| io::Error::other("A capture output path is required."))?;
    let seconds = args
        .get(4)
        .and_then(|s| s.to_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5)
        .min(120);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    let mut reader = socket.try_clone()?;
    let worker = std::thread::spawn(move || -> io::Result<u64> {
        let mut frames = 0;
        loop {
            match protocol::read(&mut reader)? {
                (Kind::Video, payload) => {
                    file.write_all(&payload[9..])?;
                    frames += 1;
                }
                (Kind::Error, _) => return Err(io::Error::other("Desktop encoding failed.")),
                (Kind::State, _) => break,
                _ => {}
            }
        }
        file.flush()?;
        Ok(frames)
    });
    std::thread::sleep(Duration::from_secs(seconds));
    protocol::write(&mut socket, Kind::Stop, b"{}")?;
    let frames = worker
        .join()
        .map_err(|_| io::Error::other("Desktop stream reader stopped."))??;
    if json {
        println!("{{\"frames\":{frames}}}");
    } else {
        println!("\nSaved stream\n  Frames  {frames}\n  State   Stopped");
    }
    Ok(())
}
