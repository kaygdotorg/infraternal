//! Reduces local SSH diagnostics to fixed messages without retaining peer-supplied text.

use crate::model::Failure;

/// Messages emitted by the local client and socket connector under the C locale.
pub(crate) fn dial_reason(text: &str) -> Option<&'static str> {
    for line in text.lines() {
        if line.starts_with("ssh: Could not resolve hostname ")
            || line == "infraternal SSH connector: Could not resolve hostname"
        {
            return Some(
                "This server couldn't look up the host name. Check its spelling or use the host's IP address.",
            );
        }
        if (line.starts_with("ssh: connect to host ")
            || line.starts_with("infraternal SSH connector: "))
            && line.ends_with(": Connection refused")
        {
            return Some(
                "The host refused the SSH connection. Check that SSH is running and that the port is correct.",
            );
        }
        if ((line.starts_with("ssh: connect to host ")
            || line.starts_with("infraternal SSH connector: "))
            && line.ends_with(": Connection timed out"))
            || line == "Connection timed out during banner exchange"
        {
            return Some(TIMEOUT);
        }
    }
    None
}

/// The local client or outer deadline expired before SSH finished connecting.
pub(crate) const TIMEOUT: &str =
    "The SSH connection timed out. Check that this server can reach the host's SSH port.";

/// Read one scoped OpenSSH `LogVerbose` receipt, excluding arbitrary peer text.
fn receipt<'a>(line: &'a str, scope: &str) -> Option<&'a str> {
    let line = line
        .strip_prefix("debug1: ")
        .or_else(|| line.strip_prefix("debug2: "))
        .unwrap_or(line);
    let (line_number, context) = line.strip_prefix(scope)?.split_once(" (")?;
    // Newer clients include the program name before the process id.
    let context = match context.strip_prefix("bin=") {
        Some(context) => context.split_once(", ")?.1,
        None => context,
    };
    let (pid, message) = context.strip_prefix("pid=")?.split_once("): ")?;
    (!line_number.is_empty()
        && line_number.bytes().all(|byte| byte.is_ascii_digit())
        && !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit()))
    .then_some(message)
}

/// Identify the product token from the protocol identification log. This is a hint,
/// never a trust or authentication decision.
pub(crate) fn netbird(text: &str) -> bool {
    text.lines().any(|line| {
        receipt(line, "kex.c:kex_exchange_identification():")
            .and_then(|line| {
                line.strip_prefix("Remote protocol version 2.0, remote software version ")
            })
            .and_then(|software| software.split_ascii_whitespace().next())
            .is_some_and(|product| {
                product == "NetBird-SSH-Server"
                    || product
                        .strip_prefix("NetBird-SSH-Server-")
                        .is_some_and(|version| {
                            version.starts_with(|ch: char| ch.is_ascii_digit())
                                && version.bytes().all(|byte| {
                                    byte.is_ascii_alphanumeric() || b".+-".contains(&byte)
                                })
                        })
            })
    })
}

/// Add the fixed names of methods offered by the peer or selected by the local client.
pub(crate) fn authentication(text: &str, failure: &mut Failure) {
    for line in text.lines() {
        if let Some(offered) = receipt(line, "sshconnect2.c:input_userauth_failure():")
            .and_then(|line| line.strip_prefix("Authentications that can continue:"))
        {
            // A failure reply also proves that the built-in initial none probe ran.
            add(failure, "Tried signing in without a key or password.");
            if offered.trim().is_empty() {
                add(
                    failure,
                    "The SSH server offered no further sign-in methods.",
                );
                continue;
            }
            for method in offered.trim().split(',') {
                add(
                    failure,
                    match method {
                        "publickey" => "The SSH server offered sign-in with a key.",
                        "password" => "The SSH server offered sign-in with a password.",
                        "keyboard-interactive" => {
                            "The SSH server offered sign-in with interactive prompts."
                        }
                        "hostbased" => "The SSH server offered host-based sign-in.",
                        "gssapi-with-mic" => "The SSH server offered GSSAPI sign-in.",
                        _ => "The SSH server offered an unrecognized sign-in method.",
                    },
                );
            }
        }
        match receipt(line, "sshconnect2.c:userauth():") {
            Some("we sent a publickey packet, wait for reply") => {
                add(failure, "Tried signing in with an SSH key.");
            }
            Some("we sent a password packet, wait for reply") => {
                add(failure, "Tried signing in with an SSH password.");
            }
            _ => {}
        }
    }
}

/// Recognize the local sign-in refusal while ignoring diagnostic fields supplied by the peer.
pub(crate) fn auth_refused(text: &str) -> bool {
    text.lines().any(|line| {
        let message = receipt(line, "sshconnect2.c:userauth():").unwrap_or(line);
        let refusal = message
            .split_once(": Permission denied")
            .is_some_and(|(target, _)| {
                target.contains('@') && !target.contains(char::is_whitespace)
            });
        refusal
            || matches!(
                message,
                "Permission denied"
                    | "Permission denied, please try again."
                    | "Authentication failed"
            )
    })
}

/// Keep repeated method receipts from growing a failure payload.
fn add(failure: &mut Failure, line: &'static str) {
    if !failure.log_tail.contains(&line) {
        failure.log_tail.push(line);
    }
}
