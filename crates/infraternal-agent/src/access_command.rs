//! Resolve bounded direct scheduler inputs without executing any job text.
//! Cron uses a conservative shell lexer; systemd supplies typed argument vectors
//! through its own D-Bus API. Both feed the same input collector. Expansion,
//! identity-changing wrappers and unfamiliar wrapper syntax remain unknown.
//! This checks executable and file arguments, not libraries or sourced graphs.
use std::path::{Path, PathBuf};

/// Split one simple shell command, preserving quoted argument boundaries.
/// Shell operators, expansion and globbing are deliberately not interpreted.
fn words(command: &str) -> Option<Vec<String>> {
    if command.len() > 4096
        || command.contains('%')
        || command
            .chars()
            .any(|c| (c.is_control() || c.is_whitespace()) && !matches!(c, ' ' | '\t'))
    {
        return None;
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for c in command.chars() {
        if escaped {
            // Inside double quotes the shell preserves unfamiliar backslashes.
            // Reject those rather than checking a different, unescaped filename.
            if quote == Some('"') && !matches!(c, '$' | '`' | '"' | '\\') {
                return None;
            }
            word.push(c);
            escaped = false;
        } else if c == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
        } else if Some(c) == quote {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if quote.is_none() && c.is_ascii_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            // Brace and tilde expansion can select files that the literal
            // spelling does not name. Their evaluation stays outside this scan.
            if "$`;|&<>()\n%*?[{}~".contains(c) && quote != Some('\'') {
                return None;
            }
            word.push(c);
            started = true;
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

/// Resolve a simple cron command; ambiguous shell evaluation fails closed.
pub(crate) fn targets(command: &str) -> Option<Vec<PathBuf>> {
    let argv = words(command)?;
    inputs(argv.first()?, &argv, None, 0)
}

/// Locate a known wrapper's next executable without treating option values as
/// commands. Unknown options remain unprovable instead of selecting a guess.
fn wrapped<'a>(name: &str, args: &'a [String]) -> Option<&'a [String]> {
    let mut index = 1;
    if name == "flock" {
        while args.get(index)?.starts_with('-') {
            match args[index].as_str() {
                "-w" | "--wait" | "-E" | "--conflict-exit-code" => index += 2,
                "-s" | "-x" | "-n" | "-o" | "-F" | "-e" | "--shared" | "--exclusive"
                | "--nonblock" | "--close" | "--no-fork" | "--no-fcntl" => index += 1,
                "--" => {
                    index += 1;
                    break;
                }
                _ => return None,
            }
        }
        index += 1; // The first operand is the lock file or descriptor.
        return args.get(index..).filter(|tail| !tail.is_empty());
    }
    while let Some(arg) = args.get(index) {
        if arg == "--" {
            index += 1;
            break;
        }
        if name == "env"
            && arg.split_once('=').is_some_and(|(key, _)| {
                !key.is_empty() && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
        {
            index += 1;
            continue;
        }
        if !arg.starts_with('-') {
            break;
        }
        match (name, arg.as_str()) {
            ("nice", "-n" | "--adjustment")
            | ("ionice", "-c" | "-n" | "--class" | "--classdata")
            | ("env", "-u" | "--unset") => index += 2,
            ("ionice", "-t" | "--ignore") | ("env", "-i" | "--ignore-environment") => index += 1,
            ("nice", value)
                if value
                    .strip_prefix('-')
                    .is_some_and(|v| v.parse::<i32>().is_ok()) =>
            {
                index += 1;
            }
            _ => return None,
        }
    }
    args.get(index..).filter(|tail| !tail.is_empty())
}

/// Collect direct files using the actual executable, independently of argv[0]
/// (`ExecStart=@path argv0`). No text from these arguments enters the report.
pub(crate) fn arguments(
    executable: &str,
    argv: &[String],
    directory: &Path,
) -> Option<Vec<PathBuf>> {
    inputs(executable, argv, Some(directory), 0)
}

/// Bound nested wrappers and shell commands even when their inputs are valid.
fn inputs(
    executable: &str,
    argv: &[String],
    directory: Option<&Path>,
    depth: usize,
) -> Option<Vec<PathBuf>> {
    if depth >= 8
        || argv.is_empty()
        || argv.len() > 256
        || argv.iter().map(String::len).sum::<usize>() > 4096
        || !Path::new(executable).is_absolute()
    {
        return None;
    }
    let mut paths = vec![PathBuf::from(executable)];
    let name = Path::new(executable).file_name()?.to_str()?;
    if matches!(name, "sudo" | "doas" | "runuser" | "su") {
        return None;
    }
    if matches!(name, "nice" | "env" | "ionice" | "flock") {
        let tail = wrapped(name, argv)?;
        // Known wrapper options are not script names. Still retain absolute
        // file values, then resolve the actual nested executable separately.
        for argument in argv.iter().skip(1) {
            let value = argument
                .split_once('=')
                .map_or(argument.as_str(), |(_, value)| value);
            if Path::new(value).is_absolute() {
                paths.push(PathBuf::from(value));
            }
        }
        paths.extend(inputs(tail.first()?, tail, directory, depth + 1)?);
        paths.sort();
        paths.dedup();
        return Some(paths);
    }
    let shell_command = matches!(name, "sh" | "bash" | "dash" | "zsh")
        .then(|| {
            argv.iter().skip(1).position(|arg| {
                arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('c')
            })
        })
        .flatten()
        .map(|index| index + 2);
    // Every file argument counts, including arguments after interpreter flags
    // and --option=/path forms. Relative files use the scheduler's working dir.
    for (index, arg) in argv.iter().enumerate().skip(1) {
        if Some(index) == shell_command {
            continue;
        }
        if arg.contains('$') || arg.contains('`') {
            return None;
        }
        let value = arg.split_once('=').map_or(arg.as_str(), |(_, value)| value);
        if Path::new(value).is_absolute() {
            paths.push(PathBuf::from(value));
        } else if !value.starts_with('-') || value.contains('/') || value.contains('=') {
            // A bare operand may select an executable through PATH. Cron can
            // also override HOME, so its relative files have no proven base.
            // Never guess either path from the scanner's working directory.
            if !value.contains('/') || value.contains("://") {
                return None;
            }
            paths.push(directory?.join(value));
        }
    }
    if matches!(name, "sh" | "bash" | "dash" | "zsh") {
        if let Some(index) = shell_command {
            let command = argv.get(index)?;
            let nested = words(command)?;
            paths.extend(inputs(nested.first()?, &nested, directory, depth + 1)?);
        } else if argv
            .get(1)
            .is_some_and(|arg| !arg.starts_with('-') && !Path::new(arg).is_absolute())
        {
            return None;
        }
    }
    paths.sort();
    paths.dedup();
    Some(paths)
}

#[cfg(test)]
mod tests {
    //! Shell syntax outside the bounded lexer must remain visibly uncertain.
    use super::*;

    /// Expansion and unfamiliar separators cannot become guessed literal paths.
    #[test]
    fn uncertain_shell_paths_fail_closed() {
        for command in [
            "/bin/sh /run/job{,.backup}",
            "/bin/sh ~/job",
            "/bin/sh \"/run/job\\q\"",
            "/bin/sh /run/job\r",
            "/bin/sh\u{00a0}/run/job",
        ] {
            let argv = vec!["bash".into(), "-c".into(), command.into()];
            assert!(
                arguments("/bin/bash", &argv, Path::new("/")).is_none(),
                "{command:?}"
            );
        }
    }

    /// Ordinary quoting and escaped spaces still identify the exact file.
    #[test]
    fn literal_shell_paths_keep_their_boundaries() {
        for command in ["/bin/sh '/run/job file'", "/bin/sh /run/job\\ file"] {
            assert!(
                targets(command)
                    .unwrap()
                    .contains(&PathBuf::from("/run/job file"))
            );
        }
    }
}
