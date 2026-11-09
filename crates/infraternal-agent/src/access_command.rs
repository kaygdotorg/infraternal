//! Resolve the files a root-run job's command can execute or read, without
//! executing any job text (D367, #355).
//!
//! Cron hands its command line to a shell; systemd supplies typed argument
//! vectors through its own D-Bus API. Both feed one resolver, and every
//! possible meaning of a word becomes a candidate path:
//!
//! - an absolute operand is itself a candidate; when it names a directory,
//!   its entries other than subdirectories are candidates too (a launcher
//!   may run them), and it becomes a possible working directory and
//!   filesystem root for later operands;
//! - a relative operand is joined to every possible working directory;
//! - a bare word (no `/`) may be a file in the working directory or a program
//!   found through the search path, so it is joined to both.
//!
//! The candidates form a superset of what the job can touch, so a program
//! that treats a word as plain data only adds harmless candidates. A candidate
//! that does not exist yet is still checked through its nearest existing
//! parent by the caller, because the account could create it there.
//!
//! Command text that this bounded reading cannot pin down fails closed
//! (`None`): runtime shell expansion (`$`, backticks, globs, braces, tilde),
//! subshells, here-documents, loops and `case`, `eval`, an identity
//! change (`sudo`, `su`, `runuser`, `doas`, `setpriv`) and anything over the
//! size bounds. Libraries and files a program sources by its own logic are
//! not traced.
use std::{
    fs,
    path::{Path, PathBuf},
};

/// The directories every supported scheduler's default search path draws on.
/// Searching all of them is a superset of the exact default of cron and systemd.
const SEARCH: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// Most entries read from one directory operand. A larger directory leaves
/// its contents unchecked, so the job fails closed instead of being trimmed.
const DIRECTORY_ENTRIES: usize = 256;

/// Most working directories plus roots one command may accumulate. Each bare
/// word costs one candidate per directory and per root and search entry.
const BASES: usize = 16;

/// Words that start shell syntax this reader does not evaluate. A command
/// starting with one of them fails closed.
const RESERVED: &[&str] = &[
    "for", "case", "esac", "function", "select", "in", "time", "coproc", "[[", "]]", "eval",
    "trap", "alias",
];

/// Condition and loop keywords that only choose which commands run, and how
/// often. Every command in every branch is resolved anyway, so they separate
/// commands like `;` does. Loops that bind a variable use `$`, which fails.
const BRANCHES: &[&str] = &[
    "if", "then", "elif", "else", "fi", "while", "until", "do", "done",
];

/// Programs that run their operands as another identity. That work belongs to
/// a different account's inventory, so it is never resolved as root's own.
const IDENTITY: &[&str] = &["sudo", "doas", "runuser", "su", "setpriv"];

/// Where a job's command starts and how it finds bare program names.
///
/// Build one with [`Context::new`] from what the scheduler states: the job's
/// working directories and any search path it sets. Every field holds absolute
/// paths only, so no candidate depends on the scanner's own working directory.
#[derive(Clone, Debug)]
pub(crate) struct Context {
    /// Every directory the command may start in. Usually one; cron may name
    /// several because a file can override `HOME`.
    directories: Vec<PathBuf>,
    /// Filesystem roots that bare names are searched under. `/` at first; a
    /// directory operand adds itself, which covers launchers that change root.
    roots: Vec<PathBuf>,
    /// Absolute search directories, always including [`SEARCH`].
    search: Vec<PathBuf>,
}

impl Context {
    /// Describe a job that starts in `directories` and also searches each
    /// colon-separated `path` value. Returns `None` for a relative directory
    /// or search entry, whose meaning would depend on the scanner itself. An
    /// empty search entry means "the working directory", as in the shell.
    pub(crate) fn new(directories: Vec<PathBuf>, path: &[&str]) -> Option<Self> {
        if directories.is_empty() || directories.iter().any(|d| !d.is_absolute()) {
            return None;
        }
        let mut search: Vec<PathBuf> = SEARCH.iter().map(PathBuf::from).collect();
        for entry in path.iter().flat_map(|value| value.split(':')) {
            if entry.is_empty() {
                search.extend(directories.iter().cloned());
            } else if Path::new(entry).is_absolute() {
                search.push(PathBuf::from(entry));
            } else {
                return None;
            }
        }
        search.sort();
        search.dedup();
        if search.len() > 64 {
            return None;
        }
        Some(Self {
            directories,
            roots: vec![PathBuf::from("/")],
            search,
        })
    }

    /// Record a directory operand as a possible working directory and root
    /// for the words after it. Too many bases fail closed.
    fn base(&mut self, directory: &Path) -> Option<()> {
        for list in [&mut self.directories, &mut self.roots] {
            if !list.iter().any(|known| known == directory) {
                list.push(directory.to_owned());
            }
        }
        (self.directories.len() + self.roots.len() <= BASES).then_some(())
    }

    /// Every place a bare program name may be found: each search directory
    /// under each root.
    fn programs(&self, name: &str, paths: &mut Vec<PathBuf>) {
        for root in &self.roots {
            for directory in &self.search {
                let relative = directory.strip_prefix("/").unwrap_or(directory);
                paths.push(root.join(relative).join(name));
            }
        }
    }
}

/// One lexical unit of shell command text.
#[derive(Debug, PartialEq)]
enum Token {
    /// A word after quote removal. `plain` marks a word without any quoting
    /// or escape before its first `=`, the only form that can be a keyword
    /// or an assignment.
    Word { text: String, plain: bool },
    /// A list separator, group brace or redirection operator.
    Op(&'static str),
}

/// Split shell command text into words and operators.
///
/// Only quoting, escapes, list separators, `{ }` groups and redirections are
/// understood. Expansion, globbing, subshells and here-documents return `None`
/// so they can never be mistaken for a literal path.
fn tokens(text: &str) -> Option<Vec<Token>> {
    if text.len() > 4096
        || text
            .chars()
            .any(|c| (c.is_control() || c.is_whitespace()) && !matches!(c, ' ' | '\t'))
    {
        return None;
    }
    let mut out = Vec::new();
    let mut word = String::new();
    let mut started = false;
    // Byte length of `word` when its first quote or escape appeared.
    let mut quoted_at: Option<usize> = None;
    let mut brace = false;
    let mut chars = text.chars().peekable();
    // Close the current word. Braces are only group words when they stand
    // alone, and `[` only the test command; anywhere else they are brace
    // expansion or a glob, which we do not evaluate.
    let finish = |out: &mut Vec<Token>,
                  word: &mut String,
                  started: &mut bool,
                  quoted_at: &mut Option<usize>,
                  brace: &mut bool|
     -> Option<()> {
        if *started {
            let text = std::mem::take(word);
            if *brace {
                match (quoted_at.is_none(), text.as_str()) {
                    (true, "{") => out.push(Token::Op("{")),
                    (true, "}") => out.push(Token::Op("}")),
                    (true, "[") => out.push(Token::Word { text, plain: true }),
                    _ => return None,
                }
            } else {
                let plain = quoted_at.is_none_or(|at| text.find('=').is_some_and(|eq| eq < at));
                out.push(Token::Word { text, plain });
            }
        }
        *started = false;
        *quoted_at = None;
        *brace = false;
        Some(())
    };
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => finish(
                &mut out,
                &mut word,
                &mut started,
                &mut quoted_at,
                &mut brace,
            )?,
            '\'' => {
                quoted_at.get_or_insert(word.len());
                started = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        c => word.push(c),
                    }
                }
            }
            '"' => {
                quoted_at.get_or_insert(word.len());
                started = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        // Inside double quotes the shell keeps unfamiliar
                        // backslashes, so such a word is not checked as if
                        // it had been unescaped.
                        '\\' => match chars.next()? {
                            c @ ('$' | '`' | '"' | '\\') => word.push(c),
                            _ => return None,
                        },
                        '$' | '`' => return None,
                        c => word.push(c),
                    }
                }
            }
            '\\' => {
                quoted_at.get_or_insert(word.len());
                started = true;
                word.push(chars.next()?);
            }
            ';' => {
                finish(
                    &mut out,
                    &mut word,
                    &mut started,
                    &mut quoted_at,
                    &mut brace,
                )?;
                out.push(Token::Op(";"));
            }
            '&' => {
                finish(
                    &mut out,
                    &mut word,
                    &mut started,
                    &mut quoted_at,
                    &mut brace,
                )?;
                out.push(Token::Op(match chars.peek() {
                    Some('&') => {
                        chars.next();
                        "&&"
                    }
                    Some('>') => {
                        chars.next();
                        if chars.peek() == Some(&'>') {
                            chars.next();
                        }
                        ">"
                    }
                    _ => "&",
                }));
            }
            '|' => {
                finish(
                    &mut out,
                    &mut word,
                    &mut started,
                    &mut quoted_at,
                    &mut brace,
                )?;
                if matches!(chars.peek(), Some('|' | '&')) {
                    let next = chars.next();
                    out.push(Token::Op(if next == Some('|') { "||" } else { "|" }));
                } else {
                    out.push(Token::Op("|"));
                }
            }
            '>' | '<' => {
                // Digits written directly before the operator name a
                // descriptor (`2>`), not a word.
                if started && quoted_at.is_none() && word.bytes().all(|b| b.is_ascii_digit()) {
                    word.clear();
                    started = false;
                } else {
                    finish(
                        &mut out,
                        &mut word,
                        &mut started,
                        &mut quoted_at,
                        &mut brace,
                    )?;
                }
                let op = match (c, chars.peek()) {
                    ('<', Some('<' | '(')) | ('>', Some('(')) => return None,
                    (_, Some('&')) => {
                        chars.next();
                        "dup"
                    }
                    ('>', Some('>' | '|')) | ('<', Some('>')) => {
                        let next = chars.next();
                        if next == Some('>') && c == '<' {
                            // `<>` opens the file for reading too.
                            "<"
                        } else {
                            ">"
                        }
                    }
                    ('>', _) => ">",
                    _ => "<",
                };
                out.push(Token::Op(op));
            }
            '{' | '}' | '[' => {
                brace = true;
                started = true;
                word.push(c);
            }
            '#' if !started => return None,
            '$' | '`' | '(' | ')' | '*' | '?' | '~' => return None,
            c => {
                started = true;
                word.push(c);
            }
        }
    }
    finish(
        &mut out,
        &mut word,
        &mut started,
        &mut quoted_at,
        &mut brace,
    )?;
    Some(out)
}

/// True for an unquoted `NAME=value` word, which assigns a variable instead of
/// naming a program when it leads a command.
fn assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.bytes().next().is_some_and(|c| !c.is_ascii_digit())
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    })
}

/// Collect the candidates of a shell command list: simple commands joined by
/// `;`, `&&`, `||`, `|` or `&`, optionally inside `{ }` groups, with
/// redirections and leading assignments. A `cd` to an absolute directory adds
/// that directory as a possible working directory for every later command,
/// which stays a superset whichever branch or subshell actually ran.
fn list(text: &str, context: &Context, depth: usize, paths: &mut Vec<PathBuf>) -> Option<()> {
    if depth >= 8 {
        return None;
    }
    let mut context = context.clone();
    let mut command: Vec<String> = Vec::new();
    let mut tokens = tokens(text)?.into_iter();
    loop {
        let token = tokens.next();
        match token {
            None | Some(Token::Op(";" | "&&" | "||" | "|" | "&" | "{" | "}")) => {
                if !command.is_empty() {
                    simple(&std::mem::take(&mut command), &mut context, depth, paths)?;
                }
                if token.is_none() {
                    break;
                }
            }
            // The shell reads this file into the command, so it is an input.
            Some(Token::Op("<")) => {
                let Some(Token::Word { text, .. }) = tokens.next() else {
                    return None;
                };
                file(&text, &context, paths);
            }
            // Root writes an output file; that cannot change what root runs.
            Some(Token::Op(">")) => {
                let Some(Token::Word { .. }) = tokens.next() else {
                    return None;
                };
            }
            // Only descriptor copies and closes (`2>&1`, `<&-`) are understood.
            Some(Token::Op("dup")) => {
                let Some(Token::Word { text, .. }) = tokens.next() else {
                    return None;
                };
                if !(text == "-" || (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())))
                {
                    return None;
                }
            }
            Some(Token::Word { text, plain }) => {
                if command.is_empty() && plain {
                    if text == "!" {
                        continue;
                    }
                    if RESERVED.contains(&text.as_str()) {
                        return None;
                    }
                    if BRANCHES.contains(&text.as_str()) {
                        continue;
                    }
                    if assignment(&text) {
                        let (name, value) = text.split_once('=')?;
                        // A changed search path changes which program runs.
                        if name == "PATH" {
                            return None;
                        }
                        // Values may name files the command reads, such as a
                        // startup file for `BASH_ENV`.
                        for part in value.split(':') {
                            value_candidates(part, &mut context, paths)?;
                        }
                        continue;
                    }
                }
                command.push(text);
            }
            Some(Token::Op(_)) => return None,
        }
    }
    Some(())
}

/// Resolve one simple command: its program name and its operands.
fn simple(
    argv: &[String],
    context: &mut Context,
    depth: usize,
    paths: &mut Vec<PathBuf>,
) -> Option<()> {
    let name = argv.first()?;
    if name == "cd" {
        let [_, directory] = argv else {
            return None;
        };
        let directory = Path::new(directory);
        if !directory.is_absolute() {
            return None;
        }
        if !context.directories.iter().any(|known| known == directory) {
            context.directories.push(directory.to_owned());
        }
        return (context.directories.len() + context.roots.len() <= BASES).then_some(());
    }
    if name.contains('/') {
        file(name, context, paths);
    } else {
        context.programs(name, paths);
    }
    program(name, argv, context, depth, paths)
}

/// Add the candidates for a file word: itself if absolute, else joined to
/// every possible working directory.
fn file(word: &str, context: &Context, paths: &mut Vec<PathBuf>) {
    if Path::new(word).is_absolute() {
        paths.push(PathBuf::from(word));
    } else {
        paths.extend(context.directories.iter().map(|d| d.join(word)));
    }
}

/// Add the candidates of one operand value (see the module doc). An absolute
/// directory also contributes its entries and becomes a base for later words.
fn value_candidates(value: &str, context: &mut Context, paths: &mut Vec<PathBuf>) -> Option<()> {
    if value.is_empty() {
        return Some(());
    }
    let path = Path::new(value);
    if path.is_absolute() {
        paths.push(path.to_owned());
        if fs::metadata(path).is_ok_and(|meta| meta.is_dir()) {
            let entries = fs::read_dir(path).ok()?;
            for (index, entry) in entries.enumerate() {
                if index >= DIRECTORY_ENTRIES {
                    return None;
                }
                // A launcher such as run-parts runs the files in a directory,
                // not its subdirectories; `/` as an operand must not make a
                // world-writable `/tmp` look like a script.
                let entry = entry.ok()?;
                if !entry.file_type().ok()?.is_dir() {
                    paths.push(entry.path());
                }
            }
            context.base(path)?;
        }
        return Some(());
    }
    file(value, context, paths);
    if !value.contains('/') {
        context.programs(value, paths);
    }
    Some(())
}

/// Add the candidates of one argument. Text that needs a shell to mean
/// anything (spaces, quotes, operators) is read as a nested command list, so a
/// script handed to any launcher (`sh -c`, `flock -c`, `timeout 5 sh -c`) is
/// still resolved. Options contribute the file named after `=` or after the
/// first `/`; bare flags are not files.
fn argument(
    arg: &str,
    context: &mut Context,
    depth: usize,
    paths: &mut Vec<PathBuf>,
) -> Option<()> {
    if arg.contains(|c: char| c.is_whitespace() || "$`;&|<>(){}*?[~'\"\\#".contains(c)) {
        // The word may also be a literal file name such as `/srv/a b`. Both
        // readings stay candidates; a failed shell reading is unknown.
        value_candidates(arg, context, paths)?;
        return list(arg, context, depth + 1, paths);
    }
    if let Some(flag) = arg.strip_prefix('-') {
        if let Some((_, value)) = arg.split_once('=') {
            return value_candidates(value, context, paths);
        }
        if let Some(index) = arg.find('/') {
            value_candidates(&arg[index..], context, paths)?;
            // `-cdir/file` may also mean the relative file `dir/file`.
            let attached = flag.trim_start_matches('-');
            return value_candidates(attached.get(1..).unwrap_or_default(), context, paths);
        }
        return Some(());
    }
    if let Some((_, value)) = arg.split_once('=') {
        for part in value.split(':') {
            value_candidates(part, context, paths)?;
        }
    }
    value_candidates(arg, context, paths)
}

/// Resolve a program's operands. `executable` names the program actually
/// run, which may differ from `argv[0]`; `argv[0]` itself is never a file.
fn program(
    executable: &str,
    argv: &[String],
    context: &Context,
    depth: usize,
    paths: &mut Vec<PathBuf>,
) -> Option<()> {
    if depth >= 8
        || argv.is_empty()
        || argv.len() > 256
        || argv.iter().map(String::len).sum::<usize>() > 4096
    {
        return None;
    }
    let name = Path::new(executable).file_name()?.to_str()?;
    if IDENTITY.contains(&name) {
        return None;
    }
    // `env PATH=...` changes where the next program is found.
    if name == "env" && argv.iter().any(|arg| arg.starts_with("PATH=")) {
        return None;
    }
    let mut context = context.clone();
    for arg in argv.iter().skip(1) {
        argument(arg, &mut context, depth, paths)?;
    }
    Some(())
}

/// Resolve a cron command line in `context`. Cron turns `%` into a newline
/// fed to the command's input, which this reader does not follow, so any `%`
/// fails closed.
pub(crate) fn targets(command: &str, context: &Context) -> Option<Vec<PathBuf>> {
    if command.contains('%') {
        return None;
    }
    let mut paths = Vec::new();
    list(command, context, 0, &mut paths)?;
    paths.sort();
    paths.dedup();
    Some(paths)
}

/// Resolve one systemd command: the real `executable` (systemd's `path=`,
/// independent of argv[0] for `ExecStart=@path argv0`) and its already
/// variable-expanded `argv`. The manager keeps a bare name such as
/// `journalctl` when it looks the program up only at start time, so a bare
/// executable is searched for like any other bare program name.
pub(crate) fn arguments(
    executable: &str,
    argv: &[String],
    context: &Context,
) -> Option<Vec<PathBuf>> {
    if executable.is_empty() {
        return None;
    }
    let mut paths = Vec::new();
    if executable.contains('/') {
        file(executable, context, &mut paths);
    } else {
        context.programs(executable, &mut paths);
    }
    program(executable, argv, context, 0, &mut paths)?;
    paths.sort();
    paths.dedup();
    Some(paths)
}

#[cfg(test)]
mod tests {
    //! Shell syntax outside the bounded reader must remain visibly uncertain,
    //! and every word must keep a candidate for each thing it may mean.
    use super::*;

    /// A context that starts in `/` with the default search path only.
    fn root() -> Context {
        Context::new(vec![PathBuf::from("/")], &[]).unwrap()
    }

    /// Expansion and unfamiliar separators cannot become guessed literal paths.
    #[test]
    fn uncertain_shell_paths_fail_closed() {
        for command in [
            "/bin/sh /run/job{,.backup}",
            "/bin/sh ~/job",
            "/bin/sh \"/run/job\\q\"",
            "/bin/sh /run/job\r",
            "/bin/sh\u{00a0}/run/job",
            "/bin/sh $JOB",
            "(/bin/sh /run/job)",
            "for job in /run/*; do /bin/sh /run/job; done",
            "case x in x) /bin/sh /run/job;; esac",
            "/bin/sh /run/job[12]",
            "eval /bin/sh /run/job",
            "/bin/sh <<EOF",
            "sudo /bin/sh /run/job",
            "PATH=/run /bin/sh job",
            "/usr/bin/env PATH=/run sh job",
        ] {
            let argv = vec!["bash".into(), "-c".into(), command.into()];
            assert!(
                arguments("/bin/bash", &argv, &root()).is_none(),
                "{command:?}"
            );
        }
        assert!(targets("/bin/sh /run/job%", &root()).is_none());
    }

    /// A bare systemd executable is searched for on the search path.
    #[test]
    fn bare_manager_executables_are_searched() {
        let paths = arguments(
            "journalctl",
            &["journalctl".into(), "--flush".into()],
            &root(),
        )
        .unwrap();
        assert!(paths.contains(&PathBuf::from("/usr/bin/journalctl")));
        assert!(paths.contains(&PathBuf::from("/usr/local/sbin/journalctl")));
    }

    /// Ordinary quoting and escaped spaces still identify the exact file.
    #[test]
    fn literal_shell_paths_keep_their_boundaries() {
        for command in ["/bin/sh '/run/job file'", "/bin/sh /run/job\\ file"] {
            assert!(
                targets(command, &root())
                    .unwrap()
                    .contains(&PathBuf::from("/run/job file"))
            );
        }
    }

    /// Lists, groups, redirections and assignments resolve every command.
    #[test]
    fn command_lists_resolve_every_command() {
        let paths = targets(
            "test -e /run/x || { cd /srv && FLAG=1 ./job < /etc/job.in 2>&1 > /dev/null; }",
            &root(),
        )
        .unwrap();
        for expected in ["/usr/bin/test", "/run/x", "/srv/./job", "/etc/job.in"] {
            assert!(paths.contains(&PathBuf::from(expected)), "{expected}");
        }
        // Output targets are root's writes, not inputs.
        assert!(!paths.contains(&PathBuf::from("/dev/null")));
        // A stock unit's test and branch shapes resolve every branch.
        let paths = targets(
            "[ -s /boot/env ] || rm -f /boot/env; if grep -q x /boot/env; then /run/job; fi",
            &root(),
        )
        .unwrap();
        for expected in ["/usr/bin/[", "/usr/bin/rm", "/usr/bin/grep", "/run/job"] {
            assert!(paths.contains(&PathBuf::from(expected)), "{expected}");
        }
    }

    /// A bare word may be a file in the working directory or a program on
    /// the search path; both stay candidates.
    #[test]
    fn bare_words_cover_directory_and_search_path() {
        let context = Context::new(vec![PathBuf::from("/root")], &["/opt/tools"]).unwrap();
        let paths = targets("debian-sa1 1 1", &context).unwrap();
        for expected in [
            "/usr/bin/debian-sa1",
            "/usr/local/sbin/debian-sa1",
            "/opt/tools/debian-sa1",
            "/root/1",
            "/usr/bin/1",
        ] {
            assert!(paths.contains(&PathBuf::from(expected)), "{expected}");
        }
        assert!(Context::new(vec![PathBuf::from("/")], &["bin"]).is_none());
    }

    /// A directory operand contributes its entries and becomes a base, so a
    /// launcher that runs a directory or changes into it cannot hide a script.
    #[test]
    fn directory_operands_cover_their_entries_and_later_words() {
        /// Remove only this test's own directory, on failure too.
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            /// Delete the temporary directory and its single entry.
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let directory = std::env::temp_dir().join(format!("ifrv-dir-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let _fixture = Fixture(directory.clone());
        fs::write(directory.join("hourly"), "").unwrap();
        let shown = directory.display();
        fs::create_dir(directory.join("nested")).unwrap();
        let paths = targets(&format!("run-parts {shown}"), &root()).unwrap();
        assert!(paths.contains(&directory.join("hourly")));
        assert!(!paths.contains(&directory.join("nested")));
        let paths = targets(&format!("/usr/bin/env -C {shown} /bin/sh ./job"), &root()).unwrap();
        assert!(paths.contains(&directory.join("./job")));
        let paths = targets(&format!("chroot {shown} job"), &root()).unwrap();
        assert!(paths.contains(&directory.join("usr/bin/job")));
    }

    /// A script handed to any launcher is read as the shell would read it.
    #[test]
    fn launcher_scripts_are_resolved() {
        let paths = targets(
            "/usr/bin/timeout 5 /bin/sh -c 'cd /srv; ./job --config=/etc/job.conf'",
            &root(),
        )
        .unwrap();
        assert!(paths.contains(&PathBuf::from("/srv/./job")));
        assert!(paths.contains(&PathBuf::from("/etc/job.conf")));
    }
}
