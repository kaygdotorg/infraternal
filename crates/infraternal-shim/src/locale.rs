//! Select the locale variables passed through the scrubbed session environment.
use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    process::{Command, Stdio},
    sync::OnceLock,
};

// Host locale configuration is stable during the agent lifetime. Cache it so
// session creation does not repeat filesystem reads or locale inventory work.
static HOST_LANG: OnceLock<Option<OsString>> = OnceLock::new();

/// The locale variables (`LANG` and every `LC_*`) to give a new session, as
/// name/value pairs.
///
/// Inherited values are passed through as they are. If the environment has no
/// `LANG`, the host's configured language is added, but only when that locale is
/// installed. The host lookup runs once per process and its result is reused.
pub(super) fn environment() -> Vec<(OsString, OsString)> {
    let inherited = std::env::vars_os()
        .filter(|(name, _)| is_locale_name(name))
        .collect::<Vec<_>>();
    if inherited.iter().any(|(name, _)| is_lang_name(name)) {
        return inherited;
    }

    let mut variables = inherited;
    if let Some(language) = HOST_LANG
        .get_or_init(|| host_language().map(OsString::from))
        .clone()
    {
        variables.push((OsString::from("LANG"), language));
    }
    variables
}

/// True for `LANG` and any name starting with `LC_`.
fn is_locale_name(name: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    is_lang_name(name) || name.as_bytes().starts_with(b"LC_")
}

/// True only for the exact name `LANG`.
fn is_lang_name(name: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    name.as_bytes() == b"LANG"
}

/// The best installed language for the host, or `None`. Reads the system's
/// locale configuration and checks each candidate against the installed locales.
fn host_language() -> Option<String> {
    let files = system_locale_files();
    let contents = files.iter().map(String::as_str).collect::<Vec<_>>();
    select_language(&contents, locale_is_installed)
}

/// Contents of the system locale configuration files that exist
/// (`/etc/default/locale` and `/etc/locale.conf`), in that order.
#[cfg(target_os = "linux")]
fn system_locale_files() -> Vec<String> {
    ["/etc/default/locale", "/etc/locale.conf"]
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect()
}

// macOS stores the user's region locale in AppleLocale. Query it only when the
// launch context supplied no LANG; inherited LC_* overrides remain untouched.
/// One synthetic `LANG=<locale>` line built from the user's `AppleLocale`
/// setting, or nothing if it cannot be read. It is only asked for when no `LANG`
/// was inherited.
#[cfg(target_os = "macos")]
fn system_locale_files() -> Vec<String> {
    let Ok(output) = Command::new("/usr/bin/defaults")
        .args(["read", "-g", "AppleLocale"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let Ok(value) = String::from_utf8(output.stdout) else {
        return Vec::new();
    };
    value
        .lines()
        .next()
        .and_then(macos_locale_to_posix)
        .map(|locale| vec![format!("LANG={locale}")])
        .unwrap_or_default()
}

/// Other platforms have no locale configuration to read.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn system_locale_files() -> Vec<String> {
    Vec::new()
}

/// Picks the first `LANG` value in `configs` that `installed` accepts. If none
/// qualifies, falls back to `C.UTF-8` when it is installed; otherwise `None`.
fn select_language(configs: &[&str], mut installed: impl FnMut(&str) -> bool) -> Option<String> {
    for config in configs {
        for locale in configured_languages(config) {
            if installed(&locale) {
                return Some(locale);
            }
        }
    }
    installed("C.UTF-8").then(|| "C.UTF-8".to_owned())
}

/// Yields every `LANG=value` assignment found in `contents`, skipping lines
/// whose value is not a plain, safe locale name (see `locale_value`).
fn configured_languages(contents: &str) -> impl Iterator<Item = String> + '_ {
    contents.lines().filter_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == "LANG")
            .then(|| locale_value(value))
            .flatten()
    })
}

/// Cleans one assignment value: trims, removes matching quotes and a trailing
/// `#` comment. Returns `None` when it is empty, has stray text after a closing
/// quote, or contains characters other than letters, digits and `._@+-`, so
/// nothing odd is ever passed to a shell's environment.
fn locale_value(value: &str) -> Option<String> {
    let value = value.trim();
    let value = if let Some(quote) = value
        .as_bytes()
        .first()
        .copied()
        .filter(|b| *b == b'\'' || *b == b'"')
    {
        let end = value[1..].find(char::from(quote))? + 1;
        let tail = value[end + 1..].trim();
        if !tail.is_empty() && !tail.starts_with('#') {
            return None;
        }
        &value[1..end]
    } else {
        value
            .split_once('#')
            .map_or(value, |(value, _)| value)
            .trim()
    };
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@+-".contains(&byte))
    {
        return None;
    }
    Some(value.to_owned())
}

/// True if `locale` is installed, comparing without case or punctuation. The
/// installed list is read once per process.
fn locale_is_installed(locale: &str) -> bool {
    static INSTALLED: OnceLock<Option<HashSet<String>>> = OnceLock::new();
    INSTALLED
        .get_or_init(installed_locales)
        .as_ref()
        .is_some_and(|locales| locales.contains(&normalize_locale(locale)))
}

/// The set of normalized names printed by `locale -a`, run with a cleared
/// environment, or `None` if the command is missing or fails.
fn installed_locales() -> Option<HashSet<String>> {
    let output = Command::new("/usr/bin/locale")
        .arg("-a")
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8(output.stdout)
            .ok()?
            .lines()
            .map(normalize_locale)
            .collect(),
    )
}

/// Lowercases and strips everything but letters and digits, so `C.UTF-8` and
/// `C.utf8` compare equal.
fn normalize_locale(locale: &str) -> String {
    // `locale -a` commonly spells C.UTF-8 as C.utf8; punctuation and case do
    // not distinguish those installed aliases from the configured spelling.
    locale
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

/// Test helper: the same decision as `environment`, with the inherited
/// variables, configuration text and installed check supplied by the caller.
#[cfg(test)]
fn select_environment(
    mut inherited: Vec<(OsString, OsString)>,
    configs: &[&str],
    installed: impl FnMut(&str) -> bool,
) -> Vec<(OsString, OsString)> {
    inherited.retain(|(name, _)| is_locale_name(name));
    if !inherited.iter().any(|(name, _)| is_lang_name(name))
        && let Some(language) = select_language(configs, installed)
    {
        inherited.push((OsString::from("LANG"), OsString::from(language)));
    }
    inherited
}

/// Turns a macOS locale identifier such as `en_US` into a POSIX one, adding
/// `.UTF-8` when it has no encoding. `None` if the identifier is not a safe name.
#[cfg(any(target_os = "macos", test))]
fn macos_locale_to_posix(identifier: &str) -> Option<String> {
    let locale = locale_value(identifier)?;
    if locale.contains('.') {
        Some(locale)
    } else {
        Some(format!("{locale}.UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(values: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        values
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    #[test]
    fn configured_locale_is_selected_from_login_locale_files() {
        let actual = select_environment(
            Vec::new(),
            &[
                "# generated locale settings\nLANG=$(invalid)",
                "LANG=\"fr_FR.UTF-8\" # configured by the host",
            ],
            |locale| locale == "fr_FR.UTF-8",
        );
        assert_eq!(actual, pairs(&[("LANG", "fr_FR.UTF-8")]));
    }

    #[test]
    fn unsupported_configured_locale_uses_installed_utf8_fallback() {
        let actual = select_environment(Vec::new(), &["LANG=missing_LOCALE"], |locale| {
            locale == "C.UTF-8"
        });
        assert_eq!(actual, pairs(&[("LANG", "C.UTF-8")]));
    }

    #[test]
    fn absent_locale_uses_fallback_only_when_it_is_installed() {
        let available = select_environment(Vec::new(), &[], |locale| locale == "C.UTF-8");
        let unavailable = select_environment(Vec::new(), &[], |_| false);
        assert_eq!(available, pairs(&[("LANG", "C.UTF-8")]));
        assert_eq!(unavailable, Vec::new());
    }

    #[test]
    fn existing_user_locale_values_are_preserved_without_replacement() {
        let actual = select_environment(
            pairs(&[("LANG", "user_LOCALE"), ("LC_TIME", "user_TIME")]),
            &["LANG=system_LOCALE"],
            |_| panic!("an existing user LANG must bypass host locale selection"),
        );
        assert_eq!(
            actual,
            pairs(&[("LANG", "user_LOCALE"), ("LC_TIME", "user_TIME")])
        );
    }

    #[test]
    fn missing_lang_preserves_other_locale_values_and_fills_only_lang() {
        let actual = select_environment(
            pairs(&[("LC_ALL", "user_ALL"), ("LC_TIME", "user_TIME")]),
            &["LANG=system_LOCALE"],
            |locale| locale == "system_LOCALE",
        );
        assert_eq!(
            actual,
            pairs(&[
                ("LC_ALL", "user_ALL"),
                ("LC_TIME", "user_TIME"),
                ("LANG", "system_LOCALE")
            ])
        );
    }

    #[test]
    fn non_locale_values_do_not_cross_the_scrubbed_shell_boundary() {
        let actual = select_environment(
            pairs(&[
                ("LANG", "user_LOCALE"),
                ("LC_TIME", "user_TIME"),
                ("UNRELATED_SETTING", "kept_out"),
            ]),
            &["LANG=system_LOCALE"],
            |_| panic!("an existing user LANG must bypass host locale selection"),
        );
        assert_eq!(
            actual,
            pairs(&[("LANG", "user_LOCALE"), ("LC_TIME", "user_TIME")])
        );
    }

    #[test]
    fn invalid_shell_expressions_are_ignored() {
        let actual = select_environment(Vec::new(), &["LANG=$(unexpected-command)"], |locale| {
            locale == "C.UTF-8"
        });
        assert_eq!(actual, pairs(&[("LANG", "C.UTF-8")]));
    }

    #[test]
    fn macos_locale_identifier_gets_a_utf8_codeset() {
        assert_eq!(
            macos_locale_to_posix("en_US"),
            Some("en_US.UTF-8".to_owned())
        );
        assert_eq!(
            macos_locale_to_posix("fr_FR.ISO8859-1"),
            Some("fr_FR.ISO8859-1".to_owned())
        );
    }
}
