//! Select the locale variables passed through the scrubbed session environment.
use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    process::{Command, Stdio},
    sync::OnceLock,
};

pub(super) fn environment() -> Vec<(OsString, OsString)> {
    let inherited = std::env::vars_os()
        .filter(|(name, _)| is_locale_name(name))
        .collect::<Vec<_>>();
    if inherited.iter().any(|(name, _)| is_lang_name(name)) {
        return inherited;
    }

    static HOST_LANG: OnceLock<Option<OsString>> = OnceLock::new();
    let mut variables = inherited;
    if let Some(language) = HOST_LANG
        .get_or_init(|| host_language().map(OsString::from))
        .clone()
    {
        variables.push((OsString::from("LANG"), language));
    }
    variables
}

fn is_locale_name(name: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    is_lang_name(name) || name.as_bytes().starts_with(b"LC_")
}

fn is_lang_name(name: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    name.as_bytes() == b"LANG"
}

fn host_language() -> Option<String> {
    let files = system_locale_files();
    let contents = files.iter().map(String::as_str).collect::<Vec<_>>();
    select_language(&contents, locale_is_installed)
}

#[cfg(target_os = "linux")]
fn system_locale_files() -> Vec<String> {
    ["/etc/default/locale", "/etc/locale.conf"]
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect()
}

// macOS obtains the user's locale from the environment installed by that user's
// launch context. Keep those values in `environment`; only the POSIX fallback
// below is consulted when the launch context supplied no locale.
#[cfg(not(target_os = "linux"))]
fn system_locale_files() -> Vec<String> {
    Vec::new()
}

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

fn configured_languages(contents: &str) -> impl Iterator<Item = String> + '_ {
    contents.lines().filter_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == "LANG")
            .then(|| locale_value(value))
            .flatten()
    })
}

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

fn locale_is_installed(locale: &str) -> bool {
    static INSTALLED: OnceLock<Option<HashSet<String>>> = OnceLock::new();
    INSTALLED
        .get_or_init(installed_locales)
        .as_ref()
        .is_some_and(|locales| locales.contains(&normalize_locale(locale)))
}

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

fn normalize_locale(locale: &str) -> String {
    // `locale -a` commonly spells C.UTF-8 as C.utf8; punctuation and case do
    // not distinguish those installed aliases from the configured spelling.
    locale
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

#[cfg(test)]
fn select_environment(
    mut inherited: Vec<(OsString, OsString)>,
    configs: &[&str],
    installed: impl FnMut(&str) -> bool,
) -> Vec<(OsString, OsString)> {
    inherited.retain(|(name, _)| is_locale_name(name));
    if !inherited.iter().any(|(name, _)| is_lang_name(name)) {
        if let Some(language) = select_language(configs, installed) {
            inherited.push((OsString::from("LANG"), OsString::from(language)));
        }
    }
    inherited
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
        assert!(unavailable.is_empty());
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
}
