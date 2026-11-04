//! Converts an address or reported hostname into its safe machine label for shared inventory presentation.

/// The machine name in an address (`user@minipc01`, `minipc01.lan:22`) or reported hostname.
///
/// Takes the first DNS label, lowercased. Anything address-like gives nothing, so a numeric address never becomes
/// a name and the caller can use another source: IPv4 in any spelling (shortened `10.69.69`, hex `0x0a.0x45`,
/// octal), IPv6 in any spelling (bracketed, with a zone `%eth0` or `%25eth0`), and labels made only of digits.
/// Invalid host labels and `localhost` also give nothing (D339: those fall back to [`fallback_machine_name`]).
#[must_use]
pub fn machine_name(source: &str) -> Option<String> {
    let host = source
        .rsplit_once('@')
        .map_or(source, |(_, host)| host)
        .trim();
    // Two colons, a bracket or a zone mark only occur in IPv6 spellings; one colon separates a port.
    if host.matches(':').count() > 1 || host.contains(['[', '%']) {
        return None;
    }
    let host = host.split_once(':').map_or(host, |(host, _)| host);
    if is_ipv4_spelling(host) {
        return None;
    }
    let label = host.split('.').next()?.to_ascii_lowercase();
    if label.bytes().all(|byte| byte.is_ascii_digit())
        || label.is_empty()
        || label.len() > 63
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || label.starts_with('-')
        || label.ends_with('-')
        // D339: `localhost` says nothing about the machine, so it is treated like an empty name.
        || label == "localhost"
    {
        return None;
    }
    Some(label)
}

/// The name of a machine that reports no usable hostname (D339): `<os>-<first 6 characters of the host id>`.
///
/// The id is the host's UUID without dashes, lowercased (any other id keeps its first six letters and digits, so
/// the label is never empty or malformed), so the same machine always gets the same fallback and
/// two machines differ unless their ids share six hex digits (the caller then suffixes the later one).
/// `os` is whatever the machine reported (`Debian GNU/Linux`, `macOS`); unknown or missing gives `host`, which
/// never claims an operating system the machine did not report.
#[must_use]
pub fn fallback_machine_name(os: Option<&str>, host_id: &str) -> String {
    let id: String = host_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(6)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    format!("{}-{id}", os_family(os))
}

/// The short operating-system word used in fallback names.
fn os_family(os: Option<&str>) -> &'static str {
    let os = os.unwrap_or_default().to_ascii_lowercase();
    if os.contains("mac") || os.contains("darwin") {
        "macos"
    } else if os.contains("windows") {
        "windows"
    } else if os.contains("bsd") {
        "freebsd"
    } else if os.contains("linux") || os.contains("debian") || os.contains("ubuntu") {
        "linux"
    } else {
        "host"
    }
}

/// Whether `host` is an IPv4 address in any spelling the C resolver accepts: one to four dot-separated numbers,
/// each decimal, octal (leading `0`) or hex, so `10.69.69`, `0x0a454505` and `0x7f.1` are addresses too.
fn is_ipv4_spelling(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let number = |part: &str| match part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        Some(hex) => hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()),
    };
    !host.is_empty() && host.split('.').count() <= 4 && host.split('.').all(number)
}

#[cfg(test)]
#[path = "host_name_tests.rs"]
mod tests;
