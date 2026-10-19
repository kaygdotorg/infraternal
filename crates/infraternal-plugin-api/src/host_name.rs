//! Converts an address or reported hostname into its safe machine label for shared inventory presentation.

/// The machine name in an address (`user@minipc01`, `minipc01.lan:22`) or reported hostname.
///
/// Takes the first DNS label, lowercased. Anything address-like gives nothing, so a numeric address never becomes
/// a name and the caller can use another source: IPv4 in any spelling (shortened `10.69.69`, hex `0x0a.0x45`,
/// octal), IPv6 in any spelling (bracketed, with a zone `%eth0` or `%25eth0`), and labels made only of digits.
/// Invalid host labels and reserved labels for unnamed machines also give nothing.
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
        || is_unnamed_label(&label)
    {
        return None;
    }
    Some(label)
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

/// Labels reserved to describe machines whose actual name is not known.
fn is_unnamed_label(name: &str) -> bool {
    name == "unnamed"
        || name
            .strip_prefix("unnamed-")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|byte| byte.is_ascii_digit()))
}
