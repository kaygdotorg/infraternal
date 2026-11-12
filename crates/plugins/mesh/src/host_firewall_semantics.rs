//! Compares nft's JSON objects as policy values instead of comparing renderer output.

use super::{AllowRule, IpPrefix, Listener, Policy, PolicyError};
use serde_json::Value;
use std::{fmt::Write as _, net::IpAddr, path::Path, str::FromStr};

/// The policy-bearing objects from one `inet infraternal_host` table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct HostTable {
    /// The input chain's effective hook, priority and default policy.
    chain: Option<HostChain>,
    /// Input rules in their kernel order, which remains meaningful for nft.
    rules: Vec<HostRule>,
    /// Other table objects that the host-policy renderer does not create.
    extras: Vec<Value>,
}

/// The base chain settings that determine when and how input rules run.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HostChain {
    /// The nft chain type, normally `filter`.
    kind: Option<String>,
    /// The netfilter hook, normally `input`.
    hook: Option<String>,
    /// The numeric priority after nft resolves named priority expressions.
    priority: Option<i64>,
    /// The chain's default verdict.
    policy: Option<String>,
}

/// One rule represented as selectors and a final verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HostRule {
    /// Conditions whose order does not change the packet set selected by a rule.
    selectors: Vec<Selector>,
    /// The explicit terminal verdict, or the JSON form of an unrecognized verdict.
    verdict: Option<String>,
}

/// A typed condition extracted from an nft JSON expression.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Selector {
    /// A set of incoming interface names.
    Interface(Vec<String>),
    /// An incoming source network.
    Source(IpPrefix),
    /// A destination address or network.
    Destination(IpPrefix),
    /// One or more conntrack states, treated as an unordered set.
    Conntrack(Vec<String>),
    /// An IP or transport protocol constraint.
    Protocol(String),
    /// A destination transport port, which also implies its protocol.
    DestinationPort { protocol: String, port: u16 },
    /// An expression the product does not need to interpret yet.
    Other(Value),
}

/// Parse the live table JSON into a stable model, ignoring nft handles and comments.
///
/// The caller has already checked that the table exists. Every unknown rule expression
/// remains in the model so a future policy replacement still reports it as a difference.
///
/// # Errors
/// Returns [`PolicyError::BadInventory`] if nft did not return a complete table document.
pub(super) fn from_nft_json(value: &Value, nft: &Path) -> Result<HostTable, PolicyError> {
    let Some(items) = value.get("nftables").and_then(Value::as_array) else {
        return Err(PolicyError::BadInventory {
            path: nft.to_owned(),
        });
    };
    let mut table = HostTable::default();
    let mut found_table = false;
    for item in items {
        if let Some(object) = item.get("table") {
            if object.get("family").and_then(Value::as_str) == Some("inet")
                && object.get("name").and_then(Value::as_str) == Some(super::HOST_TABLE)
            {
                found_table = true;
            }
            continue;
        }
        if let Some(object) = item.get("chain") {
            if belongs_to_host_table(object) {
                found_table = true;
                if object.get("name").and_then(Value::as_str) == Some("input") {
                    table.chain = Some(chain_from_json(object));
                } else {
                    table.extras.push(without_nft_metadata(item));
                }
            }
            continue;
        }
        if let Some(object) = item.get("rule") {
            if belongs_to_host_table(object) {
                found_table = true;
                if object.get("chain").and_then(Value::as_str) == Some("input") {
                    table.rules.push(rule_from_json(object));
                } else {
                    table.extras.push(without_nft_metadata(item));
                }
            }
            continue;
        }
        if nft_object_belongs_to_host_table(item) {
            found_table = true;
            table.extras.push(without_nft_metadata(item));
        }
    }
    if !found_table {
        return Err(PolicyError::BadInventory {
            path: nft.to_owned(),
        });
    }
    Ok(table)
}

/// Build the same semantic model directly from typed product settings.
pub(super) fn from_policy(policy: &Policy) -> HostTable {
    let mut table = HostTable {
        chain: Some(HostChain {
            kind: Some("filter".to_owned()),
            hook: Some("input".to_owned()),
            priority: Some(-10),
            policy: Some("drop".to_owned()),
        }),
        ..HostTable::default()
    };
    for interface in &policy.accept_interfaces {
        table.push_rule(rule(
            [Selector::Interface(vec![interface.clone()])],
            "accept",
        ));
    }
    table.push_rule(rule([Selector::Interface(vec!["lo".to_owned()])], "accept"));
    table.push_rule(rule(
        [Selector::Conntrack(vec!["invalid".to_owned()])],
        "drop",
    ));
    table.push_rule(rule(
        [Selector::Conntrack(vec![
            "established".to_owned(),
            "related".to_owned(),
        ])],
        "accept",
    ));
    table.push_rule(rule([Selector::Protocol("icmp".to_owned())], "accept"));
    table.push_rule(rule([Selector::Protocol("ipv6-icmp".to_owned())], "accept"));
    for admin in &policy.admin_rules {
        table.push_rule(allow_rule(admin));
    }
    for listener in &policy.listeners {
        table.push_listener(listener);
    }
    if policy.mesh_enabled {
        table.push_rule(rule(
            [Selector::Interface(vec!["infraternal0".to_owned()])],
            "accept",
        ));
        table.push_rule(rule(
            [Selector::DestinationPort {
                protocol: "udp".to_owned(),
                port: 10254,
            }],
            "accept",
        ));
    }
    table
}

/// Report structured differences while retaining the existing readable rule summary.
pub(super) fn report(current: Option<&HostTable>, desired: Option<&HostTable>) -> String {
    let empty = HostTable::default();
    let current = current.unwrap_or(&empty);
    let desired = desired.unwrap_or(&empty);
    if current == desired {
        return "host firewall migration: no rule differences\n".to_owned();
    }
    let mut output = String::from("host firewall migration: current and desired rules differ\n");
    if current.chain != desired.chain {
        if let Some(chain) = &current.chain {
            let _ = writeln!(output, "- current: {}", chain.describe());
        }
        if let Some(chain) = &desired.chain {
            let _ = writeln!(output, "+ desired: {}", chain.describe());
        }
    }
    report_ordered_diff(
        &current.rules,
        &desired.rules,
        &mut output,
        HostRule::describe,
    );
    report_ordered_diff(
        &current.extras,
        &desired.extras,
        &mut output,
        describe_extra,
    );
    output
}

/// Ensure an explicit current SSH exception remains present in the candidate policy.
pub(super) fn preserves_admin_rules(current: Option<&HostTable>, desired: &HostTable) -> bool {
    current.is_none_or(|table| {
        table
            .rules
            .iter()
            .filter(|rule| rule.is_admin_ssh())
            .all(|rule| desired.rules.contains(rule))
    })
}

/// Add one product rule only when no earlier setting already rendered the same match.
impl HostTable {
    /// Keep product output duplicate-free just like [`super::render`].
    fn push_rule(&mut self, rule: HostRule) {
        if !self.rules.contains(&rule) {
            self.rules.push(rule);
        }
    }

    /// Add one listener rule for each configured source prefix.
    fn push_listener(&mut self, listener: &Listener) {
        let sources = if listener.sources.is_empty() {
            vec![None]
        } else {
            listener.sources.iter().map(Some).collect()
        };
        for source in sources {
            let mut selectors = Vec::new();
            if let Some(interface) = &listener.interface {
                selectors.push(Selector::Interface(vec![interface.clone()]));
            }
            if let Some(source) = source {
                selectors.push(Selector::Source(source.clone()));
            }
            if !listener.address.ip().is_unspecified() {
                let address = listener.address.ip();
                let prefix = match address {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                selectors.push(Selector::Destination(IpPrefix { address, prefix }));
            }
            selectors.push(Selector::DestinationPort {
                protocol: listener.protocol.to_string(),
                port: listener.address.port(),
            });
            self.push_rule(HostRule {
                selectors: sorted_selectors(selectors),
                verdict: Some("accept".to_owned()),
            });
        }
    }
}

/// Convert one administrator rule into a canonical packet selector set.
fn allow_rule(rule: &AllowRule) -> HostRule {
    let mut selectors = Vec::new();
    if let Some(interface) = &rule.interface {
        selectors.push(Selector::Interface(vec![interface.clone()]));
    }
    if let Some(source) = &rule.source {
        selectors.push(Selector::Source(source.clone()));
    }
    selectors.push(Selector::DestinationPort {
        protocol: rule.protocol.to_string(),
        port: rule.port,
    });
    HostRule {
        selectors: sorted_selectors(selectors),
        verdict: Some("accept".to_owned()),
    }
}

/// Make a rule and sort its selectors without changing its packet meaning.
fn rule<const N: usize>(selectors: [Selector; N], verdict: &str) -> HostRule {
    HostRule {
        selectors: sorted_selectors(selectors.into()),
        verdict: Some(verdict.to_owned()),
    }
}

/// Sort selectors by a stable structural key so nft expression order is irrelevant.
fn sorted_selectors(mut selectors: Vec<Selector>) -> Vec<Selector> {
    selectors.sort_by_key(selector_sort_key);
    selectors
}

/// Return the current table and chain identity for one nft JSON object.
fn belongs_to_host_table(object: &Value) -> bool {
    object.get("family").and_then(Value::as_str) == Some("inet")
        && object.get("table").and_then(Value::as_str) == Some(super::HOST_TABLE)
}

/// Find the containing nft object for sets and other table-level objects.
fn nft_object_belongs_to_host_table(item: &Value) -> bool {
    item.as_object().is_some_and(|objects| {
        objects
            .values()
            .any(|object| object.is_object() && belongs_to_host_table(object))
    })
}

/// Remove metadata that does not change the rules a table applies.
fn without_nft_metadata(item: &Value) -> Value {
    let mut item = item.clone();
    if let Some(object) = item.as_object_mut() {
        for value in object.values_mut() {
            if let Some(value) = value.as_object_mut() {
                value.remove("handle");
                value.remove("comment");
            }
        }
    }
    item
}

/// Decode the input-chain settings and resolve named priorities to numeric values.
fn chain_from_json(object: &Value) -> HostChain {
    HostChain {
        kind: object
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_owned),
        hook: object
            .get("hook")
            .and_then(Value::as_str)
            .map(str::to_owned),
        priority: object.get("prio").and_then(priority_value),
        policy: object
            .get("policy")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

/// Read an integer priority or a named expression such as `filter - 10`.
fn priority_value(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| {
        let text = value.as_str()?.trim();
        if let Ok(number) = text.parse() {
            return Some(number);
        }
        for operator in ['+', '-'] {
            if let Some((base, offset)) = text.split_once(operator) {
                let base = match base.trim() {
                    "raw" => -300,
                    "mangle" => -150,
                    "dstnat" => -100,
                    "filter" => 0,
                    "security" => 50,
                    "srcnat" => 100,
                    _ => return None,
                };
                let offset = offset.trim().parse::<i64>().ok()?;
                return Some(if operator == '+' {
                    base + offset
                } else {
                    base - offset
                });
            }
        }
        None
    })
}

/// Decode all expressions in one rule into selectors and a verdict.
fn rule_from_json(object: &Value) -> HostRule {
    let mut selectors = Vec::new();
    let mut verdict = None;
    if let Some(expressions) = object.get("expr").and_then(Value::as_array) {
        for expression in expressions {
            if expression.get("counter").is_some() {
                continue;
            }
            if expression.get("accept").is_some() {
                verdict = Some("accept".to_owned());
            } else if expression.get("drop").is_some() {
                verdict = Some("drop".to_owned());
            } else if let Some(matched) = expression.get("match") {
                if let Some(mut found) = match_selectors(matched) {
                    selectors.append(&mut found);
                } else {
                    selectors.push(Selector::Other(expression.clone()));
                }
            } else {
                selectors.push(Selector::Other(expression.clone()));
            }
        }
    }
    HostRule {
        selectors: sorted_selectors(selectors),
        verdict,
    }
}

/// Parse an nft match expression into one or more canonical selectors.
fn match_selectors(matched: &Value) -> Option<Vec<Selector>> {
    let left = matched.get("left")?;
    let right = matched.get("right")?;
    if !matches!(matched.get("op").and_then(Value::as_str), Some("==" | "in")) {
        return None;
    }
    if let Some(meta) = left.get("meta") {
        return match meta.get("key").and_then(Value::as_str)? {
            "iifname" => Some(vec![Selector::Interface(string_set(right)?)]),
            "l4proto" => Some(vec![Selector::Protocol(protocol_name(right)?)]),
            _ => None,
        };
    }
    if let Some(conntrack) = left.get("ct") {
        if conntrack.get("key").and_then(Value::as_str) == Some("state") {
            return Some(vec![Selector::Conntrack(conntrack_states(right)?)]);
        }
    }
    let payload = left.get("payload")?;
    let protocol = payload.get("protocol")?.as_str()?;
    let field = payload.get("field")?.as_str()?;
    match (protocol, field) {
        ("ip", "saddr") | ("ip6", "saddr") => Some(vec![Selector::Source(ip_prefix(right)?)]),
        ("ip", "daddr") | ("ip6", "daddr") => Some(vec![Selector::Destination(ip_prefix(right)?)]),
        ("ip", "protocol") => Some(vec![Selector::Protocol(protocol_name(right)?)]),
        ("tcp", "dport") | ("udp", "dport") => Some(vec![Selector::DestinationPort {
            protocol: protocol.to_owned(),
            port: port_number(right)?,
        }]),
        ("th", "dport") => Some(vec![Selector::DestinationPort {
            protocol: "th".to_owned(),
            port: port_number(right)?,
        }]),
        _ => None,
    }
}

/// Parse an interface name or a JSON set of names and return it in stable order.
fn string_set(value: &Value) -> Option<Vec<String>> {
    let values = set_values(value)?;
    let mut names = values
        .into_iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    names.sort();
    Some(names)
}

/// Read JSON set members whether nft emitted a scalar, array or `set` object.
fn set_values(value: &Value) -> Option<Vec<&Value>> {
    if let Some(values) = value.as_array() {
        Some(values.iter().collect())
    } else if let Some(values) = value.get("set").and_then(Value::as_array) {
        Some(values.iter().collect())
    } else {
        Some(vec![value])
    }
}

/// Parse a source or destination prefix from nft's string or prefix-object form.
fn ip_prefix(value: &Value) -> Option<IpPrefix> {
    if let Some(text) = value.as_str() {
        return IpPrefix::from_str(text).ok();
    }
    let prefix = value.get("prefix")?;
    let address = prefix.get("addr")?.as_str()?;
    let length = prefix.get("len")?.as_u64()?;
    IpPrefix::from_str(&format!("{address}/{length}")).ok()
}

/// Read one numeric port from nft's scalar or one-member-set form.
fn port_number(value: &Value) -> Option<u16> {
    let values = set_values(value)?;
    if values.len() != 1 {
        return None;
    }
    values[0]
        .as_u64()
        .and_then(|number| u16::try_from(number).ok())
        .or_else(|| values[0].as_str()?.parse().ok())
}

/// Parse conntrack states from names, numeric constants, or a bit mask.
fn conntrack_states(value: &Value) -> Option<Vec<String>> {
    let values = set_values(value)?;
    let mut states = Vec::new();
    for value in values {
        if let Some(text) = value.as_str() {
            for state in text.split(',') {
                states.push(state_name(state.trim())?);
            }
        } else {
            let number = value.as_u64().or_else(|| {
                value
                    .as_str()?
                    .strip_prefix("0x")
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            })?;
            states.extend(states_from_mask(number)?);
        }
    }
    states.sort();
    states.dedup();
    Some(states)
}

/// Expand one conntrack mask into its named state bits.
fn states_from_mask(mask: u64) -> Option<Vec<String>> {
    let known = [
        (1, "invalid"),
        (2, "established"),
        (4, "related"),
        (8, "new"),
        (64, "untracked"),
        (128, "snat"),
        (256, "dnat"),
    ];
    let states = known
        .into_iter()
        .filter_map(|(bit, name)| (mask & bit != 0).then_some(name.to_owned()))
        .collect::<Vec<_>>();
    let known_mask = known.iter().fold(0, |bits, (bit, _)| bits | *bit);
    (!states.is_empty() && mask & !known_mask == 0).then_some(states)
}

/// Map an nft protocol name or number into its canonical protocol name.
fn protocol_name(value: &Value) -> Option<String> {
    let text = value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|number| number.to_string()))?;
    Some(match text.as_str() {
        "1" => "icmp".to_owned(),
        "6" => "tcp".to_owned(),
        "17" => "udp".to_owned(),
        "58" => "ipv6-icmp".to_owned(),
        other => other.to_owned(),
    })
}

/// Map one symbolic or numeric conntrack state to its stable name.
fn state_name(value: &str) -> Option<String> {
    let numeric = value.parse::<u64>().ok().or_else(|| {
        value
            .strip_prefix("0x")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
    });
    if let Some(numeric) = numeric {
        let states = states_from_mask(numeric)?;
        return (states.len() == 1).then(|| states[0].clone());
    }
    matches!(
        value,
        "invalid" | "established" | "related" | "new" | "untracked" | "snat" | "dnat"
    )
    .then(|| value.to_owned())
}

/// Create an expression-order key used only to sort equivalent selector sets.
fn selector_sort_key(selector: &Selector) -> String {
    format!("{selector:?}")
}

/// Identify current explicit TCP/22 accepts that must stay in the candidate.
impl HostRule {
    /// Return whether this direct rule admits an administrator SSH path.
    fn is_admin_ssh(&self) -> bool {
        self.verdict.as_deref() == Some("accept")
            && self.selectors.iter().any(|selector| {
                matches!(
                    selector,
                    Selector::DestinationPort { protocol, port: 22 } if protocol == "tcp"
                )
            })
    }

    /// Write a stable human-readable rule line after semantic comparison is complete.
    fn describe(&self) -> String {
        let mut parts = Vec::new();
        for selector in &self.selectors {
            match selector {
                Selector::Interface(names) => {
                    if let [interface] = names.as_slice() {
                        parts.push(format!("iifname \"{interface}\""));
                    } else {
                        parts.push(format!("iifname {{ {} }}", names.join(", ")));
                    }
                }
                Selector::Source(prefix) => parts.push(format!(
                    "{} saddr {prefix}",
                    if prefix.address().is_ipv4() {
                        "ip"
                    } else {
                        "ip6"
                    }
                )),
                Selector::Destination(prefix) => parts.push(format!(
                    "{} daddr {prefix}",
                    if prefix.address().is_ipv4() {
                        "ip"
                    } else {
                        "ip6"
                    }
                )),
                Selector::Conntrack(states) => {
                    parts.push(format!("ct state {}", states.join(",")));
                }
                Selector::Protocol(protocol) if protocol == "icmp" => {
                    parts.push("ip protocol icmp".to_owned());
                }
                Selector::Protocol(protocol) if protocol == "ipv6-icmp" => {
                    parts.push("meta l4proto ipv6-icmp".to_owned());
                }
                Selector::Protocol(protocol) => {
                    parts.push(format!("meta l4proto {protocol}"));
                }
                Selector::DestinationPort { protocol, port } => {
                    parts.push(format!("{protocol} dport {port}"));
                }
                Selector::Other(expression) => parts.push(format!("nft expression {expression}")),
            }
        }
        if let Some(verdict) = &self.verdict {
            parts.push(verdict.clone());
        }
        parts.join(" ")
    }
}

/// Describe the canonical base-chain values used in difference reports.
impl HostChain {
    /// Format resolved values rather than nft's original priority spelling.
    fn describe(&self) -> String {
        let kind = self.kind.as_deref().unwrap_or("unknown");
        let hook = self.hook.as_deref().unwrap_or("unknown");
        let priority = self
            .priority
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
        let policy = self.policy.as_deref().unwrap_or("unknown");
        format!("type {kind} hook {hook} priority {priority}; policy {policy};")
    }
}

/// Check that nft-normalized priority, conntrack and protocol values match product policy.
#[cfg(test)]
mod tests {
    use super::{from_nft_json, from_policy, report, states_from_mask};
    use crate::host_firewall::{AllowRule, Policy};
    use serde_json::json;
    use std::path::Path;

    /// Ignore nft's spelling of equivalent priority, state masks and ICMP protocols.
    #[test]
    fn nft_json_normalization_matches_the_typed_policy() {
        let policy = Policy {
            admin_rules: vec![
                "wt0,10.69.69.0/24,tcp,22"
                    .parse::<AllowRule>()
                    .expect("valid SSH rule"),
            ],
            accept_interfaces: vec!["wt0".to_owned()],
            ..Policy::default()
        };
        let current_json = json!({
            "nftables": [
                {"table": {"family": "inet", "name": "infraternal_host", "handle": 1}},
                {"chain": {"family": "inet", "table": "infraternal_host", "name": "input", "type": "filter", "hook": "input", "prio": "filter - 10", "policy": "drop", "handle": 2}},
                {"rule": {"family": "inet", "table": "infraternal_host", "chain": "input", "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wt0"}}, {"counter": {"packets": 9, "bytes": 512}}, {"accept": null}
                ]}},
                {"rule": {"family": "inet", "table": "infraternal_host", "chain": "input", "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": null}
                ]}},
                {"rule": {"family": "inet", "table": "infraternal_host", "chain": "input", "expr": [
                    {"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "0x1"}}, {"drop": null}
                ]}},
                {"rule": {"family": "inet", "table": "infraternal_host", "chain": "input", "expr": [
                    {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "0x4,0x2"}}, {"accept": null}
                ]}},
                {"rule": {"family": "inet", "table": "infraternal_host", "chain": "input", "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "protocol"}}, "right": 1}}, {"accept": null}
                ]}},
                {"rule": {"family": "inet", "table": "infraternal_host", "chain": "input", "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": 58}}, {"accept": null}
                ]}},
                {"rule": {"family": "inet", "table": "infraternal_host", "chain": "input", "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.69.69.0", "len": 24}}}},
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wt0"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"accept": null}
                ]}}
            ]
        });
        let current =
            from_nft_json(&current_json, Path::new("/usr/sbin/nft")).expect("valid nft JSON table");
        let desired = from_policy(&policy);

        assert_eq!(
            report(Some(&current), Some(&desired)),
            "host firewall migration: no rule differences\n"
        );
    }

    /// Keep unknown conntrack mask bits visible instead of silently treating them as known.
    #[test]
    fn unknown_conntrack_mask_bits_are_not_accepted() {
        assert_eq!(states_from_mask(0x8000_0000), None);
    }
}

/// Render an extra JSON object for a useful, stable migration receipt.
fn describe_extra(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "unrenderable nft object".to_owned())
}

/// Report ordered differences by comparing typed values and formatting only for display.
fn report_ordered_diff<T: Eq>(
    current: &[T],
    desired: &[T],
    output: &mut String,
    describe: impl Fn(&T) -> String,
) {
    let mut common = vec![vec![0; desired.len() + 1]; current.len() + 1];
    for current_index in (0..current.len()).rev() {
        for desired_index in (0..desired.len()).rev() {
            common[current_index][desired_index] =
                if current[current_index] == desired[desired_index] {
                    common[current_index + 1][desired_index + 1] + 1
                } else {
                    common[current_index + 1][desired_index]
                        .max(common[current_index][desired_index + 1])
                };
        }
    }
    let mut current_index = 0;
    let mut desired_index = 0;
    while current_index < current.len() || desired_index < desired.len() {
        if current_index < current.len()
            && desired_index < desired.len()
            && current[current_index] == desired[desired_index]
        {
            current_index += 1;
            desired_index += 1;
        } else if desired_index < desired.len()
            && (current_index == current.len()
                || common[current_index][desired_index + 1]
                    >= common[current_index + 1][desired_index])
        {
            let _ = writeln!(output, "+ desired: {}", describe(&desired[desired_index]));
            desired_index += 1;
        } else {
            let _ = writeln!(output, "- current: {}", describe(&current[current_index]));
            current_index += 1;
        }
    }
}
