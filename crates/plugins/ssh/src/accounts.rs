//! Declares per-person preferred login accounts and delegates trusted persistence [16][229][231].
use infraternal_plugin_api::{
    API_VERSION, ActionDef, DryRun, Effect, Operation, Permission, PluginDescriptor, SchemaRef,
    Target,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A host without an id is the server's own host, reached through its embedded infraternal agent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub host_id: Option<uuid::Uuid>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Global,
    Host,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub scope: Scope,
    pub host_id: Option<uuid::Uuid>,
    /// None resets this scope to its default; it never names an operating-system uid.
    pub account: Option<String>,
}
#[derive(Serialize)]
pub struct Preference {
    pub account: String,
    pub global_account: String,
    pub host_account: Option<String>,
}
/// The host rechecks this person's exact session and host ownership inside the writer transaction.
pub trait Backend: Send + Sync {
    fn get<'a>(
        &'a self,
        person: &'a str,
        token_hash: &'a str,
        selection: Selection,
    ) -> Operation<'a, Result<Preference, &'static str>>;
    fn set<'a>(
        &'a self,
        person: &'a str,
        token_hash: &'a str,
        change: Change,
    ) -> Operation<'a, Result<Preference, &'static str>>;
}
/// Only account names cross the API; the authenticated infraternal agent resolves them locally.
#[must_use]
pub fn valid_account(account: &str) -> bool {
    // Match the host resolver before persistence so syntax cannot fail only at open.
    account.len() <= 32
        && account
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        && account
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
/// Dispatch the single declared action definitions for socket, CLI and future adapters.
/// # Errors
/// Refuses invalid input and propagates sanitized authorization or storage failures.
pub async fn call(
    backend: &dyn Backend,
    person: &str,
    token_hash: &str,
    action: &str,
    input: &[u8],
) -> Result<Value, &'static str> {
    if input.len() > 1024 || input.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err("invalid input");
    }
    let preference = match action {
        "ssh-accounts.get" => {
            backend
                .get(
                    person,
                    token_hash,
                    serde_json::from_slice(input).map_err(|_| "invalid input")?,
                )
                .await?
        }
        "ssh-accounts.set" => {
            let change: Change = serde_json::from_slice(input).map_err(|_| "invalid input")?;
            if (change.scope == Scope::Global && change.host_id.is_some())
                || change
                    .account
                    .as_deref()
                    .is_some_and(|account| !valid_account(account))
            {
                return Err("invalid input");
            }
            backend.set(person, token_hash, change).await?
        }
        _ => return Err("unknown action"),
    };
    serde_json::to_value(preference).map_err(|_| "preferences unavailable")
}
const fn action(
    id: &'static str,
    summary: &'static str,
    input: &'static str,
    effect: Effect,
) -> ActionDef {
    ActionDef {
        id,
        summary,
        instructions: &[
            "Sign in.",
            "Choose your global preferred account or an account for an authorized host.",
        ],
        input: SchemaRef(input),
        output: SchemaRef("ssh-accounts.preference"),
        target: Target::Global,
        effect,
        permission: Permission::One("authenticated"),
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    }
}
/// Login account preferences are removable independently of host provisioning [198].
pub static DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "ssh-accounts",
    api: API_VERSION,
    topics: &[],
    roles: &[infraternal_plugin_api::RoleDef {
        id: "server",
        requires: &["server"],
        default_enabled: true,
    }],
    max_frame_len: 2048,
    unavailable: br#"{"error":"Login account preferences are off"}"#,
    unavailable_event: br#"{"error":"Login account preferences are off"}"#,
    actions: &[
        action(
            "ssh-accounts.get",
            "Read your preferred login account",
            "ssh-accounts.selection",
            Effect::Read,
        ),
        action(
            "ssh-accounts.set",
            "Set your preferred login account",
            "ssh-accounts.change",
            Effect::Write,
        ),
    ],
    events: &[],
    streams: &[],
    settings: None,
    defaults: &[],
    dependencies: &[infraternal_plugin_api::Dependency::ExistingServer],
    can_enable_components: &[],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_names_match_host_resolver_prefix_rule() {
        for invalid in [".user", " user", ""] {
            assert!(!valid_account(invalid), "invalid account prefix: {invalid}");
        }
        for valid in [
            "-user",
            "_operator",
            "alice",
            "1001",
            "service-user",
            "user.name",
        ] {
            assert!(valid_account(valid), "valid account refused: {valid}");
        }
    }

    #[test]
    fn account_descriptor_adapts_to_valid_cli_commands() {
        let registry = infraternal_plugin_api::ActionRegistry::new(vec![
            DESCRIPTOR.cli_plugin(infraternal_plugin_api::ActionTarget::Global),
        ]);
        let registry = registry.expect("hyphenated account commands must validate");
        assert!(registry.find(&["ssh-accounts", "get"]).is_some());
        assert!(registry.find(&["ssh-accounts", "set"]).is_some());
        assert!(DESCRIPTOR.validate().is_ok());
    }
}
