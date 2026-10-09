//! Defines the stable interface used by compiled first-party plugin crates [15][16].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod channel;

/// Static operator action metadata shared by adapter help and generated skills [16][202].
pub struct ActionDef {
    /// Stable action identifier.
    pub id: &'static str,
    /// Concise operator description.
    pub summary: &'static str,
    /// Ordered instructions; no invocation-specific material belongs here.
    pub instructions: &'static [&'static str],
}

/// A plugin's runtime setting and its explicit default [198].
pub struct SettingDef {
    /// Stable setting identifier.
    pub id: &'static str,
    /// Human meaning of the setting.
    pub summary: &'static str,
    /// Serialized default; optional coordinates use null.
    pub default: &'static str,
}

/// Build-time descriptor; reading it starts no work and grants no server role [198][201].
pub struct PluginDescriptor {
    /// Unique compiled plugin identifier.
    pub id: &'static str,
    /// Shared interface version.
    pub api: u16,
    /// Operator actions, including ordered instructions.
    pub actions: &'static [ActionDef],
    /// Explicit settings and defaults.
    pub settings: &'static [SettingDef],
    /// Roles that must already exist before an action may activate.
    pub role_dependencies: &'static [&'static str],
}

impl ActionDef {
    /// Render the declared steps for operator help without a second copy of the instructions.
    #[must_use]
    pub fn help(&self) -> String {
        use std::fmt::Write;
        let mut help = self.summary.to_owned();
        for (index, step) in self.instructions.iter().enumerate() {
            // Formatting into an owned String cannot fail; only static metadata is included.
            let _ = write!(help, "\n{}. {step}", index + 1);
        }
        help
    }
}
