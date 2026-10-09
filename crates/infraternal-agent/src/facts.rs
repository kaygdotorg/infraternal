//! Returns bounded cheap native host facts over the authenticated control channel [145][156].
use serde::{Deserialize, Serialize};

/// No network addresses, listeners, workloads, or external commands are collected.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostFacts {
    pub os: String,
    pub arch: String,
    pub execution_uid: u32,
    pub version: String,
    pub logical_cpus: u32,
}

impl HostFacts {
    /// Static platform identity and OS concurrency policy require no subprocesses or polling.
    #[must_use]
    pub fn collect() -> Self {
        Self {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            execution_uid: nix::unistd::Uid::effective().as_raw(),
            version: env!("CARGO_PKG_VERSION").into(),
            logical_cpus: std::thread::available_parallelism()
                .ok()
                .and_then(|n| u32::try_from(n.get()).ok())
                .unwrap_or(1),
        }
    }
}

/// Facts has no discovery parameters; callers and fuzzers share this exact decoder.
#[must_use]
pub fn accepts_request(bytes: &[u8]) -> bool {
    bytes.len() <= 256 && serde_json::from_slice::<Input>(bytes).is_ok()
}

/// Reject non-object forms and parameters instead of turning cheap facts into discovery.
/// Empty derived structs also accept arrays, so demand map syntax explicitly.
struct Input {}
impl<'de> Deserialize<'de> for Input {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct EmptyObject;
        impl<'de> serde::de::Visitor<'de> for EmptyObject {
            type Value = Input;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an empty host facts object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Input, A::Error> {
                if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("host facts takes no parameters"));
                }
                Ok(Input {})
            }
        }
        decoder.deserialize_map(EmptyObject)
    }
}
