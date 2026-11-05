//! Collects fixed, bounded host identity and on-request live counters without subprocesses or network access.

use infraternal_plugin_api::{ActionDef, AgentPlugin, Effect, PluginDescriptor, PluginError};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs::File, io::Read, path::Path};

/// Maximum JSON body parsed by the host facts actions.
pub const MAX_FACTS_REQUEST_BYTES: usize = 1_024;
const MAX_OS_RELEASE_BYTES: usize = 16 * 1_024;
const MAX_OS_RELEASE_LINE_BYTES: usize = 1_024;
const MAX_OS_LABEL_BYTES: usize = 256;
const MAX_PROC_FILE_BYTES: usize = 64 * 1_024;
const READ_ACTION: &str = "host.facts.read";
const MEMORY_ACTION: &str = "host.memory.configure";
const CONFIGURE_ACTION: &str = "host.facts.configure";

const ACTIONS: &[ActionDef] = &[
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
        id: MEMORY_ACTION,
        summary: "Configure memory headroom for new terminal sessions",
        input: infraternal_plugin_api::SchemaRef(
            r#"{"type":"object","required":["terminalMemoryFloorMiB","terminalMemoryFloorPercent"],"properties":{"terminalMemoryFloorMiB":{"type":"integer","minimum":0,"maximum":17592186044415},"terminalMemoryFloorPercent":{"type":"integer","minimum":0,"maximum":100}},"additionalProperties":false}"#,
        ),
        output: infraternal_plugin_api::SchemaRef(
            r#"{"type":"object","properties":{"terminalMemoryFloorMiB":{"type":"integer"},"terminalMemoryFloorPercent":{"type":"integer"}},"additionalProperties":false}"#,
        ),
        instructions: &[
            "Choose the host to configure.",
            "Set both the absolute MiB floor and percentage of total RAM; the larger floor applies.",
        ],
        effect: Effect::Write,
        permission: infraternal_plugin_api::Permission::One(CONFIGURE_ACTION),
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
        id: READ_ACTION,
        summary: "Read host identity and current resource use",
        input: infraternal_plugin_api::SchemaRef(
            r#"{"type":"object","properties":{"includeLive":{"type":"boolean"}},"additionalProperties":false}"#,
        ),
        output: infraternal_plugin_api::SchemaRef(
            r#"{"type":"object","properties":{"os":{"type":"string"},"version":{"type":"string"},"kernel":{"type":"string"},"architecture":{"type":"string"},"model":{"type":"string"},"cpuModel":{"type":"string"},"logicalCpus":{"type":"integer"},"sessionCount":{"type":"integer","minimum":0},"backgroundSessionCount":{"type":"integer","minimum":0},"memory":{"type":"object"},"rootDisk":{"type":"object"},"uptimeSeconds":{"type":"integer"},"loadAverage":{"type":"array","items":{"type":"number"},"minItems":3,"maxItems":3},"mode":{"enum":["embedded","remote"]},"executionUid":{"type":"integer"},"engines":{"type":"array","items":{"enum":["Docker","Podman"]}},"init":{"type":"string"},"virtualization":{"type":"string"},"shell":{"type":"string"},"locale":{"type":"string"},"hostname":{"type":"string"}},"required":["os","version","kernel","architecture","logicalCpus","mode","executionUid","engines"],"additionalProperties":false}"#,
        ),
        instructions: &[
            "Choose the host whose identity is needed.",
            "Read its facts; include live counters only when needed.",
        ],
        effect: Effect::Read,
        permission: infraternal_plugin_api::Permission::One(READ_ACTION),
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
        id: CONFIGURE_ACTION,
        summary: "Enable or disable host facts collection",
        input: infraternal_plugin_api::SchemaRef(
            r#"{"type":"object","required":["enabled"],"properties":{"enabled":{"type":"boolean"}},"additionalProperties":false}"#,
        ),
        output: infraternal_plugin_api::SchemaRef(
            r#"{"type":"object","required":["enabled"],"properties":{"enabled":{"type":"boolean"}},"additionalProperties":false}"#,
        ),
        instructions: &[
            "Choose the host to configure.",
            "Set enabled to true or false for host facts collection.",
        ],
        effect: Effect::Write,
        permission: infraternal_plugin_api::Permission::One(CONFIGURE_ACTION),
    },
];

/// Static plugin metadata; the settings default keeps collection on unless configured off.
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    defaults: &[],
    dependencies: &[],
    can_enable_components: &[],
    events: &[],
    streams: &[],
    id: "host",
    api: infraternal_plugin_api::API_VERSION,
    actions: ACTIONS,
    settings: Some(infraternal_plugin_api::SchemaRef(
        r#"{"type":"object","required":["enabled"],"properties":{"enabled":{"type":"boolean","default":true},"terminalMemoryFloorMiB":{"type":"integer","minimum":0,"default":256},"terminalMemoryFloorPercent":{"type":"integer","minimum":0,"maximum":100,"default":5}},"additionalProperties":false}"#,
    )),
    topics: &[],
    roles: &[infraternal_plugin_api::RoleDef {
        id: "node",
        requires: &[],
        default_enabled: true,
    }],
    max_frame_len: infraternal_plugin_api::MAX_ACTION_BYTES,
    unavailable: br#"{"error":"action unavailable"}"#,
    unavailable_event: br#"{"type":"error","error":"action unavailable"}"#,
};

/// Whether the collector runs inside the server or on a separately managed host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    /// The server's own local host.
    Embedded,
    /// A host connected through a remote transport.
    Remote,
}

/// A filesystem capacity measured from the target filesystem's block counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capacity {
    /// Used bytes.
    pub used_bytes: u64,
    /// Total bytes.
    pub total_bytes: u64,
}

/// Engine socket names that were found by a path existence check only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Engine {
    /// Docker's local Unix socket exists.
    Docker,
    /// Podman's local Unix socket exists.
    Podman,
}

/// Stable host identity plus optional counters sampled only for a live read.
///
/// The initial identity fields retain the names used by the early SSH bootstrap
/// shape so the shared collector can replace that implementation without a
/// translation layer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFacts {
    /// Distribution name from `/etc/os-release`, or the OS name from `uname`.
    pub os: String,
    /// Machine architecture; the serialized field name is the UI's `architecture`.
    #[serde(rename = "architecture")]
    pub arch: String,
    /// Effective uid running the infraternal agent; named `uid` to match the SSH bootstrap shape.
    #[serde(rename = "executionUid")]
    pub uid: u32,
    /// Distribution or OS version.
    pub version: String,
    /// Number of logical CPUs online; named `cpus` to match the SSH bootstrap shape.
    #[serde(rename = "logicalCpus")]
    pub cpus: u16,
    /// Kernel release from `uname` or the corresponding sysctl.
    pub kernel: String,
    /// DMI product name or device-tree model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// CPU marketing/model string, when exposed by the OS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
    /// Live shims authenticated by this host; absent from bootstrap-only collection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_count: Option<usize>,
    /// Sessions with no attached window; a reconnecting window still owns its attachment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_session_count: Option<usize>,
    /// Current memory counters, omitted from a static-only response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<Capacity>,
    /// Root filesystem counters, omitted from a static-only response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_disk: Option<Capacity>,
    /// System uptime in whole seconds, omitted from a static-only response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
    /// One, five, and fifteen minute load averages, omitted when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_average: Option<[f64; 3]>,
    /// Execution context of this plugin instance.
    pub mode: AgentMode,
    /// Engine names for standard local sockets that exist.
    pub engines: Vec<Engine>,
    /// PID 1 name on Linux, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<String>,
    /// Container or hypervisor detection from local OS files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtualization: Option<String>,
    /// The session user's configured shell from the process environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// The session user's locale from the process environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// The machine's own hostname (`uname` node name). The server names a Mesh node by it when the host record
    /// gives no name, e.g. a host added by IP address (#236). Additive: older readers ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// Strict request decoder and collector failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactsError {
    /// Input was too large, malformed, or included an unknown field.
    InvalidRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadRequest {
    #[serde(default)]
    include_live: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigureRequest {
    enabled: bool,
}

/// Decodes a bounded strict request for the read action.
/// # Errors
/// Rejects malformed JSON, unknown fields, and bodies over the request cap.
pub fn decode_read_request(input: &[u8]) -> Result<bool, FactsError> {
    if input.len() > MAX_FACTS_REQUEST_BYTES {
        return Err(FactsError::InvalidRequest);
    }
    serde_json::from_slice::<ReadRequest>(input)
        .map(|request| request.include_live)
        .map_err(|_| FactsError::InvalidRequest)
}

/// Decodes a bounded strict request for runtime plugin configuration.
/// # Errors
/// Rejects malformed JSON, unknown fields, and bodies over the request cap.
pub fn decode_configure_request(input: &[u8]) -> Result<bool, FactsError> {
    if input.len() > MAX_FACTS_REQUEST_BYTES {
        return Err(FactsError::InvalidRequest);
    }
    serde_json::from_slice::<ConfigureRequest>(input)
        .map(|request| request.enabled)
        .map_err(|_| FactsError::InvalidRequest)
}

/// The host facts implementation registered by both embedded and remote agents.
pub struct HostFactsPlugin {
    mode: AgentMode,
    enabled: bool,
    static_facts: Option<HostFacts>,
    memory_policy: super::MemoryPolicy,
    context: Option<infraternal_plugin_api::admission::NodeContext>,
}

impl HostFactsPlugin {
    /// Collects static facts immediately; a new instance is made at agent start or reconnect.
    #[must_use]
    pub fn new(mode: AgentMode) -> Self {
        Self {
            mode,
            enabled: true,
            static_facts: Some(collect_static_facts(mode)),
            memory_policy: super::MemoryPolicy::default(),
            context: None,
        }
    }

    /// Whether runtime settings currently permit reads.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl AgentPlugin for HostFactsPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }

    fn update_context(&mut self, context: infraternal_plugin_api::admission::NodeContext) {
        self.context = Some(context);
    }

    fn admit(
        &self,
        action_id: &str,
        context: infraternal_plugin_api::admission::NodeContext,
    ) -> Result<(), infraternal_plugin_api::admission::OpenRefusal> {
        if self.enabled && action_id == "terminal.open" {
            self.memory_policy
                .admit(collect_memory(), context.session_count)
        } else {
            Ok(())
        }
    }

    fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        match action_id {
            MEMORY_ACTION => {
                if !self.enabled {
                    return Err(PluginError::Rejected);
                }
                let policy =
                    super::MemoryPolicy::decode(input).map_err(|_| PluginError::Rejected)?;
                self.memory_policy = policy;
                serde_json::to_vec(&policy).map_err(|_| PluginError::Rejected)
            }
            READ_ACTION => {
                if !self.enabled {
                    return Err(PluginError::Rejected);
                }
                let include_live = decode_read_request(input).map_err(|_| PluginError::Rejected)?;
                let mut facts = self.static_facts.clone().ok_or(PluginError::Rejected)?;
                if let Some(context) = self.context {
                    facts.session_count = Some(context.session_count);
                    facts.background_session_count = Some(context.background_session_count);
                }
                if include_live {
                    refresh_live_facts(&mut facts);
                }
                serde_json::to_vec(&facts).map_err(|_| PluginError::Rejected)
            }
            CONFIGURE_ACTION => {
                self.enabled =
                    decode_configure_request(input).map_err(|_| PluginError::Rejected)?;
                self.static_facts = self.enabled.then(|| collect_static_facts(self.mode));
                serde_json::to_vec(&serde_json::json!({ "enabled": self.enabled }))
                    .map_err(|_| PluginError::Rejected)
            }
            _ => Err(PluginError::UnknownAction),
        }
    }
}

/// Distribution identity parsed from `/etc/os-release`.
#[derive(Debug, PartialEq, Eq)]
pub struct OsRelease {
    /// Distribution name.
    pub name: String,
    /// Distribution version identifier; empty if the distribution omits it.
    pub version: String,
}

/// Parses `NAME` and `VERSION_ID` as plain text without evaluating shell syntax.
#[must_use]
pub fn parse_os_release(input: &str) -> Option<OsRelease> {
    if input.len() > MAX_OS_RELEASE_BYTES {
        return None;
    }

    let mut name = None;
    let mut version = None;
    for line in input.lines() {
        if line.len() > MAX_OS_RELEASE_LINE_BYTES || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let destination = match key {
            "NAME" => &mut name,
            "VERSION_ID" => &mut version,
            _ => continue,
        };
        if destination.is_some() {
            continue;
        }
        *destination = parse_os_release_value(raw_value);
    }

    let name = name?;
    if name.is_empty() {
        return None;
    }
    Some(OsRelease {
        name,
        version: version.unwrap_or_default(),
    })
}

fn parse_os_release_value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let quoted = raw
        .as_bytes()
        .first()
        .copied()
        .filter(|quote| matches!(quote, b'\'' | b'"') && raw.as_bytes().last() == Some(quote));
    let body = if quoted.is_some() {
        raw.get(1..raw.len().checked_sub(1)?)?
    } else {
        raw
    };
    if body.len() > MAX_OS_LABEL_BYTES {
        return None;
    }

    if quoted == Some(b'"') {
        let mut value = String::with_capacity(body.len());
        let mut chars = body.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some(escaped @ ('\\' | '"' | '$' | '`')) => value.push(escaped),
                    Some(other) => {
                        value.push('\\');
                        value.push(other);
                    }
                    None => value.push('\\'),
                }
            } else {
                value.push(ch);
            }
        }
        Some(value.trim().to_owned())
    } else {
        Some(body.trim().to_owned())
    }
}

/// Collects the bounded static identity set for a newly started agent instance.
#[must_use]
pub fn collect_static_facts(mode: AgentMode) -> HostFacts {
    let uname = nix::sys::utsname::uname().ok();
    #[cfg(not(target_os = "macos"))]
    let release = read_limited("/etc/os-release", MAX_OS_RELEASE_BYTES)
        .and_then(|value| parse_os_release(&value));
    let cpuinfo = read_limited("/proc/cpuinfo", MAX_PROC_FILE_BYTES);
    let uid = nix::unistd::geteuid().as_raw();

    #[cfg(target_os = "macos")]
    let (os, version, kernel, arch, model, cpu_model, logical_cpus) = {
        let os = "macOS".to_owned();
        let version = sysctl_string("kern.osproductversion").unwrap_or_default();
        let kernel = sysctl_string("kern.osrelease")
            .or_else(|| uname.as_ref().and_then(|name| os_text(name.release())))
            .unwrap_or_default();
        let arch = sysctl_string("hw.machine")
            .or_else(|| uname.as_ref().and_then(|name| os_text(name.machine())))
            .unwrap_or_default();
        let model = sysctl_string("hw.model");
        let cpu_model = sysctl_string("machdep.cpu.brand_string");
        let logical_cpus = sysctl_u64("hw.logicalcpu")
            .or_else(|| sysctl_u64("hw.ncpu"))
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
            .unwrap_or(1);
        (os, version, kernel, arch, model, cpu_model, logical_cpus)
    };

    #[cfg(not(target_os = "macos"))]
    let (os, version, kernel, arch, model, cpu_model, logical_cpus) = {
        let os = release
            .as_ref()
            .map(|value| value.name.clone())
            .or_else(|| uname.as_ref().and_then(|name| os_text(name.sysname())))
            .unwrap_or_else(|| "Unknown".to_owned());
        let version = release.map_or_else(String::new, |value| value.version);
        let kernel = uname
            .as_ref()
            .and_then(|name| os_text(name.release()))
            .unwrap_or_default();
        let arch = uname
            .as_ref()
            .and_then(|name| os_text(name.machine()))
            .unwrap_or_default();
        let dmi_model = read_first_label(&[
            "/sys/class/dmi/id/product_name",
            "/sys/firmware/devicetree/base/model",
        ]);
        let model = dmi_model.clone();
        let cpu_model = cpuinfo.as_deref().and_then(cpu_model_from_info);
        let logical_cpus = linux_logical_cpus(cpuinfo.as_deref()).unwrap_or_else(|| {
            std::thread::available_parallelism()
                .ok()
                .and_then(|value| u16::try_from(value.get()).ok())
                .filter(|value| *value > 0)
                .unwrap_or(1)
        });
        (os, version, kernel, arch, model, cpu_model, logical_cpus)
    };

    let dmi = read_first_label(&[
        "/sys/class/dmi/id/product_name",
        "/sys/firmware/devicetree/base/model",
    ]);
    HostFacts {
        os: bound_label(&os).unwrap_or_else(|| "Unknown".to_owned()),
        arch: bound_label(&arch).unwrap_or_default(),
        uid,
        version: bound_label(&version).unwrap_or_default(),
        cpus: logical_cpus,
        kernel: bound_label(&kernel).unwrap_or_default(),
        model: model.and_then(|value| bound_label(&value)),
        cpu_model: cpu_model.and_then(|value| bound_label(&value)),
        session_count: None,
        background_session_count: None,
        memory: None,
        root_disk: None,
        uptime_seconds: None,
        load_average: None,
        mode,
        engines: engine_sockets(uid),
        init: read_limited("/proc/1/comm", 128).and_then(|value| bound_label(&value)),
        virtualization: detect_virtualization(dmi.as_deref(), cpuinfo.as_deref()),
        shell: environment_label("SHELL"),
        locale: ["LC_ALL", "LC_MESSAGES", "LANG"]
            .into_iter()
            .find_map(environment_label),
        hostname: uname
            .as_ref()
            .and_then(|name| os_text(name.nodename()))
            .filter(|name| !name.is_empty() && name != "(none)"),
    }
}

/// Samples current resource counters into one cached identity snapshot.
pub fn refresh_live_facts(facts: &mut HostFacts) {
    facts.root_disk = root_capacity();
    #[cfg(target_os = "linux")]
    {
        facts.memory = collect_memory();
        facts.uptime_seconds = read_limited("/proc/uptime", 256)
            .and_then(|value| value.split_ascii_whitespace().next().map(str::to_owned))
            .and_then(|value| value.split('.').next().and_then(|whole| whole.parse().ok()));
        facts.load_average = read_limited("/proc/loadavg", 256)
            .as_deref()
            .and_then(parse_load_average_text);
    }
    #[cfg(target_os = "macos")]
    collect_macos_live(facts);
}

// Admission samples memory only: disk and identity work are unnecessary on this path.
fn collect_memory() -> Option<Capacity> {
    #[cfg(target_os = "linux")]
    {
        read_limited("/proc/meminfo", 8 * 1_024)
            .as_deref()
            .and_then(memory_from_meminfo)
    }
    #[cfg(target_os = "macos")]
    {
        let mut facts = collect_static_facts(AgentMode::Embedded);
        collect_macos_live(&mut facts);
        facts.memory
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

fn read_limited(path: &str, limit: usize) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(limit.min(4 * 1_024));
    file.take(u64::try_from(limit).ok()?.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn bound_label(value: &str) -> Option<String> {
    let mut label = String::with_capacity(value.len().min(MAX_OS_LABEL_BYTES));
    for character in value
        .trim_matches(|character: char| character == '\0' || character.is_whitespace())
        .chars()
    {
        if !character.is_control() && label.len() + character.len_utf8() <= MAX_OS_LABEL_BYTES {
            label.push(character);
        }
    }
    (!label.is_empty()).then_some(label)
}

fn read_first_label(paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| read_limited(path, 4 * 1_024).and_then(|value| bound_label(&value)))
}

fn os_text(value: &std::ffi::OsStr) -> Option<String> {
    bound_label(&value.to_string_lossy())
}

fn environment_label(name: &str) -> Option<String> {
    env::var_os(name).and_then(|value| bound_label(&value.to_string_lossy()))
}

fn engine_sockets(uid: u32) -> Vec<Engine> {
    let docker_user_socket = format!("/run/user/{uid}/docker.sock");
    let podman_user_socket = format!("/run/user/{uid}/podman/podman.sock");
    let mut engines = Vec::with_capacity(2);
    if Path::new("/var/run/docker.sock").exists() || Path::new(&docker_user_socket).exists() {
        engines.push(Engine::Docker);
    }
    if Path::new("/run/podman/podman.sock").exists() || Path::new(&podman_user_socket).exists() {
        engines.push(Engine::Podman);
    }
    engines
}

fn detect_virtualization(dmi: Option<&str>, cpuinfo: Option<&str>) -> Option<String> {
    for path in ["/run/systemd/container", "/run/host/container-manager"] {
        if let Some(value) = read_limited(path, 128).and_then(|value| bound_label(&value)) {
            return Some(format!("Container ({value})"));
        }
    }
    let product = dmi.unwrap_or_default().to_ascii_lowercase();
    for (needle, label) in [
        ("kvm", "KVM"),
        ("qemu", "QEMU"),
        ("virtualbox", "VirtualBox"),
        ("vmware", "VMware"),
        ("hyper-v", "Hyper-V"),
        ("xen", "Xen"),
    ] {
        if product.contains(needle) {
            return Some(label.to_owned());
        }
    }
    if cpuinfo.is_some_and(|value| {
        value
            .lines()
            .any(|line| line.starts_with("flags") && line.contains(" hypervisor"))
    }) {
        return Some("Virtual machine".to_owned());
    }
    read_first_label(&["/sys/hypervisor/type"])
}

#[cfg(target_os = "linux")]
fn cpu_model_from_info(cpuinfo: &str) -> Option<String> {
    cpuinfo.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        matches!(key.trim(), "model name" | "Hardware" | "Processor")
            .then(|| bound_label(value))
            .flatten()
    })
}

#[cfg(target_os = "linux")]
fn linux_logical_cpus(cpuinfo: Option<&str>) -> Option<u16> {
    read_limited("/sys/devices/system/cpu/online", 1_024)
        .as_deref()
        .and_then(count_online_cpus)
        .or_else(|| {
            let count = cpuinfo?
                .lines()
                .filter(|line| line.starts_with("processor\t:"))
                .count();
            u16::try_from(count).ok().filter(|value| *value > 0)
        })
}

#[cfg(target_os = "linux")]
fn count_online_cpus(value: &str) -> Option<u16> {
    let mut count: u32 = 0;
    for range in value.trim().split(',') {
        let (first, last) = if let Some((first, last)) = range.split_once('-') {
            (first.parse::<u32>().ok()?, last.parse::<u32>().ok()?)
        } else {
            let cpu = range.parse::<u32>().ok()?;
            (cpu, cpu)
        };
        if last < first || last > 65_535 {
            return None;
        }
        count = count.checked_add(last.checked_sub(first)?.checked_add(1)?)?;
        if count > 4_096 {
            return None;
        }
    }
    u16::try_from(count).ok().filter(|value| *value > 0)
}

#[cfg(target_os = "linux")]
fn memory_from_meminfo(value: &str) -> Option<Capacity> {
    let mut total_kib = None;
    let mut available_kib = None;
    for line in value.lines() {
        let (key, amount) = line.split_once(':')?;
        let Some(kib) = amount
            .split_ascii_whitespace()
            .next()
            .and_then(|part| part.parse::<u64>().ok())
        else {
            continue;
        };
        match key {
            "MemTotal" => total_kib = Some(kib),
            "MemAvailable" => available_kib = Some(kib),
            _ => {}
        }
    }
    let total_bytes = total_kib?.saturating_mul(1_024);
    let available_bytes = available_kib?.saturating_mul(1_024).min(total_bytes);
    Some(Capacity {
        used_bytes: total_bytes.saturating_sub(available_bytes),
        total_bytes,
    })
}

/// Parses the three leading `/proc/loadavg` values and bounds them to finite non-negative numbers.
#[must_use]
pub fn parse_load_average_text(value: &str) -> Option<[f64; 3]> {
    if value.len() > 256 {
        return None;
    }
    let mut values = value
        .split_ascii_whitespace()
        .take(3)
        .map(str::parse::<f64>);
    let first = values.next()?.ok()?;
    let second = values.next()?.ok()?;
    let third = values.next()?.ok()?;
    let result = [first, second, third];
    result
        .iter()
        .all(|value| value.is_finite() && *value >= 0.0)
        .then_some(result)
}

/// Parses the bounded 64-bit `vm.loadavg` payload returned by macOS sysctl.
#[must_use]
pub fn parse_macos_load_average(value: &[u8]) -> Option<[f64; 3]> {
    // The 64-bit vm.loadavg payload is three u32 fixed-point values followed
    // by an aligned i64 scale. Reject other layouts instead of guessing.
    if value.len() != 24 {
        return None;
    }
    let scale = u32::try_from(i64::from_ne_bytes(value.get(16..24)?.try_into().ok()?)).ok()?;
    if scale == 0 {
        return None;
    }
    let scale = f64::from(scale);
    let result = [
        f64::from(u32::from_ne_bytes(value.get(0..4)?.try_into().ok()?)) / scale,
        f64::from(u32::from_ne_bytes(value.get(4..8)?.try_into().ok()?)) / scale,
        f64::from(u32::from_ne_bytes(value.get(8..12)?.try_into().ok()?)) / scale,
    ];
    result
        .iter()
        .all(|item| item.is_finite() && *item >= 0.0)
        .then_some(result)
}

fn root_capacity() -> Option<Capacity> {
    let info = nix::sys::statvfs::statvfs("/").ok()?;
    let block_size = u128::from(info.fragment_size().max(1));
    let total = u128::from(info.blocks()).checked_mul(block_size)?;
    let free = u128::from(info.blocks_free())
        .checked_mul(block_size)?
        .min(total);
    Some(Capacity {
        used_bytes: u64::try_from(total - free).unwrap_or(u64::MAX),
        total_bytes: u64::try_from(total).unwrap_or(u64::MAX),
    })
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &str) -> Option<String> {
    use sysctl::Sysctl;
    let mut value = sysctl::Ctl::new(name).ok()?.value_string().ok()?;
    if value.len() > MAX_OS_LABEL_BYTES {
        value.truncate(MAX_OS_LABEL_BYTES);
    }
    bound_label(&value)
}

#[cfg(target_os = "macos")]
fn sysctl_u64(name: &str) -> Option<u64> {
    sysctl_string(name)?.parse().ok()
}

#[cfg(target_os = "macos")]
fn collect_macos_live(facts: &mut HostFacts) {
    use sysctl::Sysctl;

    let total = sysctl_u64("hw.memsize");
    let free = sysctl_u64("vm.page_free_count")
        .zip(sysctl_u64("hw.pagesize"))
        .map(|(pages, size)| pages.saturating_mul(size));
    facts.memory = total.zip(free).map(|(total_bytes, free_bytes)| Capacity {
        used_bytes: total_bytes.saturating_sub(free_bytes.min(total_bytes)),
        total_bytes,
    });
    facts.uptime_seconds =
        sysctl::Ctl::new("kern.boottime")
            .ok()
            .and_then(|value| match value.value().ok()? {
                sysctl::CtlValue::Struct(bytes) => {
                    let seconds = i64::from_ne_bytes(bytes.get(..8)?.try_into().ok()?);
                    let boot = u64::try_from(seconds).ok()?;
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
                    Some(now.saturating_sub(boot))
                }
                _ => None,
            });
    facts.load_average =
        sysctl::Ctl::new("vm.loadavg")
            .ok()
            .and_then(|value| match value.value().ok()? {
                sysctl::CtlValue::Struct(bytes) => parse_macos_load_average(&bytes),
                _ => None,
            });
}
