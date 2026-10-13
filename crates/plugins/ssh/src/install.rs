//! Stages a matching binary and identity, preserving previous artifacts until authenticated readiness [17][139].

use crate::{
    model::{Failure, InstallMode, InstallStep, Target},
    probe::Architecture,
    transport::{Input, PayloadInput, Secret, SshSession, shell_quote},
};
use std::fmt::Write as _;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[path = "setup_scripts.rs"]
mod setup_scripts;

/// Paths are trusted server settings; no target may select an executable to upload.
#[derive(Clone)]
pub struct BinaryPaths {
    pub x86_64: PathBuf,
    pub aarch64: PathBuf,
}
impl BinaryPaths {
    #[must_use]
    pub fn get(&self, architecture: Architecture) -> &Path {
        match architecture {
            Architecture::X86_64 => &self.x86_64,
            Architecture::Aarch64 => &self.aarch64,
        }
    }
}

/// Supplies a trusted architecture payload before any remote installation writes.
/// Existing path-based adapters remain available; the server supplies its verified release resolver [225].
pub trait PayloadSource: Send + Sync {
    fn get(&self, architecture: Architecture) -> crate::transport::Operation<'_, PathBuf>;
}
impl PayloadSource for BinaryPaths {
    fn get(&self, architecture: Architecture) -> crate::transport::Operation<'_, PathBuf> {
        Box::pin(async move { Ok(BinaryPaths::get(self, architecture).to_owned()) })
    }
}

/// One-time capability and pin are produced by trusted enrollment, never serialized by bootstrap.
pub struct JoinMaterial {
    pub host: uuid::Uuid,
    pub url: String,
    pub stdin: Secret,
}

/// Holds a host-local transaction lock until commit or explicit rollback.
/// Callers must run rollback on cancellation; Drop cannot perform asynchronous remote I/O.
#[derive(Clone)]
pub struct Installation {
    session: Arc<dyn SshSession>,
    host: uuid::Uuid,
    transaction: uuid::Uuid,
    mode: InstallMode,
}

/// Nonsecret rollback coordinates retained for a later retry with fresh SSH credentials.
#[derive(Clone, Copy)]
pub struct Cleanup {
    host: uuid::Uuid,
    transaction: uuid::Uuid,
    mode: InstallMode,
}

/// One prepared public upload; input borrows cached bytes instead of copying them per host.
struct PreparedPayload {
    body: String,
    reuse: bool,
    packed: Option<Arc<[u8]>>,
    binary: PathBuf,
}
impl PreparedPayload {
    fn input(&self) -> Input<'_> {
        if self.reuse {
            Input::Empty
        } else if let Some(bytes) = &self.packed {
            Input::Bytes(bytes)
        } else {
            Input::File(&self.binary)
        }
    }
}

/// Negotiated sources share the existing bounded compressor and digest cache.
struct Transfer {
    body: String,
    raw_size: u64,
    gzip: Option<Arc<[u8]>>,
    zstd: Option<Arc<[u8]>>,
}
impl Transfer {
    fn input<'a>(&'a self, binary: &'a Path, invitation: &'a [u8]) -> Input<'a> {
        Input::Negotiated {
            raw: PayloadInput::File {
                path: binary,
                size: self.raw_size,
            },
            gzip: self.gzip.as_deref(),
            zstd: self.zstd.as_deref(),
            invitation,
        }
    }
}

impl Installation {
    #[must_use]
    pub fn cleanup_coordinates(&self) -> Cleanup {
        Cleanup {
            host: self.host,
            transaction: self.transaction,
            mode: self.mode,
        }
    }

    /// Reconstruct cleanup without retaining an SSH password, agent or join capability.
    /// # Errors
    /// Refuses changed privilege mode or missing explicit root consent.
    pub fn resume_cleanup(
        session: Arc<dyn SshSession>,
        target: &Target,
        cleanup: Cleanup,
    ) -> Result<Self, Failure> {
        target.validate()?;
        if target.mode != cleanup.mode {
            return Err(Failure::install(
                "Cleanup privilege mode does not match the host attempt.",
            ));
        }
        Ok(Self {
            session,
            host: cleanup.host,
            transaction: cleanup.transaction,
            mode: cleanup.mode,
        })
    }
    /// Validate consent and URL again at the mutation boundary.
    /// # Errors
    /// Refuses absent consent, unsafe enrollment URLs, missing binaries or remote setup failure.
    pub fn new(
        session: Arc<dyn SshSession>,
        target: &Target,
        join: &JoinMaterial,
    ) -> Result<Self, Failure> {
        target.validate()?;
        let url = url::Url::parse(&join.url)
            .map_err(|_| Failure::install("The enrollment address is invalid."))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Failure::install(
                "The enrollment address must be a pinned HTTPS endpoint.",
            ));
        }
        Ok(Self {
            session,
            host: join.host,
            transaction: uuid::Uuid::new_v4(),
            mode: target.mode,
        })
    }

    /// Upload with a per-attempt lock; the caller retains this handle even on failure.
    /// # Errors
    /// Reports binary, ownership, concurrent install or upload failure.
    pub async fn stage(&self, binary: &Path) -> Result<(), Failure> {
        let payload = self.prepare_payload(binary).await?;
        self.session
            .run(&self.script(&payload.body), payload.input())
            .await
            .map_err(|error| error.at(InstallStep::Upload).in_mode(self.mode))?;
        Ok(())
    }

    /// Frame a public upload before the private invitation in one setup channel.
    /// # Errors
    /// Preserves named upload/join/activation failures and the existing rollback journal.
    pub async fn stage_and_setup(
        &self,
        binary: &Path,
        join: &JoinMaterial,
    ) -> Result<bool, Failure> {
        if !self.session.setup_steps() {
            self.stage(binary).await?;
            return self.setup(join).await;
        }
        if join.host != self.host {
            return Err(Failure::install(
                "The enrollment invitation belongs to another host.",
            ));
        }
        let transfer = Self::negotiated_payload(binary).await?;
        let script = self.setup_script(join, Some(&transfer.body))?;
        let input = transfer.input(binary, join.stdin.expose());
        let output = self
            .session
            .run(&script, input)
            .await
            .map_err(|mut error| {
                if error.failed_step.is_none() {
                    error = error.at(InstallStep::Upload);
                }
                error.in_mode(self.mode)
            })?;
        parse_transfer_setup(&output.stdout).map_err(|error| error.in_mode(self.mode))
    }

    async fn negotiated_payload(binary: &Path) -> Result<Transfer, Failure> {
        let digest = crate::payload::digest(binary)
            .await
            .map_err(|error| error.at(InstallStep::Upload))?;
        let zstd =
            crate::payload_encoding::encoded(binary, crate::payload_encoding::Codec::Zstd).await?;
        let gzip =
            crate::payload_encoding::encoded(binary, crate::payload_encoding::Codec::Gzip).await?;
        let raw_size = tokio::fs::metadata(binary)
            .await
            .map_err(|_| {
                Failure::install("The matching static infraternal binary is unavailable.")
            })?
            .len();
        let body = format!(
            "{PAYLOAD_CACHE}\nvalidate_cache\nchoice=raw\nif [ -f \"$cache/payload\" ] && printf '%s  %s\\n' {digest} \"$cache/payload\" | sha256sum -c - >/dev/null 2>&1; then choice=reuse; elif {has_zstd} && command -v zstd >/dev/null 2>&1; then choice=zstd; elif {has_gzip} && command -v gzip >/dev/null 2>&1; then choice=gzip; fi\n{STAGE_TRANSACTION}\nprintf 'TRANSFER %s\\n' \"$choice\"\ncase \"$choice\" in\nreuse) ln \"$cache/payload\" \"$stage/payload\";;\nzstd) head -c {zstd_size} | zstd -dc > \"$stage/payload\";;\ngzip) head -c {gzip_size} | gzip -dc > \"$stage/payload\";;\nraw) head -c {raw_size} > \"$stage/payload\";;\n*) exit 1;;\nesac\nprintf '%s  %s\\n' {digest} \"$stage/payload\" | sha256sum -c - >/dev/null\nchmod 700 \"$stage/payload\"\nif [ \"$choice\" != reuse ]; then\n{PUBLISH_PAYLOAD_CACHE}\nfi",
            digest = shell_quote(&digest),
            has_zstd = if zstd.is_some() { "true" } else { "false" },
            has_gzip = if gzip.is_some() { "true" } else { "false" },
            zstd_size = zstd.as_ref().map_or(0, |bytes| bytes.len()),
            gzip_size = gzip.as_ref().map_or(0, |bytes| bytes.len()),
        );
        Ok(Transfer {
            body,
            raw_size,
            gzip,
            zstd,
        })
    }

    /// Stage the verified payload and start a shim-owned shell on this SSH master.
    /// The returned channel retains SSH until the installed transport reattaches.
    /// # Errors
    /// Refuses noncanonical transfer/session receipts and incomplete uploads.
    pub async fn stage_session(
        &self,
        binary: &Path,
    ) -> Result<(uuid::Uuid, crate::duplex::Duplex), Failure> {
        use tokio::io::AsyncReadExt;
        let transfer = Self::negotiated_payload(binary).await?;
        let start = "stage=\"$base/.bootstrap-lock\"\n[ \"$(cat \"$stage/transaction\")\" = \"$transaction\" ] || exit 72\nexec 9<&-\nexec \"$stage/payload\" __ssh-session --state \"$base/sessions\"";
        let script = format!(
            "{SETUP_HEADER}setup_step upload {}\nsetup_step start {}\n",
            shell_quote(&self.script(&transfer.body)),
            shell_quote(&self.script(start))
        );
        let channel = self.session.stream(&script).await?;
        if channel.line(32).await? != b"STEP upload\n" {
            return Err(invalid_setup().at(InstallStep::Upload));
        }
        let receipt = channel.line(64).await?;
        if let Some(failure) = refusal(&receipt, InstallStep::Upload) {
            return Err(failure.in_mode(self.mode));
        }
        let choice = crate::transport::TransferChoice::parse(&receipt)
            .ok_or_else(|| invalid_setup().at(InstallStep::Upload))?;
        let bytes = match choice {
            crate::transport::TransferChoice::Reuse => None,
            crate::transport::TransferChoice::Gzip => {
                Some(transfer.gzip.as_deref().ok_or_else(invalid_setup)?)
            }
            crate::transport::TransferChoice::Zstd => {
                Some(transfer.zstd.as_deref().ok_or_else(invalid_setup)?)
            }
            crate::transport::TransferChoice::Raw => {
                let mut file = tokio::fs::File::open(binary)
                    .await
                    .map_err(|_| invalid_setup())?;
                let mut buffer = vec![0; 65536];
                let mut remaining = transfer.raw_size;
                while remaining != 0 {
                    let limit =
                        usize::try_from(remaining.min(65536)).map_err(|_| invalid_setup())?;
                    let count = file
                        .read(&mut buffer[..limit])
                        .await
                        .map_err(|_| invalid_setup())?;
                    if count == 0 {
                        return Err(invalid_setup());
                    }
                    channel
                        .write(&buffer[..count])
                        .await
                        .map_err(|_| invalid_setup())?;
                    remaining -= count as u64;
                }
                None
            }
        };
        if let Some(bytes) = bytes {
            channel.write(bytes).await.map_err(|_| invalid_setup())?;
        }
        let receipt = channel.line(64).await?;
        if let Some(failure) = refusal(&receipt, InstallStep::Upload) {
            return Err(failure.in_mode(self.mode));
        }
        if receipt != b"STEP start\n" {
            return Err(invalid_setup().at(InstallStep::Start));
        }
        let receipt = channel.line(64).await?;
        if let Some(failure) = refusal(&receipt, InstallStep::Start) {
            return Err(failure.in_mode(self.mode));
        }
        let id = std::str::from_utf8(&receipt)
            .ok()
            .and_then(|s| s.strip_prefix("SESSION "))
            .and_then(|s| s.strip_suffix('\n'))
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .filter(|id| receipt == format!("SESSION {id}\n").as_bytes())
            .ok_or_else(invalid_setup)?;
        Ok((id, channel))
    }

    async fn prepare_payload(&self, binary: &Path) -> Result<PreparedPayload, Failure> {
        let digest = crate::payload::digest(binary)
            .await
            .map_err(|error| error.at(InstallStep::Upload).in_mode(self.mode))?;
        let query = format!(
            "{PAYLOAD_CACHE}\nvalidate_cache\nif [ -f \"$cache/payload\" ] && printf '%s  %s\\n' {} \"$cache/payload\" | sha256sum -c - >/dev/null 2>&1; then printf 'reuse\\n'; elif command -v zstd >/dev/null 2>&1; then printf 'zstd\\n'; elif command -v gzip >/dev/null 2>&1; then printf 'gzip\\n'; fi",
            shell_quote(&digest)
        );
        let cached = self
            .session
            .run(&self.script(&query), Input::Empty)
            .await
            .map_err(|error| error.at(InstallStep::Upload).in_mode(self.mode))?;
        let (reuse, codec) = match cached.stdout.as_slice() {
            b"reuse\n" => (true, None),
            b"" => (false, None),
            b"zstd\n" => (false, Some(crate::payload_encoding::Codec::Zstd)),
            b"gzip\n" => (false, Some(crate::payload_encoding::Codec::Gzip)),
            _ => {
                return Err(Failure::install("The payload reuse response was invalid.")
                    .at(InstallStep::Upload));
            }
        };
        let packed = if let Some(codec) = codec {
            crate::payload_encoding::encoded(binary, codec)
                .await
                .map_err(|error| error.at(InstallStep::Upload).in_mode(self.mode))?
        } else {
            None
        };
        let transfer = if reuse {
            "ln \"$cache/payload\" \"$stage/payload\""
        } else if packed.is_some() {
            match codec {
                Some(crate::payload_encoding::Codec::Zstd) => "zstd -dc > \"$stage/payload\"",
                Some(crate::payload_encoding::Codec::Gzip) => "gzip -dc > \"$stage/payload\"",
                None => return Err(Failure::install("The payload encoding is unavailable.")),
            }
        } else {
            "cat > \"$stage/payload\""
        };
        let publish = if reuse { "" } else { PUBLISH_PAYLOAD_CACHE };
        let body = format!(
            "{PAYLOAD_CACHE}\n{STAGE_TRANSACTION}\n{transfer}\nprintf '%s  %s\\n' {} \"$stage/payload\" | sha256sum -c - >/dev/null\nchmod 700 \"$stage/payload\"\n{publish}",
            shell_quote(&digest)
        );
        Ok(PreparedPayload {
            body,
            reuse,
            packed,
            binary: binary.to_path_buf(),
        })
    }

    fn script(&self, body: &str) -> String {
        let guarded = format!("{}\nsetup_guard\n{body}", include_str!("setup_lock.sh"));
        Self::script_for(self.mode, self.host, self.transaction, &guarded)
    }

    pub(crate) fn script_for(
        mode: InstallMode,
        host: uuid::Uuid,
        transaction: uuid::Uuid,
        body: &str,
    ) -> String {
        let host = host.simple().to_string();
        let (base, launcher, unit, manager) = match mode {
            InstallMode::Rootless => (
                "$HOME/.local/share/infraternal",
                "$HOME/.local/bin/infraternal",
                "$HOME/.config/systemd/user/infraternal-agent.service",
                "systemctl --user",
            ),
            InstallMode::Root => (
                "/var/lib/infraternal",
                "/usr/local/bin/infraternal",
                "/etc/systemd/system/infraternal-agent.service",
                "systemctl",
            ),
        };
        let wanted = if mode == InstallMode::Root {
            "multi-user.target"
        } else {
            "default.target"
        };
        let script = format!(
            "set -euC\numask 077\nhost={}\ntransaction={}\nbase=\"{base}\"\nlauncher=\"{launcher}\"\nunit=\"{unit}\"\nmanager={}\nwanted={wanted}\n# Existing data must be private to the execution uid before any read or write.\nif [ -e \"$base\" ] || [ -L \"$base\" ]; then\n    [ ! -L \"$base\" ] && [ -d \"$base\" ] && [ -O \"$base\" ] && [ \"$(stat -c '%a' \"$base\")\" = 700 ] || exit 71\nfi\n{body}",
            shell_quote(&host),
            shell_quote(&transaction.simple().to_string()),
            shell_quote(manager)
        );
        if mode == InstallMode::Root {
            format!(
                "if [ \"$(id -u)\" = 0 ]; then exec sh -c {}; else exec sudo -n sh -c {}; fi",
                shell_quote(&script),
                shell_quote(&script)
            )
        } else {
            script
        }
    }

    /// Join into staged state on private stdin; previous enrolled state remains untouched.
    /// # Errors
    /// Refuses a mismatched invitation or failed pinned enrollment/installation command.
    pub async fn enroll_and_start(&self, join: &JoinMaterial) -> Result<(), Failure> {
        if join.host != self.host {
            return Err(Failure::install(
                "The enrollment invitation belongs to another host.",
            ));
        }
        let join_body = setup_scripts::join(&join.url);
        self.session
            .run(&self.script(&join_body), Input::Bytes(join.stdin.expose()))
            .await
            .map_err(|error| error.at(InstallStep::Join).in_mode(self.mode))?;
        // Never replace unrelated launcher/unit files. A previous installation is
        // recognizable only through the same host marker and exact launcher target.
        let start_body = setup_scripts::ACTIVATE;
        self.session
            .run(&self.script(start_body), Input::Empty)
            .await
            .map_err(|error| error.at(InstallStep::Install).in_mode(self.mode))?;
        self.session
            .run(&self.script(setup_scripts::START), Input::Empty)
            .await
            .map_err(|error| error.at(InstallStep::Start).in_mode(self.mode))?;
        Ok(())
    }

    /// Collapse fixed remote setup steps while preserving their scripts and journal.
    /// # Errors
    /// Returns the exact named step/status receipt or a classified transport failure.
    pub async fn setup(&self, join: &JoinMaterial) -> Result<bool, Failure> {
        if !self.session.setup_steps() {
            self.enroll_and_start(join).await?;
            return self.enable_linger().await;
        }
        if join.host != self.host {
            return Err(Failure::install(
                "The enrollment invitation belongs to another host.",
            ));
        }
        let script = self.setup_script(join, None)?;
        let output = self
            .session
            .run(&script, Input::Bytes(join.stdin.expose()))
            .await
            .map_err(|mut error| {
                if error.failed_step.is_none() {
                    error = error.at(InstallStep::Join);
                }
                error.in_mode(self.mode)
            })?;
        parse_setup(&output.stdout).map_err(|error| error.in_mode(self.mode))
    }

    fn setup_script(&self, join: &JoinMaterial, upload: Option<&str>) -> Result<String, Failure> {
        let mut script = SETUP_HEADER.to_owned();
        // Share only representation: each fresh child still executes the full
        // immutable prelude, ownership checks and its own body with errexit.
        // Root steps retain their existing independent privilege wrapper.
        let shared = matches!(self.mode, InstallMode::Rootless);
        if shared {
            writeln!(script, "setup_common={}", shell_quote(&self.script("")))
                .map_err(|_| Failure::install("The host setup script could not be prepared."))?;
        }
        let argument = |body: &str| {
            if shared {
                format!("\"$setup_common\"{}", shell_quote(body))
            } else {
                shell_quote(&self.script(body))
            }
        };
        if let Some(upload) = upload {
            script = script.replace(
                "# INFRATERNAL_SETUP_STEPS_V1",
                "# INFRATERNAL_TRANSFER_SETUP_V1",
            );
            script = script.replace(
                "exit 0; fi",
                "if [ \"$1\" = upload ]; then exit \"$status\"; fi; exit 0; fi",
            );
            writeln!(script, "setup_step upload {}", argument(upload))
                .map_err(|_| Failure::install("The host setup script could not be prepared."))?;
        }
        for (name, body) in [
            ("join", setup_scripts::join(&join.url)),
            ("install", setup_scripts::ACTIVATE.to_owned()),
            ("start", setup_scripts::START.to_owned()),
            (
                "linger",
                if self.mode == InstallMode::Root {
                    "printf 'yes\\n'".to_owned()
                } else {
                    setup_scripts::LINGER.to_owned()
                },
            ),
        ] {
            // A fresh child shell keeps errexit active even when its parent
            // observes status. Testing a shell function would suppress errexit.
            writeln!(script, "setup_step {name} {}", argument(&body))
                .map_err(|_| Failure::install("The host setup script could not be prepared."))?;
        }
        script.push_str("printf 'DONE\\n'\n");
        Ok(script)
    }

    /// Ask policy to persist this user's manager without sudo or an interactive prompt.
    /// A denied request is a warning; only a policy-confirmed change is owned by rollback.
    /// # Errors
    /// Reports a failed SSH operation or an invalid bounded policy receipt.
    pub async fn enable_linger(&self) -> Result<bool, Failure> {
        if self.mode == InstallMode::Root {
            return Ok(true);
        }
        let output = self
            .session
            .run(&self.script(setup_scripts::LINGER), Input::Empty)
            .await
            .map_err(|error| error.at(InstallStep::Install).in_mode(self.mode))?;
        parse_linger(&output.stdout)
    }

    /// Only authenticated connection/facts/terminal proof permits deletion of previous artifacts.
    /// # Errors
    /// Reports failed cleanup without claiming that installation is complete.
    pub async fn commit(&self) -> Result<(), Failure> {
        self.session.run(&self.script(r#"[ -f "$base/.bootstrap-lock/activating" ] && [ "$(cat "$base/.bootstrap-lock/transaction")" = "$transaction" ] || exit 71
stage="$base/.bootstrap-lock"
retire_setup_lease
rm -rf "$stage"
"#), Input::Empty).await.map_err(|error| error.at(InstallStep::Install).in_mode(self.mode))?;
        Ok(())
    }

    /// Start read-only commit admission while terminal proof is in flight.
    /// Deletion requires the caller's one-use signal after marker plus status-zero exit.
    /// # Errors
    /// Retains rollback artifacts when proof/cancellation closes the signal.
    pub async fn commit_after(
        &self,
        release: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), Failure> {
        if !self.session.setup_steps() {
            release.await.map_err(|_| {
                Failure::install("Host provisioning stopped before terminal proof.")
            })?;
            return self.commit().await;
        }
        let script = self.script(
            r#"stage="$base/.bootstrap-lock"
[ -f "$stage/activating" ] && [ "$(cat "$stage/transaction")" = "$transaction" ] || exit 71
# No journal or artifact changes occur before the caller proves the terminal.
read -r approved || exit 1
[ -z "$approved" ] || exit 1
[ -f "$stage/activating" ] && [ "$(cat "$stage/transaction")" = "$transaction" ] || exit 71
retire_setup_lease
rm -rf "$stage"
"#,
        );
        self.session
            .run(&script, Input::Signal(release))
            .await
            .map_err(|error| error.at(InstallStep::Install).in_mode(self.mode))?;
        Ok(())
    }

    /// Publish the exact public manual readiness receipt before ordinary commit.
    /// The target requires this nonce and an absent lock before reporting success.
    /// # Errors
    /// Refuses stale transaction state or failed receipt publication/cleanup.
    pub async fn commit_manual(&self, receipt: uuid::Uuid) -> Result<(), Failure> {
        let body = format!(
            r#"[ -f "$base/.bootstrap-lock/activating" ] && [ "$(cat "$base/.bootstrap-lock/transaction")" = "$transaction" ] || exit 71
printf '%s\n' {} > "$base/.bootstrap-lock/ready"
mv -T "$base/.bootstrap-lock/ready" "$base/.bootstrap-ready"
"#,
            shell_quote(&receipt.simple().to_string())
        );
        self.session.run(&self.script(&body), Input::Empty).await?;
        self.commit().await
    }

    /// Retry the same owned installation without ending or replacing its shim.
    /// Existing fresh-host enrollment state stays with that host's private root.
    /// # Errors
    /// Refuses foreign journals and any rollback/staging/setup failure.
    pub async fn restart_setup(&self, binary: &Path, join: &JoinMaterial) -> Result<bool, Failure> {
        let retain = r#"
preserve_session=yes
stage="$base/.bootstrap-lock"
if [ -d "$stage" ] && [ ! -L "$stage" ]; then
    [ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
    [ ! -L "$stage/state" ] && [ ! -L "$base/state" ] || exit 71
    # A join may have completed before activation. Keep that host-local key
    # outside the disposable transaction, just as the live service does.
    if [ -d "$stage/state" ] && [ ! -e "$base/state" ]; then mv "$stage/state" "$base/state"; fi
fi
"#;
        self.session.run(&self.script(&format!("{FRESH_CLEANUP}\n{retain}\nstage=\"$base/.bootstrap-lock\"\nretire_setup_lease\n{ROLLBACK_TRANSACTION}")), Input::Empty).await?;
        self.stage(binary).await?;
        self.setup(join).await
    }

    /// Restore the previous installation, or remove only this host-bound fresh installation.
    /// # Errors
    /// Reports an unreachable host/failed cleanup; callers retain that fact in progress.
    pub async fn rollback(&self) -> Result<(), Failure> {
        self.session
            .run(
                &self.script(&format!("{FRESH_CLEANUP}\npreserve_session=no\nstage=\"$base/.bootstrap-lock\"\nretire_setup_lease\n{ROLLBACK_TRANSACTION}")),
                Input::Empty,
            )
            .await?;
        Ok(())
    }
}

// Every compound operation observes a fresh errexit child and emits only this
// canonical receipt. The duplex bridge shares the existing refusal decoder.
const SETUP_HEADER: &str = "# INFRATERNAL_SETUP_STEPS_V1\nset -u\nsetup_step() {\n    printf 'STEP %s\\n' \"$1\"\n    if sh -c \"$2\"; then :; else status=$?; printf 'FAIL %s %s\\n' \"$1\" \"$status\"; exit 0; fi\n}\n";

fn refusal(receipt: &[u8], step: InstallStep) -> Option<Failure> {
    // Prefixes supply the frozen decoder's context; they are never published
    // as completed setup stages or copied from remote diagnostics.
    let (prefix, transfer) = match step {
        InstallStep::Upload => (b"STEP upload\n".as_slice(), true),
        InstallStep::Start => (b"STEP join\nSTEP install\nSTEP start\n".as_slice(), false),
        _ => return None,
    };
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(receipt);
    let result = if transfer {
        parse_transfer_setup(&bytes)
    } else {
        parse_setup(&bytes)
    };
    result.err().filter(|failure| failure.exit_status.is_some())
}

// Cache records contain only public executable content. Every lookup repeats
// ownership, link, private-parent and fixed-marker checks before any content read.
const PAYLOAD_CACHE: &str = r#"
cache="$base.bootstrap-cache"
validate_cache() {
    if [ -e "$cache" ] || [ -L "$cache" ]; then
        parent=$(dirname "$cache")
        [ -d "$parent" ] && [ ! -L "$parent" ] && [ -O "$parent" ] || exit 71
        mode=$(stat -c '%a' "$parent")
        [ "$((0$mode & 022))" -eq 0 ] || exit 71
        [ -d "$cache" ] && [ ! -L "$cache" ] && [ -O "$cache" ] && [ "$(stat -c '%a' "$cache")" = 700 ] || exit 71
        [ -f "$cache/owner" ] && [ ! -L "$cache/owner" ] && [ -O "$cache/owner" ] && [ "$(stat -c '%a' "$cache/owner")" = 600 ] || exit 71
        [ "$(stat -c '%s' "$cache/owner")" = 29 ] && [ "$(cat "$cache/owner")" = INFRATERNAL_PAYLOAD_CACHE_V1 ] || exit 71
        if [ -e "$cache/payload" ] || [ -L "$cache/payload" ]; then
            [ -f "$cache/payload" ] && [ ! -L "$cache/payload" ] && [ -O "$cache/payload" ] && [ "$(stat -c '%a' "$cache/payload")" = 700 ] || exit 71
        fi
    fi
}
"#;

// Setup retains its existing attempt lock and ownership proof irrespective of
// whether the payload arrives through stdin or a verified cache hard link.
const STAGE_TRANSACTION: &str = r#"
# Admission and cleanup share the same private-parent rule. Refuse a parent
# that cannot protect a rollback receipt before creating any installation data.
parent=$(dirname "$base")
if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then mkdir -p "$parent"; fi
[ -d "$parent" ] && [ ! -L "$parent" ] && [ -O "$parent" ] || exit 71
parent_mode=$(stat -c '%a' "$parent")
[ "$((0$parent_mode & 022))" -eq 0 ] || exit 71
setup_guard
# A retired fresh transaction still owns final cleanup outside the base.
# Admit no replacement until its receipt is removed after successful cleanup.
for receipt in "$base".bootstrap-rollback-*; do
    [ ! -e "$receipt" ] && [ ! -L "$receipt" ] || exit 72
done
if [ -e "$base" ] || [ -L "$base" ]; then
    [ ! -L "$base" ] && [ -f "$base/.bootstrap-owner" ] && [ ! -L "$base/.bootstrap-owner" ] && [ "$(cat "$base/.bootstrap-owner")" = "$host" ] || exit 71
else
    mkdir -p "$base"
    printf '%s\n' "$host" > "$base/.bootstrap-owner"
fi
[ ! -L "$base/bin" ] && [ ! -L "$base/state" ] || exit 71
stage="$base/.bootstrap-lock"
[ ! -e "$stage" ] && [ ! -L "$stage" ] || exit 72
if [ -e "$base/bin/current" ] || [ -L "$base/bin/current" ]; then
    [ -L "$base/bin/current" ] && [ "$(readlink "$base/bin/current")" = "$base/bin/live" ] || exit 71
    kind=upgrade
else
    kind=fresh
fi
# The private acquisition journal precedes mkdir. It proves this attempt's
# empty lock if the command stops before the lock's ordinary receipts exist.
printf '%s %s\n' "$transaction" "$kind" > "$base/.bootstrap-acquiring"
mkdir "$stage" || exit 72
printf '%s\n' "$transaction" > "$stage/transaction"
printf '%s\n' "$kind" > "$stage/kind"
rm -f "$base/.bootstrap-acquiring"
start_setup_lease
"#;

// Publish at most one payload, after the staged hash has passed. Cache creation
// is a prepared-directory rename that cannot adopt an existing foreign path.
const PUBLISH_PAYLOAD_CACHE: &str = r#"
validate_cache
mkdir "$stage/cache"
printf 'INFRATERNAL_PAYLOAD_CACHE_V1\n' > "$stage/cache/owner"
ln "$stage/payload" "$stage/cache/payload"
if [ -e "$cache" ] || [ -L "$cache" ]; then
    mv -Tf "$stage/cache/payload" "$cache/payload"
else
    mv -Tn "$stage/cache" "$cache"
    [ ! -e "$stage/cache" ] && [ ! -L "$stage/cache" ] || exit 71
fi
"#;

// The rollback journal is a fixed shell program. Keeping it outside the Rust
// adapter makes its ownership and interruption invariants reviewable together.
pub(crate) const ROLLBACK_TRANSACTION: &str = r#"
if [ -e "$receipt" ] || [ -L "$receipt" ]; then
    validate_receipt
    if [ ! -e "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ]; then
        finish_fresh
        exit 0
    fi
fi
if [ ! -e "$base" ] && [ ! -L "$base" ]; then exit 0; fi
[ -f "$base/.bootstrap-owner" ] && [ ! -L "$base/.bootstrap-owner" ] && [ "$(cat "$base/.bootstrap-owner")" = "$host" ] || exit 71
stage="$base/.bootstrap-lock"
acquiring="$base/.bootstrap-acquiring"
acquired=no
if [ -e "$acquiring" ] || [ -L "$acquiring" ]; then
    [ -f "$acquiring" ] && [ ! -L "$acquiring" ] && [ -O "$acquiring" ] && [ "$(stat -c '%a' "$acquiring")" = 600 ] || exit 71
    size=$(stat -c '%s' "$acquiring")
    [ "$size" = 39 ] || [ "$size" = 41 ] || exit 71
    case "$(cat "$acquiring")" in
        "$transaction fresh") kind=fresh;;
        "$transaction upgrade") kind=upgrade;;
        *) exit 72;;
    esac
    acquired=yes
fi
if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then
    [ "$acquired" = yes ] || exit 0
    if [ "$kind" = fresh ]; then
        printf '%s %s fresh %s\n' "$host" "$transaction" "$(stat -c '%d:%i' "$base")" > "$receipt"
        rm -f "$acquiring"
        finish_fresh
    else
        rm -f "$acquiring"
    fi
    exit 0
fi
[ -d "$stage" ] && [ ! -L "$stage" ] || exit 71
if [ -e "$stage/transaction" ] || [ -L "$stage/transaction" ]; then
    [ -f "$stage/transaction" ] && [ ! -L "$stage/transaction" ] || exit 72
    if [ "$(cat "$stage/transaction")" != "$transaction" ]; then
        # Creation can succeed before the receipt's bytes fit on disk. Only
        # the exact acquisition journal owns this private, empty lock; never
        # treat a different nonempty transaction as an interrupted write.
        [ "$acquired" = yes ] && [ -O "$stage" ] && [ "$(stat -c '%a' "$stage")" = 700 ] || exit 72
        [ -O "$stage/transaction" ] && [ "$(stat -c '%a:%s:%h' "$stage/transaction")" = 600:0:1 ] || exit 72
        rm "$stage/transaction"
        rmdir "$stage" || exit 72
    fi
else
    # Only the pre-mkdir journal authorizes an empty, uninitialized lock.
    [ "$acquired" = yes ] || exit 72
    rmdir "$stage" || exit 72
fi
# Refused stop retains both installation and policy receipts for cleanup retry.
if [ -f "$stage/kind" ] && [ ! -L "$stage/kind" ]; then kind=$(cat "$stage/kind"); else [ "$acquired" = yes ] || exit 72; fi
case "$kind" in
    fresh) validate_parent;;
    upgrade) :;;
    *) exit 71;;
esac
if [ -f "$stage/activating" ]; then
    $manager stop infraternal-agent.service >/dev/null 2>&1
fi
if [ -f "$stage/linger-requested" ]; then
    uid=$(id -u)
    if [ "$(loginctl show-user "$uid" -p Linger --value 2>/dev/null || :)" = yes ]; then
        loginctl --no-ask-password disable-linger "$uid" >/dev/null 2>&1
    fi
    rm -f "$stage/linger-requested"
fi
if [ -f "$stage/activating" ]; then
    $manager disable infraternal-agent.service >/dev/null 2>&1 || :
    if [ -f "$stage/replacing-binary" ] || [ -f "$stage/previous-binary" ]; then rm -f "$base/bin/live" "$base/bin/current"; fi
    if [ "${preserve_session:-no}" != yes ] || [ "$kind" != fresh ]; then
        if [ -f "$stage/replacing-state" ] || [ -d "$stage/previous-state" ]; then rm -rf "$base/state"; fi
    fi
    # Only a journaled final replacement belongs to this attempt. Temporary
    # files stay in stage; unrelated suffix files are never cleanup targets.
    if [ -f "$stage/replacing-launcher" ] && [ ! -f "$stage/had-launcher" ]; then rm -f "$launcher"; fi
    [ ! -f "$stage/replacing-unit" ] || rm -f "$unit"
    # Retire replacement markers before restoring backups: a retry must never
    # delete an original already restored by an interrupted rollback. Backups
    # still present remain sufficient evidence to retry interrupted restoration.
    rm -f "$stage/replacing-binary" "$stage/replacing-state" "$stage/replacing-unit" "$stage/replacing-launcher"
    if [ -f "$stage/previous-binary" ]; then
        mv "$stage/previous-binary" "$base/bin/live"
    fi
    # Restoration can stop between moving the backup and recreating links.
    # The original-presence marker survives both operations and makes retry safe.
    if [ -f "$stage/had-binary" ]; then
        [ -L "$base/bin/current" ] || ln -s "$base/bin/live" "$base/bin/current"
        [ -L "$launcher" ] || ln -s "$base/bin/current" "$launcher"
    fi
    [ ! -d "$stage/previous-state" ] || mv "$stage/previous-state" "$base/state"
    [ ! -f "$stage/previous-unit" ] || mv "$stage/previous-unit" "$unit"
    $manager daemon-reload
    [ ! -f "$stage/was-enabled" ] || $manager enable infraternal-agent.service
    [ ! -f "$stage/was-active" ] || $manager start infraternal-agent.service
fi
# No replacement began, but a lost stop reply may have stopped the old service.
# An acknowledged refusal is staging-only cleanup and must not restart it.
if [ -f "$stage/stopping" ] && [ -f "$stage/was-active" ] && [ ! -f "$stage/stop-refused" ] && [ ! -f "$stage/activating" ]; then
    $manager start infraternal-agent.service
fi
if [ "$kind" = fresh ]; then
    # An incomplete upload is owned by this transaction. Reclaim it before
    # allocating the outside receipt, including when the home filesystem is full.
    rm -f "$stage/payload"
    if [ ! -e "$receipt" ] && [ ! -L "$receipt" ]; then
        printf '%s %s fresh %s\n' "$host" "$transaction" "$(stat -c '%d:%i' "$base")" > "$receipt"
    fi
    validate_receipt
fi
rm -rf "$stage"
[ "$acquired" = no ] || rm -f "$acquiring"
if [ "$kind" = fresh ]; then
    finish_fresh
fi
"#;

// This public ownership receipt survives removal of the transaction directory,
// owner marker and base. Noclobber creation, bounded reads, uid/mode and directory
// identity checks preserve exact binding
// prevent stale or foreign cleanup from being mistaken for this fresh attempt.
pub(crate) const FRESH_CLEANUP: &str = r#"
receipt="$base.bootstrap-rollback-$transaction"
validate_parent() {
    parent=$(dirname "$base")
    [ -d "$parent" ] && [ ! -L "$parent" ] && [ -O "$parent" ] || exit 71
    mode=$(stat -c '%a' "$parent")
    [ "$((0$mode & 022))" -eq 0 ] || exit 71
}
validate_receipt() {
    validate_parent
    [ -f "$receipt" ] && [ ! -L "$receipt" ] && [ -O "$receipt" ] && [ "$(stat -c '%a' "$receipt")" = 600 ] || exit 71
    size=$(stat -c '%s' "$receipt")
    [ "$size" -ge 76 ] && [ "$size" -le 114 ] || exit 71
    binding="$host $transaction fresh "
    data=$(cat "$receipt")
    case "$data" in "$binding"*) identity=${data#"$binding"};; *) exit 71;; esac
    case "$identity" in ''|:*|*:|*:*:*|*[!0-9:]*) exit 71;; esac
    case "$identity" in *:*) :;; *) exit 71;; esac
    if [ -e "$base" ] || [ -L "$base" ]; then
        [ "$(stat -c '%d:%i' "$base")" = "$identity" ] || exit 71
    fi
}
# The outside receipt can outlive an interrupted retirement of the acquisition
# journal. Remove only its exact fresh binding, after validating the base owner.
retire_fresh_acquisition() {
    acquiring="$base/.bootstrap-acquiring"
    if [ -e "$acquiring" ] || [ -L "$acquiring" ]; then
        [ -f "$acquiring" ] && [ ! -L "$acquiring" ] && [ -O "$acquiring" ] && [ "$(stat -c '%a' "$acquiring")" = 600 ] || exit 71
        [ "$(stat -c '%s' "$acquiring")" = 39 ] && [ "$(cat "$acquiring")" = "$transaction fresh" ] || exit 72
        rm -f "$acquiring"
    fi
}
finish_fresh() {
    if [ "${preserve_session:-no}" = yes ]; then validate_receipt; rm -f "$receipt"; return; fi
    validate_receipt
    if [ -e "$base" ] || [ -L "$base" ]; then
        [ ! -e "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] || exit 72
        if [ -e "$base/.bootstrap-owner" ] || [ -L "$base/.bootstrap-owner" ]; then
            [ -f "$base/.bootstrap-owner" ] && [ ! -L "$base/.bootstrap-owner" ] && [ "$(cat "$base/.bootstrap-owner")" = "$host" ] || exit 71
        fi
        retire_fresh_acquisition
        # Never recursively delete unjournaled contents. Unexpected data keeps
        # the receipt and makes cleanup fail rather than claiming success.
        rm -f "$base/.bootstrap-ready"
        rmdir "$base/bin" 2>/dev/null || :
        # The service creates these rendezvous directories before its first PTY.
        # Remove only empty owned directories; never follow a parent link or
        # remove retained shim/session data merely because installation failed.
        if [ -d "$base/sessions" ] && [ ! -L "$base/sessions" ] && [ -O "$base/sessions" ]; then
            if [ ! -L "$base/sessions/sessions" ] && [ -O "$base/sessions/sessions" ]; then
                rmdir "$base/sessions/sessions" 2>/dev/null || :
            fi
            rmdir "$base/sessions" 2>/dev/null || :
        fi
        # Preserve the owner marker alongside the receipt if unknown data keeps
        # the root nonempty. Another attempt cannot claim this unfinished root.
        for entry in "$base"/* "$base"/.[!.]* "$base"/..?*; do
            [ "$entry" = "$base/.bootstrap-owner" ] || { [ ! -e "$entry" ] && [ ! -L "$entry" ]; } || exit 72
        done
        [ ! -e "$base/.bootstrap-owner" ] && [ ! -L "$base/.bootstrap-owner" ] || rm -f "$base/.bootstrap-owner"
        rmdir "$base"
    fi
    rm -f "$receipt"
}
"#;

/// Decode only the fixed public policy receipt; remote diagnostics never become logs.
/// # Errors
/// Refuses any additional fields, malformed bytes or oversized output.
pub fn parse_linger(bytes: &[u8]) -> Result<bool, Failure> {
    match bytes {
        b"yes\n" => Ok(true),
        b"no\n" => Ok(false),
        _ => Err(Failure::install("The linger policy response was invalid.")),
    }
}

/// Decode bounded setup receipts; arbitrary command text never becomes diagnostics.
/// # Errors
/// Refuses malformed order, extra output, zero failure status and unknown step names.
pub fn parse_setup(bytes: &[u8]) -> Result<bool, Failure> {
    parse_steps(bytes, false)
}

/// Decode the same fixed setup receipts with an initial verified upload step.
/// # Errors
/// Rejects noncanonical output and preserves the exact named failure/status.
pub fn parse_transfer_setup(bytes: &[u8]) -> Result<bool, Failure> {
    parse_steps(bytes, true)
}

fn parse_steps(bytes: &[u8], upload: bool) -> Result<bool, Failure> {
    if bytes.len() > 256 {
        return Err(invalid_setup());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_setup())?;
    if !text.ends_with('\n') {
        return Err(invalid_setup());
    }
    // Preserve CR bytes: only the fixed LF receipt is canonical.
    let mut lines = text.split_terminator('\n');
    let names = if upload {
        &["upload", "join", "install", "start", "linger"][..]
    } else {
        &["join", "install", "start", "linger"][..]
    };
    for (index, name) in names.iter().copied().enumerate() {
        if lines.next() != Some(format!("STEP {name}").as_str()) {
            return Err(invalid_setup());
        }
        if upload
            && index == 0
            && lines
                .clone()
                .next()
                .is_some_and(|line| line.starts_with("TRANSFER "))
        {
            let choice = format!("{}\n", lines.next().ok_or_else(invalid_setup)?);
            if crate::transport::TransferChoice::parse(choice.as_bytes()).is_none() {
                return Err(invalid_setup());
            }
        }
        let next = lines.clone().next().ok_or_else(invalid_setup)?;
        if let Some(failed) = next.strip_prefix("FAIL ") {
            let (step, status) = failed.split_once(' ').ok_or_else(invalid_setup)?;
            let status: u8 = status.parse().map_err(|_| invalid_setup())?;
            if step != name
                || status == 0
                || next != format!("FAIL {name} {status}")
                || lines.count() != 1
            {
                return Err(invalid_setup());
            }
            let mut error =
                Failure::install("The remote setup step failed.").at(if upload && index == 0 {
                    InstallStep::Upload
                } else {
                    setup_step(index - usize::from(upload))
                });
            error.exit_status = Some(status);
            return Err(error);
        }
    }
    let linger = parse_linger(format!("{}\n", lines.next().ok_or_else(invalid_setup)?).as_bytes())?;
    if lines.next() != Some("DONE") || lines.next().is_some() {
        return Err(invalid_setup());
    }
    Ok(linger)
}

/// Retain the last authenticated fixed step on an interrupted compound command.
#[must_use]
pub fn interrupted_setup_step(bytes: &[u8]) -> Option<InstallStep> {
    interrupted_steps(bytes, false)
}

/// Retain only exact complete step prefixes from an interrupted framed transfer.
#[must_use]
pub fn interrupted_transfer_step(bytes: &[u8]) -> Option<InstallStep> {
    interrupted_steps(bytes, true)
}

fn interrupted_steps(bytes: &[u8], upload: bool) -> Option<InstallStep> {
    if bytes.len() > 256 {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.ends_with('\n') {
        return None;
    }
    let names = if upload {
        &["upload", "join", "install", "start", "linger"][..]
    } else {
        &["join", "install", "start", "linger"][..]
    };
    let mut last = None;
    let mut lines = text.split_terminator('\n').peekable();
    for (index, name) in names.iter().copied().enumerate() {
        let Some(line) = lines.next() else {
            return last;
        };
        if line != format!("STEP {name}") {
            return None;
        }
        last = Some(if upload && index == 0 {
            InstallStep::Upload
        } else {
            setup_step(index - usize::from(upload))
        });
        if upload
            && index == 0
            && lines
                .peek()
                .is_some_and(|line| line.starts_with("TRANSFER "))
        {
            let choice = format!("{}\n", lines.next()?);
            crate::transport::TransferChoice::parse(choice.as_bytes())?;
        }
    }
    if lines.next().is_some() {
        return None;
    }
    last
}

fn setup_step(index: usize) -> InstallStep {
    match index {
        0 => InstallStep::Join,
        2 => InstallStep::Start,
        _ => InstallStep::Install,
    }
}
fn invalid_setup() -> Failure {
    Failure::install("The host setup response was invalid.")
}
