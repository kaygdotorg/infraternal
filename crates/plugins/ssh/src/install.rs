//! Stages a matching binary and identity, preserving previous artifacts until authenticated readiness [17][139].

use crate::{
    model::{Failure, InstallMode, InstallStep, Target},
    probe::Architecture,
    transport::{Input, PayloadInput, Secret, SshSession, TransferChoice, shell_quote},
};
use std::fmt::Write as _;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[path = "setup_scripts.rs"]
mod setup_scripts;

// Mutating commands need both the parent guard and transaction lease; the
// read-only ownership check and cache refresh carry only the guard they execute.
pub(crate) const SETUP_GUARD: &str = include_str!("setup_guard.sh");
pub(crate) const SETUP_LOCK: &str = concat!(
    include_str!("setup_guard.sh"),
    include_str!("setup_lock.sh")
);

/// Paths are trusted server settings; no target may select an executable to upload.
#[derive(Clone)]
pub struct BinaryPaths {
    pub x86_64: PathBuf,
    pub aarch64: PathBuf,
}
impl BinaryPaths {
    /// Prefer the same executable built with only session/SSH support. Missing
    /// optional release artifacts preserve the full-payload installation path.
    /// Paths remain trusted server settings, never supplied by a target.
    /// # Errors
    /// Refuses a present artifact that is a symlink, directory or inaccessible.
    pub fn session_payload(&self, architecture: Architecture) -> Result<PathBuf, Failure> {
        let name = match architecture {
            Architecture::X86_64 => "infraternal-x86_64-session-musl",
            Architecture::Aarch64 => "infraternal-aarch64-session-musl",
        };
        let full = self.get(architecture);
        let session = full.with_file_name(name);
        match std::fs::symlink_metadata(&session) {
            Ok(metadata) if metadata.is_file() => Ok(session),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(full.to_path_buf()),
            _ => Err(Failure::install(
                "The matching static infraternal binary is unavailable.",
            )),
        }
    }

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

    /// An authenticated optional session image; absence selects the full payload.
    /// Existing sources retain their full-payload behavior without local guessing.
    fn session(
        &self,
        _architecture: Architecture,
    ) -> crate::transport::Operation<'_, Option<PathBuf>> {
        Box::pin(async { Ok(None) })
    }
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
    // Cloned retries share at most the original session image and the full
    // exact-version image. Neither digest comes from the target or its journal.
    images: Arc<[std::sync::OnceLock<Arc<str>>; 2]>,
}
impl Installation {
    /// Rebind a failed retry to a freshly authenticated SSH route without changing shell ownership or image pins.
    pub(crate) fn with_session(&self, session: Arc<dyn SshSession>) -> Self {
        Self {
            session,
            host: self.host,
            transaction: self.transaction,
            mode: self.mode,
            images: self.images.clone(),
        }
    }
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
    digest: Arc<str>,
    raw_size: u64,
    gzip: Option<Arc<[u8]>>,
    zstd: Option<Arc<[u8]>>,
}
impl Transfer {
    /// One staging program; only how `choice` is selected differs. The remote
    /// selection runs under the setup lock; a declared choice comes from the
    /// read-only check and is still verified by digest after staging.
    fn body_with(&self, selection: &str) -> String {
        // The digest is taken from the same byte stream `tee` writes, on its
        // own core while the decoder runs, instead of re-reading the file
        // afterwards. A failed file write leaves the file short (tee drops a
        // failed output), so the exact size completes the proof. A reused
        // cache entry is read back and hashed as before.
        format!(
            r#"{PAYLOAD_CACHE}
validate_cache
{selection}
{STAGE_TRANSACTION}
printf 'TRANSFER %s\n' "$choice"
case "$choice" in
reuse) ln "$cache/payload" "$stage/payload"; streamed=$(sha256sum < "$stage/payload");;
zstd) streamed=$(head -c {zstd_size} | zstd -dc | tee "$stage/payload" | sha256sum);;
gzip) streamed=$(head -c {gzip_size} | gzip -dc | tee "$stage/payload" | sha256sum);;
raw) streamed=$(head -c {raw_size} | tee "$stage/payload" | sha256sum);;
*) exit 1;;
esac
[ "$streamed" = "{digest}  -" ] || exit 1
[ "$(stat -c '%s' "$stage/payload")" = {raw_size} ] || exit 1
chmod 700 "$stage/payload"
if [ "$choice" != reuse ]; then
{PUBLISH_PAYLOAD_CACHE}
fi"#,
            digest = self.digest,
            zstd_size = self.zstd.as_ref().map_or(0, |bytes| bytes.len()),
            gzip_size = self.gzip.as_ref().map_or(0, |bytes| bytes.len()),
            raw_size = self.raw_size,
        )
    }

    /// Choose from capabilities the check observed, so the payload can follow
    /// the setup script without waiting for a remote selection receipt.
    fn declared(&self, caps: &TransferCaps) -> crate::transport::TransferChoice {
        if caps.cache.as_deref() == Some(&*self.digest) {
            TransferChoice::Reuse
        } else if caps.zstd && self.zstd.is_some() {
            TransferChoice::Zstd
        } else if caps.gzip && self.gzip.is_some() {
            TransferChoice::Gzip
        } else {
            TransferChoice::Raw
        }
    }

    fn input<'a>(
        &'a self,
        binary: &'a Path,
        invitation: &'a [u8],
        declared: Option<crate::transport::TransferChoice>,
    ) -> Input<'a> {
        Input::Negotiated {
            raw: PayloadInput::File {
                path: binary,
                size: self.raw_size,
            },
            gzip: self.gzip.as_deref(),
            zstd: self.zstd.as_deref(),
            invitation,
            payload_ack: true,
            declared,
        }
    }
}

/// Public transfer facts reported by the read-only check (D255, #189). They
/// only select an encoding; staging still verifies the payload digest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TransferCaps {
    zstd: bool,
    gzip: bool,
    /// SHA-256 of an owned cached payload, when one exists.
    cache: Option<String>,
}
impl TransferCaps {
    fn parse(line: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(line).ok()?.strip_suffix('\n')?;
        let mut fields = text.strip_prefix("CAPS ")?.split(' ');
        let zstd = match fields.next()? {
            "zstd" => true,
            "-" => false,
            _ => return None,
        };
        let gzip = match fields.next()? {
            "gzip" => true,
            "-" => false,
            _ => return None,
        };
        let cache = match fields.next()? {
            "-" => None,
            digest
                if digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
            {
                Some(digest.to_owned())
            }
            _ => return None,
        };
        fields
            .next()
            .is_none()
            .then_some(Self { zstd, gzip, cache })
    }
}

/// The read-only check's command channel, held open for one public setup script.
/// `caps` is present only when the host reported transfer facts and reads the
/// setup script with an exact reader, so payload bytes may follow it at once.
pub struct Checked {
    channel: crate::duplex::Duplex,
    caps: Option<TransferCaps>,
}

impl Checked {
    /// Public encoding support from this same authenticated check channel.
    /// This hint never selects reuse or skips the later digest verification.
    #[must_use]
    pub fn encoding(&self) -> Option<crate::transport::TransferChoice> {
        self.caps.as_ref().map(|caps| {
            if caps.zstd {
                TransferChoice::Zstd
            } else if caps.gzip {
                TransferChoice::Gzip
            } else {
                TransferChoice::Raw
            }
        })
    }
}

// Rootless transfer facts for the check channel. Root installs keep the
// remote selection under sudo: this account cannot read root's cache.
const TRANSFER_PROBE: &str = r#"
digest=-
if (validate_cache) && [ -f "$cache/payload" ] && [ ! -L "$cache/payload" ]; then
    digest=$(sha256sum < "$cache/payload" | cut -c1-64) || digest=-
fi
zstd=-
if command -v zstd >/dev/null 2>&1; then zstd=zstd; fi
gzip=-
if command -v gzip >/dev/null 2>&1; then gzip=gzip; fi
printf 'CAPS %s %s %s\n' "$zstd" "$gzip" "$digest"
"#;

/// Drop full-line comments and indentation from a generated shell program
/// before it crosses a high-latency link (D255, #189). Bytes on a fresh
/// connection are paced out, so the check script's size is on the prompt
/// path. Valid only for programs without here-documents, line continuations
/// or quoted strings that span lines; the embedded setup scripts have none.
fn compact(script: &str) -> String {
    let mut compacted = String::with_capacity(script.len());
    for line in script.lines() {
        let line = line.trim_start_matches([' ', '\t']);
        if !line.is_empty() && !line.starts_with('#') {
            compacted.push_str(line);
            compacted.push('\n');
        }
    }
    compacted
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
            images: Arc::default(),
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
            images: Arc::default(),
        })
    }

    /// Create the journal owner before the host has a server-issued invitation.
    /// # Errors
    /// Refuses invalid targets or privilege consent before any remote write.
    pub fn new_pending(
        session: Arc<dyn SshSession>,
        target: &Target,
        host: uuid::Uuid,
    ) -> Result<Self, Failure> {
        target.validate()?;
        Ok(Self {
            session,
            host,
            transaction: uuid::Uuid::new_v4(),
            mode: target.mode,
            images: Arc::default(),
        })
    }

    /// Upload with a per-attempt lock; the caller retains this handle even on failure.
    /// # Errors
    /// Reports binary, ownership, concurrent install or upload failure.
    pub async fn stage(&self, binary: &Path) -> Result<(), Failure> {
        let payload = self.prepare_payload(binary, true).await?;
        self.session
            .run(&self.script(&payload.body), payload.input())
            .await
            .map_err(|error| error.at(InstallStep::Upload).in_mode(self.mode))?;
        Ok(())
    }

    /// Run the staged infraternal agent's HTTPS preflight and prepare its private key.
    /// The returned digest is safe to bind to the invitation issued after this SSH proof.
    /// # Errors
    /// Names DNS, TCP, TLS and proxy-upgrade failures without returning private key material.
    pub async fn prepare_join_key(&self, binary: &Path, origin: &str) -> Result<[u8; 32], Failure> {
        let payload = self.prepare_payload(binary, false).await?;
        self.session
            .run(&self.script(&payload.body), payload.input())
            .await
            .map_err(|error| error.at(InstallStep::Upload).in_mode(self.mode))?;
        // retire_setup_lease stops the staged lease but keeps its record, and
        // start_setup_lease creates a new one under `set -C`. Remove the record
        // first, as handoff_setup_lease does; this shell keeps the stage flock
        // on fd 7 in between (#305).
        let body = format!(
            r#"stage="$base/.bootstrap-lock"
[ -f "$stage/kind" ] && [ ! -L "$stage" ] || exit 71
[ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
retire_setup_lease
rm -f "$stage/lease"
if [ -e "$base/state" ] || [ -L "$base/state" ]; then
    [ -d "$base/state" ] && [ ! -L "$base/state" ] && [ -O "$base/state" ] && [ "$(stat -c '%a' "$base/state")" = 700 ] || exit 71
    cp -a "$base/state" "$stage/state"
else
    mkdir -m 700 "$stage/state"
fi
[ -d "$stage/state" ] && [ ! -L "$stage/state" ] && [ -O "$stage/state" ] && [ "$(stat -c '%a' "$stage/state")" = 700 ] || exit 71
"$stage/payload" agent --data "$stage/state" prepare-join-key {}
start_setup_lease
"#,
            shell_quote(origin)
        );
        let output = self
            .session
            .run(&self.script(&body), Input::Empty)
            .await
            .map_err(|error| error.at(InstallStep::Connect).in_mode(self.mode))?;
        parse_join_key_receipt(&output.stdout).map_err(|error| error.in_mode(self.mode))
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
        self.transfer_setup(binary, join, None, None).await
    }

    /// Both initial staging and session-preserving restaging use the same
    /// bounded transfer and refusal parser. Cleanup runs in its own errexit
    /// child before upload; its early exits cannot skip the upload program.
    async fn transfer_setup(
        &self,
        binary: &Path,
        join: &JoinMaterial,
        cleanup: Option<&str>,
        hint: Option<crate::transport::TransferChoice>,
    ) -> Result<bool, Failure> {
        if join.host != self.host {
            return Err(Failure::install(
                "The enrollment invitation belongs to another host.",
            ));
        }
        let transfer = Self::negotiated_payload(binary).await?;
        self.pin_image(1, &transfer.digest)?;
        let mut upload = String::new();
        if let Some(cleanup) = cleanup {
            // Observe the child status explicitly: conditional function calls
            // would disable errexit inside the journal recovery program.
            // The upload step already runs privileged in root mode, so the
            // child takes only the prelude. A second root wrapper would quote
            // the cleanup four levels deep and push the root restage command
            // past the kernel's 128 KiB limit for one argument (#230).
            let guarded_cleanup = Self::unprivileged_script(
                self.mode,
                self.host,
                self.transaction,
                &format!("setup_guarded=yes\n{SETUP_LOCK}\n{cleanup}"),
            );
            writeln!(upload, "sh -c {}", shell_quote(&guarded_cleanup))
                .map_err(|_| Failure::install("The host setup script could not be prepared."))?;
        }
        // Local compressor availability can differ from the remote check.
        // Raw is always supported; reuse still requires remote hash selection.
        let declared = hint.and_then(|choice| match choice {
            TransferChoice::Reuse => None,
            TransferChoice::Zstd if transfer.zstd.is_none() => Some(TransferChoice::Raw),
            TransferChoice::Gzip if transfer.gzip.is_none() => Some(TransferChoice::Raw),
            choice => Some(choice),
        });
        if let Some(choice) = declared {
            upload.push_str(&transfer.body_with(&format!("choice={}", choice.word())));
        } else {
            upload.push_str(&transfer.body);
        }
        // Only the full image carries the runtime-lock helper; the early
        // session image is staged without it and owns no lifetime lock.
        upload.push_str(RUNTIME_HANDOFF);
        let script = self.setup_script(join, Some(&upload))?;
        let input = transfer.input(binary, join.stdin.expose(), declared);
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
        let raw_size = std::fs::metadata(binary)
            .map_err(|_| {
                Failure::install("The matching static infraternal binary is unavailable.")
            })?
            .len();
        let quoted = shell_quote(&digest);
        let selection = format!(
            "choice=raw\nif [ -f \"$cache/payload\" ] && printf '%s  %s\\n' {quoted} \"$cache/payload\" | sha256sum -c - >/dev/null 2>&1; then choice=reuse; elif {has_zstd} && command -v zstd >/dev/null 2>&1; then choice=zstd; elif {has_gzip} && command -v gzip >/dev/null 2>&1; then choice=gzip; fi",
            has_zstd = if zstd.is_some() { "true" } else { "false" },
            has_gzip = if gzip.is_some() { "true" } else { "false" },
        );
        let mut transfer = Transfer {
            body: String::new(),
            digest,
            raw_size,
            gzip,
            zstd,
        };
        transfer.body = transfer.body_with(&selection);
        Ok(transfer)
    }

    /// Keep the authenticated command channel through read-only admission and staging.
    /// Only a bounded public script follows these existing canonical check records.
    /// # Errors
    /// Preserves named check refusals; rejects missing delimiters and oversized records.
    pub async fn check_channel(
        session: &dyn SshSession,
        check: &str,
    ) -> Result<(crate::transport::CommandOutput, Checked), Failure> {
        // The probe never fails the check: missing facts fall back to the
        // remote selection receipt. `dd bs=1` reads exactly the setup script,
        // so payload bytes sent right behind it stay in the pipe for staging;
        // a buffering `head` could consume them. Without dd, the server waits
        // for the selection receipt before sending any payload byte.
        let probe = Self::script_for(
            InstallMode::Rootless,
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            &format!("{PAYLOAD_CACHE}\n{TRANSFER_PROBE}"),
        );
        let script = compact(&format!(
            "{SETUP_HEADER}setup_step connect {}\ncaps=$(sh -c {} </dev/null 2>/dev/null) || caps=\n[ -z \"$caps\" ] || printf '%s\\n' \"$caps\"\nreader=head\nif command -v dd >/dev/null 2>&1; then reader=dd; fi\nprintf 'CHECK ready %s\\n' \"$reader\"\nIFS= read -r setup_length\ncase \"$setup_length\" in ''|*[!0-9]*) exit 1;; esac\n[ \"$setup_length\" -le 65536 ] || exit 1\nif [ \"$reader\" = dd ]; then setup_body=$(dd bs=1 count=\"$setup_length\" 2>/dev/null); else setup_body=$(head -c \"$setup_length\"); fi\nexec sh -c \"$setup_body\"\n",
            shell_quote(check),
            shell_quote(&probe),
        ));
        let channel = session.stream(&script).await?;
        if channel.line(32).await? != b"STEP connect\n" {
            return Err(invalid_setup().at(InstallStep::Connect));
        }
        let mut stdout = Vec::new();
        let mut caps = None;
        let exact = loop {
            let receipt = channel
                .line(512)
                .await
                .map_err(|error| error.at(InstallStep::Connect))?;
            if let Some(failure) = parse_refusal(&receipt, InstallStep::Connect) {
                return Err(crate::previous_attempt::classify(failure));
            }
            match receipt.as_slice() {
                b"CHECK ready dd\n" => break true,
                b"CHECK ready head\n" => break false,
                _ => {}
            }
            if receipt.starts_with(b"CAPS ") {
                if caps.is_some() {
                    return Err(invalid_setup().at(InstallStep::Connect));
                }
                caps = Some(TransferCaps::parse(&receipt));
                continue;
            }
            if stdout.len() + receipt.len() > 512 {
                return Err(invalid_setup().at(InstallStep::Connect));
            }
            stdout.extend_from_slice(&receipt);
        };
        Ok((
            crate::transport::CommandOutput { stdout },
            Checked {
                channel,
                caps: caps.flatten().filter(|_| exact),
            },
        ))
    }

    /// Stage the verified payload and start a shim-owned shell on this SSH master.
    /// The returned channel retains SSH until the installed transport reattaches.
    /// # Errors
    /// Refuses noncanonical transfer/session receipts and incomplete uploads.
    pub async fn stage_session(
        &self,
        binary: &Path,
    ) -> Result<(uuid::Uuid, crate::duplex::Duplex), Failure> {
        self.stage_session_on(binary, None).await
    }

    /// Continue staging on the read-only check channel, avoiding another SSH exec.
    /// # Errors
    /// Uses the same verified payload/session receipts as `stage_session`.
    pub async fn stage_session_on(
        &self,
        binary: &Path,
        checked: Option<Checked>,
    ) -> Result<(uuid::Uuid, crate::duplex::Duplex), Failure> {
        let transfer = Self::negotiated_payload(binary).await?;
        self.pin_image(0, &transfer.digest)?;
        // A declared encoding lets the payload follow the setup script at once.
        // Root mode keeps selection under sudo, where its own cache is visible.
        let declared = checked
            .as_ref()
            .and_then(|checked| checked.caps.as_ref())
            .filter(|_| self.mode == InstallMode::Rootless)
            .map(|caps| transfer.declared(caps));
        let upload = match declared {
            Some(choice) => transfer.body_with(&format!("choice={}", choice.word())),
            None => transfer.body.clone(),
        };
        let start = "stage=\"$base/.bootstrap-lock\"\n[ \"$(cat \"$stage/transaction\")\" = \"$transaction\" ] || exit 72\nexec 9<&-\nexec \"$stage/payload\" __ssh-session --state \"$base/sessions\"";
        let script = format!(
            "{}setup_step upload {}\nsetup_step start {}\n",
            self.step_header()?,
            self.step_argument(&upload),
            self.step_argument(start)
        );
        let channel = if let Some(checked) = checked {
            let script = compact(&script);
            if script.len() > 65536 {
                return Err(invalid_setup().at(InstallStep::Upload));
            }
            let mut framed = format!("{}\n", script.len()).into_bytes();
            framed.extend_from_slice(script.as_bytes());
            checked
                .channel
                .write(&framed)
                .await
                .map_err(|_| invalid_setup().at(InstallStep::Upload))?;
            checked.channel
        } else {
            self.session.stream(&script).await?
        };
        let written = if let Some(choice) = declared {
            // Bytes flow while the host takes its lock; a refusal receipt
            // stops sending. The receipt must name the declared encoding.
            let send = send_transfer(&channel, &transfer, binary, choice);
            let receipt = self.upload_receipt(&channel, Some(choice));
            tokio::pin!(send, receipt);
            let mut written = None;
            loop {
                tokio::select! {
                    biased;
                    result = &mut receipt => {
                        result?;
                        break;
                    }
                    result = &mut send, if written.is_none() => written = Some(result),
                }
            }
            match written {
                Some(written) => written,
                None => send.await,
            }
        } else {
            let choice = self.upload_receipt(&channel, None).await?;
            send_transfer(&channel, &transfer, binary, choice).await
        };
        if let Err(error) = &written
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(invalid_setup().at(InstallStep::Upload));
        }
        let receipt = channel.line(64).await?;
        if let Some(failure) = parse_refusal(&receipt, InstallStep::Upload) {
            return Err(failure.in_mode(self.mode));
        }
        written.map_err(|_| invalid_setup().at(InstallStep::Upload))?;
        if receipt != b"STEP start\n" {
            return Err(invalid_setup().at(InstallStep::Start));
        }
        let receipt = channel.line(64).await?;
        if let Some(failure) = parse_refusal(&receipt, InstallStep::Start) {
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

    /// Read the upload step's canonical selection receipt or named refusal.
    async fn upload_receipt(
        &self,
        channel: &crate::duplex::Duplex,
        declared: Option<crate::transport::TransferChoice>,
    ) -> Result<crate::transport::TransferChoice, Failure> {
        if channel.line(32).await? != b"STEP upload\n" {
            return Err(invalid_setup().at(InstallStep::Upload));
        }
        let receipt = channel.line(64).await?;
        if let Some(failure) = parse_refusal(&receipt, InstallStep::Upload) {
            return Err(failure.in_mode(self.mode));
        }
        crate::transport::TransferChoice::parse(&receipt)
            .filter(|choice| declared.is_none_or(|declared| declared == *choice))
            .ok_or_else(|| invalid_setup().at(InstallStep::Upload))
    }

    async fn prepare_payload(
        &self,
        binary: &Path,
        runtime_handoff: bool,
    ) -> Result<PreparedPayload, Failure> {
        let digest = crate::payload::digest(binary)
            .await
            .map_err(|error| error.at(InstallStep::Upload).in_mode(self.mode))?;
        self.pin_image(1, &digest)?;
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
        let runtime_handoff = if runtime_handoff { RUNTIME_HANDOFF } else { "" };
        let body = format!(
            "{PAYLOAD_CACHE}\n{STAGE_TRANSACTION}\n{transfer}\nprintf '%s  %s\\n' {} \"$stage/payload\" | sha256sum -c - >/dev/null\nchmod 700 \"$stage/payload\"\n{publish}\n{runtime_handoff}",
            shell_quote(&digest)
        );
        Ok(PreparedPayload {
            body,
            reuse,
            packed,
            binary: binary.to_path_buf(),
        })
    }

    /// Publish only the trusted executable cache when legacy recovery needs a newer helper.
    /// # Errors
    /// Refuses unsafe cache/parent ownership or a partial/mismatched transfer.
    #[cold]
    #[inline(never)]
    pub fn prepare_recovery<'a>(
        session: &'a dyn SshSession,
        target: &'a Target,
        binary: &'a Path,
    ) -> crate::transport::Operation<'a, ()> {
        // Share the recovery poller through the existing operation boundary.
        // Its temporary allocation is confined to migration of an earlier cache [243].
        Box::pin(async move {
            target.validate()?;
            let digest = crate::payload::digest(binary).await?;
            let body = format!(
                r#"{SETUP_GUARD}
setup_guard
{PAYLOAD_CACHE}
validate_cache
prepared="$cache.recovery-$transaction"
mkdir "$prepared"
trap 'rm -f "$prepared/payload" "$prepared/owner"; rmdir "$prepared" 2>/dev/null || :' EXIT
cat > "$prepared/payload"
printf '%s  %s\n' {} "$prepared/payload" | sha256sum -c - >/dev/null
chmod 700 "$prepared/payload"
printf 'INFRATERNAL_PAYLOAD_CACHE_V1\n' > "$prepared/owner"
if [ -e "$cache" ]; then
    mv -Tf "$prepared/payload" "$cache/payload"
else
    mv -Tn "$prepared" "$cache"
    [ ! -e "$prepared" ] || exit 71
fi
"#,
                shell_quote(&digest),
            );
            session
                .run(
                    &Self::script_for(target.mode, uuid::Uuid::nil(), uuid::Uuid::new_v4(), &body),
                    Input::File(binary),
                )
                .await?;
            Ok(())
        })
    }

    #[cold]
    #[inline(never)]
    fn script(&self, body: &str) -> String {
        // setup_guard.sh / setup_lock.sh proof notes [17][243]:
        // Every new installer command takes this same directory lock. It leaves
        // no lock file and serializes admission, recovery and journal mutation.
        // A bounded lease holds the transaction directory across SSH command gaps. Its
        // public PID/start-time receipt is not authority by itself: retirement also
        // requires the process's inherited descriptor to refer to this exact directory.
        // Also detect a holder whose creation was interrupted before PID journaling.
        // Such an unrecorded lease expires at the same bounded setup deadline.
        let guarded = format!("{SETUP_LOCK}\nsetup_guard\n{body}");
        Self::script_for(self.mode, self.host, self.transaction, &guarded)
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn script_for(
        mode: InstallMode,
        host: uuid::Uuid,
        transaction: uuid::Uuid,
        body: &str,
    ) -> String {
        let script = Self::unprivileged_script(mode, host, transaction, body);
        if mode == InstallMode::Root {
            // Bind the program once: both branches execute the same bytes, and
            // a second quoted copy would double every root command, which
            // nests inside restaging and must fit one kernel argument (#230).
            format!(
                "program={}\nif [ \"$(id -u)\" = 0 ]; then exec sh -c \"$program\"; else exec sudo -n sh -c \"$program\"; fi",
                shell_quote(&script)
            )
        } else {
            script
        }
    }

    /// The mode's installation variables and ownership prelude, without the
    /// root privilege wrapper. Only a program already running inside a
    /// wrapped root step may use it directly (#230).
    #[cold]
    #[inline(never)]
    fn unprivileged_script(
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
        // Existing data must be private to the execution uid before any read or write.
        // Only the root base may also be 0711: that is `infraternal up`'s
        // /var/lib/infraternal, where others pass through to its 0755 `bin/`
        // but cannot list it (#263). Nothing makes the rootless base 0711, so it
        // stays exactly 0700 (J145 P3-4).
        let private_modes = if mode == InstallMode::Root {
            "700|711"
        } else {
            "700"
        };
        // The shared routines read their control flags with defaults; a login
        // environment must never preset them (an inherited setup_check=yes would
        // turn every refusal into success), so the prelude fixes them (#305).
        format!(
            "set -euC\nsetup_check=no setup_blocked=no setup_guarded=no setup_allow_locked_inspection=no runtime_locked=no lease_runtime=no preserve_session=no previous_kind= parent= up_root_base=/var/lib/infraternal\numask 077\nhost={}\ntransaction={}\nbase=\"{base}\"\nlauncher=\"{launcher}\"\nunit=\"{unit}\"\nmanager={}\nwanted={wanted}\nif [ -e \"$base\" ] || [ -L \"$base\" ]; then\n    [ ! -L \"$base\" ] && [ -d \"$base\" ] && [ -O \"$base\" ] || exit 71\n    case \"$(stat -c '%a' \"$base\")\" in {private_modes}) ;; *) exit 71 ;; esac\nfi\n{body}",
            shell_quote(&host),
            shell_quote(&transaction.simple().to_string()),
            shell_quote(manager)
        )
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

    /// Each step still runs a fresh errexit child with the full ownership
    /// prelude. Only its representation is shared before crossing SSH, so
    /// early session startup and enrollment carry that prelude once (D255).
    fn step_header(&self) -> Result<String, Failure> {
        let mut script = SETUP_HEADER.to_owned();
        if self.mode == InstallMode::Rootless {
            writeln!(script, "setup_common={}", shell_quote(&self.script("")))
                .map_err(|_| Failure::install("The host setup script could not be prepared."))?;
        }
        Ok(script)
    }

    fn step_argument(&self, body: &str) -> String {
        if self.mode == InstallMode::Rootless {
            format!("\"$setup_common\"{}", shell_quote(body))
        } else {
            // Preserve each root step's independent privilege wrapper.
            shell_quote(&self.script(body))
        }
    }

    fn setup_script(&self, join: &JoinMaterial, upload: Option<&str>) -> Result<String, Failure> {
        let mut script = self.step_header()?;
        let argument = |body: &str| self.step_argument(body);
        if let Some(upload) = upload {
            script = script.replace(
                "# INFRATERNAL_SETUP_STEPS_V1",
                "# INFRATERNAL_TRANSFER_SETUP_V1",
            );
            script = script.replace(
                "exit 0; fi",
                "if [ \"$1\" = upload ]; then exit \"$status\"; fi; exit 0; fi",
            );
            writeln!(
                script,
                "setup_step upload {}\nprintf 'PAYLOAD ready\\n'",
                argument(upload)
            )
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
        self.commit_with_timeout(None).await
    }

    async fn commit_with_timeout(&self, timeout: Option<Duration>) -> Result<(), Failure> {
        let script = self.script(r#"[ -f "$base/.bootstrap-lock/activating" ] && [ "$(cat "$base/.bootstrap-lock/transaction")" = "$transaction" ] || exit 71
stage="$base/.bootstrap-lock"
retire_setup_lease
rm -rf "$stage"
retire_set_aside"#);
        let result = if let Some(timeout) = timeout {
            self.session
                .run_with_timeout(&script, Input::Empty, timeout)
                .await
        } else {
            self.session.run(&script, Input::Empty).await
        };
        result.map_err(|error| error.at(InstallStep::Install).in_mode(self.mode))?;
        Ok(())
    }

    /// Start read-only commit admission while terminal proof is in flight.
    /// Deletion requires the caller's one-use signal after marker plus status-zero exit.
    /// # Errors
    /// Retains rollback artifacts when proof/cancellation closes the signal.
    pub async fn commit_after(
        &self,
        release: tokio::sync::oneshot::Receiver<()>,
        timeout: Option<Duration>,
    ) -> Result<(), Failure> {
        if !self.session.setup_steps() {
            release.await.map_err(|_| {
                Failure::install("Host provisioning stopped before terminal proof.")
            })?;
            return self.commit_with_timeout(timeout).await;
        }
        // The parent-directory guard is taken only after approval. The new
        // agent takes a shared lock on that directory before it binds (#230);
        // holding the exclusive guard across the proof wait would keep the
        // agent from connecting, and so the proof from ever arriving.
        let script = Self::script_for(
            self.mode,
            self.host,
            self.transaction,
            &format!(
                r#"{SETUP_LOCK}
stage="$base/.bootstrap-lock"
[ -f "$stage/activating" ] && [ "$(cat "$stage/transaction")" = "$transaction" ] || exit 71
# No journal or artifact changes occur before the caller proves the terminal.
read -r approved || exit 1
[ -z "$approved" ] || exit 1
setup_guard
[ -f "$stage/activating" ] && [ "$(cat "$stage/transaction")" = "$transaction" ] || exit 71
retire_setup_lease
rm -rf "$stage"
retire_set_aside"#
            ),
        );
        let result = if let Some(timeout) = timeout {
            self.session
                .run_with_timeout(&script, Input::Signal(release), timeout)
                .await
        } else {
            self.session.run(&script, Input::Signal(release)).await
        };
        result.map_err(|error| error.at(InstallStep::Install).in_mode(self.mode))?;
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

    /// Retain the same authenticated master when rebuilding an early route.
    #[must_use]
    pub fn ssh_session(&self) -> Arc<dyn SshSession> {
        self.session.clone()
    }

    /// Keep each attempt on its two admitted exact-version images. A different
    /// full image cannot silently change what an already-published retry executes.
    fn pin_image(&self, slot: usize, digest: &Arc<str>) -> Result<(), Failure> {
        if self.images[slot].get_or_init(|| digest.clone()) == digest {
            Ok(())
        } else {
            Err(invalid_setup())
        }
    }

    /// Reattach the same shim after a setup failure; never launch a replacement shell.
    /// # Errors
    /// Refuses foreign ownership, missing payloads and a changed session receipt.
    pub async fn resume_session(&self, id: uuid::Uuid) -> Result<crate::duplex::Duplex, Failure> {
        let mut images = self.images.iter().filter_map(std::sync::OnceLock::get);
        let first = images.next().ok_or_else(invalid_setup)?;
        let allowed = images
            .next()
            .map_or_else(|| first.to_string(), |full| format!("{first}|{full}"));
        // The stage can contain a partial full-image write. The cache changes
        // only after upload verification; hash it again before any execution.
        // Both its structural checks and the same transaction guard still apply.
        let body = format!(
            r#"
{PAYLOAD_CACHE}
validate_cache
[ -f "$base/.bootstrap-owner" ] && [ ! -L "$base/.bootstrap-owner" ] && [ "$(cat "$base/.bootstrap-owner")" = "$host" ] || exit 71
stage="$base/.bootstrap-lock"
if [ -e "$stage" ] || [ -L "$stage" ]; then
    [ -d "$stage" ] && [ ! -L "$stage" ] && [ -f "$stage/transaction" ] && [ ! -L "$stage/transaction" ] && [ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
fi
[ -f "$cache/payload" ] && [ ! -L "$cache/payload" ] || exit 71
digest=$(sha256sum < "$cache/payload")
digest=${{digest%% *}}
case "$digest" in {allowed}) :;; *) exit 71;; esac
exec 9<&-
exec "$cache/payload" __ssh-session --state "$base/sessions" --session {id}
"#
        );
        let channel = self.session.stream(&self.script(&body)).await?;
        if channel.line(64).await? != format!("SESSION {id}\n").as_bytes() {
            return Err(invalid_setup());
        }
        Ok(channel)
    }

    /// Retry the same owned installation without ending or replacing its shim.
    /// Existing fresh-host enrollment state stays with that host's private root.
    /// # Errors
    /// Refuses foreign journals and any rollback/staging/setup failure.
    pub async fn restart_setup(&self, binary: &Path, join: &JoinMaterial) -> Result<bool, Failure> {
        self.restart_setup_with(binary, join, None).await
    }

    /// Restage using public encoding support from this same SSH check.
    /// Unknown/root/retry paths retain ordinary negotiation. Private enrollment
    /// still waits for the exact selection and verified full-payload receipt.
    /// # Errors
    /// Refuses changed ownership, encoding, upload or enrollment as usual.
    pub async fn restart_setup_with(
        &self,
        binary: &Path,
        join: &JoinMaterial,
        hint: Option<crate::transport::TransferChoice>,
    ) -> Result<bool, Failure> {
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
        // As in rollback, the lease is retired inside ROLLBACK_TRANSACTION
        // only after this transaction's ownership is validated (#230).
        let cleanup =
            format!("{RUNTIME_CLEANUP}\n{FRESH_CLEANUP}\n{retain}\n{ROLLBACK_TRANSACTION}");
        if self.session.setup_steps() {
            // Recover only this journal before selecting the full payload.
            // The early shim keeps its open executable and private rendezvous;
            // no upload starts until its prompt has already been published.
            self.transfer_setup(binary, join, Some(&cleanup), hint)
                .await
        } else {
            self.session
                .run(&self.script(&cleanup), Input::Empty)
                .await?;
            self.stage_and_setup(binary, join).await
        }
    }

    /// Restore the previous installation, or remove only this host-bound fresh installation.
    /// # Errors
    /// Reports an unreachable host/failed cleanup; callers retain that fact in progress.
    pub fn rollback(&self) -> crate::transport::Operation<'_, ()> {
        // Failure and earlier-attempt recovery share one teardown poller [243].
        // The temporary allocation is confined to cleanup, outside the happy path.
        // ROLLBACK_TRANSACTION retires the lease only after validating that
        // this exact transaction owns it (#230).
        Box::pin(async move {
            self.session
                .run(
                    &self.script(&format!(
                        "{RUNTIME_CLEANUP}\n{FRESH_CLEANUP}\npreserve_session=no\n{ROLLBACK_TRANSACTION}"
                    )),
                    Input::Empty,
                )
                .await
                .map_err(|error| error.at(InstallStep::Install).in_mode(self.mode))?;
            Ok(())
        })
    }
}

async fn send_transfer(
    channel: &crate::duplex::Duplex,
    transfer: &Transfer,
    binary: &Path,
    choice: crate::transport::TransferChoice,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    let bytes = match choice {
        crate::transport::TransferChoice::Reuse => None,
        crate::transport::TransferChoice::Gzip => {
            Some(transfer.gzip.as_deref().ok_or_else(invalid)?)
        }
        crate::transport::TransferChoice::Zstd => {
            Some(transfer.zstd.as_deref().ok_or_else(invalid)?)
        }
        crate::transport::TransferChoice::Raw => {
            let mut file = tokio::fs::File::open(binary).await?;
            let mut buffer = vec![0; 65536];
            let mut remaining = transfer.raw_size;
            while remaining != 0 {
                let limit = usize::try_from(remaining.min(65536)).map_err(|_| invalid())?;
                let count = file.read(&mut buffer[..limit]).await?;
                if count == 0 {
                    return Err(invalid());
                }
                channel.write(&buffer[..count]).await?;
                remaining -= count as u64;
            }
            None
        }
    };
    if let Some(bytes) = bytes {
        channel.write(bytes).await?;
    }
    Ok(())
}

// Every compound operation observes a fresh errexit child and emits only this
// canonical receipt. The duplex bridge shares the existing refusal decoder.
const SETUP_HEADER: &str = "# INFRATERNAL_SETUP_STEPS_V1\nset -u\nsetup_step() {\n    printf 'STEP %s\\n' \"$1\"\n    if sh -c \"$2\"; then :; else status=$?; printf 'FAIL %s %s\\n' \"$1\" \"$status\"; exit 0; fi\n}\n";

/// Decode only canonical named refusals through the existing bounded setup parser.
/// Context prefixes are local metadata, never completed stages or remote diagnostics.
#[must_use]
pub fn parse_refusal(receipt: &[u8], step: InstallStep) -> Option<Failure> {
    // Prefixes supply the frozen decoder's context; they are never published
    // as completed setup stages or copied from remote diagnostics.
    if matches!(step, InstallStep::Connect) {
        let status = receipt.strip_prefix(b"FAIL connect ")?;
        let mut upload = b"FAIL upload ".to_vec();
        upload.extend_from_slice(status);
        return parse_refusal(&upload, InstallStep::Upload)
            .map(|failure| failure.at(InstallStep::Connect));
    }
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

// The staged binary validates and takes the inherited runtime lock on fd 6.
// The shell keeps the same open description until all receipt cleanup ends.
// Legacy runtimes without that file use the binary's conservative socket probe.
// A private parent-directory setup guard fences startup during final lock unlink.
// `refuse <cause>` names why an earlier journal is not recoverable with a fixed
// token (#305). The read-only check sets setup_check=yes, so the record reaches
// parse_check and the person sees the cause; every mutating caller still exits 75.
pub(crate) const RUNTIME_CLEANUP: &str = include_str!("runtime_cleanup.sh");

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
// Admission and cleanup share the same private-parent rule. Refuse a parent
// that cannot protect a rollback receipt before creating any installation data.
// A retired fresh transaction still owns final cleanup outside the base.
// Admit no replacement until its receipt is removed after successful cleanup.
// The private acquisition journal precedes mkdir. It proves this attempt's
// empty lock if the command stops before the lock's ordinary receipts exist.
const STAGE_TRANSACTION: &str = r#"
parent=$(dirname "$base")
if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then mkdir -p "$parent"; fi
[ -d "$parent" ] && [ ! -L "$parent" ] && [ -O "$parent" ] || exit 71
parent_mode=$(stat -c '%a' "$parent")
[ "$((0$parent_mode & 022))" -eq 0 ] || exit 71
setup_guard
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
printf '%s %s\n' "$transaction" "$kind" > "$base/.bootstrap-acquiring"
mkdir "$stage" || exit 72
printf '%s\n' "$transaction" > "$stage/transaction"
printf '%s\n' "$kind" > "$stage/kind"
rm -f "$base/.bootstrap-acquiring"
start_setup_lease
"#;

// A fresh full-image stage takes the runtime lifetime lock before any
// service can bind, and its lease keeps it across SSH command gaps (#230).
// Only the full image implements the runtime-lock helper; the early session
// image is never passed here.
const RUNTIME_HANDOFF: &str =
    "\nif [ \"$kind\" = fresh ]; then handoff_setup_lease \"$stage/payload\" yes; fi\n";

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
// Shell proof notes (kept out of the transmitted program [243]):
// This receipt means service rollback is complete. Do not repeat service
// changes after a stop inside stage retirement, even if its markers are gone.
// Creation can succeed before the receipt's bytes fit on disk. Only
// the exact acquisition journal owns this private, empty lock; never
// treat a different nonempty transaction as an interrupted write.
// Only the pre-mkdir journal authorizes an empty, uninitialized lock.
// Refused stop retains both installation and policy receipts for cleanup retry.
// Only the validated original transaction may retire its cross-command lease.
// A losing installer must not stop another attempt's lease before refusing it.
// Only a journaled final replacement belongs to this attempt. Temporary
// files stay in stage; unrelated suffix files are never cleanup targets.
// Retire replacement markers before restoring backups: a retry must never
// delete an original already restored by an interrupted rollback. Backups
// still present remain sufficient evidence to retry interrupted restoration.
// Restoration can stop between moving the backup and recreating links.
// The original-presence marker survives both operations and makes retry safe.
// No replacement began, but a lost stop reply may have stopped the old service.
// An acknowledged refusal is staging-only cleanup and must not restart it.
// An incomplete upload is owned by this transaction. Reclaim it before
// allocating the outside receipt, including when the home filesystem is full.
pub(crate) const ROLLBACK_TRANSACTION: &str = r#"
if [ -e "$receipt" ] || [ -L "$receipt" ]; then
    validate_receipt
    validate_control_socket
    stage="$base/.bootstrap-lock"
    if [ -e "$stage" ] || [ -L "$stage" ]; then
        validate_retired_stage "$transaction" "$host"
        retire_setup_lease
        rm -rf "$stage"
    fi
    finish_fresh
    exit 0
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
        [ "$acquired" = yes ] && [ -O "$stage" ] && [ "$(stat -c '%a' "$stage")" = 700 ] || exit 72
        [ -O "$stage/transaction" ] && [ "$(stat -c '%a:%s:%h' "$stage/transaction")" = 600:0:1 ] || exit 72
        rm "$stage/transaction"
        rmdir "$stage" || exit 72
    fi
else
    [ "$acquired" = yes ] || exit 72
    rmdir "$stage" || exit 72
fi
if [ -f "$stage/kind" ] && [ ! -L "$stage/kind" ]; then kind=$(cat "$stage/kind"); else [ "$acquired" = yes ] || exit 72; fi
case "$kind" in
    fresh) validate_parent;;
    upgrade) :;;
    *) exit 71;;
esac
if [ -e "$stage/activating" ] || [ -L "$stage/activating" ]; then
    [ -f "$stage/activating" ] && [ ! -L "$stage/activating" ] && [ -O "$stage/activating" ] && [ "$(stat -c '%a:%h:%s' "$stage/activating")" = 600:1:0 ] || exit 71
    [ ! -e "$stage/failed" ] && [ ! -L "$stage/failed" ] || exit 71
    mv -T "$stage/activating" "$stage/failed"
fi
if [ -e "$stage/failed" ] || [ -L "$stage/failed" ]; then
    [ -f "$stage/failed" ] && [ ! -L "$stage/failed" ] && [ -O "$stage/failed" ] && [ "$(stat -c '%a:%h:%s' "$stage/failed")" = 600:1:0 ] || exit 71
fi
retire_setup_lease
if [ -f "$stage/failed" ]; then
    $manager stop infraternal-agent.service >/dev/null 2>&1
fi
if [ "$kind" = fresh ]; then
    identity=$(stat -c '%d:%i' "$base")
    validate_control_socket
fi
if [ -f "$stage/linger-requested" ]; then
    uid=$(id -u)
    if [ "$(loginctl show-user "$uid" -p Linger --value 2>/dev/null || :)" = yes ]; then
        loginctl --no-ask-password disable-linger "$uid" >/dev/null 2>&1
    fi
    rm -f "$stage/linger-requested"
fi
if [ -f "$stage/failed" ]; then
    $manager disable infraternal-agent.service >/dev/null 2>&1 || :
    if [ -f "$stage/replacing-binary" ] || [ -f "$stage/previous-binary" ]; then rm -f "$base/bin/live" "$base/bin/current"; fi
    if [ "${preserve_session:-no}" != yes ] || [ "$kind" != fresh ]; then
        if [ -f "$stage/replacing-state" ] || [ -d "$stage/previous-state" ]; then rm -rf "$base/state"; fi
    fi
    if [ -f "$stage/replacing-launcher" ] && [ ! -f "$stage/had-launcher" ]; then rm -f "$launcher"; fi
    [ ! -f "$stage/replacing-unit" ] || rm -f "$unit"
    rm -f "$stage/replacing-binary" "$stage/replacing-state" "$stage/replacing-unit" "$stage/replacing-launcher"
    if [ -f "$stage/previous-binary" ]; then
        mv "$stage/previous-binary" "$base/bin/live"
    fi
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
if [ -f "$stage/stopping" ] && [ -f "$stage/was-active" ] && [ ! -f "$stage/stop-refused" ] && [ ! -f "$stage/activating" ] && [ ! -f "$stage/failed" ]; then
    $manager start infraternal-agent.service
fi
if [ "$kind" = fresh ]; then
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
// Shell proof notes (kept out of the transmitted program [243]):
// The outside receipt can outlive an interrupted retirement of the acquisition
// journal. Remove only its exact fresh binding, after validating the base owner.
// Never recursively delete unjournaled contents. Unexpected data keeps
// the receipt and makes cleanup fail rather than claiming success.
// The service creates these rendezvous directories before its first PTY.
// Remove only empty owned directories; never follow a parent link or
// remove retained shim/session data merely because installation failed.
// Preserve the owner marker alongside the receipt if unknown data keeps
// the root nonempty. Another attempt cannot claim this unfinished root.
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
        rm -f "$base/.bootstrap-ready"
        retire_control_socket
        rmdir "$base/bin" 2>/dev/null || :
        if [ -d "$base/sessions" ] && [ ! -L "$base/sessions" ] && [ -O "$base/sessions" ]; then
            if [ ! -L "$base/sessions/sessions" ] && [ -O "$base/sessions/sessions" ]; then
                rmdir "$base/sessions/sessions" 2>/dev/null || :
            fi
            if [ -e "$base/sessions/.lifetime-lock" ]; then rm -- "$base/sessions/.lifetime-lock"; fi
            rmdir "$base/sessions" 2>/dev/null || :
        fi
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

fn parse_join_key_receipt(bytes: &[u8]) -> Result<[u8; 32], Failure> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_setup())?;
    if let Some(digest) = text
        .strip_prefix("KEY-DIGEST ")
        .and_then(|value| value.strip_suffix('\n'))
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        let mut decoded = [0u8; 32];
        for (index, pair) in digest.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        return Ok(decoded);
    }
    let message = match text {
        "PREPARE-REFUSED DNS\n" => {
            "The infraternal agent on this host cannot resolve the server's HTTPS origin. Check DNS and allow outbound TCP 443."
        }
        "PREPARE-REFUSED CONNECT\n" => {
            "The infraternal agent on this host cannot reach the server over HTTPS. Allow outbound TCP 443 to the server's public origin."
        }
        "PREPARE-REFUSED TLS\n" => {
            "The infraternal agent on this host cannot verify the server's public HTTPS certificate. Check the public certificate chain and server name."
        }
        "PREPARE-REFUSED UPGRADE\n" => {
            "The infraternal agent on this host reached the server over HTTPS, but the WebSocket upgrade failed. Allow WebSocket upgrades through the HTTPS proxy."
        }
        "PREPARE-REFUSED CHALLENGE\n" => {
            "The infraternal agent reached the server over HTTPS, but the server did not return a valid challenge. Deploy a compatible server build."
        }
        "PREPARE-REFUSED REFUSED\n" => {
            "The infraternal agent could not prepare its host key. Check its private state directory and try again."
        }
        _ => return Err(invalid_setup()),
    };
    // Failure::at replaces Install text with the generic per-step remedy; these
    // fixed receipts already name the exact HTTPS cause, so only record the step.
    let mut failure = Failure::install(message);
    failure.failed_step = Some(InstallStep::Connect);
    Err(failure)
}

fn hex_nibble(byte: u8) -> Result<u8, Failure> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid_setup()),
    }
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

#[cfg(test)]
mod tests {
    //! Pins the check-time transfer record and the script compaction rules (#189).
    use super::*;

    #[test]
    fn only_the_root_base_may_be_traversable() {
        // J145 P3-4: the rootless base stays exactly 0700.
        use std::os::unix::fs::PermissionsExt;
        let home =
            std::env::temp_dir().join(format!("infraternal-base-modes-{}", std::process::id()));
        let base = home.join(".local/share/infraternal");
        std::fs::create_dir_all(&base).unwrap();
        let script = Installation::unprivileged_script(
            InstallMode::Rootless,
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            "exit 0",
        );
        let run = || {
            std::process::Command::new("sh")
                .args(["-c", &script])
                .env("HOME", &home)
                .status()
                .unwrap()
                .code()
        };
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(run(), Some(0), "a private rootless base is accepted");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o711)).unwrap();
        assert_eq!(run(), Some(71), "a 0711 rootless base is refused");
        let root = Installation::unprivileged_script(
            InstallMode::Root,
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            "exit 0",
        );
        assert!(
            root.contains("in 700|711) ;;"),
            "the root base keeps `up`'s 0711"
        );
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn transfer_caps_accept_only_the_fixed_record() {
        let digest = "a".repeat(64);
        assert_eq!(
            TransferCaps::parse(format!("CAPS zstd - {digest}\n").as_bytes()),
            Some(TransferCaps {
                zstd: true,
                gzip: false,
                cache: Some(digest.clone()),
            })
        );
        assert_eq!(
            TransferCaps::parse(b"CAPS - gzip -\n"),
            Some(TransferCaps {
                zstd: false,
                gzip: true,
                cache: None,
            })
        );
        for invalid in [
            "CAPS zstd gzip -".to_owned(),
            "CAPS zstd gzip - extra\n".to_owned(),
            "CAPS xz gzip -\n".to_owned(),
            format!("CAPS zstd gzip {}\n", "A".repeat(64)),
            format!("CAPS zstd gzip {}\n", "a".repeat(63)),
            "CAPS  zstd gzip -\n".to_owned(),
            "CAPS zstd gzip -\r\n".to_owned(),
        ] {
            assert_eq!(TransferCaps::parse(invalid.as_bytes()), None, "{invalid:?}");
        }
    }

    #[test]
    fn inherited_control_variables_cannot_change_a_setup_program() {
        // The login environment can carry any of these names. A mutating
        // program must still refuse with 75, never report success (#305).
        let body = format!(
            "{RUNTIME_CLEANUP}\nprintf '%s ' \"$setup_check\" \"$setup_blocked\" \"$setup_guarded\" \"$setup_allow_locked_inspection\" \"$runtime_locked\" \"$lease_runtime\" \"$preserve_session\" \"${{previous_kind:-unset}}\" \"${{parent:-unset}}\"\nrefuse kind"
        );
        let script = Installation::script_for(
            InstallMode::Rootless,
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            &body,
        );
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .env("HOME", "/nonexistent/j93d-prelude")
            .env("setup_check", "yes")
            .env("setup_blocked", "yes")
            .env("setup_guarded", "yes")
            .env("setup_allow_locked_inspection", "yes")
            .env("runtime_locked", "yes")
            .env("lease_runtime", "yes")
            .env("preserve_session", "yes")
            .env("previous_kind", "upgrade")
            .env("parent", "/tmp")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(75));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "no no no no no no no unset unset INFRATERNAL_SETUP_REFUSED kind\n"
        );
    }

    #[test]
    fn compaction_drops_only_comment_lines_and_indentation() {
        assert_eq!(
            compact(
                "# header\nif true; then\n    # note\n\tprintf '%s\\n' \"a # b\"\n\nfi # tail\n"
            ),
            "if true; then\nprintf '%s\\n' \"a # b\"\nfi # tail\n"
        );
    }

    #[test]
    fn embedded_setup_programs_have_no_constructs_compaction_would_change() {
        // Compaction is sound only without here-documents, line continuations
        // and quoted strings spanning lines; keep that true for these sources.
        for source in [
            crate::probe::CHECK_SCRIPT,
            crate::previous_attempt::INSPECT,
            SETUP_GUARD,
            RUNTIME_CLEANUP,
            PAYLOAD_CACHE,
            STAGE_TRANSACTION,
            PUBLISH_PAYLOAD_CACHE,
            TRANSFER_PROBE,
            SETUP_HEADER,
        ] {
            for line in source.lines() {
                let code = if line.trim_start().starts_with('#') {
                    ""
                } else {
                    line
                };
                assert!(!code.contains("<<"), "{line}");
                assert!(!code.ends_with('\\'), "{line}");
                assert_eq!(code.matches('\'').count() % 2, 0, "{line}");
                assert_eq!(
                    code.matches('"').count() % 2,
                    code.matches("\\\"").count() % 2,
                    "{line}"
                );
            }
        }
    }
}
