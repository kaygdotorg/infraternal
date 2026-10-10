//! Stages a matching binary and identity, preserving previous artifacts until authenticated readiness [17][139].

use crate::{
    model::{Failure, InstallMode, Target},
    probe::Architecture,
    transport::{Input, Secret, SshSession, shell_quote},
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::AsyncReadExt;

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

/// One-time capability and pin are produced by trusted enrollment, never serialized by bootstrap.
pub struct JoinMaterial {
    pub host: uuid::Uuid,
    pub url: String,
    pub stdin: Secret,
}

/// Holds a host-local transaction lock until commit or explicit rollback.
/// Callers must run rollback on cancellation; Drop cannot perform asynchronous remote I/O.
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
        let digest = binary_digest(binary).await?;
        self.session.run(&self.script(&format!(r#"
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
mkdir "$base/.bootstrap-lock" || exit 72
stage="$base/.bootstrap-lock"
printf '%s\n' "$transaction" > "$stage/transaction"
if [ -e "$base/bin/current" ] || [ -L "$base/bin/current" ]; then
    [ -L "$base/bin/current" ] && [ "$(readlink "$base/bin/current")" = "$base/bin/live" ] || exit 71
    printf 'upgrade\n' > "$stage/kind"
else
    printf 'fresh\n' > "$stage/kind"
fi
cat > "$stage/payload"
printf '%s  %s\n' {} "$stage/payload" | sha256sum -c - >/dev/null
chmod 700 "$stage/payload"
"#, shell_quote(&digest))), Input::File(binary)).await?;
        Ok(())
    }

    fn script(&self, body: &str) -> String {
        let host = self.host.simple().to_string();
        let (base, launcher, unit, manager) = match self.mode {
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
        let wanted = if self.mode == InstallMode::Root {
            "multi-user.target"
        } else {
            "default.target"
        };
        let script = format!(
            "set -euC\numask 077\nhost={}\ntransaction={}\nbase=\"{base}\"\nlauncher=\"{launcher}\"\nunit=\"{unit}\"\nmanager={}\nwanted={wanted}\n# Existing data must be private to the execution uid before any read or write.\nif [ -e \"$base\" ] || [ -L \"$base\" ]; then\n    [ ! -L \"$base\" ] && [ -d \"$base\" ] && [ -O \"$base\" ] && [ \"$(stat -c '%a' \"$base\")\" = 700 ] || exit 71\nfi\n{body}",
            shell_quote(&host),
            shell_quote(&self.transaction.simple().to_string()),
            shell_quote(manager)
        );
        if self.mode == InstallMode::Root {
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
        let join_body = format!(
            r#"
stage="$base/.bootstrap-lock"
[ -f "$stage/kind" ] && [ ! -L "$stage" ] || exit 71
[ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
[ ! -e "$stage/state" ] && [ ! -L "$stage/state" ] || exit 71
# Retain the host's existing identity for immutable same-key re-enrollment.
# The copy stays in its private host-local transaction, never crossing SSH.
if [ -d "$base/state" ]; then cp -a "$base/state" "$stage/state"; fi
# Enrollment writes only the staged identity and returns before service activation.
# Shim rendezvous belongs to the live service, outside identity replacement.
"$stage/payload" agent --data "$stage/state" join {} --enroll-only >/dev/null 2>&1
"#,
            shell_quote(&join.url)
        );
        self.session
            .run(&self.script(&join_body), Input::Bytes(join.stdin.expose()))
            .await?;
        // Never replace unrelated launcher/unit files. A previous installation is
        // recognizable only through the same host marker and exact launcher target.
        let start_body = r##"
stage="$base/.bootstrap-lock"
[ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
if [ -e "$launcher" ] || [ -L "$launcher" ]; then
    [ -L "$launcher" ] && [ "$(readlink "$launcher")" = "$base/bin/current" ] || exit 71
    : > "$stage/had-launcher"
fi
if [ -e "$unit" ] || [ -L "$unit" ]; then
    [ -f "$unit" ] && [ ! -L "$unit" ] && grep -Fxq "# infraternal bootstrap $host" "$unit" || exit 71
    cp "$unit" "$stage/previous-unit"
fi
$manager is-enabled infraternal-agent.service >/dev/null 2>&1 && : > "$stage/was-enabled" || :
$manager is-active infraternal-agent.service >/dev/null 2>&1 && : > "$stage/was-active" || :
mkdir -p "$base/bin" "$(dirname "$launcher")" "$(dirname "$unit")"
# Rename the old live binary/state into the transaction, not into a disposable
# upload file. This makes failures after a service stop explicitly reversible.
# Replacing a running daemon requires an acknowledged stop; otherwise its old
# authenticated connection could conceal a failed upgrade.
# Intent survives an interrupted reply after the manager stopped the old service.
: > "$stage/stopping"
if [ -f "$stage/was-active" ]; then
    if ! $manager stop infraternal-agent.service >/dev/null 2>&1; then
        : > "$stage/stop-refused"
        exit 1
    fi
else
    $manager stop infraternal-agent.service >/dev/null 2>&1 || :
fi
# Journal ownership before replacement, after stopping the previous service.
# A refused prior stop is separate from an unknown/interrupted reply.
: > "$stage/activating"
if [ -e "$base/bin/live" ]; then : > "$stage/had-binary"; mv "$base/bin/live" "$stage/previous-binary"; fi
: > "$stage/replacing-binary"
mv "$stage/payload" "$base/bin/live"
if [ -e "$base/state" ]; then : > "$stage/had-state"; mv "$base/state" "$stage/previous-state"; fi
: > "$stage/replacing-state"
mv "$stage/state" "$base/state"
ln -s "$base/bin/live" "$base/bin/current.new"
mv -Tf "$base/bin/current.new" "$base/bin/current"
ln -s "$base/bin/current" "$launcher.new"
mv -Tf "$launcher.new" "$launcher"
printf '# infraternal bootstrap %s\n[Unit]\nDescription=infraternal host daemon\n[Service]\nExecStart="%s/bin/current" agent --data "%s/state" --state "%s/sessions" run\nRestart=on-failure\nKillMode=process\n[Install]\nWantedBy=%s\n' "$host" "$base" "$base" "$base" "$wanted" > "$unit.new"
: > "$stage/replacing-unit"
mv -f "$unit.new" "$unit"
$manager daemon-reload
$manager enable --now infraternal-agent.service
"##;
        self.session
            .run(&self.script(start_body), Input::Empty)
            .await?;
        Ok(())
    }

    /// Ask policy to persist this user's manager without sudo or an interactive prompt.
    /// A denied request is a warning; only a policy-confirmed change is owned by rollback.
    /// # Errors
    /// Reports a failed SSH operation or an invalid bounded policy receipt.
    pub async fn enable_linger(&self) -> Result<bool, Failure> {
        if self.mode == InstallMode::Root {
            return Ok(true);
        }
        let output = self.session.run(&self.script(r#"
stage="$base/.bootstrap-lock"
[ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
if ! command -v loginctl >/dev/null 2>&1; then printf 'no\n'; exit 0; fi
uid=$(id -u)
if [ "$(loginctl show-user "$uid" -p Linger --value 2>/dev/null || :)" = yes ]; then printf 'yes\n'; exit 0; fi
# Intent precedes mutation so interrupted policy calls remain reversible.
: > "$stage/linger-requested"
if ! loginctl --no-ask-password enable-linger "$uid" >/dev/null 2>&1; then
    # An acknowledged refusal owns no policy change. Interrupted calls retain
    # intent, but later external enablement must not belong to this attempt.
    rm -f "$stage/linger-requested"
    printf 'no\n'
    exit 0
fi
state=$(loginctl show-user "$uid" -p Linger --value 2>/dev/null || :)
case "$state" in
    yes) printf 'yes\n';;
    no) rm -f "$stage/linger-requested"; printf 'no\n';;
    *) printf 'no\n';;
esac
"#), Input::Empty).await?;
        parse_linger(&output.stdout)
    }

    /// Only authenticated connection/facts/terminal proof permits deletion of previous artifacts.
    /// # Errors
    /// Reports failed cleanup without claiming that installation is complete.
    pub async fn commit(&self) -> Result<(), Failure> {
        self.session.run(&self.script(r#"[ -f "$base/.bootstrap-lock/activating" ] && [ "$(cat "$base/.bootstrap-lock/transaction")" = "$transaction" ] || exit 71
rm -rf "$base/.bootstrap-lock"
"#), Input::Empty).await?;
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

    /// Restore the previous installation, or remove only this host-bound fresh installation.
    /// # Errors
    /// Reports an unreachable host/failed cleanup; callers retain that fact in progress.
    pub async fn rollback(&self) -> Result<(), Failure> {
        self.session.run(&self.script(&format!("{FRESH_CLEANUP}\n{}", r#"
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
if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then exit 0; fi
[ -d "$stage" ] && [ ! -L "$stage" ] || exit 71
[ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
# Refused stop retains both installation and policy receipts for cleanup retry.
kind=$(cat "$stage/kind")
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
    if [ -f "$stage/replacing-state" ] || [ -d "$stage/previous-state" ]; then rm -rf "$base/state"; fi
    rm -f "$base/bin/current.new" "$launcher.new" "$unit.new"
    [ -f "$stage/had-launcher" ] || rm -f "$launcher"
    [ ! -f "$stage/replacing-unit" ] || rm -f "$unit"
    # Retire replacement markers before restoring backups: a retry must never
    # delete an original already restored by an interrupted rollback. Backups
    # still present remain sufficient evidence to retry interrupted restoration.
    rm -f "$stage/replacing-binary" "$stage/replacing-state" "$stage/replacing-unit"
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
    if [ ! -e "$receipt" ] && [ ! -L "$receipt" ]; then
        printf '%s %s fresh %s\n' "$host" "$transaction" "$(stat -c '%d:%i' "$base")" > "$receipt"
    fi
    validate_receipt
fi
rm -rf "$stage"
if [ "$kind" = fresh ]; then
    finish_fresh
fi
"#)), Input::Empty).await?;
        Ok(())
    }
}

// This public ownership receipt survives removal of the transaction directory,
// owner marker and base. Noclobber creation, bounded reads, uid/mode and directory
// identity checks preserve exact binding
// prevent stale or foreign cleanup from being mistaken for this fresh attempt.
const FRESH_CLEANUP: &str = r#"
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
finish_fresh() {
    validate_receipt
    if [ -e "$base" ] || [ -L "$base" ]; then
        [ ! -e "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] || exit 72
        if [ -e "$base/.bootstrap-owner" ] || [ -L "$base/.bootstrap-owner" ]; then
            [ -f "$base/.bootstrap-owner" ] && [ ! -L "$base/.bootstrap-owner" ] && [ "$(cat "$base/.bootstrap-owner")" = "$host" ] || exit 71
        fi
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

async fn binary_digest(path: &Path) -> Result<String, Failure> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| Failure::install("The matching static infraternal binary is unavailable."))?;
    let mut digest = Sha256::new();
    let mut bytes = vec![0; 64 * 1024];
    loop {
        let count = file
            .read(&mut bytes)
            .await
            .map_err(|_| Failure::install("The static infraternal binary could not be read."))?;
        if count == 0 {
            break;
        }
        digest.update(&bytes[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

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
