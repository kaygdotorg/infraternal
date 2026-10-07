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
            "set -euC\numask 077\nhost={}\ntransaction={}\nbase=\"{base}\"\nlauncher=\"{launcher}\"\nunit=\"{unit}\"\nmanager={}\nwanted={wanted}\n{body}",
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
"$stage/payload" agent join {} --state "$stage/state"
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
: > "$stage/activating"
$manager stop infraternal-agent.service >/dev/null 2>&1 || :
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
printf '# infraternal bootstrap %s\n[Unit]\nDescription=infraternal host daemon\n[Service]\nExecStart="%s/bin/current" agent --state "%s/state"\nRestart=on-failure\nKillMode=process\n[Install]\nWantedBy=%s\n' "$host" "$base" "$base" "$wanted" > "$unit.new"
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

    /// Only authenticated connection/facts/terminal proof permits deletion of previous artifacts.
    /// # Errors
    /// Reports failed cleanup without claiming that installation is complete.
    pub async fn commit(&self) -> Result<(), Failure> {
        self.session.run(&self.script(r#"[ -f "$base/.bootstrap-lock/activating" ] && [ "$(cat "$base/.bootstrap-lock/transaction")" = "$transaction" ] || exit 71
rm -rf "$base/.bootstrap-lock"
"#), Input::Empty).await?;
        Ok(())
    }

    /// Restore the previous installation, or remove only this host-bound fresh installation.
    /// # Errors
    /// Reports an unreachable host/failed cleanup; callers retain that fact in progress.
    pub async fn rollback(&self) -> Result<(), Failure> {
        self.session.run(&self.script(r#"
if [ ! -e "$base" ] && [ ! -L "$base" ]; then exit 0; fi
[ -f "$base/.bootstrap-owner" ] && [ "$(cat "$base/.bootstrap-owner")" = "$host" ] || exit 71
stage="$base/.bootstrap-lock"
if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then exit 0; fi
[ -d "$stage" ] && [ ! -L "$stage" ] || exit 71
[ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
if [ -f "$stage/activating" ]; then
    $manager stop infraternal-agent.service >/dev/null 2>&1 || :
    $manager disable infraternal-agent.service >/dev/null 2>&1 || :
    if [ -f "$stage/replacing-binary" ] || [ -f "$stage/previous-binary" ]; then rm -f "$base/bin/live" "$base/bin/current"; fi
    if [ -f "$stage/replacing-state" ] || [ -d "$stage/previous-state" ]; then rm -rf "$base/state"; fi
    rm -f "$base/bin/current.new" "$launcher.new" "$unit.new"
    [ -f "$stage/had-launcher" ] || rm -f "$launcher"
    [ ! -f "$stage/replacing-unit" ] || rm -f "$unit"
    if [ -f "$stage/previous-binary" ]; then
        mv "$stage/previous-binary" "$base/bin/live"
        ln -s "$base/bin/live" "$base/bin/current"
        [ -L "$launcher" ] || ln -s "$base/bin/current" "$launcher"
    fi
    [ ! -d "$stage/previous-state" ] || mv "$stage/previous-state" "$base/state"
    [ ! -f "$stage/previous-unit" ] || mv "$stage/previous-unit" "$unit"
    $manager daemon-reload
    [ ! -f "$stage/was-enabled" ] || $manager enable infraternal-agent.service
    [ ! -f "$stage/was-active" ] || $manager start infraternal-agent.service
fi
kind=$(cat "$stage/kind")
rm -rf "$stage"
if [ "$kind" = fresh ]; then
    rm -f "$base/.bootstrap-owner"
    rmdir "$base/bin" 2>/dev/null || :
    rmdir "$base" 2>/dev/null || :
fi
"#), Input::Empty).await?;
        Ok(())
    }
}

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
