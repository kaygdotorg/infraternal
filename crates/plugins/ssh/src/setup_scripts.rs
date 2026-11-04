//! Builds the existing journaled enrollment, activation, start and linger steps for SSH setup (#190).

/// Enroll into private staged state before replacing a running installation.
pub(super) fn join(url: &str) -> String {
    format!(
        r#"
stage="$base/.bootstrap-lock"
[ -f "$stage/kind" ] && [ ! -L "$stage" ] || exit 71
[ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
# Retain the host's existing identity for immutable same-key re-enrollment.
# A preflight-prepared state copy already contains the proved private key.
# The copy stays in its private host-local transaction, never crossing SSH.
if [ ! -e "$stage/state" ] && [ ! -L "$stage/state" ]; then
    if [ -d "$base/state" ] && [ ! -L "$base/state" ]; then cp -a "$base/state" "$stage/state"; else mkdir -m 700 "$stage/state"; fi
fi
[ -d "$stage/state" ] && [ ! -L "$stage/state" ] && [ -O "$stage/state" ] && [ "$(stat -c '%a' "$stage/state")" = 700 ] || exit 71
# Enrollment writes only the staged identity and returns before service activation.
# Shim rendezvous belongs to the live service, outside identity replacement.
"$stage/payload" agent --data "$stage/state" join {} --enroll-only >/dev/null
"#,
        crate::transport::shell_quote(url)
    )
}

/// Publish the staged image, canonical launcher and optional short CLI symlink.
pub(super) const ACTIVATE: &str = r##"
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
# Conventional replacement suffixes may belong to another writer. Refuse them
# before activation; build all our replacements inside the owned transaction.
for replacement in "$base/bin/current.new" "$launcher.new" "$unit.new"; do
    [ ! -e "$replacement" ] && [ ! -L "$replacement" ] || exit 71
done
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
# Transfer lifetime ownership from the staging lease while replacing artifacts (#230).
handoff_setup_lease "$stage/payload" yes
# Journal ownership before replacement, after stopping the previous service.
# A refused prior stop is separate from an unknown/interrupted reply.
: > "$stage/activating"
if [ -e "$base/bin/live" ]; then : > "$stage/had-binary"; mv "$base/bin/live" "$stage/previous-binary"; fi
: > "$stage/replacing-binary"
mv "$stage/payload" "$base/bin/live"
if [ -e "$base/state" ]; then : > "$stage/had-state"; mv "$base/state" "$stage/previous-state"; fi
: > "$stage/replacing-state"
mv "$stage/state" "$base/state"
ln -s "$base/bin/live" "$stage/current"
mv -Tf "$stage/current" "$base/bin/current"
ln -s "$base/bin/current" "$stage/launcher"
: > "$stage/replacing-launcher"
mv -Tf "$stage/launcher" "$launcher"
# Create without replacement: even a dangling foreign infra belongs to its owner.
# Journal intent first so an interrupted activation can retire only our new link.
alias="${launcher%/*}/infra"
if [ ! -e "$alias" ] && [ ! -L "$alias" ]; then
    : > "$stage/creating-alias"
    if ! ln -sT infraternal "$alias"; then
        rm -f "$stage/creating-alias"
        printf 'ALIAS skipped\n'
    fi
elif [ ! -L "$alias" ] || [ "$(stat -c '%u' "$alias")" != "$(id -u)" ] || [ "$(readlink "$alias")" != infraternal ]; then
    printf 'ALIAS skipped\n'
fi
printf '# infraternal bootstrap %s\n[Unit]\nDescription=infraternal host daemon\nStartLimitIntervalSec=0\n[Service]\nExecStart="%s/bin/current" agent --data "%s/state" --state "%s/sessions" run\nRestart=always\nRestartSec=2\nKillMode=process\nDelegate=yes\n[Install]\nWantedBy=%s\n' "$host" "$base" "$base" "$base" "$wanted" > "$stage/unit"
: > "$stage/replacing-unit"
mv -f "$stage/unit" "$unit"
"##;

pub(super) const START: &str = r#"
stage="$base/.bootstrap-lock"
[ ! -L "$stage" ] && [ "$(cat "$stage/transaction")" = "$transaction" ] || exit 72
# Keep the lease without the lifetime lock, then release this shell's copy so
# the service takes that lock itself before binding (#230).
handoff_setup_lease "$base/bin/live" no
$manager daemon-reload
exec 6<&-
$manager enable --now infraternal-agent.service
"#;

pub(super) const LINGER: &str = r#"
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
"#;
