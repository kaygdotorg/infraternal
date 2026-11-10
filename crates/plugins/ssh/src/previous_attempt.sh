# Classify earlier host provisioning using private ownership receipts; never adopt foreign data.
# The installation base is 0700, except root's /var/lib/infraternal, which
# `infraternal up` lays out as 0711 so every user can reach its 0755 bin/
# while only root can list it (#263). The installer preamble accepts the same
# and nothing else (J145 P3-4); recovering a stuck root install must too.
# Every directory under the base stays exactly 0700. up_root_base is set by
# the installation prelude (install.rs), never by the login environment; only
# the shell oracle points it at a fixture.
private_base_mode() {
 case "$(stat -c '%a' "$base")" in
  700) return 0;;
  711) [ "$(id -u)" = 0 ] && [ "$base" = "$up_root_base" ];;
  *) return 1;;
 esac
}
private_file() {
 [ -f "$1" ] && [ ! -L "$1" ] && [ -O "$1" ] && [ "$(stat -c '%a:%h' "$1")" = 600:1 ] || exit 71
 [ "$(stat -c '%s' "$1")" -le 128 ] || exit 71
}
hex_id() {
 [ "${#1}" = 32 ] || refuse id
 case "$1" in *[!0-9a-f]*) refuse id;; esac
}
setup_process_start_epoch() {
 process_start_ticks "$1" || return 1
 setup_ticks=$process_start_ticks
 setup_boot=
 while read -r setup_key setup_value setup_rest; do
  [ "$setup_key" = btime ] || continue
  setup_boot=$setup_value
  break
 done < /proc/stat
 setup_hz=$(getconf CLK_TCK 2>/dev/null) || return 1
 case "$setup_boot:$setup_hz" in *[!0-9:]*|:*|*:) return 1;; esac
 [ "$setup_hz" -gt 0 ] || return 1
 setup_lock_epoch=$((setup_boot + setup_ticks / setup_hz))
}
setup_lock_descriptor() {
 setup_candidate=$1
 setup_descriptor=$2
 setup_expected=$3
 [ -L "$setup_descriptor" ] && [ "$setup_expected" -ef "$setup_descriptor" ] || return 1
 process_start_ticks "$setup_candidate" || return 1
 setup_lock_pid=$setup_candidate
 setup_lock_birth=$process_start_ticks
 setup_lock_epoch=
 # The lease record dates the lock only when it names this holder. Any other
 # holder, such as the parent guard's, is dated by its own start (#305).
 if parse_setup_lease "$base/.bootstrap-lock/lease" && [ "$setup_lease_pid" = "$setup_candidate" ]; then
  setup_lease_epoch=$(stat -c '%Y' "$base/.bootstrap-lock/lease" 2>/dev/null || :)
  case "$setup_lease_epoch" in ''|*[!0-9]*) :;; *) setup_lock_epoch=$setup_lease_epoch;; esac
 fi
 [ -n "$setup_lock_epoch" ] || setup_process_start_epoch "$setup_candidate" || return 1
}
parse_setup_lease() {
 setup_lease_file=$1
 [ -f "$setup_lease_file" ] && [ ! -L "$setup_lease_file" ] && [ -O "$setup_lease_file" ] || return 1
 [ "$(stat -c '%a:%h' "$setup_lease_file" 2>/dev/null || :)" = 600:1 ] || return 1
 setup_lease_size=$(stat -c '%s' "$setup_lease_file" 2>/dev/null || :)
 case "$setup_lease_size" in ''|*[!0-9]*) return 1;; esac
 [ "$setup_lease_size" -ge 4 ] && [ "$setup_lease_size" -le 64 ] || return 1
 IFS=' ' read -r setup_lease_pid setup_lease_birth setup_lease_extra < "$setup_lease_file" || return 1
 [ -z "$setup_lease_extra" ] || return 1
 case "$setup_lease_pid:$setup_lease_birth" in *[!0-9:]*|:*|*:|*:*:*) return 1;; esac
 [ "$(cat "$setup_lease_file" 2>/dev/null || :)" = "$setup_lease_pid $setup_lease_birth" ] || return 1
 [ "$setup_lease_size" -eq $((${#setup_lease_pid} + ${#setup_lease_birth} + 2)) ] || return 1
}
report_setup_lock() {
 setup_locked_machine=$(hostname 2>/dev/null || :)
 case "$setup_locked_machine" in
  ''|[-.]*|*[!a-zA-Z0-9._-]*) setup_locked_machine=unknown;;
 esac
 [ "${#setup_locked_machine}" -le 253 ] || setup_locked_machine=unknown
 setup_lock_pid=unknown
 setup_lock_birth=unknown
 setup_lock_epoch=
 setup_stage="$base/.bootstrap-lock"
 if [ -d "$setup_stage" ] && [ ! -L "$setup_stage" ] && [ -f "$setup_stage/lease" ] && [ ! -L "$setup_stage/lease" ]; then
  if parse_setup_lease "$setup_stage/lease"; then
   if [ -n "$setup_lease_pid" ] && process_start_ticks "$setup_lease_pid"; then
    if [ "$process_start_ticks" = "$setup_lease_birth" ] && [ -L "/proc/$setup_lease_pid/fd/7" ] && [ "$setup_stage" -ef "/proc/$setup_lease_pid/fd/7" ]; then
     setup_lock_pid=$setup_lease_pid
     setup_lock_birth=$setup_lease_birth
     setup_lock_epoch=$(stat -c '%Y' "$setup_stage/lease" 2>/dev/null || :)
    fi
   fi
  fi
 fi
 if [ "$setup_lock_pid" = unknown ]; then
  for setup_process in /proc/[0-9]*; do
   [ -O "$setup_process" ] || continue
   setup_candidate=${setup_process##*/}
   [ "$setup_candidate" != "$$" ] || continue
   if [ -d "$setup_stage" ] && setup_lock_descriptor "$setup_candidate" "$setup_process/fd/7" "$setup_stage"; then break; fi
   if [ -n "${parent:-}" ] && setup_lock_descriptor "$setup_candidate" "$setup_process/fd/9" "$parent"; then break; fi
  done
 fi
 setup_lock_attempt=$(setup_attempt "$setup_stage")
 setup_since=unknown
 case "$setup_lock_epoch" in ''|*[!0-9]*) :;;
  *) setup_since=$(date -u -d "@$setup_lock_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || :);;
 esac
 case "$setup_since" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) :;;
  *) setup_since=unknown;;
 esac
 printf 'INFRATERNAL_SETUP_LOCKED %s %s %s %s %s\n' "$setup_locked_machine" "$setup_lock_pid" "$setup_lock_birth" "$setup_since" "$setup_lock_attempt"
}
# The setup attempt that owns a stage, from its own transaction record, or
# "unknown"; it names the lock holder in the diagnostic (#305).
setup_attempt() {
 setup_attempt_value=
 if [ -f "$1/transaction" ] && [ ! -L "$1/transaction" ] && [ -O "$1/transaction" ] && [ "$(stat -c '%s' "$1/transaction" 2>/dev/null || :)" = 33 ]; then
  IFS= read -r setup_attempt_value < "$1/transaction" || setup_attempt_value=
 fi
 case "$setup_attempt_value" in *[!0-9a-f]*|'') setup_attempt_value=unknown;; esac
 [ "${#setup_attempt_value}" = 32 ] || [ "$setup_attempt_value" = unknown ] || setup_attempt_value=unknown
 printf '%s\n' "$setup_attempt_value"
}
private_tree() {
 setup_tree=$1
 [ -d "$setup_tree" ] && [ ! -L "$setup_tree" ] && [ -O "$setup_tree" ] && [ "$(stat -c '%a' "$setup_tree")" = 700 ] || exit 71
 setup_bad=$(find "$setup_tree" \( ! -uid "$(id -u)" -o ! \( -type d -o -type f \) -o -perm /077 -o \( -type d ! -perm 0700 \) \) -print -quit) || exit 71
 [ -z "$setup_bad" ] || exit 71
 setup_count=$(find "$setup_tree" -printf . | wc -c)
 [ "$setup_count" -le 4096 ] || refuse size
}
validate_upgrade_socket_dir() {
 setup_socket_dir=$1
 [ -d "$setup_socket_dir" ] && [ ! -L "$setup_socket_dir" ] && [ -O "$setup_socket_dir" ] && [ "$(stat -c '%a' "$setup_socket_dir")" = 700 ] || exit 71
 setup_entry_count=0
 for setup_socket in "$setup_socket_dir"/* "$setup_socket_dir"/.[!.]* "$setup_socket_dir"/..?*; do
  [ -e "$setup_socket" ] || [ -L "$setup_socket" ] || continue
  setup_entry_count=$((setup_entry_count + 1))
  [ "$setup_entry_count" -le 1024 ] || refuse size
  setup_socket_name=${setup_socket##*/}
  case "$setup_socket_name" in
   *.stop)
    # A shim's lifecycle cleanup endpoint beside its session socket
    # (crates/infraternal-shim, cleanup.rs): not a terminal, not counted.
    [ -S "$setup_socket" ] && [ ! -L "$setup_socket" ] && [ -O "$setup_socket" ] && [ "$(stat -c '%a' "$setup_socket")" = 600 ] || exit 71
    hex_id "${setup_socket_name%.stop}";;
   *.ending)
    setup_socket_id=${setup_socket_name%.*}
    hex_id "$setup_socket_id"
    private_file "$setup_socket"
    setup_record_size=$(stat -c '%s' "$setup_socket")
    case "$setup_socket_name:$setup_record_size" in
     *.ending:*) [ "$setup_record_size" -le 17 ] || exit 71;;
     *) exit 71;;
    esac;;
   *)
    [ -S "$setup_socket" ] && [ ! -L "$setup_socket" ] && [ -O "$setup_socket" ] && [ "$(stat -c '%a' "$setup_socket")" = 600 ] || exit 71
    setup_socket_id=${setup_socket_name%.sock}
    [ "$setup_socket_name" = "$setup_socket_id.sock" ] || exit 71
    hex_id "$setup_socket_id";;
  esac
 done
}
validate_upgrade_sessions() {
 setup_runtime=$1
 [ -d "$setup_runtime" ] && [ ! -L "$setup_runtime" ] && [ -O "$setup_runtime" ] && [ "$(stat -c '%a' "$setup_runtime")" = 700 ] || exit 71
 for setup_runtime_entry in "$setup_runtime"/* "$setup_runtime"/.[!.]* "$setup_runtime"/..?*; do
  [ -e "$setup_runtime_entry" ] || [ -L "$setup_runtime_entry" ] || continue
  case "${setup_runtime_entry##*/}" in
   .lifetime-lock)
    [ -f "$setup_runtime_entry" ] && [ ! -L "$setup_runtime_entry" ] && [ -O "$setup_runtime_entry" ] && [ "$(stat -c '%a:%h' "$setup_runtime_entry")" = 600:1 ] || exit 71;;
   plugins.sock)
    [ -S "$setup_runtime_entry" ] && [ ! -L "$setup_runtime_entry" ] && [ -O "$setup_runtime_entry" ] || exit 71;;
   sessions) validate_upgrade_socket_dir "$setup_runtime_entry";;
   *.stop)
    # A shim's cleanup endpoint, as in validate_upgrade_socket_dir.
    [ -S "$setup_runtime_entry" ] && [ ! -L "$setup_runtime_entry" ] && [ -O "$setup_runtime_entry" ] && [ "$(stat -c '%a' "$setup_runtime_entry")" = 600 ] || exit 71
    setup_runtime_name=${setup_runtime_entry##*/}
    hex_id "${setup_runtime_name%.stop}";;
   # The proxy plugin's owner-only credential store (crates/plugins/proxy,
   # custody.rs): 0700 directories and 0600 files, all this user's (#281).
   proxy-secrets) private_tree "$setup_runtime_entry";;
   # A finished root install's mesh state (crates/plugins/mesh, node_state.rs):
   # private files the agent wrote; Take over moves them, never reads them.
   mesh-public.json|mesh-routes.json|mesh-interface.json|mesh-key-rotation.bin|mesh-engine.json|mesh-private-key)
    [ "${validating_finished:-no}" = yes ] || exit 71
    [ -f "$setup_runtime_entry" ] && [ ! -L "$setup_runtime_entry" ] && [ -O "$setup_runtime_entry" ] && [ "$(stat -c '%a:%h' "$setup_runtime_entry")" = 600:1 ] || exit 71
    [ "$(stat -c '%s' "$setup_runtime_entry")" -le 65536 ] || exit 71;;
   *)
    [ -S "$setup_runtime_entry" ] && [ ! -L "$setup_runtime_entry" ] && [ -O "$setup_runtime_entry" ] && [ "$(stat -c '%a' "$setup_runtime_entry")" = 600 ] || exit 71
    setup_runtime_name=${setup_runtime_entry##*/}
    setup_runtime_id=${setup_runtime_name%.sock}
    [ "$setup_runtime_name" = "$setup_runtime_id.sock" ] || exit 71
    hex_id "$setup_runtime_id";;
  esac
 done
}
validate_upgrade_stage() {
 stage="$base/.bootstrap-lock"
 [ -d "$stage" ] && [ ! -L "$stage" ] && [ -O "$stage" ] && [ "$(stat -c '%a' "$stage")" = 700 ] || exit 71
 private_file "$stage/transaction"
 [ "$(cat "$stage/transaction")" = "$previous_transaction" ] || refuse transaction
 private_file "$stage/kind"
 [ "$(cat "$stage/kind")" = upgrade ] || refuse kind
 parse_setup_lease "$stage/lease" || refuse lease
 setup_upgrade_lease_pid=$setup_lease_pid
 setup_upgrade_lease_birth=$setup_lease_birth
 for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  case "${entry##*/}" in
   transaction|kind|lease) :;;
   transfer-chunk) private_file "$entry"; [ "$(stat -c '%s' "$entry")" -le 65536 ] || refuse size;;
   transfer-progress|transfer-progress-next) private_file "$entry"; [ "$(stat -c '%s' "$entry")" -le 24 ] || refuse size;;
   activating|failed|stopping|stop-refused|had-binary|had-state|had-launcher|was-active|was-enabled|replacing-binary|replacing-state|replacing-unit|replacing-launcher|linger-requested|creating-alias)
    private_file "$entry"
    [ "$(stat -c '%s' "$entry")" = 0 ] || refuse marker;;
   found-service)
    # A replacement interrupted before its trap ran (SIGKILL, power loss)
    # leaves the service state it recorded; it is still the same journal.
    private_file "$entry"
    case "$(cat "$entry")" in 'yes yes'|'yes no'|'no yes'|'no no') :;; *) refuse marker;; esac;;
   payload)
    [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a' "$entry")" = 700 ] || exit 71;;
   previous-binary)
    [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a:%h' "$entry")" = 700:1 ] || exit 71;;
   unit|previous-unit)
    [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a:%h' "$entry")" = 600:1 ] || exit 71
    [ "$(stat -c '%s' "$entry")" -le 4096 ] || refuse size;;
   cache)
    private_tree "$entry"
    for cache_entry in "$entry"/* "$entry"/.[!.]* "$entry"/..?*; do
     [ -e "$cache_entry" ] || [ -L "$cache_entry" ] || continue
     case "${cache_entry##*/}" in
      owner) private_file "$cache_entry"; [ "$(cat "$cache_entry")" = INFRATERNAL_PAYLOAD_CACHE_V1 ] || refuse cache;;
      payload)
       [ -f "$cache_entry" ] && [ ! -L "$cache_entry" ] && [ -O "$cache_entry" ] && [ "$(stat -c '%a:%h' "$cache_entry")" = 700:2 ] || exit 71
       [ "$stage/payload" -ef "$cache_entry" ] || exit 71;;
      *) refuse entry;;
     esac
    done;;
   state|previous-state) private_tree "$entry";;
   *) refuse entry;;
  esac
 done
 if [ -f "$stage/payload" ] && [ ! -L "$stage/payload" ]; then
  setup_payload_links=$(stat -c '%h' "$stage/payload")
  case "$setup_payload_links" in
   1)
    [ ! -e "$stage/cache/payload" ] && [ ! -L "$stage/cache/payload" ] || exit 71;;
   2)
    if [ -e "$stage/cache/payload" ] || [ -L "$stage/cache/payload" ]; then
     [ -f "$stage/cache/payload" ] && [ ! -L "$stage/cache/payload" ] && [ "$stage/payload" -ef "$stage/cache/payload" ] || exit 71
    else
     setup_cache="$base.bootstrap-cache"
     [ -d "$setup_cache" ] && [ ! -L "$setup_cache" ] && [ -O "$setup_cache" ] && [ "$(stat -c '%a' "$setup_cache")" = 700 ] || exit 71
     private_file "$setup_cache/owner"
     [ "$(cat "$setup_cache/owner")" = INFRATERNAL_PAYLOAD_CACHE_V1 ] || refuse cache
     [ -f "$setup_cache/payload" ] && [ ! -L "$setup_cache/payload" ] && [ -O "$setup_cache/payload" ] && [ "$(stat -c '%a:%h' "$setup_cache/payload")" = 700:2 ] && [ "$stage/payload" -ef "$setup_cache/payload" ] || exit 71
    fi;;
   *) exit 71;;
  esac
 fi
 [ ! -e "$stage/activating" ] || [ ! -e "$stage/failed" ] || refuse marker
 [ -f "$stage/activating" ] || [ -f "$stage/failed" ] || refuse marker
}
validate_upgrade_root() {
 [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] && private_base_mode || exit 71
 private_file "$base/.bootstrap-owner"
 [ "$(stat -c '%s' "$base/.bootstrap-owner")" = 33 ] || refuse owner
 previous_host=$(cat "$base/.bootstrap-owner")
 hex_id "$previous_host"
 identity=$(stat -c '%d:%i' "$base")
 [ -d "$base/bin" ] && [ ! -L "$base/bin" ] && [ -O "$base/bin" ] && [ "$(stat -c '%a' "$base/bin")" = 700 ] || exit 71
 [ -f "$base/bin/live" ] && [ ! -L "$base/bin/live" ] && [ -O "$base/bin/live" ] || exit 71
 case "$(stat -c '%a:%h' "$base/bin/live")" in
  700:1) :;;
  700:2) finished_cache_link || exit 71;;
  *) exit 71;;
 esac
 [ -L "$base/bin/current" ] && [ "$(readlink "$base/bin/current")" = "$base/bin/live" ] || exit 71
 for entry in "$base"/* "$base"/.[!.]* "$base"/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  case "${entry##*/}" in
   .bootstrap-owner|.bootstrap-lock|bin|state|sessions) :;;
   .bootstrap-ready)
    private_file "$entry"
    [ "$(cat "$entry")" = "$previous_host" ] || refuse owner;;
   *) exit 71;;
  esac
 done
 private_tree "$base/state"
 if [ -e "$base/sessions" ] || [ -L "$base/sessions" ]; then validate_upgrade_sessions "$base/sessions"; fi
 # Nothing at or under it is a mount point: Take over and Re-enroll move the
 # whole tree and later delete it, and that delete must never reach into a
 # mounted filesystem (J342 P3-1). A same-filesystem bind mount keeps the
 # device number, so mountinfo is read rather than comparing devices.
 setup_real=$(CDPATH= cd -P "$base" && pwd -P) || exit 71
 [ -r /proc/self/mountinfo ] || exit 71
 setup_mounted=$(awk -v under="$setup_real/" 'index($5 "/", under) == 1 { print $5; exit }' /proc/self/mountinfo) || exit 71
 [ -z "$setup_mounted" ] || exit 71
 for entry in "$base/bin"/* "$base/bin"/.[!.]* "$base/bin"/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  case "${entry##*/}" in live) :;; current) [ -L "$entry" ] && [ "$(readlink "$entry")" = "$base/bin/live" ] || exit 71;; *) exit 71;; esac
 done
 [ -L "$launcher" ] && [ "$(readlink "$launcher")" = "$base/bin/current" ] || exit 71
 [ -f "$unit" ] && [ ! -L "$unit" ] && [ -O "$unit" ] && [ "$(stat -c '%a:%h' "$unit")" = 600:1 ] || exit 71
 [ "$(stat -c '%s' "$unit")" -le 4096 ] || refuse size
 grep -Fxq "# infraternal bootstrap $previous_host" "$unit" || exit 71
 grep -Fxq "ExecStart=\"$base/bin/current\" agent --data \"$base/state\" --state \"$base/sessions\" run" "$unit" || exit 71
 # Drop-ins change what systemd runs without touching the unit file (J342
 # P3-3): none for this unit, beside it or anywhere systemd reports one. That
 # includes the prefix form systemd also applies to it, infraternal-.service.d
 # (J349 P3-3). Drop-ins for every service (a distribution's service.d) are not
 # ours to judge.
 for setup_dropin_dir in "$unit.d" "${unit%/*}/infraternal-.service.d"; do
  [ ! -e "$setup_dropin_dir" ] && [ ! -L "$setup_dropin_dir" ] || exit 71
 done
 setup_dropins=$($manager show -p DropInPaths --value infraternal-agent.service 2>/dev/null || :)
 case "$setup_dropins" in *infraternal-agent.service.d/*|*/infraternal-.service.d/*) exit 71;; esac
 setup_wanted=$(sed -n 's/^WantedBy=//p' "$unit")
 case "$setup_wanted" in default.target|multi-user.target) :;; *) refuse unit;; esac
 setup_wants_dir="$(dirname "$unit")/$setup_wanted.wants"
 setup_wants="$setup_wants_dir/infraternal-agent.service"
 if [ -e "$setup_wants_dir" ] || [ -L "$setup_wants_dir" ]; then
  [ -d "$setup_wants_dir" ] && [ ! -L "$setup_wants_dir" ] && [ -O "$setup_wants_dir" ] || exit 71
  setup_wants_mode=$(stat -c '%a' "$setup_wants_dir")
  [ "$((0$setup_wants_mode & 022))" = 0 ] || exit 71
 fi
 if [ -e "$setup_wants" ] || [ -L "$setup_wants" ]; then
  [ -L "$setup_wants" ] || exit 71
  case "$(readlink "$setup_wants")" in "$unit"|../infraternal-agent.service) :;; *) exit 71;; esac
 fi
}
# A finished install's binary is linked to the private payload cache setup
# verified it from (bin/live and the cache payload are one inode). Only that
# second link is accepted, and only when proving a finished install (D359).
finished_cache_link() {
 [ "${validating_finished:-no}" = yes ] || return 1
 finished_cache="$base.bootstrap-cache"
 [ -d "$finished_cache" ] && [ ! -L "$finished_cache" ] && [ -O "$finished_cache" ] && [ "$(stat -c '%a' "$finished_cache")" = 700 ] || return 1
 [ -f "$finished_cache/payload" ] && [ ! -L "$finished_cache/payload" ] && [ -O "$finished_cache/payload" ] || return 1
 [ "$base/bin/live" -ef "$finished_cache/payload" ]
}
# validate_upgrade_root for a finished install (D359): the same proof, plus
# what a finished root install also holds (finished_cache_link, mesh state).
validate_finished_install() {
 validating_finished=yes
 validate_upgrade_root
 validating_finished=no
}
inspect_upgrade() {
 validate_upgrade_root
 validate_upgrade_stage
 [ -d /proc ] || refuse tool
 setup_lock_epoch=$(stat -c '%Y' "$stage/lease" 2>/dev/null || :)
 case "$setup_lock_epoch" in ''|*[!0-9]*) refuse lease;; esac
 setup_since=$(date -u -d "@$setup_lock_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || :)
 case "$setup_since" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) :;; *) refuse lease;; esac
 setup_locked_machine=$(hostname 2>/dev/null || :)
 case "$setup_locked_machine" in ''|[-.]*|*[!a-zA-Z0-9._-]*) setup_locked_machine=unknown;; esac
 [ "${#setup_locked_machine}" -le 253 ] || setup_locked_machine=unknown
 if [ -e "/proc/$setup_upgrade_lease_pid/stat" ]; then
  process_start_ticks "$setup_upgrade_lease_pid" || refuse lease
  if [ "$process_start_ticks" = "$setup_upgrade_lease_birth" ] && [ -L "/proc/$setup_upgrade_lease_pid/fd/7" ] && [ "$stage" -ef "/proc/$setup_upgrade_lease_pid/fd/7" ]; then
   printf 'INFRATERNAL_SETUP_LOCKED %s %s %s %s %s\n' "$setup_locked_machine" "$setup_upgrade_lease_pid" "$setup_upgrade_lease_birth" "$setup_since" "$previous_transaction"
   return
  fi
 fi
 # Discover an old or missing helper before offering replacement. The public
 # recovery path can refresh it now, before stopping the enrolled service.
 runtime_helper
 setup_sockets=0
 if [ -d "$base/sessions" ]; then
  # Only an endpoint a live shim still serves is an open terminal session; the
  # confirmation names how many the replacement ends (#305).
  setup_sockets=$("$helper" --bootstrap-runtime "$base" "$identity" sessions-count </dev/null) || exit $?
  case "$setup_sockets" in ''|*[!0-9]*) exit 77;; esac
 fi
 # The server matches the enrolled key digest and server name before it
 # offers anything; "- -" means the identity cannot be read (#305, D335).
 setup_enrolled=$("$helper" --bootstrap-runtime "$base" "$identity" enrolled </dev/null) || exit $?
 case "$setup_enrolled" in *[!0-9a-zA-Z._\ -]*|*\ *\ *) exit 77;; esac
 printf 'INFRATERNAL_SETUP_UPGRADE %s %s %s %s %s %s %s %s %s %s\n' "$previous_host" "$previous_transaction" "$identity" "$setup_locked_machine" "$setup_upgrade_lease_pid" "$setup_upgrade_lease_birth" "$setup_since" "$setup_sockets" "$setup_enrolled" "$(upgrade_liveness)"
}
# "live" when the unit is active, whatever started it: the upgrade's own START
# (only the commit was lost) or the old agent an upgrade never reached
# ACTIVATE to stop. Either may be serving sessions and connected to the server
# that enrolled it. "idle" otherwise. The person is told before anything is
# stopped (#305 P2-2). The mutating steps refuse (75) an idle record that has
# turned live, so the warning is shown again; live turning idle stops nothing
# more than was confirmed.
upgrade_liveness() {
 if $manager is-active --quiet infraternal-agent.service >/dev/null 2>&1; then printf 'live\n'; else printf 'idle\n'; fi
}
# Refuse (73) while setup runs here: another command holds the journal, a shim
# serves a terminal, or any process of this user holds a file under $base.
#
# One holder is not "setup running": the infraternal agent unit that a fresh
# setup started before it was interrupted (journal kind fresh, still marked
# activating). Its setup is gone (the journal lock above is free), it serves no
# terminal (a shim would still be a holder), and its journal never committed,
# so no server finished enrolling it; it can only retry its server link. Left
# counted, every later add said "Setup is already running" forever and Start
# fresh was never offered (#305, J257). Rollback stops and removes it by the
# journal's own markers.
not_live() {
 not_live_scan=all
 if [ -d "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ]; then
  exec 8< "$base/.bootstrap-lock"
  flock -n 8 || exit 73
  exec 8<&-
  if [ -f "$base/.bootstrap-lock/activating" ] && [ ! -L "$base/.bootstrap-lock/activating" ] && [ -f "$base/.bootstrap-lock/kind" ] && [ ! -L "$base/.bootstrap-lock/kind" ] && [ "$(cat "$base/.bootstrap-lock/kind")" = fresh ]; then
   not_live_scan=unit
   # Only the unit's main process (the agent itself) is skipped; anything else
   # in its cgroup, such as a terminal shim it started, still refuses (#305 J272).
   agent_main_pid=$($manager show -p MainPID --value infraternal-agent.service 2>/dev/null || :)
   case "$agent_main_pid" in ''|*[!0-9]*) agent_main_pid=0;; esac
  fi
 fi
 # D368 (#433, J205c legacy1): a first install that crashed while activating
 # can leave a terminal of its own running. When the helper attributes every
 # live endpoint to this install's own shims, those terminals are listed in
 # the record and Start fresh closes them after confirmation; any endpoint it
 # cannot attribute still refuses (73) through live_session_sockets.
 stale_terminals=
 if [ "$not_live_scan" = unit ]; then
  set +e
  stale_terminals=$(set -e; finished_terminal_records)
  stale_status=$?
  set -e
  case "$stale_status" in 0) :;; 76) exit 76;; *) stale_terminals=;; esac
 fi
 installed_terminals=$stale_terminals
 [ -n "$stale_terminals" ] || live_session_sockets
 scan_holders "$not_live_scan"
}
# Start fresh with listed terminals: after the activated agent stopped, the
# terminals must still be exactly the ones the person reviewed (else 75, with
# nothing closed); then their units stop. A unit that will not stop ends it
# with 79 (some may be closed, the rest are open). Once every one stopped, a
# holder refusal (73) leaves 74, so the message can say they were all closed.
close_stale_terminals() {
 [ -n "${stale_terminals:-}" ] || return 0
 [ "$(finished_terminal_records)" = "$stale_terminals" ] || exit 75
 set --
 for stale_terminal in $stale_terminals; do
  terminal_unit "$stale_terminal"
  case " $* " in *" $terminal_unit "*) :;; *) set -- "$@" "$terminal_unit";; esac
 done
 stale_closed=no
 trap 'stale_status=$?; [ "$stale_status:$stale_closed" != 73:yes ] || stale_status=74; exit "$stale_status"' EXIT
 for stale_close in "$@"; do
  $manager stop "$stale_close" >/dev/null 2>&1 || exit 79
  stale_closed=yes
 done
}
# Refuse (73) while a shim serves a session socket under $base. Non-dumpable
# shims: the helper asks the kernel by owner+inode, never by name.
live_session_sockets() {
 for entry in "$base/sessions"/*.sock "$base/sessions/sessions"/*.sock; do
  [ -S "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] || continue
  [ "$entry" != "$base/sessions/plugins.sock" ] || continue
  runtime_helper
  "$helper" --bootstrap-runtime "$base" "$(stat -c '%d:%i' "$base")" sessions </dev/null || exit $?
  break
 done
}
# Start fresh, after confirmation: stop the agent an interrupted activation left
# running (see not_live), then require that nothing holds a file under $base any
# more. Without one, this does nothing.
stop_activated_agent() {
 [ "${not_live_scan:-all}" = unit ] || return 0
 stop_agent_unit
 close_stale_terminals
 live_session_sockets
 scan_holders all
 for marker in "$base/sessions/sessions"/*.readiness; do
  [ -f "$marker" ] && [ ! -L "$marker" ] && [ -O "$marker" ] || continue
  rm -- "$marker"
 done
 not_live_scan=all
}
# Stop the infraternal agent's unit, then refuse (73) while anything else it
# started is still running. KillMode=process leaves it: a shim that started
# after the earlier checks, or never bound a socket, is still in the unit's
# cgroup (#305 J272).
stop_agent_unit() {
 # Read the unit's cgroup while it runs; systemd may forget it once stopped.
 agent_cgroup=$($manager show -p ControlGroup --value infraternal-agent.service 2>/dev/null || :)
 $manager stop infraternal-agent.service >/dev/null 2>&1 || exit 73
 case "$agent_cgroup" in
  /*) agent_procs="${agent_cgroup_root:-/sys/fs/cgroup}$agent_cgroup/cgroup.procs"
      if [ -e "$agent_procs" ]; then
       [ -z "$(cat "$agent_procs" 2>/dev/null || echo unreadable)" ] || exit 73
      fi;;
 esac
}
# Whether this fresh journal was interrupted during activation and carries the
# rollback marker $1 for what activation created (see not_live).
activated_marker() {
 [ "${not_live_scan:-all}" = unit ] && [ -f "$base/.bootstrap-lock/$1" ] && [ ! -L "$base/.bootstrap-lock/$1" ]
}
# Whether this account provably has no infraternal install at all (D355): its
# base, unit and launcher each fail to stat with "No such file or directory".
# A permission error, a dangling link or any other answer is not proof.
install_absent() {
 for install_path in "$base" "$unit" "$launcher"; do
  install_error=$(LC_ALL=C stat -c %i -- "$install_path" 2>&1 >/dev/null) && return 1
  case "$install_error" in *": No such file or directory") :;; *) return 1;; esac
 done
 return 0
}
# Whether /proc entry $1 runs in the infraternal agent's own service unit.
agent_unit_process() {
 agent_unit=no
 { while IFS= read -r scan_cgroup; do
    case "$scan_cgroup" in */infraternal-agent.service|*/infraternal-agent.service/*) agent_unit=yes;; esac
   done < "$1/cgroup"; } 2>/dev/null || :
 [ "$agent_unit" = yes ]
}
# Refuse (73) while a process of this user runs from or holds a file under
# $base. "service" skips the enrolled unit's own processes and the journaled
# payload's shims, which a replacement is about to stop itself (#305). "unit"
# skips only the unit's main process (see not_live). "agent" skips every
# process in the agent's unit and nothing else, not even a terminal's shim: a
# Take over stops only the old agent (D359). "takeover" additionally skips
# exactly the authenticated terminal scopes reviewed in the confirmation (D368).
# "takeover-all" keeps the all-account root scan after closing, with no skips.
# Those close units are an old terminal's own scope or, since host login, the
# logind session of the login its shim runs in.
scan_holders() {
 scan_skip=$1
 scan_root=no
 [ "$(id -u)" != 0 ] || scan_root=yes
 if [ -e "$base" ] || [ -L "$base" ]; then
  base_real=$(CDPATH= cd -P "$base" 2>/dev/null && pwd -P) || refuse tool
 else
  base_real=$(CDPATH= cd -P "$(dirname "$base")" && pwd -P)/${base##*/}
 fi
 case "$base" in *[\*\?\[]*) refuse tool;; esac
 case "$base_real" in *[\*\?\[]*) refuse tool;; esac
 set --
 for process in /proc/[0-9]*; do
  case "$scan_skip:$scan_root" in
   takeover:yes|takeover-all:yes) :;;
   *) [ -O "$process" ] || continue;;
  esac
  if [ "$scan_skip" = service ]; then
   [ ! "$base/.bootstrap-lock/payload" -ef "$process/exe" ] || continue
   ! agent_unit_process "$process" || continue
  elif [ "$scan_skip" = unit ] && [ "${process##*/}" = "${agent_main_pid:-0}" ]; then
   agent_unit_process "$process" && continue
  elif [ "$scan_skip" = unit ] && [ -n "${stale_terminals:-}" ] && reviewed_terminal_process "$process"; then
   continue
  elif [ "$scan_skip" = agent ] || [ "$scan_skip" = takeover ]; then
   ! agent_unit_process "$process" || continue
   if [ "$scan_skip" = takeover ] && reviewed_terminal_process "$process"; then continue; fi
  fi
  # A non-dumpable process (every infraternal agent and shim, and OpenSSH's own
  # session process) hides its exe and fds even from its owner. Never read that
  # as "holds nothing": decide from what stays readable (#305 J272).
  if ! readlink "$process/exe" >/dev/null 2>&1 || ! ls "$process/fd" >/dev/null 2>&1; then
   hidden_holder "$process" && exit 73
   continue
  fi
  set -- "$@" "$process/exe" "$process/fd"
  [ "$#" -le 8192 ] || refuse size
 done
 [ "$#" -le 8192 ] || refuse size
 command -v find >/dev/null 2>&1 || refuse tool
 # find's errors are kept, never read as "nothing found". An error about a
 # process that has exited meanwhile is moot; a permission error about one that
 # turned non-dumpable meanwhile (an ssh or a shim starting) is decided as
 # above; any other error is unknown and refuses.
 live=$( { LC_ALL=C find "$@" -maxdepth 1 \( -lname "$base/*" -o -lname "$base_real/*" \) -print 2>&1 >&4 | sed 's/^/unreadable: /'; } 4>&1 )
 # One line per entry; no here-document (compaction, see install.rs) and no
 # pipeline, whose subshell would swallow exit 73.
 scan_nl=$(printf '\n_'); scan_nl=${scan_nl%_}
 scan_ifs=$IFS; IFS=$scan_nl; set -f
 for scan_line in $live; do
  case "$scan_line" in
   '') continue;;
   "unreadable: find: "?/proc/*)
    scan_pid=${scan_line#*/proc/}
    scan_pid=${scan_pid%%[!0-9]*}
    [ -n "$scan_pid" ] || exit 73
    [ -e "/proc/$scan_pid/stat" ] || continue
    case "$scan_line" in
     # The fd or process vanished while find read it: it holds nothing now.
     *": No such file or directory"|*": No such process") continue;;
     *": Permission denied") ! hidden_holder "/proc/$scan_pid" || exit 73;;
     *) exit 73;;
    esac;;
   *) scan_ours "$scan_line" || continue; exit 73;;
  esac
 done
 set +f; IFS=$scan_ifs
}
# Whether /proc link $1, whose text names a path under $base, is that very
# file here. A process in another mount namespace, such as a container that
# runs its own infraternal, names its own /var/lib/infraternal, which is not
# this install: refusing on it made every add on such a host "busy" (#394,
# J315 on compute01). A link that vanished holds nothing; a deleted file
# cannot be compared, so it still counts.
scan_ours() {
 scan_target=$(readlink "$1" 2>/dev/null) || return 1
 case "$scan_target" in *" (deleted)") return 0;; esac
 [ "$1" -ef "$scan_target" ]
}
# Whether /proc entry $1, whose exe or fds are hidden (non-dumpable), may hold
# this install. A process that has exited (or is a zombie) holds nothing.
hidden_holder() {
 [ -e "$1/stat" ] || return 1
 hidden_state=$(sed 's/.*) //' "$1/stat" 2>/dev/null | cut -d' ' -f1) || return 1
 case "$hidden_state" in Z|X|'') return 1;; esac
 install_process "$1" || return 1
 # The kept shims of a Replace (D337) are the only ones allowed to stay.
 if [ "$scan_skip" = service ] && session_scope_process "$1"; then return 1; fi
 return 0
}
# Whether /proc entry $1, whose exe and fds are hidden, is one of this
# install's: in the agent unit's cgroup, in a terminal session scope, or started
# from a path under $base. Other hidden processes of this account (its SSH
# session processes, key agents) cannot be told apart by uid alone and are
# not this install's: refusing on them would refuse every add over OpenSSH.
install_process() {
 agent_unit_process "$1" && return 0
 session_scope_process "$1" && return 0
 install_argv0=$({ tr '\0' '\n' < "$1/cmdline" | sed -n 1p; } 2>/dev/null || :)
 case "$install_argv0" in
  "$base"/*|"$base_real"/*)
   # Started from that path in its own root: when that file is visibly
   # another one (a container's own install), it is not this install's.
   if [ -e "$1/root$install_argv0" ] && [ -e "$install_argv0" ] && ! [ "$1/root$install_argv0" -ef "$install_argv0" ]; then return 1; fi
   return 0;;
 esac
 return 1
}
# Whether /proc entry $1 runs in a terminal scope belonging to this install.
# Scope names identify sessions, not installations: another install of this
# account can use the same manager. Bind the scope's canonical session id to
# an owned endpoint here, including a stale endpoint whose hidden holder is
# still alive. A shim not yet bound is checked by its install path above.
# The close unit a reviewed terminal record names (its seventh field), in one
# of the only two shapes the helper produces (D368, #433): an old terminal's
# own scope, or the logind session scope of a host login. Anything else refuses.
terminal_unit() {
 terminal_unit=$(printf '%s\n' "$1" | cut -d, -f7)
 case "$terminal_unit" in
  infraternal-session-*.scope)
   terminal_unit_id=${terminal_unit#infraternal-session-}
   hex_id "${terminal_unit_id%.scope}";;
  session-*.scope)
   terminal_unit_id=${terminal_unit#session-}
   terminal_unit_id=${terminal_unit_id%.scope}
   case "$terminal_unit_id" in ''|*[!0-9A-Za-z]*) refuse id;; esac;;
  *) refuse id;;
 esac
}
# Whether /proc entry $1 runs inside the close unit of a terminal record in
# $installed_terminals. The helper authenticated those units from each shim;
# this only keeps the holder scan from counting what Take over is about to
# close. A login scope matches only as exactly
# /user.slice/user-<uid>.slice/session-<N>.scope, never nested or elsewhere.
reviewed_terminal_process() {
 reviewed_unit=
 { while IFS= read -r scan_cgroup; do
    case "$scan_cgroup" in
     0::/system.slice/infraternal-session-*.scope|0::/system.slice/infraternal-session-*.scope/*)
      # Only a direct child of system.slice: the unit Take over stops (#433 P3-4).
      reviewed_rest=${scan_cgroup#0::/system.slice/}
      reviewed_unit=${reviewed_rest%%/*};;
     0::/user.slice/user-*.slice/session-*.scope)
      reviewed_rest=${scan_cgroup#0::/user.slice/}
      case "$reviewed_rest" in */*/*) :;; *) reviewed_unit=${reviewed_rest#*/};; esac;;
    esac
   done < "$1/cgroup"; } 2>/dev/null || :
 [ -n "$reviewed_unit" ] || return 1
 case " $installed_terminals " in *",$reviewed_unit,"*) return 0;; esac
 return 1
}
session_scope_process() {
 session_scope=no
 { while IFS= read -r scan_cgroup; do
    case "$scan_cgroup" in */infraternal-session-*.scope|*/infraternal-session-*.scope/*)
     session_scope_id=${scan_cgroup##*/infraternal-session-}
     session_scope_id=${session_scope_id%%.scope*}
     case "$session_scope_id" in ''|*[!0-9a-f]*) continue;; esac
     [ "${#session_scope_id}" = 32 ] || continue
     for session_scope_socket in "$base/sessions/$session_scope_id.sock" "$base/sessions/sessions/$session_scope_id.sock"; do
      if [ -S "$session_scope_socket" ] && [ ! -L "$session_scope_socket" ] && [ -O "$session_scope_socket" ]; then session_scope=yes; fi
     done;;
    esac
   done < "$1/cgroup"; } 2>/dev/null || :
 [ "$session_scope" = yes ]
}
no_redirect() {
 path=
 rest=${base#/}
 while [ -n "$rest" ]; do
  part=${rest%%/*}
  [ "$part" = "$rest" ] && rest= || rest=${rest#*/}
  path="$path/$part"
  if [ -L "$path" ]; then
   case "$HOME/" in "$path"/*) ;; *) exit 71;; esac
  fi
 done
}
# $base is a committed install (no journal, no acquisition, no receipt), and
# the setup guard is held. A crash between a commit and its retire_set_aside
# leaves a superseded install, or a replaced journal beside the running agent.
# Delete them now: no set-aside copy is kept (D337). A replaced journal beside
# a stopped agent is a Replace whose restore never ran; it is kept, for Put it
# back (report_set_aside).
discard_committed_set_aside() {
 for set_aside in "$base".bootstrap-superseded-* "$base".bootstrap-replaced-* "$base".bootstrap-takeover-*; do
  [ -d "$set_aside" ] && [ ! -L "$set_aside" ] && [ -O "$set_aside" ] || continue
  case "$set_aside" in
   "$base".bootstrap-replaced-*) $manager is-active --quiet infraternal-agent.service >/dev/null 2>&1 || continue;;
   # A Re-enroll's whole old install goes only beside a base that is provably
   # a finished install, as for Take over below (J342 P1-1, D335).
   "$base".bootstrap-superseded-*)
    probe validate_finished_install
    [ "$probed" = 0 ] || continue;;
   # A Take over killed before it moved the old install: $base is still
   # that install, so the set-aside holds its service state; Put it back.
   # Otherwise the set-aside goes only beside a base that is provably a
   # finished install: a base with no journal is not proof enough (J342
   # P1-1: a bare owner record once deleted the only remaining install).
   "$base".bootstrap-takeover-*)
    [ -d "$set_aside/install" ] && [ ! -L "$set_aside/install" ] || continue
    probe validate_finished_install
    [ "$probed" = 0 ] || continue;;
  esac
  rm -rf "$set_aside"
 done
}
# An earlier Replace or Re-enroll set the stuck install aside and could not
# put it back: its restore never ran (a dropped session) or failed. Name it,
# so the person can put it back instead of installing beside it (#305 P2-1).
# A commit deletes both kinds, and so does discard_committed_set_aside for one
# a crash left beside a committed install, so neither is reported. Nor is a
# replaced journal while the unit is active: a newer install is serving, and
# putting the stale journal into it would make a healthy host stuck again
# (#305 P2-3).
# A Take over's set-aside (D359) is reported while the old install is in it
# and nothing is in its place, or while it never left its place (a Take over
# killed between its stop and its move). Beside a new install it is the
# new install's rollback that comes first, or the commit's delete.
# Fails (1) when there is nothing to report.
report_set_aside() {
 set_aside=
 for candidate in "$base".bootstrap-superseded-* "$base".bootstrap-replaced-* "$base".bootstrap-takeover-*; do
  [ -e "$candidate" ] || [ -L "$candidate" ] || continue
  case "$candidate" in
   "$base".bootstrap-superseded-*)
    [ ! -e "$base" ] && [ ! -L "$base" ] || continue
    set_aside_kind=superseded
    set_aside_transaction=${candidate#"$base.bootstrap-superseded-"}
    set_aside_owner="$candidate/.bootstrap-owner"
    set_aside_service="$candidate/.superseded-service";;
   "$base".bootstrap-replaced-*)
    [ -d "$base" ] && [ ! -L "$base" ] || continue
    ! $manager is-active --quiet infraternal-agent.service >/dev/null 2>&1 || continue
    set_aside_kind=replaced
    set_aside_transaction=${candidate#"$base.bootstrap-replaced-"}
    set_aside_owner="$base/.bootstrap-owner"
    set_aside_service="$candidate/found-service";;
   "$base".bootstrap-takeover-*)
    if [ -e "$candidate/install" ] || [ -L "$candidate/install" ]; then
     [ ! -e "$base" ] && [ ! -L "$base" ] || continue
    fi
    set_aside_kind=taken_over
    set_aside_transaction=${candidate#"$base.bootstrap-takeover-"}
    set_aside_owner="$candidate/owner"
    set_aside_service="$candidate/service";;
  esac
  [ -z "$set_aside" ] || refuse aside
  set_aside=$candidate
  [ -d "$candidate" ] && [ ! -L "$candidate" ] && [ -O "$candidate" ] || exit 71
  hex_id "$set_aside_transaction"
  private_file "$set_aside_owner"
  [ "$(stat -c '%s' "$set_aside_owner")" = 33 ] || refuse owner
  set_aside_host=$(cat "$set_aside_owner")
  hex_id "$set_aside_host"
  private_file "$set_aside_service"
  read -r set_aside_enabled set_aside_active < "$set_aside_service"
  case "$set_aside_enabled:$set_aside_active" in yes:yes|yes:no|no:yes|no:no) :;; *) refuse marker;; esac
 done
 [ -n "$set_aside" ] || return 1
 setup_locked_machine=$(hostname 2>/dev/null || :)
 case "$setup_locked_machine" in ''|[-.]*|*[!a-zA-Z0-9._-]*) setup_locked_machine=unknown;; esac
 [ "${#setup_locked_machine}" -le 253 ] || setup_locked_machine=unknown
 printf 'INFRATERNAL_SETUP_SET_ASIDE %s %s %s %s %s %s\n' "$set_aside_kind" "$set_aside_host" "$set_aside_transaction" "$setup_locked_machine" "$set_aside_enabled" "$set_aside_active"
}
# Run "$@" in a subshell with errexit in force and refusals fatal and quiet,
# and leave its exit status in $probed. Inside an if or an || list the shell
# ignores errexit, so a check that relies on it would read as passing.
probe() {
 set +e
 (set -e; setup_check=no; "$@") >/dev/null 2>&1
 probed=$?
 set -e
}
# D368: authenticated records bind every bound endpoint to this install's own
# shim and to the unit that closes it: the terminal's own scope (before host
# login) or its host login's logind session (#433). Missing runtime state means
# there are no terminals.
finished_terminal_records() {
 for terminal_socket in "$base/sessions"/*.sock "$base/sessions/sessions"/*.sock; do
  [ -S "$terminal_socket" ] && [ ! -L "$terminal_socket" ] || continue
  [ "$terminal_socket" != "$base/sessions/plugins.sock" ] || continue
  runtime_helper
  "$helper" --bootstrap-runtime "$base" "$(stat -c '%d:%i' "$base")" takeover-terminals </dev/null || exit $?
  break
 done
}
# Refuse any holder outside the old unit and the authenticated scopes. A
# scope name or an unbound socket alone never authorizes stopping a process.
holders_beside_agent() {
 scan_holders takeover
}
# A finished install (#394), with what Take over needs (D359):
# `INFRATERNAL_SETUP_INSTALLED <host> <dev:ino> <live|idle> <takeover>`.
# The takeover field is "ready" only for root's own base whose every entry,
# launcher and unit are proven infraternal's (validate_upgrade_root) and that
# only its own unit and authenticated terminal scopes use; "busy" when
# another holder uses it or a terminal cannot be attributed; "unproven" otherwise, including every
# rootless install. Only "ready" is ever offered. A runtime helper that needs
# a refresh (76) ends the check, which then asks for one.
report_installed() {
 installed_takeover=unproven
 installed_terminals=
 if [ "$base" = "$up_root_base" ]; then
  probe validate_finished_install
  if [ "$probed" = 0 ]; then
   set +e
   installed_terminals=$(set -e; finished_terminal_records)
   terminals_status=$?
   set -e
   case "$terminals_status" in
    0)
     probe holders_beside_agent
     case "$probed" in 0) installed_takeover=ready;; 73) installed_takeover=busy;; 76) exit 76;; esac;;
    73) installed_takeover=busy;;
    76) exit 76;;
   esac
  fi
 fi
 [ "$installed_takeover" = ready ] || installed_terminals=
 printf 'INFRATERNAL_SETUP_INSTALLED %s %s %s %s' "$(cat "$base/.bootstrap-owner")" "$(stat -c '%d:%i' "$base")" "$(upgrade_liveness)" "$installed_takeover"
 [ -z "$installed_terminals" ] || printf ' %s' "$installed_terminals"
 printf '\n'
}
inspect_previous() {
 no_redirect
 setup_allow_locked_inspection=yes
 setup_guard
 if [ "${setup_blocked:-no}" = yes ]; then
  report_setup_lock
  return
 fi
 if [ -d "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ]; then
  exec 8< "$base/.bootstrap-lock"
  if ! flock -n 8; then
   exec 8<&-
   report_setup_lock
   return
  fi
  exec 8<&-
 fi
 receipt=
 for candidate in "$base".bootstrap-rollback-*; do
  [ -e "$candidate" ] || [ -L "$candidate" ] || continue
  [ -z "$receipt" ] || refuse receipt
  receipt=$candidate
 done
 if [ -z "$receipt" ] && [ ! -e "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] && [ ! -e "$base/.bootstrap-acquiring" ] && [ ! -L "$base/.bootstrap-acquiring" ]; then
  if [ -e "$base" ] || [ -L "$base" ]; then
   private_file "$base/.bootstrap-owner"
   [ "$(stat -c '%s' "$base/.bootstrap-owner")" = 33 ] || refuse owner
   hex_id "$(cat "$base/.bootstrap-owner")"
  fi
  if [ -e "$base" ] || [ -L "$base" ]; then discard_committed_set_aside; fi
  report_set_aside && return
  # A base with no journal is a finished install, owned by the host id in
  # .bootstrap-owner. A new attempt carries a new host id, and staging refuses
  # (71) any base whose owner names another host. Reporting CLEAR here sent
  # every Add host and retry into that refusal, and nothing was ever offered
  # (#394). Name the install instead, so the server answers before staging.
  if [ -e "$base" ] || [ -L "$base" ]; then
   report_installed
   return
  fi
  # D355: proven absence lets the server finish this person's stale entries.
  if install_absent; then printf 'INFRATERNAL_SETUP_ABSENT\n'; else printf 'INFRATERNAL_SETUP_CLEAR\n'; fi
  return
 fi
 if [ -n "$receipt" ]; then
  private_file "$receipt"
  previous_transaction=${receipt#"$base.bootstrap-rollback-"}
  hex_id "$previous_transaction"
  read -r previous_host recorded_transaction kind identity extra < "$receipt"
  hex_id "$previous_host"
  [ "$(cat "$receipt")" = "$previous_host $previous_transaction fresh $identity" ] || refuse receipt
  case "$identity" in ''|:*|*:|*:*:*|*[!0-9:]*) refuse receipt;; esac
  case "$identity" in *:*) :;; *) refuse receipt;; esac
  if [ ! -e "$base" ] && [ ! -L "$base" ]; then
   not_live
   printf 'INFRATERNAL_SETUP_STALE %s %s %s 0\n' "$previous_host" "$previous_transaction" "$identity"
   return
  fi
  [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] && private_base_mode || exit 71
  [ "$(stat -c '%d:%i' "$base")" = "$identity" ] || refuse identity
  if [ ! -e "$base/.bootstrap-owner" ] && [ ! -L "$base/.bootstrap-owner" ]; then
   for entry in "$base"/* "$base"/.[!.]* "$base"/..?*; do
    [ ! -e "$entry" ] && [ ! -L "$entry" ] || exit 71
   done
  else
   private_file "$base/.bootstrap-owner"
   [ "$(stat -c '%s' "$base/.bootstrap-owner")" = 33 ] || refuse owner
   [ "$(cat "$base/.bootstrap-owner")" = "$previous_host" ] || refuse owner
  fi
 else
  [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] && private_base_mode || exit 71
  private_file "$base/.bootstrap-owner"
  [ "$(stat -c '%s' "$base/.bootstrap-owner")" = 33 ] || refuse owner
  previous_host=$(cat "$base/.bootstrap-owner")
  hex_id "$previous_host"
  identity=$(stat -c '%d:%i' "$base")
  if [ -e "$base/.bootstrap-acquiring" ] || [ -L "$base/.bootstrap-acquiring" ]; then
   private_file "$base/.bootstrap-acquiring"
   record=$(cat "$base/.bootstrap-acquiring")
   previous_transaction=${record% fresh}
   [ "$record" = "$previous_transaction fresh" ] || refuse transaction
  else
   [ -d "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] && [ -O "$base/.bootstrap-lock" ] && [ "$(stat -c '%a' "$base/.bootstrap-lock")" = 700 ] || exit 71
   private_file "$base/.bootstrap-lock/transaction"
   private_file "$base/.bootstrap-lock/kind"
   previous_kind=$(cat "$base/.bootstrap-lock/kind")
   case "$previous_kind" in fresh|upgrade) :;; *) refuse kind;; esac
   previous_transaction=$(cat "$base/.bootstrap-lock/transaction")
  fi
  hex_id "$previous_transaction"
 fi
 if [ -z "$receipt" ] && [ "${previous_kind:-fresh}" = upgrade ]; then
  inspect_upgrade
  return
 fi
 not_live
 # The interrupted activation's agent holds the runtime lifetime lock; not_live
 # proved it is the only holder, so the socket is checked after it is stopped.
 [ "$not_live_scan" = unit ] || validate_control_socket
 if [ -n "$receipt" ]; then
  validate_retired_stage "$previous_transaction" "$previous_host"
 elif [ -e "$base/.bootstrap-lock" ] || [ -L "$base/.bootstrap-lock" ]; then
  stage="$base/.bootstrap-lock"
  [ -d "$stage" ] && [ ! -L "$stage" ] && [ -O "$stage" ] && [ "$(stat -c '%a' "$stage")" = 700 ] || exit 71
  if [ -e "$stage/transaction" ] || [ -L "$stage/transaction" ]; then
   private_file "$stage/transaction"
   [ "$(cat "$stage/transaction")" = "$previous_transaction" ] || refuse transaction
   private_file "$stage/kind"
   [ "$(cat "$stage/kind")" = fresh ] || refuse kind
   for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    case "${entry##*/}" in
     transaction|kind) private_file "$entry";;
     lease) private_file "$entry";;
     transfer-chunk) private_file "$entry"; [ "$(stat -c '%s' "$entry")" -le 65536 ] || refuse size;;
     transfer-progress|transfer-progress-next) private_file "$entry"; [ "$(stat -c '%s' "$entry")" -le 24 ] || refuse size;;
     activating|failed|stopping|stop-refused|had-binary|had-state|had-launcher|was-active|was-enabled|replacing-binary|replacing-state|replacing-unit|replacing-launcher|linger-requested|creating-alias)
      private_file "$entry"
      [ "$(stat -c '%s' "$entry")" = 0 ] || refuse marker;;
     state|cache) private_tree "$entry";;
     payload)
      [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] || exit 71
      case "$(stat -c '%a' "$entry")" in 600|700) :;; *) exit 71;; esac;;
     *) refuse entry;;
    esac
   done
  else
   private_file "$base/.bootstrap-acquiring"
   [ "$(cat "$base/.bootstrap-acquiring")" = "$previous_transaction fresh" ] || refuse transaction
   for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
    [ ! -e "$entry" ] && [ ! -L "$entry" ] || exit 71
   done
  fi
 fi
 if [ -e "$base/.bootstrap-acquiring" ] || [ -L "$base/.bootstrap-acquiring" ]; then
  private_file "$base/.bootstrap-acquiring"
  [ "$(stat -c '%s' "$base/.bootstrap-acquiring")" = 39 ] || refuse transaction
  [ "$(cat "$base/.bootstrap-acquiring")" = "$previous_transaction fresh" ] || refuse transaction
 fi
 for entry in "$base"/* "$base"/.[!.]* "$base"/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  case "${entry##*/}" in
   .bootstrap-owner|.bootstrap-lock|.bootstrap-acquiring|sessions) :;;
   .bootstrap-ready)
    private_file "$entry"
    [ "$(cat "$entry")" = "$previous_host" ] || refuse owner;;
   bin)
    [ -d "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a' "$entry")" = 700 ] || exit 71
    for child in "$entry"/* "$entry"/.[!.]* "$entry"/..?*; do
     [ -e "$child" ] || [ -L "$child" ] || continue
     # An interrupted activation of this fresh journal installed its binary;
     # rollback removes exactly these two by the replacing-binary marker.
     activated_marker replacing-binary || exit 71
     case "${child##*/}" in
      live) [ -f "$child" ] && [ ! -L "$child" ] && [ -O "$child" ] && [ "$(stat -c '%a' "$child")" = 700 ] || exit 71;;
      current) [ -L "$child" ] && [ "$(readlink "$child")" = "$base/bin/live" ] || exit 71;;
      *) exit 71;;
     esac
    done;;
   state)
    # Its enrolment state, removed by rollback under the replacing-state marker.
    activated_marker replacing-state || exit 71
    private_tree "$entry";;
   *) exit 71;;
  esac
 done
 sockets=0
 for directory in "$base/sessions" "$base/sessions/sessions"; do
  [ -e "$directory" ] || [ -L "$directory" ] || continue
  [ -d "$directory" ] && [ ! -L "$directory" ] && [ -O "$directory" ] && [ "$(stat -c '%a' "$directory")" = 700 ] || exit 71
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
   [ -e "$entry" ] || [ -L "$entry" ] || continue
   [ "$entry" != "$base/sessions/sessions" ] || continue
   [ "$entry" != "$base/sessions/.lifetime-lock" ] || continue
   if [ "$entry" = "$base/sessions/plugins.sock" ]; then
    [ "$not_live_scan" = unit ] || validate_control_socket
    sockets=$((sockets + 1))
    [ "$sockets" -le 1024 ] || refuse size
    continue
   fi
   name=${entry##*/}
   case "$name" in *.readiness)
    # The readiness marker of the setup's own terminal probe, whose shim died
    # with the setup; stop_activated_agent removes it (see not_live).
    activated_marker activating || exit 71
    [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a' "$entry")" = 600 ] || exit 71
    hex_id "${name%.readiness}"
    continue;;
   esac
   [ -S "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a' "$entry")" = 600 ] || exit 71
   socket_id=${name%.sock}
   [ "$name" = "$socket_id.sock" ] || exit 71
   hex_id "$socket_id"
   sockets=$((sockets + 1))
   [ "$sockets" -le 1024 ] || refuse size
  done
 done
 printf 'INFRATERNAL_SETUP_STALE %s %s %s %s' "$previous_host" "$previous_transaction" "$identity" "$sockets"
 [ -z "${stale_terminals:-}" ] || printf ' %s' "$stale_terminals"
 printf '\n'
}
stop_stage_shims() {
 runtime_helper
 "$helper" --bootstrap-runtime "$base" "$(stat -c '%d:%i' "$base")" sessions-stop </dev/null || exit $?
 # Shims were stopped above through their authenticated session sockets. A
 # process still running the journaled payload has no such endpoint and is
 # never signalled: refuse (73), keep the install and let the caller retry.
 # The read-only stage-processes check already refused before the stop; this
 # catches one that started since.
 for setup_process in /proc/[0-9]*; do
  [ -O "$setup_process" ] || continue
  [ "${setup_process##*/}" != "$$" ] || continue
  [ ! "$stage/payload" -ef "$setup_process/exe" ] || exit 73
 done
}
# Stop the stuck install's service and shims for the exact confirmed record.
# Every read-only proof runs first; after the stop, any failure puts the
# service back as it was found (#305 P1-2). Callers clear the traps only
# once the old install is moved out of the way. With replace_inherit=yes
# (a Replace, same server) only the agent stops: the unit's KillMode=process
# leaves the shims running, and the new agent adopts their open terminals
# from $base/sessions, as an upgrade does (D337, D13).
retire_stuck_service() {
 replace_expected=$1
 replace_cancel=${2:--}
 aside=
 aside_origin=
 setup_guard
 # This attempt's restore took the guard first and found nothing moved: the
 # attempt was cancelled, so its set-aside never starts. The token is the
 # attempt's own, so no other attempt is held back (#305, J202 P2).
 refuse_cancelled "$replace_cancel"
 replace_observed=$(inspect_previous)
 [ "${replace_observed% *}" = "${replace_expected% *}" ] || exit 75
 # The agent started since the person confirmed an idle install (upgrade_liveness).
 [ "${replace_expected##* }" != idle ] || [ "${replace_observed##* }" != live ] || exit 75
 set -- $replace_expected
 [ "$#" = 12 ] && [ "$1" = INFRATERNAL_SETUP_UPGRADE ] || exit 75
 replace_transaction=$3
 replace_identity=$4
 stage="$base/.bootstrap-lock"
 runtime_helper
 scan_holders service
 # A payload process that serves no session endpoint cannot be stopped
 # through one: refuse now, while the service and sessions are untouched
 # (#305 P2-3). stop_stage_shims repeats the check after the stop.
 "$helper" --bootstrap-runtime "$base" "$replace_identity" stage-processes </dev/null || exit $?
 # Put back means as first found, not as an earlier set-aside left it
 # (#305 P3-1). A found-service already in the journal was written by a
 # set-aside killed after its stop, before any trap could run; a pending
 # replaced journal belongs to a Replace whose restore never ran. Either one
 # stopped this service, so its record is kept, not measured again.
 replace_found=
 for candidate in "$stage/found-service" "$base".bootstrap-replaced-*/found-service; do
  [ -e "$candidate" ] || [ -L "$candidate" ] || continue
  replace_found=$candidate
  break
 done
 if [ -n "$replace_found" ]; then
  private_file "$replace_found"
  read -r replace_enabled replace_active < "$replace_found"
  case "$replace_enabled:$replace_active" in yes:yes|yes:no|no:yes|no:no) :;; *) exit 71;; esac
 else
  replace_enabled=no
  replace_active=no
  if $manager is-enabled --quiet infraternal-agent.service >/dev/null 2>&1; then replace_enabled=yes; fi
  if $manager is-active --quiet infraternal-agent.service >/dev/null 2>&1; then replace_active=yes; fi
 fi
 # The state found travels with the journal, so whatever step fails later,
 # in this script or after it, can put the service back as it was (#305 P1-1).
 # dash runs no EXIT trap when a signal ends it, and a dropped SSH session
 # ends it with HUP or PIPE: trap those too (#305 P2-1). While restoring, the
 # signals are ignored, so a closed stdout cannot cut the restore short.
 trap 'replace_status=$?; replace_untrap; restore_stuck_service; exit "$replace_status"' EXIT
 trap 'replace_untrap; restore_stuck_service; exit 129' HUP
 trap 'replace_untrap; restore_stuck_service; exit 130' INT
 trap 'replace_untrap; restore_stuck_service; exit 143' TERM
 trap 'replace_untrap; restore_stuck_service; exit 141' PIPE
 printf '%s %s\n' "$replace_enabled" "$replace_active" >| "$stage/found-service"
 retire_setup_lease
 $manager stop infraternal-agent.service >/dev/null 2>&1 || exit 73
 $manager disable infraternal-agent.service >/dev/null 2>&1 || exit 73
 $manager daemon-reload >/dev/null 2>&1 || exit 73
 exec 7<&-
 if [ "${replace_inherit:-no}" = yes ]; then
  # The shims stay: the unit's own and the journal payload's. Anything else
  # holding a file under $base still refuses.
  not_live_beside_sessions
 else
  stop_stage_shims
  not_live
 fi
 exec 7< "$stage"
 flock -n 7 || exit 73
}
# not_live for a Replace that keeps the open terminals: no other setup holds
# the journal, and no process holds a file under $base apart from the
# stopped unit's shims and the journal payload's (scan_holders service).
not_live_beside_sessions() {
 if [ -d "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ]; then
  exec 8< "$base/.bootstrap-lock"
  flock -n 8 || exit 73
  exec 8<&-
 fi
 scan_holders service
}
# Refuse (75) a set-aside whose attempt's restore already ran: the restore
# found nothing moved and left the token $1 (cancel_set_aside). The token
# is used up. `-` (no token) never refuses.
refuse_cancelled() {
 [ "$1" != - ] || return 0
 hex_id "$1"
 replace_cancelled="$base.bootstrap-cancel-$1"
 if [ -e "$replace_cancelled" ] || [ -L "$replace_cancelled" ]; then
  rm -f -- "$replace_cancelled"
  exit 75
 fi
}
replace_untrap() {
 trap - EXIT
 trap '' HUP INT TERM PIPE
}
# The set-aside is complete: from here a failure belongs to the caller's restore.
replace_done() {
 trap - EXIT HUP INT TERM PIPE
}
# Undo retire_stuck_service: move what this command set aside ($aside) back
# to where it was ($aside_origin), then re-enable and restart the service if
# it was so found.
restore_stuck_service() {
 if [ -n "$aside" ] && [ -d "$aside" ] && [ ! -L "$aside" ] && [ ! -e "$aside_origin" ] && [ ! -L "$aside_origin" ]; then
  mv -T "$aside" "$aside_origin"
  if [ -f "$base/.superseded-unit" ] && [ ! -e "$unit" ] && [ ! -L "$unit" ]; then mv "$base/.superseded-unit" "$unit"; fi
  [ -e "$launcher" ] || [ -L "$launcher" ] || ln -s "$base/bin/current" "$launcher"
  rm -f "$base/.superseded-service"
 fi
 # The journal is in place again exactly as it was found.
 rm -f "$base/.bootstrap-lock/found-service"
 $manager daemon-reload >/dev/null 2>&1 || :
 [ "$replace_enabled" != yes ] || $manager enable infraternal-agent.service >/dev/null 2>&1 || :
 [ "$replace_active" != yes ] || $manager start infraternal-agent.service >/dev/null 2>&1 || :
}
# Replace a stuck upgrade this server enrolled. The journal moves aside with
# its rollback copies (previous-binary, -state, -unit) and the service state
# found; the next commit of this host removes it, so nothing is lost before
# a new enrollment commits.
replace_stuck_install() {
 replace_inherit=yes
 retire_stuck_service "$1" "${2:--}"
 replaced="$base.bootstrap-replaced-$replace_transaction"
 [ ! -e "$replaced" ] && [ ! -L "$replaced" ] || exit 72
 aside=$replaced
 aside_origin=$stage
 mv -T "$stage" "$replaced"
 replace_done
}
# The journal was never moved. found-service in it means a set-aside stopped
# the service and was killed before the move, so no trap ran (SIGKILL, power
# loss): start and enable it again as found. Prints "restored", or
# "untouched" when nothing was stopped (#305 P2-1).
# A restore that finds nothing moved may have run before its attempt's
# set-aside, which sshd keeps running after a cancel. Leave the attempt's
# cancel token so that set-aside refuses when it gets the guard; the two are
# then mutually exclusive whichever runs first (#305, J202 P2). `-` (Put it
# back, from a later Check) has no set-aside of its own to stop.
cancel_set_aside() {
 [ "${1:--}" != - ] || return 0
 hex_id "$1"
 : >| "$base.bootstrap-cancel-$1"
}
restore_unmoved() {
 aside=
 found="$base/.bootstrap-lock/found-service"
 if [ ! -e "$found" ] && [ ! -L "$found" ]; then
  printf 'untouched\n'
  return
 fi
 private_file "$found"
 read -r replace_enabled replace_active < "$found"
 case "$replace_enabled:$replace_active" in yes:yes|yes:no|no:yes|no:no) :;; *) exit 71;; esac
 restore_stuck_service
 printf 'restored\n'
}
# Put back a journal that replace_stuck_install moved aside, after the new
# enrollment failed and its own rollback removed its journal: the stuck
# install and its service end up as they were found (#305 P1-1). Prints
# "restored", or "untouched" when this transaction was never replaced.
# Restores wait for the setup guard (setup_guard_wait): a cancelled attempt
# kills only its local ssh client, and the set-aside it started runs on to
# the end on the host; refusing then would leave the service stopped (#305 P2-1).
restore_replaced_install() {
 setup_guard_wait=25
 setup_guard
 replaced="$base.bootstrap-replaced-$1"
 if [ ! -e "$replaced" ] && [ ! -L "$replaced" ]; then
  [ -f "$base/.bootstrap-lock/transaction" ] && [ "$(cat "$base/.bootstrap-lock/transaction")" = "$1" ] || exit 71
  cancel_set_aside "${2:--}"
  restore_unmoved
  return
 fi
 [ -d "$replaced" ] && [ ! -L "$replaced" ] && [ -O "$replaced" ] || exit 71
 [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] || exit 71
 [ ! -e "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] || exit 72
 # A newer install is serving: the replaced journal is stale (#305 P2-3).
 ! $manager is-active --quiet infraternal-agent.service >/dev/null 2>&1 || exit 72
 private_file "$replaced/found-service"
 read -r replace_enabled replace_active < "$replaced/found-service"
 case "$replace_enabled:$replace_active" in yes:yes|yes:no|no:yes|no:no) :;; *) exit 71;; esac
 aside=$replaced
 aside_origin="$base/.bootstrap-lock"
 restore_stuck_service
 printf 'restored\n'
}
# Set aside an install another server enrolled, whole, so the machine can
# join this server as a new host (D335). Nothing is deleted: the directory,
# its unit and the service state it was found in stay restorable.
supersede_stuck_install() {
 # Never take over another server's install that runs with open terminals:
 # it may be in use there (D337). The server refuses it before offering; an
 # idle record that turned live is refused by retire_stuck_service.
 supersede_record=$1
 supersede_cancel=${2:--}
 set -- $supersede_record
 [ "${12-}" != live ] || [ "${9-}" = 0 ] || exit 75
 retire_stuck_service "$supersede_record" "$supersede_cancel"
 aside="$base.bootstrap-superseded-$replace_transaction"
 aside_origin=$base
 [ ! -e "$aside" ] && [ ! -L "$aside" ] || { aside=; exit 72; }
 mv -T "$base" "$aside"
 printf '%s %s\n' "$replace_enabled" "$replace_active" > "$aside/.superseded-service"
 mv "$unit" "$aside/.superseded-unit"
 rm -f "$launcher"
 if ! $manager daemon-reload >/dev/null 2>&1; then
  [ "$takeover_closed" = no ] || exit 79
  exit 73
 fi
 replace_done
}
# Put back an install set aside by supersede_stuck_install after the new
# enrollment failed and its own rollback removed the new installation.
# Prints "restored", or "untouched" when this transaction was never set aside.
restore_superseded_install() {
 setup_guard_wait=25
 setup_guard
 aside="$base.bootstrap-superseded-$1"
 aside_origin=$base
 if [ ! -e "$aside" ] && [ ! -L "$aside" ]; then
  [ -f "$base/.bootstrap-lock/transaction" ] && [ "$(cat "$base/.bootstrap-lock/transaction")" = "$1" ] || exit 71
  cancel_set_aside "${2:--}"
  restore_unmoved
  return
 fi
 [ -d "$aside" ] && [ ! -L "$aside" ] && [ -O "$aside" ] || exit 71
 [ ! -e "$base" ] && [ ! -L "$base" ] || exit 72
 [ ! -e "$unit" ] && [ ! -L "$unit" ] || exit 72
 private_file "$aside/.superseded-service"
 read -r replace_enabled replace_active < "$aside/.superseded-service"
 case "$replace_enabled:$replace_active" in yes:yes|yes:no|no:yes|no:no) :;; *) exit 71;; esac
 restore_stuck_service
 printf 'restored\n'
}
# The server saw this host connected with the journal's own identity: the
# upgrade worked and only its commit was lost. Finish it as commit would.
finish_stuck_upgrade() {
 setup_guard
 finish_observed=$(inspect_previous)
 [ "${finish_observed% *}" = "${1% *}" ] || exit 75
 stage="$base/.bootstrap-lock"
 # A failed activation keeps its rollback journal; nothing to finish.
 [ -f "$stage/activating" ] || exit 0
 # The server chose Finish because it saw this agent online, but that was a
 # moment before this command. Deleting the journal removes the rollback
 # copies, so re-check under the guard, right before the delete: an agent
 # that has stopped since keeps everything, and the next add-host sees it
 # again (#305, J202 P2).
 $manager is-active --quiet infraternal-agent.service >/dev/null 2>&1 || exit 75
 # As every commit does (COMMIT_RETIRE in install.rs): durable first (J349 P2-1).
 settle_set_aside
 retire_setup_lease
 rm -rf "$stage"
 retire_set_aside
}
# D359: take over a finished install another server enrolled (#394), after
# the person confirmed the exact record Check reported (report_installed),
# which names the old install's id. $2 is this attempt's token: it names the
# set-aside, and a restore that ran first refuses it (refuse_cancelled).
#
# Root only: $base must be root's /var/lib/infraternal. The prelude fixes
# up_root_base, and no rootless base can be equal to it.
#
# A crash at any step leaves the old install whole, either in its place or
# in the set-aside $base.bootstrap-takeover-<token>, a 0700 sibling that only
# root can enter. The set-aside is built under a temporary name with the old
# install's id, the service state found and a copy of its unit, and renamed
# into place complete before anything is stopped. Then the agent is stopped
# and disabled (validate_upgrade_root proved the unit is ours), nothing else
# may still use the install, the install is renamed into the set-aside, and
# the unit and launcher are removed. Any failure or signal before the end
# puts it back (put_back_taken_over). After the end, the server puts it back
# if the new install fails (restore_taken_over_install), a later Check offers
# it after a crash (report_set_aside), and the new install's commit deletes
# it (retire_set_aside).
take_over_finished_install() {
 takeover_expected=$1
 takeover_token=$2
 hex_id "$takeover_token"
 [ "$base" = "$up_root_base" ] || exit 71
 setup_guard
 refuse_cancelled "$takeover_token"
 takeover_observed=$(inspect_previous)
 set -- $takeover_expected
 [ "$#" -ge 5 ] && [ "$1" = INFRATERNAL_SETUP_INSTALLED ] && [ "$5" = ready ] || exit 75
 takeover_host=$2
 takeover_identity=$3
 takeover_live=$4
 shift 5
 takeover_terminals_expected=$*
 set -- $takeover_observed
 [ "$#" -ge 5 ] && [ "$1" = INFRATERNAL_SETUP_INSTALLED ] || exit 75
 [ "$2" = "$takeover_host" ] && [ "$3" = "$takeover_identity" ] || exit 75
 case "$5" in ready) :;; busy) exit 73;; *) exit 75;; esac
 [ "$takeover_live" != idle ] || [ "$4" != live ] || exit 75
 shift 5
 [ "$*" = "$takeover_terminals_expected" ] || exit 75
 validate_finished_install
 aside="$base.bootstrap-takeover-$takeover_token"
 takeover_part="$base.bootstrap-taking-$takeover_token"
 for takeover_path in "$aside" "$takeover_part"; do
  [ ! -e "$takeover_path" ] && [ ! -L "$takeover_path" ] || exit 72
 done
 takeover_enabled=no
 takeover_active=no
 if $manager is-enabled --quiet infraternal-agent.service >/dev/null 2>&1; then takeover_enabled=yes; fi
 if $manager is-active --quiet infraternal-agent.service >/dev/null 2>&1; then takeover_active=yes; fi
 mkdir -m 700 "$takeover_part"
 printf '%s\n' "$takeover_host" > "$takeover_part/owner"
 printf '%s %s\n' "$takeover_enabled" "$takeover_active" > "$takeover_part/service"
 cp "$unit" "$takeover_part/unit"
 [ "$(cat "$takeover_part/unit")" = "$(cat "$unit")" ] || exit 71
 mv -T "$takeover_part" "$aside"
 # From here every way out puts the old install back, until the end.
 # A terminal unit that will not stop, or a service step failing after a
 # terminal closed, ends with 79: some confirmed terminals may be closed and
 # the rest are open. Once every confirmed terminal closed, a holder refusal
 # (73) leaves 74; every 73 before that closed none (#433 P2, P3-1).
 takeover_closed=no
 trap 'takeover_status=$?; replace_untrap; put_back_taken_over; [ "$takeover_status:$takeover_closed" != 73:yes ] || takeover_status=74; exit "$takeover_status"' EXIT
 trap 'replace_untrap; put_back_taken_over; exit 129' HUP
 trap 'replace_untrap; put_back_taken_over; exit 130' INT
 trap 'replace_untrap; put_back_taken_over; exit 143' TERM
 trap 'replace_untrap; put_back_taken_over; exit 141' PIPE
 stop_agent_unit
 # Stop the source of new terminals first, then compare every record again
 # immediately before stopping exactly the units the person reviewed (D368).
 installed_terminals=$takeover_terminals_expected
 holders_beside_agent
 installed_terminals=$(finished_terminal_records)
 [ "$installed_terminals" = "$takeover_terminals_expected" ] || exit 75
 # Several terminals of one host login share its logind session: stop it once.
 set --
 for takeover_terminal in $installed_terminals; do
  terminal_unit "$takeover_terminal"
  case " $* " in *" $terminal_unit "*) :;; *) set -- "$@" "$terminal_unit";; esac
 done
 for takeover_close in "$@"; do
  $manager stop "$takeover_close" >/dev/null 2>&1 || exit 79
  takeover_closed=yes
 done
 if ! $manager disable infraternal-agent.service >/dev/null 2>&1; then
  [ "$takeover_closed" = no ] || exit 79
  exit 73
 fi
 # The old unit and only the confirmed terminals' units have stopped.
 live_session_sockets
 scan_holders takeover-all
 mv -T "$base" "$aside/install"
 rm -f "$unit"
 rm -f "$launcher"
 $manager daemon-reload >/dev/null 2>&1 || exit 73
 replace_done
}
# Put back what take_over_finished_install set aside in $aside, whatever step
# it reached: the install, its unit and its launcher go back where they were,
# its service is enabled and started again as it was found, and the set-aside
# is removed. Each step checks first, so running it again after any
# interruption, its own included, finishes the same way. Refuses (72) while a
# new install, or a unit or launcher that is not the old one's, is in place.
put_back_taken_over() {
 [ -d "$aside" ] && [ ! -L "$aside" ] && [ -O "$aside" ] && [ "$(stat -c '%a' "$aside")" = 700 ] || exit 71
 private_file "$aside/owner"
 hex_id "$(cat "$aside/owner")"
 private_file "$aside/service"
 # Its own IFS: a trap can run it after scan_holders left IFS at a newline.
 IFS=' ' read -r takeover_enabled takeover_active takeover_extra < "$aside/service"
 [ -z "$takeover_extra" ] || exit 71
 case "$takeover_enabled:$takeover_active" in yes:yes|yes:no|no:yes|no:no) :;; *) exit 71;; esac
 takeover_unit="$aside/unit"
 [ -f "$takeover_unit" ] && [ ! -L "$takeover_unit" ] && [ -O "$takeover_unit" ] && [ "$(stat -c '%a:%h' "$takeover_unit")" = 600:1 ] || exit 71
 [ "$(stat -c '%s' "$takeover_unit")" -le 4096 ] || exit 71
 if [ -e "$aside/install" ] || [ -L "$aside/install" ]; then
  [ -d "$aside/install" ] && [ ! -L "$aside/install" ] && [ -O "$aside/install" ] || exit 71
  [ ! -e "$base" ] && [ ! -L "$base" ] || exit 72
 else
  # Never moved: the old install is still in its place.
  [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] || exit 71
 fi
 if [ -e "$unit" ] || [ -L "$unit" ]; then
  [ -f "$unit" ] && [ ! -L "$unit" ] && [ "$(cat "$unit")" = "$(cat "$takeover_unit")" ] || exit 72
 fi
 if [ -e "$launcher" ] || [ -L "$launcher" ]; then
  [ -L "$launcher" ] && [ "$(readlink "$launcher")" = "$base/bin/current" ] || exit 72
 fi
 if [ -e "$aside/install" ]; then mv -T "$aside/install" "$base"; fi
 if [ ! -e "$unit" ]; then
  # Copied beside the unit, then renamed: the unit appears whole or not at all.
  takeover_restoring="${unit%/*}/.infraternal-agent.service.restore"
  rm -f "$takeover_restoring"
  cp "$takeover_unit" "$takeover_restoring"
  mv -T "$takeover_restoring" "$unit"
 fi
 [ -L "$launcher" ] || ln -s "$base/bin/current" "$launcher"
 $manager daemon-reload >/dev/null 2>&1 || :
 [ "$takeover_enabled" != yes ] || $manager enable infraternal-agent.service >/dev/null 2>&1 || :
 [ "$takeover_active" != yes ] || $manager start infraternal-agent.service >/dev/null 2>&1 || :
 rm -rf "$aside"
}
# Put back the install Take over token $1 set aside, after the new install
# failed and its own rollback removed it (D359). Prints "restored", or
# "untouched" when that token set nothing aside; the token then stays, so a
# Take over still on its way refuses (cancel_set_aside). A set-aside left
# half-built, before anything was stopped, is removed. Waits for a Take over
# still running (setup_guard_wait), as the other restores do.
restore_taken_over_install() {
 hex_id "$1"
 setup_guard_wait=25
 setup_guard
 takeover_part="$base.bootstrap-taking-$1"
 if [ -d "$takeover_part" ] && [ ! -L "$takeover_part" ] && [ -O "$takeover_part" ]; then rm -rf "$takeover_part"; fi
 aside="$base.bootstrap-takeover-$1"
 if [ ! -e "$aside" ] && [ ! -L "$aside" ]; then
  cancel_set_aside "$1"
  printf 'untouched\n'
  return
 fi
 put_back_taken_over
 printf 'restored\n'
}
