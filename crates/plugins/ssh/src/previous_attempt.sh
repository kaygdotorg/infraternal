# Classify earlier host provisioning using private ownership receipts; never adopt foreign data.
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
   activating|failed|stopping|stop-refused|had-binary|had-state|had-launcher|was-active|was-enabled|replacing-binary|replacing-state|replacing-unit|replacing-launcher|linger-requested)
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
 [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] && [ "$(stat -c '%a' "$base")" = 700 ] || exit 71
 private_file "$base/.bootstrap-owner"
 [ "$(stat -c '%s' "$base/.bootstrap-owner")" = 33 ] || refuse owner
 previous_host=$(cat "$base/.bootstrap-owner")
 hex_id "$previous_host"
 identity=$(stat -c '%d:%i' "$base")
 [ -d "$base/bin" ] && [ ! -L "$base/bin" ] && [ -O "$base/bin" ] && [ "$(stat -c '%a' "$base/bin")" = 700 ] || exit 71
 [ -f "$base/bin/live" ] && [ ! -L "$base/bin/live" ] && [ -O "$base/bin/live" ] && [ "$(stat -c '%a:%h' "$base/bin/live")" = 700:1 ] || exit 71
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
 for entry in "$base/bin"/* "$base/bin"/.[!.]* "$base/bin"/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  case "${entry##*/}" in live) :;; current) [ -L "$entry" ] && [ "$(readlink "$entry")" = "$base/bin/live" ] || exit 71;; *) exit 71;; esac
 done
 [ -L "$launcher" ] && [ "$(readlink "$launcher")" = "$base/bin/current" ] || exit 71
 [ -f "$unit" ] && [ ! -L "$unit" ] && [ -O "$unit" ] && [ "$(stat -c '%a:%h' "$unit")" = 600:1 ] || exit 71
 [ "$(stat -c '%s' "$unit")" -le 4096 ] || refuse size
 grep -Fxq "# infraternal bootstrap $previous_host" "$unit" || exit 71
 grep -Fxq "ExecStart=\"$base/bin/current\" agent --data \"$base/state\" --state \"$base/sessions\" run" "$unit" || exit 71
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
not_live() {
 if [ -d "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ]; then
  exec 8< "$base/.bootstrap-lock"
  flock -n 8 || exit 73
  exec 8<&-
 fi
 # Non-dumpable shims: the helper asks the kernel by owner+inode, never by name.
 for entry in "$base/sessions"/*.sock "$base/sessions/sessions"/*.sock; do
  [ -S "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] || continue
  [ "$entry" != "$base/sessions/plugins.sock" ] || continue
  runtime_helper
  "$helper" --bootstrap-runtime "$base" "$(stat -c '%d:%i' "$base")" sessions </dev/null || exit $?
  break
 done
 scan_holders all
}
# Refuse (73) while a process of this user runs from or holds a file under
# $base. "service" skips the enrolled unit's own processes and the journaled
# payload's shims, which a replacement is about to stop itself (#305).
scan_holders() {
 scan_skip=$1
 if [ -e "$base" ] || [ -L "$base" ]; then
  base_real=$(CDPATH= cd -P "$base" 2>/dev/null && pwd -P) || refuse tool
 else
  base_real=$(CDPATH= cd -P "$(dirname "$base")" && pwd -P)/${base##*/}
 fi
 case "$base" in *[\*\?\[]*) refuse tool;; esac
 case "$base_real" in *[\*\?\[]*) refuse tool;; esac
 set --
 for process in /proc/[0-9]*; do
  [ -O "$process" ] || continue
  if [ "$scan_skip" = service ]; then
   [ ! "$base/.bootstrap-lock/payload" -ef "$process/exe" ] || continue
   scan_unit=no
   { while IFS= read -r scan_cgroup; do
      case "$scan_cgroup" in */infraternal-agent.service|*/infraternal-agent.service/*) scan_unit=yes;; esac
     done < "$process/cgroup"; } 2>/dev/null || :
   [ "$scan_unit" = no ] || continue
  fi
  set -- "$@" "$process/exe" "$process/fd"
  [ "$#" -le 8192 ] || refuse size
 done
 [ "$#" -le 8192 ] || refuse size
 command -v find >/dev/null 2>&1 || refuse tool
 if live=$(find "$@" -maxdepth 1 \( -lname "$base/*" -o -lname "$base_real/*" \) -print -quit 2>/dev/null); then
  :
 else
  [ "$?" = 1 ] || refuse tool
 fi
 [ -z "$live" ] || exit 73
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
# An earlier Replace or Re-enroll set the stuck install aside and could not
# put it back: its restore never ran (a dropped session) or failed. Name it,
# so the person can put it back instead of installing beside it (#305 P2-1).
# A Re-enroll that committed keeps its old install beside the new $base, and
# a Replace that committed removed its journal, so neither is reported. Nor
# is a replaced journal while the unit is active: a newer install is serving,
# and putting the stale journal into it would make a healthy host stuck again
# (#305 P2-3).
# Fails (1) when there is nothing to report.
report_set_aside() {
 set_aside=
 for candidate in "$base".bootstrap-superseded-* "$base".bootstrap-replaced-*; do
  [ -e "$candidate" ] || [ -L "$candidate" ] || continue
  case "$candidate" in
   "$base".bootstrap-superseded-*)
    [ ! -e "$base" ] && [ ! -L "$base" ] || continue
    set_aside_kind=superseded
    set_aside_transaction=${candidate#"$base.bootstrap-superseded-"}
    set_aside_owner="$candidate/.bootstrap-owner"
    set_aside_service="$candidate/.superseded-service";;
   *)
    [ -d "$base" ] && [ ! -L "$base" ] || continue
    ! $manager is-active --quiet infraternal-agent.service >/dev/null 2>&1 || continue
    set_aside_kind=replaced
    set_aside_transaction=${candidate#"$base.bootstrap-replaced-"}
    set_aside_owner="$base/.bootstrap-owner"
    set_aside_service="$candidate/found-service";;
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
  report_set_aside && return
  printf 'INFRATERNAL_SETUP_CLEAR\n'
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
  [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] && [ "$(stat -c '%a' "$base")" = 700 ] || exit 71
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
  [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] && [ "$(stat -c '%a' "$base")" = 700 ] || exit 71
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
 validate_control_socket
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
     activating|failed|stopping|stop-refused|had-binary|had-state|had-launcher|was-active|was-enabled|replacing-binary|replacing-state|replacing-unit|replacing-launcher|linger-requested)
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
     [ ! -e "$child" ] && [ ! -L "$child" ] || exit 71
    done;;
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
    validate_control_socket
    sockets=$((sockets + 1))
    [ "$sockets" -le 1024 ] || refuse size
    continue
   fi
   [ -S "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a' "$entry")" = 600 ] || exit 71
   name=${entry##*/}
   socket_id=${name%.sock}
   [ "$name" = "$socket_id.sock" ] || exit 71
   hex_id "$socket_id"
   sockets=$((sockets + 1))
   [ "$sockets" -le 1024 ] || refuse size
  done
 done
 printf 'INFRATERNAL_SETUP_STALE %s %s %s %s\n' "$previous_host" "$previous_transaction" "$identity" "$sockets"
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
# once the old install is moved out of the way.
retire_stuck_service() {
 replace_expected=$1
 aside=
 aside_origin=
 setup_guard
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
 stop_stage_shims
 exec 7<&-
 not_live
 exec 7< "$stage"
 flock -n 7 || exit 73
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
 retire_stuck_service "$1"
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
 set -- $supersede_record
 [ "${12-}" != live ] || [ "${9-}" = 0 ] || exit 75
 retire_stuck_service "$supersede_record"
 aside="$base.bootstrap-superseded-$replace_transaction"
 aside_origin=$base
 [ ! -e "$aside" ] && [ ! -L "$aside" ] || { aside=; exit 72; }
 mv -T "$base" "$aside"
 printf '%s %s\n' "$replace_enabled" "$replace_active" > "$aside/.superseded-service"
 mv "$unit" "$aside/.superseded-unit"
 rm -f "$launcher"
 $manager daemon-reload >/dev/null 2>&1 || exit 73
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
 retire_setup_lease
 rm -rf "$stage"
 retire_replaced
}
