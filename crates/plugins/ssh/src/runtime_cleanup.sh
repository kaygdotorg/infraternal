# Validate runtime lifetime under the cleanup shell's inherited lock descriptor (#230).
refuse() {
 printf 'INFRATERNAL_SETUP_REFUSED %s\n' "$1"
 [ "${setup_check:-no}" != yes ] || exit 0
 exit 75
}
runtime_helper() {
 helper="$base.bootstrap-cache/payload"
 [ -d "$base.bootstrap-cache" ] && [ ! -L "$base.bootstrap-cache" ] && [ -O "$base.bootstrap-cache" ] && [ "$(stat -c '%a' "$base.bootstrap-cache")" = 700 ] || exit 76
 [ -f "$helper" ] && [ ! -L "$helper" ] && [ -O "$helper" ] && [ "$(stat -c '%a' "$helper")" = 700 ] || exit 76
 # Capability level (runtime_lock::LEVEL); a cache at another level may lack a mode used here.
 level=$("$helper" --bootstrap-runtime-version 2>/dev/null) || exit 76
 [ "$level" = 9 ] || exit 76
}
control_socket() {
 [ -e "$base/sessions" ] || [ -L "$base/sessions" ] || return 0
 [ -d "$base/sessions" ] && [ ! -L "$base/sessions" ] && [ -O "$base/sessions" ] && [ "$(stat -c '%a' "$base/sessions")" = 700 ] || exit 71
 control="$base/sessions/plugins.sock"
 lifetime="$base/sessions/.lifetime-lock"
 if [ ! -e "$control" ] && [ ! -L "$control" ] && [ ! -e "$lifetime" ] && [ ! -L "$lifetime" ]; then return 0; fi
 runtime_helper
 if [ -e "$lifetime" ] || [ -L "$lifetime" ]; then
  [ -f "$lifetime" ] && [ ! -L "$lifetime" ] && [ -O "$lifetime" ] && [ "$(stat -c '%a:%h' "$lifetime")" = 600:1 ] || exit 71
  if [ "${runtime_locked:-no}" != yes ]; then exec 6< "$lifetime"; runtime_locked=yes; fi
  "$helper" --bootstrap-runtime "$base" "$identity" "$1" <&6 || exit $?
 else
  "$helper" --bootstrap-runtime "$base" "$identity" "$1" </dev/null || exit $?
 fi
}
validate_control_socket() { control_socket inspect; }
retire_control_socket() { control_socket retire; }

validate_retired_stage() {
 stage="$base/.bootstrap-lock"
 [ -e "$stage" ] || [ -L "$stage" ] || return 0
 [ -d "$stage" ] && [ ! -L "$stage" ] && [ -O "$stage" ] && [ "$(stat -c '%a' "$stage")" = 700 ] || exit 71
 for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  case "${entry##*/}" in
   state|cache)
    [ -d "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a' "$entry")" = 700 ] || exit 71
    bad=$(find "$entry" \( ! -uid "$(id -u)" -o ! \( -type d -o -type f \) -o -perm /077 -o \( -type d ! -perm 0700 \) \) -print -quit) || exit 71
    [ -z "$bad" ] || exit 71
    count=$(find "$entry" -printf . | wc -c)
    [ "$count" -le 1024 ] || refuse size
    continue;;
   current|launcher)
    [ -L "$entry" ] || exit 71
    case "${entry##*/}:$(readlink "$entry")" in
     "current:$base/bin/live"|"launcher:$base/bin/current") continue;;
     *) exit 71;;
    esac;;
   transfer-chunk|transfer-progress|transfer-progress-next)
    [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a:%h' "$entry")" = 600:1 ] || exit 71
    limit=24
    [ "${entry##*/}" != transfer-chunk ] || limit=65536
    [ "$(stat -c '%s' "$entry")" -le "$limit" ] || exit 71
    continue;;
   payload)
    [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] || exit 71
    case "$(stat -c '%a' "$entry")" in 600|700) continue;; *) exit 71;; esac;;
   transaction|kind|lease|unit|activating|failed|stopping|stop-refused|had-binary|had-state|had-launcher|was-active|was-enabled|replacing-binary|replacing-state|replacing-unit|replacing-launcher|linger-requested|creating-alias) :;;
   *) refuse entry;;
  esac
  [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a:%h' "$entry")" = 600:1 ] || exit 71
  [ "$(stat -c '%s' "$entry")" -le 4096 ] || exit 71
  case "${entry##*/}" in
   transaction) [ "$(cat "$entry")" = "$1" ] || refuse transaction;;
   kind) [ "$(cat "$entry")" = fresh ] || refuse kind;;
   unit) grep -Fxq "# infraternal bootstrap $2" "$entry" || exit 71;;
   lease) [ "$(stat -c '%s' "$entry")" -le 64 ] || exit 71;;
   *) [ "$(stat -c '%s' "$entry")" = 0 ] || exit 71;;
  esac
 done
}
