# Manage the bounded setup lease while the shared guard protects journal mutation.
# Proof notes are beside Installation::script in install.rs [17][243].
lease_birth_field() {
 process_birth_field "$1" || return 1
 lease_actual_birth=$process_birth
}
read_lease_birth() {
 process_start_ticks "$1" || return 1
 lease_actual_birth=$process_start_ticks
}
start_setup_lease() {
 exec 7< "$stage"
 flock -n 7 || exit 73
 (exec 9<&-; if [ "${lease_runtime:-no}" != yes ]; then exec 6<&-; fi; exec sleep 180) >/dev/null 2>&1 &
 lease_pid=$!
 read_lease_birth "$lease_pid" || exit 73
 lease_birth=$lease_actual_birth
 printf '%s %s\n' "$lease_pid" "$lease_birth" > "$stage/lease"
 # Fork publication can precede the child's descriptor teardown (#189, #190).
 # Wait until it has dropped the parent guard and, unless it keeps the
 # runtime lock, that lock too; then require the exact transaction lock.
 lease_checks=0
 while [ -L "/proc/$lease_pid/fd/9" ] || { [ "${lease_runtime:-no}" != yes ] && [ -L "/proc/$lease_pid/fd/6" ]; }; do
  lease_checks=$((lease_checks + 1))
  [ "$lease_checks" -le 1000 ] || exit 73
  sleep 0.001
 done
 [ ! -L "$stage" ] && [ "$stage" -ef "/proc/$lease_pid/fd/7" ] || exit 73
 exec 7<&-
}
retire_setup_lease() {
 if [ -e "$stage/lease" ] || [ -L "$stage/lease" ]; then
  [ -f "$stage/lease" ] && [ ! -L "$stage/lease" ] && [ -O "$stage/lease" ] || exit 71
  case "$(stat -c '%a:%h:%s' "$stage/lease")" in
   600:1:[0-9]|600:1:[1-5][0-9]|600:1:6[0-4]) :;;
   *) exit 71;;
  esac
  read -r lease_pid lease_birth extra < "$stage/lease"
  [ -z "$extra" ] || exit 71
  case "$lease_pid:$lease_birth" in *[!0-9:]*|:*|*:) exit 71;; esac
  if [ -r "/proc/$lease_pid/stat" ] && read_lease_birth "$lease_pid" && [ "$lease_actual_birth" = "$lease_birth" ]; then
   [ ! -L "$stage" ] && [ "$stage" -ef "/proc/$lease_pid/fd/7" ] || exit 73
   kill "$lease_pid" || exit 73
  fi
 fi
 if [ -d "$stage" ] && [ ! -L "$stage" ]; then
  exec 7< "$stage"
  flock -w 2 7 || exit 73
 fi
}

# Change lease ownership only under the parent setup guard and exact transaction.
handoff_setup_lease() {
 retire_setup_lease
 rm -f "$stage/lease"
 runtime="$base/sessions"
 if [ ! -e "$runtime" ] && [ ! -L "$runtime" ]; then mkdir "$runtime"; fi
 [ -d "$runtime" ] && [ ! -L "$runtime" ] && [ -O "$runtime" ] && [ "$(stat -c '%a' "$runtime")" = 700 ] || exit 71
 lifetime="$runtime/.lifetime-lock"
 identity=$(stat -c '%d:%i' "$base")
 if [ ! -e "$lifetime" ] && [ ! -L "$lifetime" ]; then
  "$1" --bootstrap-runtime "$base" "$identity" inspect </dev/null
  : > "$lifetime"
 fi
 [ -f "$lifetime" ] && [ ! -L "$lifetime" ] && [ -O "$lifetime" ] && [ "$(stat -c '%a:%h' "$lifetime")" = 600:1 ] || exit 71
 exec 6< "$lifetime"
 "$1" --bootstrap-runtime "$base" "$identity" inspect <&6
 lease_runtime=$2
 start_setup_lease
}

# A commit deletes what a Replace or Re-enroll set aside: a replaced journal
# with its rollback copies, or a whole superseded install with its old key
# and unit. The host now serves the committed install, and no set-aside copy
# is kept (D337). Until this commit they stay, for rollback and Put it back.
# Every commit runs this, including finish_stuck_upgrade (#305 P2-3). Only our
# own private directories under those fixed names are removed.
retire_set_aside() {
 for set_aside in "$base".bootstrap-replaced-* "$base".bootstrap-superseded-*; do
  [ -d "$set_aside" ] && [ ! -L "$set_aside" ] && [ -O "$set_aside" ] || continue
  rm -rf "$set_aside"
 done
 # Cancel tokens of attempts whose set-aside never arrived (#305, J202 P2).
 for set_aside in "$base".bootstrap-cancel-*; do
  [ -f "$set_aside" ] && [ ! -L "$set_aside" ] && [ -O "$set_aside" ] || continue
  rm -f -- "$set_aside"
 done
}
