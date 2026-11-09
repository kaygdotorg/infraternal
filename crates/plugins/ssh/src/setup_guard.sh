# Serialize host provisioning shell commands without creating an unowned lock file.
# Proof notes are beside Installation::script in install.rs [17][243].
process_birth_field() {
 process_stat=$1
 process_suffix=${process_stat##*) }
 [ "$process_suffix" != "$process_stat" ] || return 1
 case "$process_suffix" in *[!a-zA-Z0-9\ -]*) return 1;; esac
 set -- $process_suffix
 process_start=${20-}
 case "$process_start" in ''|*[!0-9]*) return 1;; esac
 process_birth=$process_start
}
process_start_ticks() {
 IFS= read -r process_stat < "/proc/$1/stat" || return 1
 process_birth_field "$process_stat" || return 1
 process_start_ticks=$process_birth
}
setup_guard() {
 [ "${setup_guarded:-no}" != yes ] || return 0
 [ "${setup_blocked:-no}" != yes ] || return 0
 # Installation roots are fixed absolute paths ending in infraternal, without a trailing slash.
 parent=${base%/*}
 [ -n "$parent" ] || parent=/
 if [ -e "$parent" ] || [ -L "$parent" ]; then
  [ -d "$parent" ] && [ ! -L "$parent" ] && [ -O "$parent" ] || exit 71
  permissions=$(stat -c '%a' "$parent")
  [ "$((0$permissions & 022))" = 0 ] || exit 71
  exec 9< "$parent"
  # A caller that must run after an in-flight setup (a restore) sets
  # setup_guard_wait to the seconds it may queue. The locked-state inspector
  # never waits, so a host check stays fast. Every other command waits up to
  # 5 seconds: a starting infraternal agent holds a shared lock on this
  # directory for the moment it admits its runtime (runtime_lock.rs), and a
  # setup command colliding with that must not report a finished install as
  # "setup is already running" (#439). A competing setup that holds the guard
  # past the wait still refuses here; one that releases it sooner is refused
  # by the transaction checks and the stage flock that follow.
  if [ -n "${setup_guard_wait:-}" ]; then
   setup_guard_flag="-w $setup_guard_wait"
  elif [ "${setup_allow_locked_inspection:-no}" = yes ]; then
   setup_guard_flag=-n
  else
   setup_guard_flag="-w 5"
  fi
  if ! flock $setup_guard_flag 9; then
   if [ "${setup_allow_locked_inspection:-no}" = yes ]; then
    # The inspector is not the lock owner; drop its descriptor before looking
    # through /proc so the diagnostic names the process that holds the guard.
    exec 9<&-
    setup_blocked=yes
    return 0
   fi
   exit 73
  fi
  setup_guarded=yes
 fi
}
