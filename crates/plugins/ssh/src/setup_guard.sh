# Serialize host provisioning shell commands without creating an unowned lock file.
# Proof notes are beside Installation::script in install.rs [17][243].
setup_guard() {
 [ "${setup_guarded:-no}" != yes ] || return 0
 # Installation roots are fixed absolute paths ending in infraternal, without a trailing slash.
 parent=${base%/*}
 [ -n "$parent" ] || parent=/
 if [ -e "$parent" ] || [ -L "$parent" ]; then
  [ -d "$parent" ] && [ ! -L "$parent" ] && [ -O "$parent" ] || exit 71
  permissions=$(stat -c '%a' "$parent")
  [ "$((0$permissions & 022))" = 0 ] || exit 71
  exec 9< "$parent"
  flock -n 9 || exit 73
  setup_guarded=yes
 fi
}
