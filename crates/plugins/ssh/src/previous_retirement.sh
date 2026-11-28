# Read just the ownership marker and its directory identity. The server uses
# this data to authorize runtime inspection of the account's earlier install.
retirement_candidate() {
 no_redirect
 read_bootstrap_owner
 printf '%s %s\n' "$previous_host" "$identity"
}

# Inspect only a committed bootstrap install. Unlike a requested Take over,
# retirement never closes terminals. Refuse unknown objects and holders.
retirement_installed() {
 [ ! -e "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] || exit 73
 no_redirect
 # The unit and command must not be redirected below the login home.
 (base="${unit%/*}"; no_redirect)
 (base="${launcher%/*}"; no_redirect)
 validate_finished_install
 # The data-only inspection authorized this host and inode. Check them again
 # before terminal inspection, which can execute the installed runtime helper.
 [ -z "${1:-}" ] || [ "$previous_host" = "$1" ] || exit 75
 [ -z "${2:-}" ] || [ "$identity" = "$2" ] || exit 75
 loaded_unit=$($manager show -p FragmentPath --value infraternal-agent.service)
 [ -n "$loaded_unit" ] && [ "$loaded_unit" -ef "$unit" ] || exit 71
 installed_terminals=$(finished_terminal_records)
 [ -z "$installed_terminals" ] || exit 73
 holders_beside_agent
 printf 'INFRATERNAL_SETUP_INSTALLED %s %s %s ready\n' "$previous_host" "$identity" "$(upgrade_liveness)"
}
# Return the exact read-only proof and path list the person will review.
retirement_record() {
 retired_install=$(retirement_installed "$@")
 set -- $retired_install
 [ "$#" = 5 ] || exit 75
 runtime_helper
 retired_enrolled=$("$helper" --bootstrap-runtime "$base" "$3" enrolled </dev/null) || exit $?
 [ "$retired_enrolled" != "- -" ] || exit 71
 printf '%s\n%s\n%s\n%s\n%s\n' "$retired_install" "$retired_enrolled" "$base" "$unit" "$launcher"
 retired_link="${unit%/*}/$wanted.wants/infraternal-agent.service"
 if [ -L "$retired_link" ]; then printf '%s\n' "$retired_link"; else printf '%s\n' -; fi
 retired_command_alias
}
# Only the alias that bootstrap can create belongs to the installation.
retired_command_alias() {
 candidate="${launcher%/*}/infra"
 if [ -L "$candidate" ] && [ "$(stat -c '%u' "$candidate")" = "$(id -u)" ] && [ "$(readlink "$candidate")" = infraternal ]; then
  printf '%s\n' "$candidate"
 else
  printf '%s\n' -
 fi
}
# Match the whole receipt, with only two allowed changes after review: the
# service can become idle and its reviewed enablement link can disappear.
match_retirement_record() (
 newline='
'
 approved_install=${1%%"$newline"*}
 observed_install=${2%%"$newline"*}
 case "$approved_install" in
  *' live ready') approved_idle="${approved_install% live ready} idle ready";;
  *) approved_idle="$approved_install";;
 esac
 [ "$observed_install" = "$approved_install" ] || [ "$observed_install" = "$approved_idle" ] || exit 75

 approved_paths=${1#*"$newline"}
 observed_paths=${2#*"$newline"}
 with_wants=${approved_paths%"$newline"*}
 without_wants=${with_wants%"$newline"*}
 alias=${approved_paths##*"$newline"}
 [ "$observed_paths" = "$approved_paths" ] || [ "$observed_paths" = "$without_wants$newline-$newline$alias" ] || exit 75
)

# Bind the mutation to the displayed proof and scopes under the same setup
# lock. The existing takeover transaction can restore after a partial stop.
set_aside_retired_install() {
 setup_guard
 set -- "$1" ${1%%'
'*}
 [ "$#" = 6 ] && [ "$2" = INFRATERNAL_SETUP_INSTALLED ] && [ "$3" = "$host" ] || exit 75
 retirement_identity=$4
 observed=$(retirement_record "$host" "$retirement_identity")
 match_retirement_record "$1" "$observed"
 confirmed_alias=${observed##*'
'}
 approved_install=${1%%'
'*}
 retirement_approved=yes
 take_over_finished_install "$approved_install" "$transaction"
}
# Cross-scope retirement runs only after the new install is ready.
# Finish only this operation's set-aside directory, never another attempt's.
finish_retired_install() {
 aside="$base.bootstrap-takeover-$transaction"
 [ -d "$aside/install" ] && [ ! -L "$aside" ] && [ -O "$aside" ] || exit 71
 private_file "$aside/owner"
 [ "$(cat "$aside/owner")" = "$host" ] || exit 75
 sync -f "$aside" || exit 1
 rm -rf -- "$aside"
 if [ "$confirmed_alias" != - ] && [ "$(retired_command_alias)" = "$confirmed_alias" ]; then
  rm -- "$confirmed_alias"
 fi
}
