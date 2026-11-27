# Inspect only a committed bootstrap install. Unlike a requested Take over,
# retirement never closes terminals. Refuse unknown objects and holders.
retirement_installed() {
 [ ! -e "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] || exit 73
 no_redirect
 # The unit and command must not be redirected below the login home.
 (base="${unit%/*}"; no_redirect)
 (base="${launcher%/*}"; no_redirect)
 validate_finished_install
 loaded_unit=$($manager show -p FragmentPath --value infraternal-agent.service)
 [ -n "$loaded_unit" ] && [ "$loaded_unit" -ef "$unit" ] || exit 71
 installed_terminals=$(finished_terminal_records)
 [ -z "$installed_terminals" ] || exit 73
 holders_beside_agent
 printf 'INFRATERNAL_SETUP_INSTALLED %s %s %s ready\n' "$previous_host" "$identity" "$(upgrade_liveness)"
}
# Return the exact read-only proof and path list the person will review.
retirement_record() {
 retired_install=$(retirement_installed)
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
# Bind the mutation to the displayed proof and scopes under the same setup
# lock. The existing takeover transaction can restore after a partial stop.
set_aside_retired_install() {
 setup_guard
 observed=$(retirement_record)
 [ "$observed" = "$1" ] || exit 75
 confirmed_alias=${observed##*'
'}
 approved_install=${observed%%'
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
