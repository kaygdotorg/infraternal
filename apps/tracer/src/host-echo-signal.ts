/**
 * Whether the infraternal agent tells the tracer when a host terminal stops echoing (`terminal.echo`, J1094, #569).
 *
 * Predictive echo is on by default (owner, 2026-11-21, D130), and a default-on prediction must never draw the keys
 * of a password: it can only be safe when the host says when echo is off. Until that signal ships, the default stays
 * off and `?predict=1` is still the explicit opt-in. DEPENDENCY: set this to `true` in the change that merges J1094
 * (branch `j1094-shim-noecho-signal`); nothing else needs to change.
 */
export const HOST_ECHO_SIGNAL_SHIPPED = false;

/**
 * Whether predictive echo runs, from the page's `?predict=` value: `1` always (explicit opt-in), `0` never, and
 * otherwise on by default once {@link HOST_ECHO_SIGNAL_SHIPPED}. Each terminal still decides per key from the 90th
 * percentile of its own key -> Ack time, and the host's echo-off report switches it off for hidden lines.
 */
export function predictiveEchoEnabled(query: string | null, signalShipped: boolean = HOST_ECHO_SIGNAL_SHIPPED): boolean {
  if (query === "1") return true;
  if (query === "0") return false;
  return signalShipped;
}
