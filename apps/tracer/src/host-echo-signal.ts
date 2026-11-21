/**
 * Whether the infraternal agent tells the tracer when a host terminal stops echoing (`terminal.echo`, J1094, #569).
 *
 * Predictive echo is on by default (owner, 2026-11-21, D130), and a default-on prediction must never draw the keys
 * of a password: it is safe because the shim now reports when echo is off (J1094's `terminal.echo` notice, which
 * `PredictiveEcho.hostEcho()` obeys). `?predict=0` still turns prediction off for a page.
 */
export const HOST_ECHO_SIGNAL_SHIPPED = true;

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
