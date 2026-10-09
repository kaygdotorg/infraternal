/**
 * What a person reads when the server or the host's agent closes a terminal stream or the connection.
 * The servers send short English reasons (crates/infraternal-server/src/{embedded,websocket}.rs and
 * crates/infraternal-agent/src/daemon.rs); they are for logs, not for people. Every known reason maps to a plain
 * sentence about what happened to the person's terminal. An unknown or empty reason gets the fallback and the raw
 * text goes to the console only.
 */
const KNOWN: Record<string, string> = {
  "detached": "This window was disconnected from its terminal. Open it again to reconnect.",
  "attachment ended": "This window was disconnected from its terminal. Open it again to reconnect.",
  "reader fell behind; reattach": "The screen could not keep up, so this window was reconnected.",
  "connection closed": "The connection to the server ended.",
  "connection ended": "The connection to the server ended.",
  "terminal shim disconnected": "The terminal on the host stopped responding.",
  "terminal command queue full; reattach and replay unacknowledged input": "Too much typing was waiting for the host. Open the terminal again to continue.",
  "shim lacks restart-safe input capability": "The infraternal agent on that host is too old for this terminal. Update it on the host.",
  "shim refused terminal request": "The host would not open this terminal.",
};

/** The plain sentence for a close reason. `fallback` says what happened when the reason is unknown. */
export function plainCloseReason(reason: string | undefined, fallback = "The terminal session ended."): string {
  const key = (reason ?? "").trim();
  if (!key) return fallback;
  const known = KNOWN[key];
  if (known) return known;
  console.warn(`unmapped close reason: ${key}`);
  return fallback;
}
