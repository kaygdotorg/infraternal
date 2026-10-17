/**
 * What a person reads when the server or the host's infraternal agent closes a terminal stream or the connection.
 * The server sends short, content-free close reasons; every known reason maps to an explanation in the existing
 * terminal status surface. Unknown text is discarded because close reasons are untrusted input.
 */
const KNOWN: Record<string, string> = {
  "detached": "This window was detached from its terminal.",
  "attachment ended": "Connection closed: the terminal stream ended.",
  "reader fell behind; reattach": "Connection closed: the terminal reader fell behind and is reconnecting.",
  "the terminal reader fell behind and is reconnecting": "Connection closed: the terminal reader fell behind and is reconnecting.",
  "connection unresponsive": "Connection closed: the server did not respond in time.",
  "connection closed": "Connection closed: the server ended the connection.",
  "connection ended": "Connection closed: the server ended the connection.",
  "session ended": "The terminal session ended.",
  "input queue full": "Connection closed: terminal input exceeded the host queue limit.",
  "terminal input exceeded the flow-control limit": "Connection closed: terminal input exceeded its flow-control limit.",
  "terminal route unresponsive": "Connection closed: the terminal on the host stopped responding.",
  "the terminal on the host stopped responding": "Connection closed: the terminal on the host stopped responding.",
  "remote stream unavailable": "Connection closed: the infraternal agent lost its connection to the server.",
  "standby writer unavailable": "Connection closed: the host could not resume this terminal stream.",
  "other": "Connection closed: the server or host ended the terminal stream.",
  "terminal shim disconnected": "Connection closed: the terminal on the host stopped responding.",
  "terminal command queue full; reattach and replay unacknowledged input": "Connection closed: terminal input exceeded the host queue limit.",
  "shim lacks restart-safe input capability": "Connection closed: the host infraternal agent needs an update.",
  "shim refused terminal request": "Connection closed: the host refused the terminal request.",
  "browser closed the connection": "Connection closed: the browser closed the connection.",
  "the infraternal agent ended the terminal stream": "Connection closed: the infraternal agent ended the terminal stream.",
  "the infraternal agent lost its connection to the server": "Connection closed: the infraternal agent lost its connection to the server.",
  "the host could not accept the terminal attachment": "Connection closed: the host could not accept the terminal attachment.",
  "terminal output credit exceeded its limit": "Connection closed: terminal output exceeded its flow-control limit.",
  "a terminal frame exceeded the size limit": "Connection closed: a terminal frame exceeded the size limit.",
  "the terminal stream sent an invalid protocol frame": "Connection closed: the terminal stream sent an invalid protocol frame.",
  "the server refused the terminal attachment": "Connection closed: the server refused the terminal attachment.",
  "the server refused to resume the connection": "Connection closed: the server refused to resume the connection.",
  "the server stopped receiving connection replies": "Connection closed: the server stopped receiving connection replies.",
  "the server could not keep up with connection replies": "Connection closed: the server could not keep up with connection replies.",
  "the server could not write to the connection": "Connection closed: the server could not write to the connection.",
  "the server could not continue the terminal stream": "Connection closed: the server could not continue the terminal stream.",
  "the stream closed repeatedly for different reasons": "Connection closed: the stream closed repeatedly for different reasons.",
  "window closed": "This window was closed.",
  "tracer connection rotation": "The connection is being refreshed.",
  "tracer resume probe": "The connection check ended the socket.",
};

/** The safe sentence for a close reason. Unknown text is never copied into the UI or console. */
export function plainCloseReason(reason: string | undefined, fallback = "Connection closed: the server did not provide a safe reason."): string {
  const key = (reason ?? "").trim();
  return Object.prototype.hasOwnProperty.call(KNOWN, key) ? KNOWN[key]! : fallback;
}
