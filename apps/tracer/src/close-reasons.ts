/**
 * What a person reads when the server or the host's infraternal agent closes a terminal stream or the connection.
 * The server and the infraternal agent send short English reasons (crates/infraternal-server/src/{embedded,websocket,
 * stream_close}.rs and crates/infraternal-agent/src/daemon.rs); they are for logs, not for people. Every known
 * reason maps to a plain sentence about what happened to the person's terminal. Close reasons are untrusted input:
 * an unknown or empty reason gets the fallback, and its text is never copied into the page or the console.
 */
const KNOWN: Record<string, string> = {
  "detached": "This window was disconnected from its terminal. Open it again to reconnect.",
  "attachment ended": "This window was disconnected from its terminal. Open it again to reconnect.",
  "reader fell behind; reattach": "The screen could not keep up, so this window was reconnected.",
  "connection unresponsive": "The connection did not respond in time.",
  "connection closed": "The connection to the server ended.",
  "connection ended": "The connection to the server ended.",
  "terminal shim disconnected": "The terminal on the host stopped responding.",
  "terminal command queue full; reattach and replay unacknowledged input": "Too much typing was waiting for the host. Open the terminal again to continue.",
  "shim lacks restart-safe input capability": "The infraternal agent on that host is too old for this terminal. Update it on the host.",
  "shim refused terminal request": "The host would not open this terminal.",
  // Reasons the infraternal agent sends for a single terminal.
  "input queue full": "Too much typing was waiting for the host, so this window reconnected.",
  "terminal route unresponsive": "The terminal on the host stopped responding.",
  "remote stream unavailable": "The infraternal agent on the host lost its connection to the server.",
  "standby writer unavailable": "The host could not continue this terminal right now.",
  // Reasons the server names when it closes a terminal or the connection (stream_close.rs).
  "the infraternal agent ended the terminal stream": "The infraternal agent on the host closed this terminal.",
  "the infraternal agent lost its connection to the server": "The infraternal agent on the host lost its connection to the server.",
  "the host could not accept the terminal attachment": "The host could not open this terminal right now.",
  "terminal input exceeded the flow-control limit": "Too much typing was waiting for the host, so this window reconnected.",
  "the terminal reader fell behind and is reconnecting": "The screen could not keep up, so this window was reconnected.",
  "the terminal on the host stopped responding": "The terminal on the host stopped responding.",
  "terminal output credit exceeded its limit": "This window asked for more of the screen than it may hold, so it was reconnected.",
  "the server could not keep up with connection replies": "The server could not keep up with this connection.",
  "a terminal frame exceeded the size limit": "This window sent a message that was too large, so the connection was closed.",
  "the terminal stream sent an invalid protocol frame": "This window sent something the server did not understand, so the connection was closed.",
  "the server refused the terminal attachment": "The server would not open this terminal.",
  "the server refused to resume the connection": "The server would not continue the previous connection.",
  "the server stopped receiving connection replies": "The server stopped hearing from this browser.",
  "the server could not write to the connection": "The server could not send to this browser.",
  "the server could not continue the terminal stream": "The server could not continue this terminal.",
  // Reasons this page sends itself; the server echoes some of them back.
  "window closed": "This window was closed.",
  "tracer connection rotation": "The connection is being refreshed.",
  "tracer resume probe": "A connection check closed the connection.",
};

const known = (key: string): string | undefined => Object.prototype.hasOwnProperty.call(KNOWN, key) ? KNOWN[key] : undefined;

/** The plain sentence for a close reason. `fallback` says what happened when the reason is unknown. */
export function plainCloseReason(reason: string | undefined, fallback = "The terminal session ended."): string {
  return known((reason ?? "").trim()) ?? fallback;
}

const CLOSE_NOTE_WINDOW_MS = 60_000;

/**
 * One console line per socket close, at most one per minute. The first close of a window prints at once; the
 * rest are only counted and summarised in the next window's line, so a reconnect storm cannot flood the console.
 * It runs once per close event (never per frame). Only numbers and mapped reason keys are printed: peer text is
 * untrusted, so an unknown reason prints as "other".
 */
export class CloseNotes {
  private windowStart = Number.NEGATIVE_INFINITY;
  private suppressed = 0;

  /** `by` names who closed: "the server" for a named Close frame, "this page" for its own checks. */
  note(now: number, code: number | undefined, reason: string | undefined, attempt: number, welcomed: boolean, by = "the server or network"): string | undefined {
    if (now - this.windowStart < CLOSE_NOTE_WINDOW_MS) {
      this.suppressed += 1;
      return undefined;
    }
    const repeats = this.suppressed;
    this.windowStart = now;
    this.suppressed = 0;
    const key = (reason ?? "").trim();
    const safe = key === "" ? "none" : known(key) !== undefined ? key : "other";
    const phase = welcomed ? "after the connection was established" : "before the connection was established (reconnect failed)";
    const more = repeats > 0 ? `; ${repeats} more closes in the previous 60 s` : "";
    return `Connection to the server closed ${phase}: closed by ${by}, code ${code ?? 0}, reason "${safe}", reconnect attempt ${attempt}${more}`;
  }
}
