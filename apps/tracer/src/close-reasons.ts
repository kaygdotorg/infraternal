/**
 * What a person reads when the server or the host's infraternal agent closes a terminal stream or the connection.
 * The server and the infraternal agent send short English reasons (crates/infraternal-server/src/{embedded,websocket,
 * stream_close}.rs and crates/infraternal-agent/src/daemon.rs); they are for logs, not for people. Every known
 * reason maps to a plain sentence about what happened to the person's terminal. Close reasons are untrusted input:
 * an unknown or empty reason gets the fallback, and its text is never copied into the page or the console.
 */
/**
 * The reason the server sends when the account already holds all the live connections it may have
 * (crates/infraternal-server/src/stream_close.rs `CONNECTION_LIMIT`). The page compares against it to say why it cannot
 * connect, and to keep a resume it may still use: the refusal comes before the server reads any resume (#523).
 */
export const CONNECTION_LIMIT_REASON = "this account has too many open connections";

/**
 * The reason the server sends when a newer tab of the same account took this hidden tab's connection, because the
 * account was at its limit (stream_close.rs `TAKEN_OVER`, owner decision B on #523). The page pauses and connects
 * again only once it is shown: reconnecting while hidden would take another hidden tab's place in turn.
 */
export const TAKEN_OVER_REASON = "another tab of this account is using this connection";

/**
 * The reasons we recognise, each with the sentence a person reads. Several reasons can share a sentence. Add a new
 * server or infraternal agent reason here when one is added there; until then it shows the fallback.
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
  "terminal stream limit": "This host already shows as many terminals as it can. Close one to open this one.",
  // Reasons the infraternal agent sends for a single terminal.
  "input queue full": "Too much typing was waiting for the host, so this window reconnected.",
  "terminal route unresponsive": "The terminal on the host stopped responding.",
  "remote stream unavailable": "The infraternal agent on the host lost its connection to the server.",
  "standby writer unavailable": "The host could not continue this terminal right now.",
  // Reasons the server names when it closes a terminal or the connection (stream_close.rs).
  "the infraternal agent ended the terminal stream": "The infraternal agent on the host closed this terminal.",
  "the infraternal agent lost its connection to the server": "The infraternal agent on the host lost its connection to the server.",
  "the host could not accept the terminal attachment": "The host could not open this terminal right now.",
  "this host already shows as many terminals as it can; close one to open another": "This host already shows as many terminals as it can. Close one to open this one.",
  "terminal input exceeded the flow-control limit": "Too much typing was waiting for the host, so this window reconnected.",
  "the terminal reader fell behind and is reconnecting": "The screen could not keep up, so this window was reconnected.",
  "the terminal on the host stopped responding": "The terminal on the host stopped responding.",
  "terminal output credit exceeded its limit": "Too much screen data was waiting for this window, so it was reconnected.",
  "the server could not keep up with connection replies": "The server could not keep up with this connection.",
  "a terminal frame exceeded the size limit": "A message was too large to send, so the connection was closed.",
  "the terminal stream sent an invalid protocol frame": "The server could not read a message from this window, so the connection was closed.",
  "the server refused the terminal attachment": "The server would not open this terminal.",
  "the server refused to resume the connection": "Couldn't restore the previous connection. Your terminals will reconnect automatically.",
  "another tab of this account is using this connection": "This tab paused so a newer tab could connect. It reconnects when you come back to it.",
  "this account has too many open connections": "This account is open in too many browser tabs. Close the ones you don't need to connect.",
  "the server stopped receiving connection replies": "The server stopped hearing from this browser.",
  "the server could not write to the connection": "The server could not send to this browser.",
  "the server could not continue the terminal stream": "The server could not continue this terminal.",
  "the server was too busy to confirm the session": "The server was too busy to confirm your session.",
  "recovery completed": "Recovery completed. This device has been signed out.",
  // Reasons this page sends itself; the server echoes some of them back.
  "window closed": "This window was closed.",
  "tracer connection rotation": "The connection is being refreshed.",
  "tracer resume probe": "A connection check closed the connection.",
};

/** The sentence for a reason, or `undefined` when it is not in {@link KNOWN}. Looks up own keys only, so a reason like `constructor` cannot match. */
const known = (key: string): string | undefined => Object.prototype.hasOwnProperty.call(KNOWN, key) ? KNOWN[key] : undefined;

/** The plain sentence for a close reason. `fallback` says what happened when the reason is unknown. */
export function plainCloseReason(reason: string | undefined, fallback = "The terminal session ended."): string {
  return known((reason ?? "").trim()) ?? fallback;
}

/** Closes after which the window reattaches by itself, so none of them may read as an ending. */
const REATTACHING = new Set(["detached", "attachment ended", "session ended"]);
/** What the window says while it reattaches. */
const REATTACH_STATUS = "Reconnecting to the terminal…";

/**
 * The status for a terminal stream close that is not final: the window reattaches by itself. A known problem keeps
 * its sentence; a routine detach, an ended attachment or an unknown reason says only that it is reconnecting.
 */
export function reattachReason(reason: string | undefined): string {
  const key = (reason ?? "").trim();
  return REATTACHING.has(key) ? REATTACH_STATUS : known(key) ?? REATTACH_STATUS;
}

/** The status while the infraternal agent's server link recovers: the cause, then that it recovers by itself. */
export function recoveringReason(reason: string | undefined): string {
  const sentence = known((reason ?? "").trim());
  return sentence ? `${sentence} Reconnecting…` : "Catching up…";
}

/** The length of one logging window: at most one console line per this time. */
const CLOSE_NOTE_WINDOW_MS = 60_000;

/**
 * One console line per socket close, at most one per minute. The first close of a window prints at once; later ones
 * are only counted, and the count prints when the window ends (`flush`, from a timer) or with the next line. Runs
 * once per close event, never per frame. Only numbers and mapped reason keys are printed: peer text is untrusted, so
 * an unknown reason prints as "other".
 */
export class CloseNotes {
  /** When the current logging window began; minus infinity before the first close. */
  private windowStart = Number.NEGATIVE_INFINITY;
  /** How many closes were counted without a line in this window. */
  private suppressed = 0;

  /**
   * The console line for a close, or `undefined` when this window already printed one (the close is then only counted).
   * @param now the time in milliseconds
   * @param code the WebSocket close code, if any
   * @param reason the close reason; printed only when it is a known one, otherwise as "other"
   * @param attempt the number of the reconnect attempt
   * @param welcomed whether the connection had been fully established before it closed
   * @param by who closed it: "the server" for a named Close frame, "this page" for its own checks
   */
  note(now: number, code: number | undefined, reason: string | undefined, attempt: number, welcomed: boolean, by = "the server or network"): string | undefined {
    if (now - this.windowStart < CLOSE_NOTE_WINDOW_MS) {
      this.suppressed += 1;
      return undefined;
    }
    const counted = this.flush(now);
    this.windowStart = now;
    const key = (reason ?? "").trim();
    const safe = key === "" ? "none" : known(key) !== undefined ? key : "other";
    const phase = welcomed ? "after the connection was established" : "before the connection was established (reconnect failed)";
    const line = `Connection to the server closed ${phase}: closed by ${by}, code ${code ?? 0}, reason "${safe}", reconnect attempt ${attempt}`;
    return counted ? `${counted}; ${line}` : line;
  }

  /** When counted closes wait for their summary, the time it is due. */
  summaryDue(): number | undefined {
    return this.suppressed > 0 ? this.windowStart + CLOSE_NOTE_WINDOW_MS : undefined;
  }

  /** The count of closes since the last printed line, once their window has ended. */
  flush(now: number): string | undefined {
    if (this.suppressed === 0 || now - this.windowStart < CLOSE_NOTE_WINDOW_MS) return undefined;
    const count = this.suppressed;
    this.suppressed = 0;
    return `Connection to the server closed ${count} more ${count === 1 ? "time" : "times"} since the previous line`;
  }
}
