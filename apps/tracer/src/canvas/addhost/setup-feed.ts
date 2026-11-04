// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The client of the host setup stream (D255, #189; contracts/host-setup.md "Host status adapter"): one WebSocket per
 * host and window on `/v1/bootstrap/setup/ws`. It belongs to the host, so it outlives the wizard's own socket, which
 * is what lets a failure that happens after the prompt appeared reach the machine pill.
 *
 * Protocol, as the contract states it:
 *   -> {"action":"subscribe","host_id":"<uuid>","window_id":"<canvas window id>","after":<last sequence seen>}
 *   <- {"setup":{...}} retained events first, then live ones      <- {"resync":true,"host_id":...} then current stages
 *   -> {"action":"retry","host_id":"<uuid>"}                      <- {"error":"..."} the status is unavailable
 *
 * Invariants:
 * - Nothing is invented. Every arc the pill draws is an event read here; a malformed frame is dropped.
 * - A dropped socket is reopened and resumes after the last sequence, so no event is shown twice and none is lost
 *   (the server reports overflow as a resync, which resets the view). After a few failed attempts the feed reports the
 *   status as lost and stops; the terminal never depended on it.
 * - The socket closes the moment `ready` is done, and when the window lets go. A retry asked while the socket is
 *   reconnecting is sent once it is back.
 * - Code here runs only while a host is setting up: it loads with the pill (`setup-pill.on-demand.ts`).
 */
import { isResync, parseSetupEvent, type SetupEvent } from "./setup-stages";
import type { SetupSignals, SetupSource } from "./setup-pill.on-demand";

/** What `createSetupFeed` needs. `open` and `backoff` exist so tests can use a fake socket and instant reconnects. */
export interface SetupFeedOptions {
  /** The canvas window that shows this host's setup. The server echoes it back; it is a presentation coordinate only. */
  windowId: string;
  /** Test seam: how a socket is opened. */
  open?: (url: string) => WebSocket;
  /** Test seam: delays between reconnects (ms). */
  backoff?: readonly number[];
}

/** Waits in milliseconds before each reconnect attempt. After this many failed attempts in a row the feed reports the status as lost. */
const BACKOFF = [400, 1000, 2500, 5000, 5000] as const;

/** The setup stream's WebSocket address on the page's own origin (`wss` on https, `ws` otherwise). */
export function setupUrl(): string {
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/v1/bootstrap/setup/ws`;
}

/**
 * Creates the feed. `subscribe(hostId, listener, signals)` opens the socket and returns a function that closes it. The listener gets
 * each new event once, in order. `signals.reset` fires when the server asks for a resync, `signals.lost` when the status is gone for
 * good (an error before any event, or the reconnect budget used up). `retry(hostId)` asks the server for another setup attempt; from
 * the lost state it first resubscribes to fetch the retained status. Which attempts are allowed is the server's decision.
 */
export function createSetupFeed(options: SetupFeedOptions): SetupSource {
  const open = options.open ?? ((url: string) => new WebSocket(url));
  const delays = options.backoff ?? BACKOFF;
  const live = new Map<string, { retry(): void }>();

  return {
    subscribe(hostId, listener, signals: SetupSignals = {}) {
      let socket: WebSocket | undefined;
      let last = 0;
      let attempts = 0;
      let stopped = false;
      let wantRetry = false;
      let seen = false;
      let timer: number | undefined;

      const pause = (): void => {
        stopped = true;
        window.clearTimeout(timer);
        const closing = socket;
        socket = undefined;
        if (closing && closing.readyState <= WebSocket.OPEN) closing.close(1000);
      };
      const end = (): void => { pause(); live.delete(hostId); };
      // Exhaustion releases transport resources but keeps the explicit recovery action
      // until the window disposes the subscription or setup completes.
      const lose = (): void => { if (!stopped) { pause(); signals.lost?.(); } };
      const connect = (): void => {
        const next = open(setupUrl());
        socket = next;
        next.onopen = () => {
          if (next !== socket) return;
          next.send(JSON.stringify({ action: "subscribe", host_id: hostId, window_id: options.windowId, after: last }));
          if (wantRetry) { wantRetry = false; next.send(JSON.stringify({ action: "retry", host_id: hostId })); }
        };
        next.onmessage = (message) => {
          if (next !== socket || typeof message.data !== "string") return;
          let value: unknown;
          try { value = JSON.parse(message.data); } catch { return; }
          // An error before any event means no status exists for this host; after one it is a refused request (a retry).
          if (value && typeof value === "object" && "error" in value) { if (!seen) lose(); return; }
          if (isResync(value, hostId)) { last = 0; signals.reset?.(); return; }
          const event: SetupEvent | undefined = parseSetupEvent(value);
          if (!event || event.hostId !== hostId) return;
          // A replay after a reconnect can repeat what was already shown.
          if (event.sequence !== undefined) { if (event.sequence <= last) return; last = event.sequence; }
          // Only useful host status restores the budget; opening an empty socket proves nothing.
          attempts = 0;
          seen = true;
          listener(event);
          if (event.stage === "ready" && event.state === "done") end();
        };
        next.onclose = () => {
          if (stopped || next !== socket) return;
          if (attempts >= delays.length) { lose(); return; }
          timer = window.setTimeout(connect, delays[attempts++]);
        };
      };
      live.set(hostId, { retry() {
        if (stopped) {
          // Fetch the retained status again before the server handles the retry.
          // Its subscription and current authority still decide whether retry is allowed.
          stopped = false;
          attempts = 0;
          last = 0;
          seen = false;
          wantRetry = true;
          connect();
        } else if (socket?.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ action: "retry", host_id: hostId }));
        } else wantRetry = true;
      } });
      connect();
      return end;
    },
    retry(hostId) { live.get(hostId)?.retry(); },
  };
}
