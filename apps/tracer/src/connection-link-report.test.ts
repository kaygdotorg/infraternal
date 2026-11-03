/**
 * The link report (`onConnectionChange`) after a loss (#314). The top pill says "offline" while the screen was last told
 * "not connected", and the only report of "connected" used to be a stream attaching. A page with no terminal to attach (every
 * window ended, or only views without terminals) therefore stayed "offline" for good after any socket drop, although the
 * route was back and carried a live inventory. A re-Welcome now reports it when no stream will attach; the first connect and
 * a page that resumes a terminal are unchanged: they report when the stream attaches.
 */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { encodeMuxedFrame } from "../../../packages/protocol/src/codec";

const welcome = (): ArrayBuffer => encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 }).slice().buffer as ArrayBuffer;

/** A connection over a scripted socket; `lose()` closes the current socket and `retry()` runs the reconnect the client armed. */
function scripted(hasSession: boolean) {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket };
  const reports: boolean[] = [];
  const sockets: Socket[] = [];
  let retry: (() => void) | undefined;
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    onclose?: (event: { code: number; reason: string }) => void;
    constructor() { sockets.push(this); }
    send() {}
    close() {}
  }
  globals.window = { setTimeout: (fn: () => void) => { retry = fn; return 1; }, clearTimeout() {} };
  globals.location = { protocol: "https:", host: "stream.example.test" };
  globals.WebSocket = Socket;
  const connection = new MuxConnection({ onConnectionChange: (connected) => reports.push(connected) });
  const handler: StreamHandler = { onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => hasSession, onStatus() {} };
  const open = (): void => { const socket = sockets.at(-1)!; socket.onopen?.(); socket.onmessage?.({ data: welcome() }); };
  return {
    connection, reports, handler, open,
    lose: () => sockets.at(-1)!.onclose?.({ code: 1011, reason: "host restarted" }),
    retry: () => { const run = retry; retry = undefined; run?.(); },
    restore: () => {
      connection.dispose();
      for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
    },
  };
}

test("a page with no terminal to attach reports the link again once it is re-welcomed", () => {
  const link = scripted(false);
  try {
    link.connection.subscribe({ topic: "terminal.sessions" }, () => {});
    link.open();
    expect(link.reports, "the first connect waits for an attach, as before").toEqual([]);
    link.lose();
    expect(link.reports).toEqual([false]);
    link.retry();
    link.open();
    expect(link.reports, "no stream will attach, so the Welcome reports the link").toEqual([false, true]);
  } finally {
    link.restore();
  }
});

test("a page that resumes a terminal waits for the attach, not the Welcome", () => {
  const link = scripted(true);
  try {
    const stream = link.connection.openStream(link.handler);
    link.open();
    link.connection.streamAttached(true, stream);
    expect(link.reports).toEqual([true]);
    link.lose();
    expect(link.reports).toEqual([true, false]);
    link.retry();
    link.open();
    expect(link.reports, "the stream holds a session: it reports when it attaches again").toEqual([true, false]);
    link.connection.streamAttached(true, stream);
    expect(link.reports).toEqual([true, false, true]);
  } finally {
    link.restore();
  }
});
