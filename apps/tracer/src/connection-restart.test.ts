/** Resume grace begins when a live socket drops, including after an overnight server restart (#199). */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { encodeMuxedFrame } from "../../../packages/protocol/src/codec";

test("an overnight connection retains its writer and pending input when the server restarts", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, now: Date.now };
  let now = 1000;
  let retry: (() => void) | undefined;
  const sockets: Socket[] = [];
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send() {}
    close() { this.readyState = 3; this.onclose?.(); }
  }
  const resumed: boolean[] = [];
  const handler: StreamHandler = {
    onSocketOpen: (value) => resumed.push(value), onWelcome() {}, onFrame() {},
    onDisconnected() {}, hasSession: () => true, onStatus() {},
  };
  let connection: MuxConnection | undefined;
  try {
    Date.now = () => now;
    globals.window = { setTimeout: (callback: () => void) => { retry = callback; return 1; }, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    connection.openStream(handler);
    sockets[0]!.onopen?.();
    const welcome = encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    sockets[0]!.onmessage?.({ data: welcome.slice().buffer as ArrayBuffer });
    now += 86_400_000;
    sockets[0]!.close();
    retry?.();
    sockets[1]!.onopen?.();
    expect(resumed).toEqual([false, true]);
    // An unwelcomed retry cannot extend grace; the next attempt after its limit
    // must discard the expired capability rather than keeping it alive forever.
    now += 120_001;
    sockets[1]!.close();
    retry?.();
    sockets[2]!.onopen?.();
    expect(resumed).toEqual([false, true, false]);
  } finally {
    connection?.dispose();
    Date.now = original.now;
    for (const key of ["window", "location", "WebSocket"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});
