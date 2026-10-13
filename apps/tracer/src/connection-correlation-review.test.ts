/** Independent #199 review: a reply must echo both fields of an issued route probe (wire §9, D265). */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

test("Pongs with a matching nonce and a different timestamp cannot retain readiness", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, performance: globals.performance };
  let now = 0;
  let timerId = 0;
  let disconnected = 0;
  const timers = new Map<number, { at: number; callback(): void }>();
  const sockets: Socket[] = [];
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: () => void;
    onerror?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send(bytes: Uint8Array) {
      new WebSocketFrameDecoder().feed(bytes, (stream, frame) => {
        if (frame.type === "Ping") {
          // The timestamp differs on every reply, including probes after the initial greeting.
          this.receive(encodeMuxedFrame(stream, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs + 1n }));
        }
      });
    }
    receive(bytes: Uint8Array) { this.onmessage?.({ data: bytes.slice().buffer as ArrayBuffer }); }
    close() {}
  }
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: (callback: () => void, delay: number) => { const id = ++timerId; timers.set(id, { at: now + delay, callback }); return id; }, clearTimeout: (id: number) => timers.delete(id) };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    globals.performance = { now: () => now };
    connection = new MuxConnection();
    connection.openStream({ onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() { disconnected++; }, hasSession: () => true, onStatus() {} });
    sockets[0]!.onopen?.();
    sockets[0]!.receive(encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 }));
    connection.streamAttached(true, 1);
    // Advance a deterministic clock past the unsampled route's grace. This is
    // a correlation oracle, not a wall-clock latency measurement.
    const until = 1100;
    for (;;) {
      const next = [...timers].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      now = next[1].at;
      timers.delete(next[0]);
      next[1].callback();
    }
    now = until;
    expect(disconnected).toBe(1);
    expect(connection.isWelcomed).toBe(false);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
