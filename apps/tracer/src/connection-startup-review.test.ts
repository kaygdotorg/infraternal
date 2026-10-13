/** Independent #199 review: a healthy route must learn an unknown RTT before applying its sampled deadline (wire §9). */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

test("a healthy startup route can learn an RTT above the initial estimate", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, performance: globals.performance };
  let now = 0;
  let timerId = 0;
  let disconnected = 0;
  const timers = new Map<number, { at: number; callback(): void }>();
  const schedule = (callback: () => void, delay: number) => { const id = ++timerId; timers.set(id, { at: now + delay, callback }); return id; };
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
          const reply = encodeMuxedFrame(stream, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs });
          // Every probe is answered correctly. Delay is a simulated link property,
          // never a measured host latency or a suspended renderer's queued reply.
          schedule(() => this.receive(reply), 1200);
        }
      });
    }
    receive(bytes: Uint8Array) { this.onmessage?.({ data: bytes.slice().buffer as ArrayBuffer }); }
    close() {}
  }
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: schedule, clearTimeout: (id: number) => timers.delete(id) };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    globals.performance = { now: () => now };
    connection = new MuxConnection();
    connection.openStream({ onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() { disconnected++; }, hasSession: () => false, onStatus() {} });
    sockets[0]!.onopen?.();
    sockets[0]!.receive(encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 }));
    const until = 1300;
    for (;;) {
      const next = [...timers].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      now = next[1].at;
      timers.delete(next[0]);
      next[1].callback();
    }
    now = until;
    expect(disconnected).toBe(0);
    expect(connection.isWelcomed).toBe(true);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
