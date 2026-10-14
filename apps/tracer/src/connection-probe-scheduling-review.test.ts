/** Independent #199 review: local scheduling delay cannot prove peer loss when every issued probe was answered (D265, wire §9). */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

test("a fully answered browser route survives a delayed next probe", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, performance: globals.performance };
  let now = 0;
  let timerId = 0;
  let disconnected = 0;
  let probes = 0;
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
          probes++;
          this.receive(encodeMuxedFrame(stream, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs }));
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
    connection.sampleRoundTrip();
    expect(probes).toBe(1);
    expect(connection.isWelcomed).toBe(true);

    // No outstanding reply exists. Advance the clock without executing timers,
    // then deliver the delayed timer as a browser event loop would. This is a
    // deterministic scheduling oracle, never a host latency measurement.
    now = 100;
    const next = [...timers].sort((a, b) => a[1].at - b[1].at)[0]!;
    timers.delete(next[0]);
    next[1].callback();
    expect(disconnected).toBe(0);
    expect(connection.isWelcomed).toBe(true);
    expect(probes).toBe(2);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
