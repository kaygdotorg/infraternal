/** Independent #199 review: local scheduling delay cannot prove peer loss when every issued probe was answered (D265, wire §9). */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

for (const attached of [false, true]) test(`a fully answered browser route survives a delayed next probe ${attached ? "with an attachment" : "before a terminal attaches"}`, () => {
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
    connection.openStream({ onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() { disconnected++; }, hasSession: () => attached, onStatus() {} });
    sockets[0]!.onopen?.();
    sockets[0]!.receive(encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 }));
    if (attached) connection.streamAttached(true, 1);
    connection.sampleRoundTrip();
    // The Welcome sample and this one are both answered at once.
    expect(probes).toBe(2);
    expect(connection.isWelcomed).toBe(true);

    // A fully answered route owns no liveness timer at all [#317], so a delayed
    // browser task has nothing to misread as peer loss. The clock then jumps,
    // as after a long renderer stall, and the next probe is still answered.
    // A deterministic scheduling oracle, never a host latency measurement.
    expect(timers.size).toBe(0);
    now = 1000;
    connection.sampleRoundTrip();
    expect(disconnected).toBe(0);
    expect(connection.isWelcomed).toBe(true);
    expect(probes).toBe(3);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
