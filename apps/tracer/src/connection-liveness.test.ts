/** Deterministic half-open route regressions: no close event, focus change or user input may be needed [D265, #199]. */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

test("a retained unresponsive route loses readiness, resumes automatically and ignores its late events", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, performance: globals.performance };
  let now = 0;
  let timerId = 0;
  const timers = new Map<number, { at: number; callback(): void }>();
  const sockets: Socket[] = [];
  let forwarding = true;
  let disconnected = 0;
  let welcomes = 0;
  const statuses: string[] = [];
  const resumed: boolean[] = [];
  let latestProbe = 0n;
  let latestStamp = 0n;
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
      new WebSocketFrameDecoder().feed(bytes, (_stream, frame) => {
        if (frame.type === "Ping") { latestProbe = frame.nonce; latestStamp = frame.sentUs; }
        if (forwarding && frame.type === "Ping") this.receive(encodeMuxedFrame(0, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs }));
      });
    }
    receive(bytes: Uint8Array) { this.onmessage?.({ data: bytes.slice().buffer as ArrayBuffer }); }
    // The intermediary retains the route even when the browser asks to close.
    close() {}
  }
  const handler: StreamHandler = {
    onSocketOpen: (value) => resumed.push(value), onWelcome: () => { welcomes++; }, onFrame() {},
    onDisconnected: () => { disconnected++; }, hasSession: () => true, onStatus: (message) => statuses.push(message),
  };
  const advance = (ms: number) => {
    const until = now + ms;
    for (;;) {
      const next = [...timers].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      now = next[1].at;
      timers.delete(next[0]);
      next[1].callback();
    }
    now = until;
  };
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: (callback: () => void, delay: number) => { const id = ++timerId; timers.set(id, { at: now + delay, callback }); return id; }, clearTimeout: (id: number) => timers.delete(id) };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    globals.performance = { now: () => now };
    connection = new MuxConnection();
    connection.openStream(handler);
    sockets[0]!.onopen?.();
    const welcome = encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    sockets[0]!.receive(welcome);
    connection.streamAttached(true, 1);
    // Attachment/typing may sample between timer ticks; the next scheduled probe must still be sent.
    advance(2);
    connection.sampleRoundTrip();
    advance(100);
    expect(connection.isWelcomed).toBe(true);
    forwarding = false;
    // An idle route is proved on demand, not on a timer [#317]: the next activity probe goes unanswered.
    connection.sampleRoundTrip();
    advance(526);
    expect(disconnected).toBe(1);
    expect(connection.isWelcomed).toBe(false);
    expect(statuses).toContain("The connection did not respond in time.");
    advance(10);
    expect(sockets).toHaveLength(2);
    sockets[1]!.onopen?.();
    expect(resumed).toEqual([false, true]);
    sockets[1]!.receive(welcome);
    connection.streamAttached(true, 1);
    // Superseded traffic and close events cannot corrupt the replacement's decoder/readiness.
    sockets[0]!.receive(new Uint8Array([255]));
    sockets[0]!.onclose?.();
    sockets[0]!.onerror?.();
    expect(connection.isWelcomed).toBe(true);
    expect(disconnected).toBe(1);
    connection.forceDrop();
    expect(disconnected).toBe(2);
    expect(connection.isWelcomed).toBe(false);
    advance(10);
    sockets[2]!.onopen?.();
    expect(resumed).toEqual([false, true, true]);
    sockets[2]!.receive(welcome);
    connection.streamAttached(true, 1);
    connection.sampleRoundTrip();
    // A suspended renderer may deliver a queued old Pong before its overdue timer.
    // That delay is not a new network RTT or evidence of a broken route (#245).
    now += 60_000;
    const pong = encodeMuxedFrame(0, { type: "Pong", nonce: latestProbe, sentUs: latestStamp });
    sockets[2]!.receive(pong);
    expect(disconnected).toBe(2);
    expect(connection.isWelcomed).toBe(true);
    expect(welcomes).toBe(3);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
