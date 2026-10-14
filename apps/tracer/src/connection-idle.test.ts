/** Deterministic idle probe counts and unchanged directional recovery bounds [D81,D265,D267,#199]. */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

function fixture(rtt: number, streams: number) {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, performance: globals.performance };
  let now = 0, timerId = 0, probes = 0, wakeups = 0, disconnects = 0;
  let forwarding = true;
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
          probes++;
          if (forwarding) schedule(() => this.receive(stream, { type: "Pong", nonce: frame.nonce, sentUs: frame.sentUs }), rtt);
        }
      });
    }
    receive(stream: number, frame: WireFrame) { this.onmessage?.({ data: encodeMuxedFrame(stream, frame).slice().buffer as ArrayBuffer }); }
    close() {}
  }
  globals.window = { setTimeout: (callback: () => void, delay: number) => schedule(() => { wakeups++; callback(); }, delay), clearTimeout: (id: number) => timers.delete(id) };
  globals.location = { protocol: "https:", host: "idle.example.test" };
  globals.WebSocket = Socket;
  globals.performance = { now: () => now };
  const connection = new MuxConnection();
  for (let i = 0; i < streams; i++) connection.openStream({ onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() { disconnects++; }, hasSession: () => true, onStatus() {} });
  sockets[0]!.onopen?.();
  sockets[0]!.receive(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 });
  connection.streamAttached(true, 1);
  return {
    connection,
    get probes() { return probes; }, get wakeups() { return wakeups; }, get disconnects() { return disconnects; },
    receive(stream: number, frame: WireFrame) { sockets[0]!.receive(stream, frame); },
    stopForwarding() { forwarding = false; },
    setRoundTrip(ms: number) { rtt = ms; },
    suspend(ms: number) { now += ms; },
    advance(ms: number) {
      const until = now + ms;
      for (;;) {
        const next = [...timers].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        now = Math.max(now, next[1].at); timers.delete(next[0]); next[1].callback();
      }
      now = until;
    },
    dispose() {
      connection.dispose();
      for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
    },
  };
}

for (const rtt of [1, 150]) for (const streams of [1, 28]) test(`healthy idle probes back off independently of ${streams} streams at RTT ${rtt}`, () => {
  const f = fixture(rtt, streams);
  try {
    f.advance(1000);
    const probes = f.probes, wakeups = f.wakeups;
    f.advance(1000);
    expect(f.disconnects).toBe(0);
    const maximum = Math.ceil(1000 / Math.max(25, rtt + 10));
    expect(f.probes - probes).toBeLessThanOrEqual(maximum);
    expect(f.wakeups - wakeups).toBeLessThanOrEqual(maximum + 1);
    // Missing both directions must still retire the socket within RTT + 50ms.
    f.stopForwarding();
    // Drain replies already in flight before starting the silence oracle.
    f.advance(rtt);
    f.advance(rtt + 50);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("unacknowledged input keeps probes fast until the matching stream acknowledges it", () => {
  const f = fixture(30, 2);
  try {
    f.advance(1000);
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes: new Uint8Array([1]) });
    f.advance(1000);
    const fast = f.probes;
    f.advance(1000);
    expect(f.probes - fast).toBeGreaterThanOrEqual(39);
    f.receive(3, { type: "Ack", inSeqAcked: 1n });
    const sibling = f.probes;
    f.advance(1000);
    expect(f.probes - sibling).toBeGreaterThanOrEqual(39);
    f.receive(1, { type: "Ack", inSeqAcked: 1n });
    f.advance(1000);
    const idle = f.probes;
    f.advance(1000);
    expect(f.probes - idle).toBeLessThanOrEqual(25);
    expect(f.disconnects).toBe(0);
  } finally { f.dispose(); }
});

for (const rtt of [1, 30, 150]) for (const phase of [0, 7, 20, 39]) test(`idle silence deadline survives probe phase ${phase} at RTT ${rtt}`, () => {
  const f = fixture(rtt, 1);
  try {
    f.advance(1000 + phase);
    f.stopForwarding();
    f.advance(rtt); // Allow only the already issued exact replies to drain.
    f.advance(rtt + 50);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});

test("retransmitting an earlier input range cannot forget a later unacknowledged byte", () => {
  const f = fixture(30, 1);
  try {
    f.advance(1000);
    const bytes = new Uint8Array([1]);
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes });
    f.connection.send(1, { type: "Input", inSeq: 1n, bytes });
    f.connection.send(1, { type: "Input", inSeq: 0n, bytes });
    f.receive(1, { type: "Ack", inSeqAcked: 1n });
    f.advance(1000);
    const probes = f.probes;
    f.advance(1000);
    expect(f.probes - probes).toBeGreaterThanOrEqual(39);
  } finally { f.dispose(); }
});

test("a delayed first timer starts unknown-RTT grace when its first probe is issued", () => {
  const f = fixture(1200, 1);
  try {
    f.suspend(1999);
    f.advance(1600);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
  } finally { f.dispose(); }
});

for (const streams of [1, 28]) test(`a healthy idle route tolerates a 20ms RTT step at ${streams} streams without consuming its scheduling allowance before probing`, () => {
  const f = fixture(1, streams);
  try {
    f.advance(1000);
    f.setRoundTrip(20);
    f.advance(120);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
  } finally { f.dispose(); }
});

for (const streams of [1, 28]) test(`a late timer on a fully answered route preserves its reply allowance across ${streams} streams`, () => {
  const f = fixture(1, streams);
  try {
    f.advance(1001);
    f.setRoundTrip(20);
    // No outstanding probe exists. The next local callback arrives 11ms late,
    // before the former answer's silence budget ends; the peer still needs time
    // to answer the request that has only just been issued.
    f.suspend(35);
    f.advance(21);
    expect(f.disconnects).toBe(0);
    expect(f.connection.isWelcomed).toBe(true);
    f.stopForwarding();
    f.advance(20);
    f.advance(70);
    expect(f.connection.isWelcomed).toBe(false);
  } finally { f.dispose(); }
});
