/** Typing cuts a reconnect backoff short, once per burst (#569, D130). */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { encodeMuxedFrame } from "../../../packages/protocol/src/codec";

/** Brings a welcomed connection with one stream to a closed socket waiting out a long backoff. */
function waitingConnection(): { connection: MuxConnection; sockets: unknown[]; timers: Map<number, number>; restore: () => void; now: { value: number } } {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, random: Math.random, now: performance.now };
  const sockets: Socket[] = [];
  const timers = new Map<number, number>();
  let nextTimer = 1;
  const now = { value: 10_000 };
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
  const handler: StreamHandler = {
    onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {},
  };
  Math.random = () => 0;
  performance.now = () => now.value;
  globals.window = {
    setTimeout: (_callback: () => void, delay: number) => { const id = nextTimer++; timers.set(id, delay); return id; },
    clearTimeout: (id: number) => { timers.delete(id); },
  };
  globals.location = { protocol: "https:", host: "input-retry.example.test" };
  globals.WebSocket = Socket;
  const connection = new MuxConnection();
  connection.openStream(handler);
  const welcome = encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 }).slice().buffer as ArrayBuffer;
  sockets[0]!.onopen?.();
  sockets[0]!.onmessage?.({ data: welcome });
  connection.streamAttached(true, 1);
  return {
    connection, sockets, timers, now,
    restore: () => {
      connection.dispose();
      Math.random = original.random;
      performance.now = original.now;
      for (const key of ["window", "location", "WebSocket"] as const) {
        if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
      }
    },
  };
}

/** Fails the socket `times` in a row without a welcome, so the backoff grows past one second. */
function failRepeatedly(rig: ReturnType<typeof waitingConnection>, times: number): void {
  (rig.sockets[0] as { close(): void }).close();
  for (let i = 1; i <= times; i += 1) {
    rig.timers.clear();
    // Run the pending retry by hand: the stub timer never fires on its own.
    (rig.connection as unknown as { retryTimer: number }).retryTimer = 0;
    (rig.connection as unknown as { connect(): void }).connect();
    (rig.sockets[i] as { close(): void }).close();
  }
}

test("a key during a long backoff retries at once, and keys in the same burst do not retry again", () => {
  const rig = waitingConnection();
  try {
    failRepeatedly(rig, 5);
    const waiting = [...rig.timers.values()].at(-1)!;
    expect(waiting).toBeGreaterThan(1000);
    const opened = rig.sockets.length;
    rig.connection.retryForInput();
    expect(rig.sockets.length).toBe(opened + 1);
    // The new attempt fails too and backs off again; more keys in the same burst leave it alone.
    (rig.sockets[opened] as { close(): void }).close();
    const again = rig.sockets.length;
    rig.now.value += 200;
    rig.connection.retryForInput();
    rig.now.value += 200;
    rig.connection.retryForInput();
    expect(rig.sockets.length).toBe(again);
    // A new burst after a quiet second may cut the next wait short once more.
    rig.now.value += 1500;
    rig.connection.retryForInput();
    expect(rig.sockets.length).toBe(again + 1);
  } finally {
    rig.restore();
  }
});

test("input does nothing while the socket is up or no retry is waiting", () => {
  const rig = waitingConnection();
  try {
    const opened = rig.sockets.length;
    rig.connection.retryForInput();
    expect(rig.sockets.length).toBe(opened);
  } finally {
    rig.restore();
  }
});

test("a refused client is not retried by typing", () => {
  const rig = waitingConnection();
  try {
    failRepeatedly(rig, 2);
    (rig.connection as unknown as { refusalBackoff: boolean }).refusalBackoff = true;
    const opened = rig.sockets.length;
    rig.now.value += 5000;
    rig.connection.retryForInput();
    expect(rig.sockets.length).toBe(opened);
  } finally {
    rig.restore();
  }
});
