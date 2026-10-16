/** Resume regressions: keep writer state after a restart, back off repeated short-lived sockets, and retain close reasons. */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { encodeMuxedFrame } from "../../../packages/protocol/src/codec";

test("an overnight connection retains its writer and pending input when the server restarts", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, now: Date.now };
  let now = 1000;
  let retry: (() => void) | undefined;
  let retryDelay = 0;
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
    globals.window = { setTimeout: (callback: () => void, delay: number) => { retry = callback; retryDelay = delay; return 1; }, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    connection.openStream(handler);
    sockets[0]!.onopen?.();
    const welcome = encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    sockets[0]!.onmessage?.({ data: welcome.slice().buffer as ArrayBuffer });
    connection.streamAttached(true, 1);
    now += 86_400_000;
    sockets[0]!.close();
    expect(retryDelay).toBeGreaterThanOrEqual(5);
    expect(retryDelay).toBeLessThan(10);
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
    const hello = encodeMuxedFrame(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "restart-refusal" });
    sockets[2]!.onmessage?.({ data: hello.slice().buffer as ArrayBuffer });
    sockets[2]!.close();
    expect(retryDelay).toBeGreaterThanOrEqual(50);
  } finally {
    connection?.dispose();
    Date.now = original.now;
    for (const key of ["window", "location", "WebSocket"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});

test("a second quick server close leaves the fast path and backs off", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, random: Math.random };
  let retry: (() => void) | undefined;
  let retryDelay = 0;
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
  const handler: StreamHandler = {
    onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {},
  };
  let connection: MuxConnection | undefined;
  const welcome = (): ArrayBuffer => encodeMuxedFrame(0, {
    type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120,
  }).slice().buffer as ArrayBuffer;
  try {
    Math.random = () => 0;
    globals.window = { setTimeout: (callback: () => void, delay: number) => { retry = callback; retryDelay = delay; return 1; }, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    connection.openStream(handler);
    sockets[0]!.onopen?.();
    sockets[0]!.onmessage?.({ data: welcome() });
    connection.streamAttached(true, 1);
    sockets[0]!.close();
    expect(retryDelay).toBe(5);

    retry?.();
    sockets[1]!.onopen?.();
    sockets[1]!.onmessage?.({ data: welcome() });
    connection.streamAttached(true, 1);
    sockets[1]!.close();
    expect(retryDelay).toBeGreaterThanOrEqual(50);
  } finally {
    connection?.dispose();
    Math.random = original.random;
    for (const key of ["window", "location", "WebSocket"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});

test("a server close reason survives socket retirement and the next retry", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket };
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
  const statuses: string[] = [];
  const handler: StreamHandler = {
    onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true,
    onStatus: (message) => statuses.push(message),
  };
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: (callback: () => void) => { retry = callback; return 1; }, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    const stream = connection.openStream(handler);
    sockets[0]!.onopen?.();
    const welcome = encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    sockets[0]!.onmessage?.({ data: welcome.slice().buffer as ArrayBuffer });
    connection.streamAttached(true, stream);
    const close = encodeMuxedFrame(0, { type: "Close", code: 1011, reason: "connection ended" });
    sockets[0]!.onmessage?.({ data: close.slice().buffer as ArrayBuffer });
    expect(statuses.at(-1)).toBe("The connection to the server ended.");
    retry?.();
    expect(statuses.at(-1)).toBe("Connection lost. Reconnecting…");
    expect(statuses).toContain("The connection to the server ended.");
  } finally {
    connection?.dispose();
    for (const key of ["window", "location", "WebSocket"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});

test("a clean server socket close keeps its fallback reason through the next retry", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket };
  let retry: (() => void) | undefined;
  const sockets: Socket[] = [];
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: (event?: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send() {}
    close() { this.readyState = 3; this.onclose?.({ code: 1005, reason: "" }); }
  }
  const statuses: string[] = [];
  const handler: StreamHandler = {
    onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true,
    onStatus: (message) => statuses.push(message),
  };
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: (callback: () => void) => { retry = callback; return 1; }, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    const stream = connection.openStream(handler);
    sockets[0]!.onopen?.();
    const welcome = encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    sockets[0]!.onmessage?.({ data: welcome.slice().buffer as ArrayBuffer });
    connection.streamAttached(true, stream);
    sockets[0]!.onclose?.({ code: 1005, reason: "" });
    expect(statuses.at(-1)).toBe("The connection to the server ended.");
    retry?.();
    expect(statuses.at(-1)).toBe("Connection lost. Reconnecting…");
    expect(statuses).toContain("The connection to the server ended.");
  } finally {
    connection?.dispose();
    for (const key of ["window", "location", "WebSocket"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});
