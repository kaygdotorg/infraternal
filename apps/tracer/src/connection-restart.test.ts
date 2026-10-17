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

test("a failed first recovery handshake exits the one quick retry", () => {
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
    onerror?: () => void;
    onclose?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send() {}
    close() { this.readyState = 3; this.onclose?.(); }
  }
  const welcome = (): ArrayBuffer => encodeMuxedFrame(0, {
    type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120,
  }).slice().buffer as ArrayBuffer;
  const handler: StreamHandler = {
    onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {},
  };
  let connection: MuxConnection | undefined;
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
    sockets[1]!.onerror?.();
    expect(retryDelay).toBeGreaterThanOrEqual(50);

    retry?.();
    sockets[2]!.onerror?.();
    expect(retryDelay).toBeGreaterThanOrEqual(100);
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

test("a prolonged outage inside the fast-recovery window does not leave recovery behind accumulated backoff", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, navigator: globals.navigator, performance: globals.performance, random: Math.random };
  let now = 0;
  let nextTimerId = 1;
  const failedPathRetryDelays: number[] = [];
  const timers = new Map<number, { at: number; callback: () => void }>();
  const sockets: Socket[] = [];
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onerror?: () => void;
    onclose?: (event?: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send() {}
    close() { this.readyState = 3; this.onclose?.({ code: 1006, reason: "" }); }
  }
  const welcome = (): ArrayBuffer => encodeMuxedFrame(0, {
    type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120,
  }).slice().buffer as ArrayBuffer;
  let recoveredAt: number | undefined;
  let connection: MuxConnection | undefined;
  try {
    Math.random = () => 0;
    globals.performance = { now: () => now };
    globals.window = {
      setTimeout: (callback: () => void, delay: number) => {
        const id = nextTimerId++;
        timers.set(id, { at: now + delay, callback });
        return id;
      },
      clearTimeout: (id: number) => { timers.delete(id); },
    };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    globals.navigator = { onLine: false };
    const handler: StreamHandler = {
      onSocketOpen() {}, onWelcome: (resumed) => { if (resumed) recoveredAt = now; }, onFrame() {}, onDisconnected() {},
      hasSession: () => true, onStatus() {},
    };
    connection = new MuxConnection();
    const stream = connection.openStream(handler);
    sockets[0]!.onopen?.();
    sockets[0]!.onmessage?.({ data: welcome() });
    connection.streamAttached(true, stream);
    sockets[0]!.onclose?.({ code: 1006, reason: "" });

    // Keep the base implementation inside its ten-second fast-recovery window,
    // while earlier sockets fail before Welcome. The real browser comparison
    // separately covers an exact ten-second cut.
    const outageEndsAt = 9_500;
    while (true) {
      const [id, timer] = [...timers.entries()].sort((left, right) => left[1].at - right[1].at)[0] ?? [];
      if (id === undefined || !timer || timer.at >= outageEndsAt) break;
      timers.delete(id);
      now = timer.at;
      timer.callback();
      const failedAt = now;
      sockets.at(-1)?.onerror?.();
      const nextRetry = [...timers.values()].sort((left, right) => left.at - right.at)[0];
      if (nextRetry) failedPathRetryDelays.push(nextRetry.at - failedAt);
    }

    expect(failedPathRetryDelays.length).toBeGreaterThan(3);
    expect(Math.max(...failedPathRetryDelays)).toBeLessThanOrEqual(10);
    now = outageEndsAt;
    const [id, timer] = [...timers.entries()].sort((left, right) => left[1].at - right[1].at)[0] ?? [];
    if (id !== undefined && timer) {
      now = timer.at;
      timers.delete(id);
      timer.callback();
      sockets.at(-1)?.onopen?.();
      sockets.at(-1)?.onmessage?.({ data: welcome() });
    }

    expect(recoveredAt).toBeDefined();
    // A local path has negligible round-trip time; D265 allows the fixed 50 ms reconnect overhead.
    expect(recoveredAt! - outageEndsAt).toBeLessThanOrEqual(50);
  } finally {
    connection?.dispose();
    Math.random = original.random;
    for (const key of ["window", "location", "WebSocket", "navigator"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
    if (original.performance === undefined) delete globals.performance; else globals.performance = original.performance;
  }
});

test("online and foreground events cancel delays and preserve handshakes in progress", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, document: globals.document, random: Math.random };
  let nextTimerId = 1;
  const timers = new Map<number, { callback: () => void; delay: number }>();
  const windowListeners = new Map<string, Set<() => void>>();
  const documentListeners = new Map<string, Set<() => void>>();
  const add = (listeners: Map<string, Set<() => void>>, type: string, callback: () => void): void => {
    const handlers = listeners.get(type) ?? new Set<() => void>();
    handlers.add(callback);
    listeners.set(type, handlers);
  };
  const remove = (listeners: Map<string, Set<() => void>>, type: string, callback: () => void): void => { listeners.get(type)?.delete(callback); };
  const fire = (listeners: Map<string, Set<() => void>>, type: string): void => {
    for (const callback of [...(listeners.get(type) ?? [])]) callback();
  };
  const sockets: Socket[] = [];
  class Socket {
    static OPEN = 1;
    static CONNECTING = 0;
    readyState = 0;
    binaryType = "";
    onopen?: () => void;
    onclose?: (event?: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send() {}
    close() { this.readyState = 3; this.onclose?.({ code: 1006, reason: "" }); }
  }
  const welcome = (): ArrayBuffer => encodeMuxedFrame(0, {
    type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120,
  }).slice().buffer as ArrayBuffer;
  let connection: MuxConnection | undefined;
  try {
    Math.random = () => 0;
    globals.window = {
      setTimeout: (callback: () => void, delay: number) => {
        const id = nextTimerId++;
        timers.set(id, { callback, delay });
        return id;
      },
      clearTimeout: (id: number) => { timers.delete(id); },
      addEventListener: (type: string, callback: () => void) => add(windowListeners, type, callback),
      removeEventListener: (type: string, callback: () => void) => remove(windowListeners, type, callback),
    };
    globals.document = {
      visibilityState: "hidden",
      addEventListener: (type: string, callback: () => void) => add(documentListeners, type, callback),
      removeEventListener: (type: string, callback: () => void) => remove(documentListeners, type, callback),
    };
    globals.location = { protocol: "https:", host: "restart.example.test" };
    globals.WebSocket = Socket;
    const handler: StreamHandler = {
      onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {},
    };
    connection = new MuxConnection();
    const stream = connection.openStream(handler);
    const admit = (socket: Socket): void => {
      socket.readyState = Socket.OPEN;
      socket.onopen?.();
      socket.onmessage?.({ data: welcome() });
      connection?.streamAttached(true, stream);
    };
    const runRetry = (): void => {
      const [id, timer] = [...timers.entries()][0] ?? [];
      expect(id).toBeDefined();
      expect(timer).toBeDefined();
      timers.delete(id!);
      timer!.callback();
    };

    admit(sockets[0]!);
    sockets[0]!.close();
    runRetry();
    admit(sockets[1]!);
    sockets[1]!.close();
    expect([...timers.values()][0]?.delay).toBeGreaterThanOrEqual(50);

    fire(windowListeners, "online");
    expect(sockets).toHaveLength(3);
    admit(sockets[2]!);
    sockets[2]!.close();
    expect([...timers.values()][0]?.delay).toBe(5);
    fire(documentListeners, "visibilitychange");
    expect(sockets).toHaveLength(3);
    (globals.document as { visibilityState: string }).visibilityState = "visible";
    fire(documentListeners, "visibilitychange");
    expect(sockets).toHaveLength(4);
    expect(sockets[3]!.readyState).toBe(Socket.CONNECTING);
    fire(windowListeners, "online");
    expect(sockets).toHaveLength(4);
    expect(sockets[3]!.readyState).toBe(Socket.CONNECTING);
    expect(timers.size).toBe(0);
    sockets[3]!.readyState = Socket.OPEN;
    fire(windowListeners, "online");
    expect(sockets).toHaveLength(4);
    expect(sockets[3]!.readyState).toBe(Socket.OPEN);
    admit(sockets[3]!);
    expect(connection.isWelcomed).toBe(true);
    expect([...timers.values()].map((timer) => timer.delay)).toEqual([25]);
    expect([...windowListeners.values()].every((handlers) => handlers.size === 0)).toBe(true);
    expect([...documentListeners.values()].every((handlers) => handlers.size === 0)).toBe(true);
  } finally {
    connection?.dispose();
    Math.random = original.random;
    for (const key of ["window", "location", "WebSocket", "document"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});
