/** Stream disposal must preserve a shared socket when a window leaves before attachment (#250). */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

test("disposing a window before its welcome microtask sends no unbound Close", async () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket };
  const frames: Array<{ stream: number; frame: WireFrame }> = [];
  let socket: Socket | undefined;
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { socket = this; }
    send(bytes: Uint8Array) { new WebSocketFrameDecoder().feed(bytes, (stream, frame) => frames.push({ stream, frame })); }
    close() {}
  }
  let connection: MuxConnection | undefined;
  const handler: StreamHandler = { onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {} };
  try {
    globals.window = { setTimeout: () => 1, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "stream.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    connection.subscribe({ topic: "canvas.layout" }, () => {});
    socket!.onopen?.();
    socket!.onmessage?.({ data: encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 }).slice().buffer as ArrayBuffer });
    const stream = connection.openStream(handler);
    connection.closeStream(stream);
    await Promise.resolve();
    expect(frames.filter((entry) => entry.stream === stream)).toEqual([]);
    const attached = connection.openStream(handler);
    connection.send(attached, { type: "AttachTerm", sessionId: new Uint8Array(16), lastOutSeq: 0n, lastInSeq: 0n });
    connection.closeStream(attached);
    expect(frames.filter((entry) => entry.stream === attached).map((entry) => entry.frame.type)).toEqual(["AttachTerm", "Close"]);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});


test("closing a desktop viewer sends Close to retire its remote lease", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket };
  const frames: Array<{ stream: number; frame: WireFrame }> = [];
  let socket: Socket | undefined;
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { socket = this; }
    send(bytes: Uint8Array) { new WebSocketFrameDecoder().feed(bytes, (stream, frame) => frames.push({ stream, frame })); }
    close() {}
  }
  let connection: MuxConnection | undefined;
  const handler: StreamHandler = { onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => false, onStatus() {} };
  try {
    globals.window = { setTimeout: () => 1, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "stream.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    connection.subscribe({ topic: "canvas.layout" }, () => {});
    socket!.onopen?.();
    socket!.onmessage?.({ data: encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 }).slice().buffer as ArrayBuffer });
    const stream = connection.openStream(handler);
    connection.send(stream, { type: "Desktop", message: { kind: "attach", sessionId: new Uint8Array(16), delivery: 0 } });
    connection.closeStream(stream);
    expect(frames.filter((entry) => entry.stream === stream).map((entry) => entry.frame.type)).toEqual(["Desktop", "Close"]);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});


/** A retained writer row does not recreate a terminal attachment on a replacement socket. */
test("review #250: disposing a previously attached window during reconnect sends no unbound Close", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket };
  const sockets: Socket[] = [];
  let retry: (() => void) | undefined;
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    frames: Array<{ stream: number; frame: WireFrame }> = [];
    onopen?: () => void;
    onclose?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send(bytes: Uint8Array) { new WebSocketFrameDecoder().feed(bytes, (stream, frame) => this.frames.push({ stream, frame })); }
    close() { this.readyState = 3; this.onclose?.(); }
  }
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: (run: () => void) => { retry = run; return 1; }, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "stream.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    const handler: StreamHandler = { onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {} };
    const stream = connection.openStream(handler);
    connection.openStream(handler);
    sockets[0]!.onopen?.();
    sockets[0]!.onmessage?.({ data: encodeMuxedFrame(0, { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 }).slice().buffer as ArrayBuffer });
    connection.send(stream, { type: "AttachTerm", sessionId: new Uint8Array(16), lastOutSeq: 0n, lastInSeq: 0n });
    expect(sockets[0]!.frames.filter((entry) => entry.stream === stream).map((entry) => entry.frame.type)).toEqual(["AttachTerm"]);
    sockets[0]!.close(); retry?.();
    expect(sockets).toHaveLength(2);
    sockets[1]!.onopen?.();
    // The server can process Hello while the resumed window has not reattached.
    // Closing it during that round trip must leave the sibling socket healthy.
    connection.closeStream(stream);
    expect(connection.streamCount).toBe(1);
    expect(sockets[1]!.frames.filter((entry) => entry.stream === stream).map((entry) => entry.frame.type)).toEqual([]);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
