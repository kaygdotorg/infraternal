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
