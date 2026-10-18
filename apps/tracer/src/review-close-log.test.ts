/** Break-it review of #227: every socket close the server initiates must reach the console line, and summaries must name the real span. */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { CloseNotes } from "./close-reasons";
import { encodeMuxedFrame } from "../../../packages/protocol/src/codec";

test("a reconnect the server refuses with a named Close frame still prints its console line", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, warn: console.warn };
  const sockets: Socket[] = [];
  class Socket {
    static OPEN = 1;
    static CLOSED = 3;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: (event: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send() {}
    // The browser fires close asynchronously with the server's native close (here 1000, no reason).
    close() { this.readyState = 3; this.onclose?.({ code: 1005, reason: "" }); }
  }
  const warnings: string[] = [];
  const handler: StreamHandler = {
    onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {},
  };
  let connection: MuxConnection | undefined;
  try {
    console.warn = (line: string) => { warnings.push(line); };
    globals.window = { setTimeout: () => 1, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "review.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    connection.openStream(handler);
    sockets[0]!.onopen?.();
    // The server now sends this before its native close when a handshake (resume) is refused (#227).
    const refused = encodeMuxedFrame(0, { type: "Close", code: 1008, reason: "the server refused to resume the connection" });
    sockets[0]!.onmessage?.({ data: refused.slice().buffer as ArrayBuffer });
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain("reconnect failed");
  } finally {
    connection?.dispose();
    console.warn = original.warn;
    for (const key of ["window", "location", "WebSocket"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});

test("a close summary does not claim closes from hours ago happened in the previous 60 s", () => {
  const notes = new CloseNotes();
  expect(notes.note(0, 1006, "", 0, true)).toBeDefined();
  expect(notes.note(1_000, 1006, "", 1, false)).toBeUndefined();
  const later = notes.note(10 * 3_600_000, 1006, "", 0, true)!;
  expect(later).not.toContain("in the previous 60 s");
});
