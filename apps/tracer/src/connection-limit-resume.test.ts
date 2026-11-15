/**
 * A resume refused only for the account's connection limit stays usable (#523, J790 review of J761).
 *
 * The server checks the account's limit at the upgrade, before it reads the page's Resume, so a refusal for the limit
 * says nothing about the resume capability: it is still valid for its window. The page used to forget it on any 1008
 * refusal, so the connect that finally succeeded was a fresh one and every terminal lost its writer.
 */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { CONNECTION_LIMIT_REASON } from "./close-reasons";
import { encodeMuxedFrame } from "../../../packages/protocol/src/codec";

/** Runs one welcomed connection that drops, then a resume attempt the server closes with `reason`; returns what each socket asked for. */
function resumeAfterRefusal(reason: string): boolean[] {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, random: Math.random };
  let retry: (() => void) | undefined;
  const sockets: Socket[] = [];
  const attempts: boolean[] = [];
  /** A socket double: the test drives open, messages and close by hand. */
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: (event: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send() {}
    receive(frame: Parameters<typeof encodeMuxedFrame>[1]) { this.onmessage?.({ data: encodeMuxedFrame(0, frame).slice().buffer as ArrayBuffer }); }
    close() { this.readyState = 3; }
  }
  let connection: MuxConnection | undefined;
  try {
    Math.random = () => 0;
    globals.window = { setTimeout: (callback: () => void) => { retry = callback; return 1; }, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "limit.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    connection.openStream({ onSocketOpen: (resume) => attempts.push(resume), onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {} });
    sockets[0]!.onopen?.();
    sockets[0]!.receive({ type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    connection.streamAttached(true, 1);
    connection.forceDrop();
    retry?.();
    sockets[1]!.onopen?.();
    sockets[1]!.receive({ type: "Close", code: 1008, reason });
    retry?.();
    sockets[2]!.onopen?.();
    return attempts;
  } finally {
    connection?.dispose();
    Math.random = original.random;
    for (const key of ["window", "location", "WebSocket"] as const) { if (original[key] === undefined) delete globals[key]; else globals[key] = original[key]; }
  }
}

test("a resume refused for the account's connection limit is tried again on the next connect", () => {
  expect(resumeAfterRefusal(CONNECTION_LIMIT_REASON)).toEqual([false, true, true]);
});

test("a resume the server really refused is still forgotten", () => {
  expect(resumeAfterRefusal("the server refused to resume the connection")).toEqual([false, true, false]);
});
