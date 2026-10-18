/** Break-it review round 2 of #227: a browser fires `error` before `close` when a socket fails, so that path must print too. */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { plainCloseReason } from "./close-reasons";

test("a reconnect that fails at the network (error, then close 1006) still prints its console line", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, warn: console.warn };
  const sockets: Socket[] = [];
  class Socket {
    static OPEN = 1;
    static CLOSED = 3;
    readyState = 0;
    binaryType = "";
    onopen?: () => void;
    onerror?: () => void;
    onclose?: (event: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send() {}
    close() { this.readyState = 3; }
    /** What a browser does when the connection cannot be established or drops uncleanly. */
    failAtNetwork() { this.readyState = 3; this.onerror?.(); this.onclose?.({ code: 1006, reason: "" }); }
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
    // The server is unreachable: the first socket never opens.
    sockets[0]!.failAtNetwork();
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain("reconnect failed");
    expect(warnings[0]).toContain("code 1006");
  } finally {
    connection?.dispose();
    console.warn = original.warn;
    for (const key of ["window", "location", "WebSocket"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});

test("the busy-server sentence reads like the other recovering sentences", () => {
  // Every other self-healing sentence ends in a full stop and, while recovering, "Reconnecting…".
  const busy = plainCloseReason("the server was too busy to confirm the session");
  expect(busy).not.toContain("; reconnecting.");
});
