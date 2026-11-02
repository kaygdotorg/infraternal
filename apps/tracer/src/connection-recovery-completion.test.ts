/** Recovery teardown reaches the account screen even when no terminal window is open (#309). */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { encodeMuxedFrame, type WireFrame } from "../../../packages/protocol/src/codec";

test("completion teardown gives the sign-out handler its notice without an open terminal", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket };
  let socket: Socket | undefined;
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: (event: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { socket = this; }
    send() {}
    close() {}
    receive(frame: WireFrame) { this.onmessage?.({ data: encodeMuxedFrame(0, frame).slice().buffer as ArrayBuffer }); }
  }
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: () => 1, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "recovery.example.test" };
    globals.WebSocket = Socket;
    const notices: string[] = [];
    connection = new MuxConnection({ onRecoveryCompleted: (message) => { notices.push(message); connection?.dispose(); } });
    connection.subscribe({ topic: "canvas.layout" }, () => {});
    socket!.onopen?.();
    socket!.receive({ type: "Hello", version: 1, caps: 4n, clientInfo: "recovery-test" });
    socket!.receive({ type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 });
    expect(connection.isWelcomed).toBe(true);
    socket!.onclose?.({ code: 1008, reason: "recovery completed" });
    expect(notices).toEqual(["Recovery completed. This device has been signed out."]);
    expect(connection.isWelcomed).toBe(false);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
