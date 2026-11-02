/** Keeps the layout-session request separate from the desktop-video capability on browser Hello frames. */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

function helloCaps(desktop: boolean): bigint {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket };
  let socket: Socket | undefined;
  let hello: WireFrame | undefined;
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { socket = this; }
    send(bytes: Uint8Array) {
      new WebSocketFrameDecoder().feed(bytes, (stream, frame) => {
        if (stream === 0 && frame.type === "Hello") hello = frame;
      });
    }
    close() { this.readyState = 3; }
  }

  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: () => 1, clearTimeout() {}, addEventListener() {}, removeEventListener() {} };
    globals.location = { protocol: "https:", host: "capability.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection({ desktop: () => desktop });
    const handler: StreamHandler = { onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => false, onStatus() {} };
    connection.openStream(handler);
    socket!.onopen?.();
    if (hello?.type !== "Hello") throw new Error("client did not send Hello");
    return hello.caps;
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete globals[key];
      else globals[key] = value;
    }
  }
}

test("layout and desktop features use separate browser Hello capability bits", () => {
  const ordinary = helloCaps(false);
  const desktop = helloCaps(true);
  expect(ordinary & 16n).toBe(0n);
  expect(desktop & 16n).toBe(16n);
  expect(ordinary & 32n).toBe(32n);
  expect(desktop & 32n).toBe(32n);
});
