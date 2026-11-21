/**
 * A Welcome that answers a Resume tells the page whether the server really resumed (#569, D265).
 *
 * When a resume has expired the server no longer closes the socket: it welcomes the same socket as a fresh
 * connection, with a new connection id. The page must then start every terminal's writer over (its input sequence
 * begins at zero on the server), while a Welcome that keeps the id it asked for is a real resume. These tests drive
 * the connection with a socket double and record what each terminal stream was told.
 */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";

/** The connection id of the first Welcome; a resume asks for it again. */
const FIRST_ID = new Uint8Array(16).fill(1);

/**
 * Runs one welcomed connection that drops, then a reconnect whose Welcome carries `secondId`. Returns, in order,
 * whether each socket open asked to resume and what each Welcome told the stream (`true` means resumed).
 */
function reconnectWelcomedWith(secondId: Uint8Array): { resumeAsked: boolean[]; welcomes: boolean[]; resumeFramesSent: number } {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, random: Math.random };
  let retry: (() => void) | undefined;
  const sockets: Socket[] = [];
  const resumeAsked: boolean[] = [];
  const welcomes: boolean[] = [];
  let resumeFramesSent = 0;
  /** A socket double: the test drives open, messages and close by hand. */
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: (event: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    /** Records each socket the connection opens. */
    constructor() { sockets.push(this); }
    /** Counts the Resume frames the page sends; nothing else is inspected. */
    send(bytes: Uint8Array) {
      new WebSocketFrameDecoder().feed(bytes, (_stream, frame) => { if (frame.type === "Resume") resumeFramesSent++; });
    }
    /** Delivers one control frame from the "server". */
    receive(frame: Parameters<typeof encodeMuxedFrame>[1]) { this.onmessage?.({ data: encodeMuxedFrame(0, frame).slice().buffer as ArrayBuffer }); }
    /** The page closed it; no close event follows, as for a socket the page already retired. */
    close() { this.readyState = 3; }
  }
  let connection: MuxConnection | undefined;
  try {
    Math.random = () => 0;
    globals.window = { setTimeout: (callback: () => void) => { retry = callback; return 1; }, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "fresh.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    connection.openStream({ onSocketOpen: (resume) => resumeAsked.push(resume), onWelcome: (resumed) => welcomes.push(resumed), onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {} });
    sockets[0]!.onopen?.();
    sockets[0]!.receive({ type: "Welcome", connectionId: FIRST_ID, resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    connection.streamAttached(true, 1);
    connection.forceDrop();
    retry?.();
    sockets[1]!.onopen?.();
    sockets[1]!.receive({ type: "Welcome", connectionId: secondId, resumeToken: new Uint8Array(32).fill(3), resumeWindowSeconds: 120 });
    return { resumeAsked, welcomes, resumeFramesSent };
  } finally {
    connection?.dispose();
    Math.random = original.random;
    for (const key of ["window", "location", "WebSocket"] as const) { if (original[key] === undefined) delete globals[key]; else globals[key] = original[key]; }
  }
}

test("a Welcome that keeps the asked connection id is a resume", () => {
  const seen = reconnectWelcomedWith(FIRST_ID);
  expect(seen.resumeAsked).toEqual([false, true]);
  expect(seen.resumeFramesSent).toBe(1);
  expect(seen.welcomes).toEqual([false, true]);
});

test("a Welcome with a new connection id after a Resume is a fresh connection on the same socket", () => {
  const seen = reconnectWelcomedWith(new Uint8Array(16).fill(9));
  expect(seen.resumeAsked).toEqual([false, true]);
  expect(seen.resumeFramesSent).toBe(1);
  expect(seen.welcomes).toEqual([false, false]);
});
