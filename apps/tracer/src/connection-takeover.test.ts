/**
 * A tab whose connection a newer tab took over pauses while hidden and resumes when shown (#523, owner decision B).
 *
 * If a hidden, taken-over tab reconnected by itself, the server would give it the place of the next hidden tab, which
 * would then do the same: the account's hidden tabs would take each other's connections in a loop.
 */
import { expect, test } from "bun:test";
import { MuxConnection } from "./connection";
import { TAKEN_OVER_REASON } from "./close-reasons";
import { encodeMuxedFrame } from "../../../packages/protocol/src/codec";

test("a taken-over tab stays disconnected while hidden, then resumes its connection when shown", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const keys = ["window", "location", "WebSocket", "document"] as const;
  const original = Object.fromEntries(keys.map((key) => [key, globals[key]]));
  const listeners = new Map<string, Set<() => void>>();
  const on = (type: string, fn: () => void) => { if (!listeners.has(type)) listeners.set(type, new Set()); listeners.get(type)!.add(fn); };
  const off = (type: string, fn: () => void) => { listeners.get(type)?.delete(fn); };
  const fire = (type: string) => { for (const fn of [...(listeners.get(type) ?? [])]) fn(); };
  const page = { hidden: false, addEventListener: on, removeEventListener: off };
  const timers: (() => void)[] = [];
  const sockets: Socket[] = [];
  const attempts: boolean[] = [];
  const paused: boolean[] = [];
  /** A socket double: the test drives open, messages and close by hand. */
  class Socket {
    static OPEN = 1;
    static CLOSED = 3;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: (event: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    /** Records each socket the connection opens. */
    constructor() { sockets.push(this); }
    /** Frames the page sends are not inspected here. */
    send() {}
    /** Delivers one control frame from the "server". */
    receive(frame: Parameters<typeof encodeMuxedFrame>[1]) { this.onmessage?.({ data: encodeMuxedFrame(0, frame).slice().buffer as ArrayBuffer }); }
    /** The page closed it; no close event follows, as for a socket the page already retired. */
    close() { this.readyState = 3; }
  }
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: (callback: () => void) => { timers.push(callback); return timers.length; }, clearTimeout() {}, addEventListener: on, removeEventListener: off };
    globals.location = { protocol: "https:", host: "takeover.example.test" };
    globals.WebSocket = Socket;
    globals.document = page;
    connection = new MuxConnection({ onPausedChange: (value) => paused.push(value) });
    connection.openStream({ onSocketOpen: (resume) => attempts.push(resume), onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {} });
    sockets[0]!.onopen?.();
    sockets[0]!.receive({ type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    connection.streamAttached(true, 1);

    page.hidden = true;
    fire("visibilitychange");
    const before = timers.length;
    sockets[0]!.receive({ type: "Close", code: 1000, reason: TAKEN_OVER_REASON });
    expect(paused).toEqual([true]);
    // Nothing brings a hidden, paused tab back: no timer it set, no network hint, no person's "Try again".
    for (const run of timers.slice(before)) run();
    fire("online");
    connection.connectNow();
    expect(sockets).toHaveLength(1);

    page.hidden = false;
    fire("visibilitychange");
    expect(sockets).toHaveLength(2);
    sockets[1]!.onopen?.();
    expect(attempts).toEqual([false, true]);
    sockets[1]!.receive({ type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(3), resumeWindowSeconds: 120 });
    expect(paused).toEqual([true, false]);
  } finally {
    connection?.dispose();
    for (const key of keys) { if (original[key] === undefined) delete globals[key]; else globals[key] = original[key]; }
  }
});
