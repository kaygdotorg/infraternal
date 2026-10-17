/** Checks native capture retirement across Retry and a real mux reconnect [D104,D208,D232,#146]. */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "../../connection";
import { decodeMuxedFrame, encodeMuxedFrame, type WireFrame } from "../../../../../packages/protocol/src/codec";
import { AppStream } from "./stream";

const settled = (): Promise<void> => new Promise(resolve => setImmediate(resolve));

for (const keepTerminal of [true, false]) test(`retry retains Stop across repeated disconnects ${keepTerminal ? "with a terminal" : "without any terminal"} before replacing the native session`, async () => {
  const originals = new Map<string, PropertyDescriptor | undefined>();
  const sockets: Socket[] = [];
  const timers = new Map<number, () => void>();
  const starts: string[] = [];
  const stops: string[] = [];
  let stopResponsesToDrop = 6;
  let nextTimer = 0;
  class Canvas { className = ""; width = 2; height = 2; transferControlToOffscreen() { return {}; } }
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    receive(frame: WireFrame): void {
      this.onmessage?.({ data: encodeMuxedFrame(0, frame).slice().buffer as ArrayBuffer });
    }
    send(bytes: Uint8Array): void {
      const { frame } = decodeMuxedFrame(bytes);
      if (frame.type !== "Call") return;
      const input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as Record<string, unknown>;
      let reply: Record<string, unknown> = {};
      if (frame.actionId === "desktop.session.start") {
        const id = `00000000-0000-0000-0000-${(starts.length + 1).toString().padStart(12, "0")}`;
        starts.push(id); reply = { session_id: id };
      } else if (frame.actionId === "desktop.session.stop") {
        stops.push(String(input.session_id));
        if (stopResponsesToDrop > 0) {
          stopResponsesToDrop--;
          queueMicrotask(() => this.close());
          return;
        }
      }
      queueMicrotask(() => this.receive({ type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify(reply)) }));
    }
    close(): void { this.readyState = 3; this.onclose?.(); }
    welcome(): void {
      this.onopen?.();
      this.receive({ type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    }
  }
  const worker = { postMessage() {}, terminate() {}, onerror: null as ((event: Event) => void) | null };
  const globals = {
    window: { setTimeout(callback: () => void) { const id = ++nextTimer; timers.set(id, callback); return id; }, clearTimeout(id: number) { timers.delete(id); } },
    location: { protocol: "https:", host: "retry.example.test" }, WebSocket: Socket,
    document: { createElement: () => new Canvas() }, HTMLCanvasElement: Canvas,
    OffscreenCanvas: class {}, VideoDecoder: class {}, EncodedVideoChunk: class {}, Worker: class {},
  };
  let connection: MuxConnection | undefined;
  let stream: AppStream | undefined;
  try {
    for (const [key, value] of Object.entries(globals)) {
      originals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
      Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
    }
    connection = new MuxConnection();
    // The canvas can contain only app windows. A Welcome waiter must also
    // establish transport before Start, which precedes viewer registration.
    const seed: StreamHandler = { onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => false, onStatus() {} };
    if (keepTerminal) { connection.openStream(seed); sockets[0]!.welcome(); }
    stream = new AppStream({ connection, hostId: "host", target: { type: "screen", displayId: 1 }, coarse: false,
      events: { state() {}, control() {}, picture() {}, surface() {}, shape() {} }, makeWorker: () => worker as unknown as Worker });
    const css = { width: 800, height: 600, density: 1 };
    const opening = stream.open(css);
    if (!keepTerminal) { expect(sockets).toHaveLength(1); sockets[0]!.welcome(); }
    await opening; stream.setVisible(true); await settled();
    sockets[0]!.close();
    worker.onerror?.(new Event("error"));
    expect(stream.current.kind).toBe("failed");
    stream.retry(css); await settled();
    // Only the reconnect timer remains after detach clears this viewer's timers.
    expect(timers.size).toBe(1);
    for (let attempt = 0; attempt < 6; attempt++) {
      expect(starts).toHaveLength(1);
      const [timerId, reconnect] = [...timers.entries()][0]!;
      timers.delete(timerId); reconnect(); sockets[attempt + 1]!.welcome(); await settled();
      expect(stops).toHaveLength(attempt + 1);
      expect(starts).toHaveLength(1);
    }
    expect(timers.size).toBe(1);
    const [timerId, reconnect] = [...timers.entries()][0]!;
    timers.delete(timerId); reconnect(); sockets[7]!.welcome(); await settled();
    expect(starts).toHaveLength(2);
    expect(stops).toEqual(Array(7).fill(starts[0]!));
    stream.dispose(); await settled();
    expect(stops).toContain(starts[0]!);
    expect(stops).toContain(starts[1]!);
  } finally {
    stream?.dispose(); connection?.dispose();
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  }
});
