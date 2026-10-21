/** Shared-view removal during reconnect must preserve sibling streams and a surviving camera anchor (#24, #243, #250). */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { ServerCanvasStore } from "./canvas/model/server-store";
import type { Ctx, ViewRec } from "./canvas/context";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

test("a reconnect snapshot removing the current view sends no unbound Close and moves its camera", async () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, matchMedia: globals.matchMedia };
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
    // Byte fields borrow the connection's reusable send buffer; retain an owned copy.
    send(bytes: Uint8Array) { new WebSocketFrameDecoder().feed(bytes, (stream, frame) => this.frames.push({ stream, frame: structuredClone(frame) })); }
    receive(frame: WireFrame) { this.onmessage?.({ data: encodeMuxedFrame(0, frame).slice().buffer as ArrayBuffer }); }
    close() { this.readyState = 3; this.onclose?.(); }
  }
  let connection: MuxConnection | undefined, store: ServerCanvasStore | undefined;
  try {
    globals.window = { setTimeout: (run: () => void) => { retry = run; return 1; }, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "layout.example.test" };
    globals.WebSocket = Socket;
    globals.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    const { reconcile } = await import("./canvas/model/reconcile");
    connection = new MuxConnection();
    const failures: string[] = [], fail = connection.fail.bind(connection);
    connection.fail = (reason) => { failures.push(reason); fail(reason); };
    store = new ServerCanvasStore(connection, "reconnect-view-removal");
    const welcome: WireFrame = { type: "Welcome", connectionId: new Uint8Array(16), resumeToken: new Uint8Array(32), resumeWindowSeconds: 120 };
    const snapshot = (socket: Socket, revision: number, views: unknown[]): void => {
      const subscription = socket.frames.find(({ frame }) => frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "canvas.layout")!.frame;
      if (subscription.type !== "Subscribe") throw Error("missing layout subscription");
      socket.receive({ type: "Event", subId: subscription.subId, eventJson: new TextEncoder().encode(JSON.stringify({
        type: "canvas.layout.snapshot", revision, initialized: true,
        document: { format: "infraternal.canvas", version: 1, revision, views },
      })) });
    };
    sockets[0]!.onopen?.(); sockets[0]!.receive(welcome);
    snapshot(sockets[0]!, 1, [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }]);
    expect(failures).toEqual([]);
    const handler: StreamHandler = { onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => true, onStatus() {} };
    const removed = connection.openStream(handler), sibling = connection.openStream(handler);
    connection.send(removed, { type: "AttachTerm", sessionId: new Uint8Array(16), lastOutSeq: 0n, lastInSeq: 0n });
    const views = new Map<string, ViewRec>([
      ["console", { view: { id: "console" } } as unknown as ViewRec],
      ["settings", { view: { id: "settings" }, wins: new Map() } as unknown as ViewRec],
    ]);
    const state = { currentView: "console", activeWin: undefined };
    let flownTo = "", settledAnchor = "", paint = Promise.resolve();
    const cx = {
      views, state,
      nav: { flyView(id: string) { flownTo = id; state.currentView = id; } },
      view: { remove(view: ViewRec) { connection!.closeStream(removed); views.delete(view.view.id); }, settle(id: string) { settledAnchor = id; } },
      win: { setActive() {} }, visibility: { unwatch() {}, lodChanged() {} },
      store: { reset() {}, changed() {}, uncommittedWindows: () => new Set(), uncommittedViews: () => new Set() },
      adapters: {}, tree: { render() {} }, pill: { paint() {} }, toolbar: { update() {} },
    } as unknown as Ctx;
    store.subscribe(() => { paint = reconcile(cx, () => ({ document: store!.current(), protectedIds: new Set(), protectedViews: new Set() }), () => undefined, () => true); });
    sockets[0]!.close(); retry?.();
    expect(sockets).toHaveLength(2);
    sockets[1]!.onopen?.(); sockets[1]!.receive(welcome);
    // The other device removed Console while this socket was down. Its fresh
    // snapshot arrives before this device has reattached that terminal.
    snapshot(sockets[1]!, 2, []); await paint;
    expect(sockets[1]!.frames.filter(({ stream }) => stream === removed)).toEqual([]);
    expect(sockets[1]!.readyState).toBe(Socket.OPEN); expect(failures).toEqual([]);
    expect(connection.streamCount).toBe(1);
    expect(state.currentView).toBe("settings"); expect(flownTo).toBe("settings"); expect(settledAnchor).toBe("settings");
    connection.send(sibling, { type: "AttachTerm", sessionId: new Uint8Array(16).fill(1), lastOutSeq: 0n, lastInSeq: 0n });
    expect(sockets[1]!.frames.filter(({ stream }) => stream === sibling).map(({ frame }) => frame.type)).toEqual(["AttachTerm"]);
    expect(sockets[1]!.frames.filter(({ frame }) => frame.type === "Subscribe" && JSON.parse(new TextDecoder().decode(frame.filterJson)).topic === "canvas.layout")).toHaveLength(1);
  } finally {
    store?.dispose(); connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
