/**
 * A doubted host link is kept (D300, #234): the viewer shows that it may be
 * reconnecting, but live output is not replay, so terminal replies and typing
 * keep flowing. Recovery clears only that indicator and is never a replay fence.
 */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "../src/connection";
import { TerminalClient } from "../src/terminal";
import { decodeMuxedFrame, type WireFrame } from "../../../packages/protocol/src/codec";

const SESSION = "00000000-0000-0000-0000-000000000000";

interface DoubtProbe {
  attachmentConfirmed: boolean;
  suppressReplayResponses: boolean;
  replayResponseFence: bigint | undefined;
  config: { status: { textContent: string; hidden: boolean } };
  handleInput(data: string): void;
  handleTerminalFrame(frame: WireFrame, message: Uint8Array, at: number): void;
}

function confirmedClient(status = "") {
  const sent: WireFrame[] = [];
  const readiness: boolean[] = [];
  const failures: string[] = [];
  const retained: number[] = [];
  const queue = {
    free: 1024 * 1024,
    get length() { return retained.length; },
    push(bytes: Uint8Array) { retained.push(...bytes); return true; },
    copyOut(offset: number, target: Uint8Array) {
      const bytes = Uint8Array.from(retained).subarray(offset, offset + target.length);
      target.set(bytes);
      return bytes.length;
    },
  };
  const client = Object.assign(Object.create(TerminalClient.prototype), {
    closed: false, attached: true, attachmentConfirmed: true, sessionGone: false,
    suppressReplayResponses: false, replayResponseFence: undefined,
    inputModifiers: { ctrl: "off", alt: "off" }, inputQueue: queue,
    inputScratch: new Uint8Array(16 * 1024), nextInSeq: 0n, ackedInSeq: 0n,
    streamId: 1, lastOutSeq: 0n, receivedOutSeq: 0n, sessionId: new Uint8Array(16),
    config: { hooks: {}, status: { textContent: status, hidden: status === "" } },
    conn: { streamAttached: (ready: boolean) => readiness.push(ready) },
    sampleRoundTrip: () => {}, startPings: () => {},
    protocolFailure: (message: string) => failures.push(message),
    sendFrame: (_stream: number, frame: WireFrame) => {
      sent.push(frame.type === "Input" ? { ...frame, bytes: frame.bytes.slice() } : frame);
    },
  }) as DoubtProbe;
  const notice = (type: string, extra = {}) => client.handleTerminalFrame({
    type: "Event", subId: 0,
    eventJson: new TextEncoder().encode(JSON.stringify({ type, session_id: SESSION, ...extra })),
  }, new Uint8Array(), 0);
  return { client, sent, readiness, failures, notice };
}

test("a link doubt shows the indicator and keeps live replies and typing flowing", () => {
  const { client, sent, readiness, failures, notice } = confirmedClient();
  notice("terminal.link_doubt");
  expect(client.config.status.textContent).toBe("Reconnecting…");
  expect(client.config.status.hidden).toBe(false);
  // Not replay: the window stays confirmed and answers live terminal queries.
  expect(client.attachmentConfirmed).toBe(true);
  expect(client.suppressReplayResponses).toBe(false);
  expect(readiness).toEqual([]);
  client.handleInput("ls");
  expect(sent).toEqual([{ type: "Input", inSeq: 0n, bytes: new TextEncoder().encode("ls") }]);
  notice("terminal.link_recovered");
  expect(client.config.status.textContent).toBe("");
  expect(client.config.status.hidden).toBe(true);
  expect(client.attachmentConfirmed).toBe(true);
  expect(client.replayResponseFence).toBeUndefined();
  expect(failures).toEqual([]);
});

test("recovery clears only its own indicator, and a real reconnect still owns the replay", () => {
  const busy = confirmedClient("Reconnected. The screen may be slightly out of date.");
  busy.notice("terminal.link_doubt");
  busy.notice("terminal.link_recovered");
  expect(busy.client.config.status.textContent).toBe("Reconnected. The screen may be slightly out of date.");

  // A doubt that ends in retirement: Reconnecting takes over, and a late
  // recovery notice can neither clear "Catching up…" nor confirm the window.
  const { client, readiness, notice } = confirmedClient();
  notice("terminal.link_doubt");
  notice("terminal.reconnecting");
  notice("terminal.link_recovered");
  expect(client.config.status.textContent).toBe("Catching up…");
  expect(client.attachmentConfirmed).toBe(false);
  expect(client.suppressReplayResponses).toBe(true);
  expect(readiness).toEqual([false]);
});

test("a notice type from a newer server is ignored, not a protocol failure", () => {
  const { client, failures, notice } = confirmedClient();
  notice("terminal.some_future_notice", { detail: 1 });
  expect(failures).toEqual([]);
  expect(client.attachmentConfirmed).toBe(true);
  expect(client.config.status.textContent).toBe("");
});

test("the viewer announces the link-doubt capability in its Hello", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket };
  const frames: WireFrame[] = [];
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: () => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    constructor() { sockets.push(this); }
    send(bytes: Uint8Array) { frames.push(decodeMuxedFrame(bytes).frame); }
    close() { this.readyState = 3; this.onclose?.(); }
  }
  const sockets: Socket[] = [];
  const handler: StreamHandler = {
    onSocketOpen() {}, onWelcome() {}, onFrame() {}, onDisconnected() {}, hasSession: () => false, onStatus() {},
  };
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: () => 1, clearTimeout() {} };
    globals.location = { protocol: "https:", host: "doubt.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    connection.openStream(handler);
    sockets[0]!.onopen?.();
    const hello = frames[0];
    expect(hello?.type).toBe("Hello");
    if (hello?.type !== "Hello") throw new Error("no Hello");
    expect(hello.caps & 2n).toBe(2n);
    // A new connection never asks the server to wait for a Resume.
    expect(hello.caps & 1n).toBe(0n);
  } finally {
    connection?.dispose();
    for (const key of ["window", "location", "WebSocket"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
  }
});
