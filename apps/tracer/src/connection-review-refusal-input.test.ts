/** Independent #244 review: a refused connection resume must retain typing never sent to the host. */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { Osc52Scanner } from "./osc52";
import { TerminalClient } from "./terminal";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

interface TerminalProbe {
  streamHandler(): StreamHandler;
  handleInput(text: string): void;
  resendRetainedInput(): void;
  releaseReplayResponsesAfterPaint(): void;
  retainedInput?: Uint8Array;
  attached: boolean;
  attachmentConfirmed: boolean;
  replayResponseFence: bigint | undefined;
}

for (const sentBeforeDrop of [false, true]) test(`review: refusal fallback preserves typing through explicit resend (previously sent: ${sentBeforeDrop})`, () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, document: globals.document };
  const sockets: Socket[] = [];
  const frames: Array<{ socket: number; frame: WireFrame }> = [];
  const timers = new Map<number, () => void>();
  let timerId = 0;
  class Socket {
    static OPEN = 1;
    readyState = 1;
    binaryType = "";
    onopen?: () => void;
    onclose?: (event?: { code: number; reason: string }) => void;
    onmessage?: (event: { data: ArrayBuffer }) => void;
    readonly index = sockets.length;
    constructor() { sockets.push(this); }
    send(bytes: Uint8Array) {
      new WebSocketFrameDecoder().feed(bytes, (_stream, frame) => {
        frames.push({ socket: this.index, frame: frame.type === "Input" ? { ...frame, bytes: frame.bytes.slice() } : frame });
      });
    }
    receive(frame: WireFrame, stream = 0) { this.onmessage?.({ data: encodeMuxedFrame(stream, frame).slice().buffer as ArrayBuffer }); }
    close() { this.readyState = 3; this.onclose?.(); }
  }
  const retained: number[] = [];
  const queue = {
    get free() { return 1024 * 1024 - retained.length; },
    get length() { return retained.length; },
    clear() { retained.length = 0; },
    consume(length: number) { retained.splice(0, length); },
    push(bytes: Uint8Array) { retained.push(...bytes); return true; },
    copyOut(offset: number, target: Uint8Array) {
      const bytes = Uint8Array.from(retained).subarray(offset, offset + target.length);
      target.set(bytes); return bytes.length;
    },
  };
  let notices = 0;
  let connection: MuxConnection | undefined;
  try {
    globals.window = { setTimeout: (callback: () => void) => { const id = ++timerId; timers.set(id, callback); return id; }, clearTimeout: (id: number) => timers.delete(id) };
    globals.document = undefined;
    globals.location = { protocol: "https:", host: "refusal-input.example.test" };
    globals.WebSocket = Socket;
    connection = new MuxConnection();
    const conn = connection;
    const terminal = Object.assign(Object.create(TerminalClient.prototype), {
      synchronizedOutput: { reset() {}, dispose() {} },
      // The constructor builds this private field, and Object.create skips it; a real scanner keeps the OSC 52 path honest (#440).
      clipboardWrites: new Osc52Scanner(),
      parsedOutputVersion: 0,
      closed: false, attached: false, attachmentConfirmed: false, sessionGone: false,
      hasAttached: false, sessionId: new Uint8Array(16), streamId: 1,
      inputModifiers: { ctrl: "off", alt: "off" }, inputQueue: queue,
      inputScratch: new Uint8Array(16 * 1024), nextInSeq: 0n, ackedInSeq: 0n,
      lastOutSeq: 0n, receivedOutSeq: 0n, cursorEpoch: 0,
      outputQueue: { length: 0, clear() {} },
      config: { hooks: {}, status: { textContent: "" } }, conn,
      terminal: { reset() {} }, lastSize: { cols: 80, rows: 24, pxW: 0, pxH: 0 },
      showInputResendNotice() { notices += 1; }, cancelStreamRetry() {}, wakeTerminal() {}, setStatus() {}, sampleRoundTrip() {}, startPings() {},
      sendFrame: (stream: number, frame: WireFrame) => conn.send(stream, frame),
    }) as TerminalProbe;
    conn.openStream(terminal.streamHandler());
    const welcome = (): WireFrame => ({ type: "Welcome", connectionId: new Uint8Array(16).fill(1), resumeToken: new Uint8Array(32).fill(2), resumeWindowSeconds: 120 });
    sockets[0]!.onopen?.(); sockets[0]!.receive(welcome());
    terminal.replayResponseFence = 0n;
    terminal.releaseReplayResponsesAfterPaint();
    if (sentBeforeDrop) {
      terminal.handleInput("prior-\n");
      sockets[0]!.receive({ type: "Ack", inSeqAcked: 7n }, 1);
      expect(retained.length).toBe(0);
      terminal.handleInput("never-sent\n");
    }
    sockets[0]!.close();
    if (!sentBeforeDrop) terminal.handleInput("never-sent\n");
    expect(retained.length).toBe(11);
    expect(frames.filter(({ frame }) => frame.type === "Input")).toHaveLength(sentBeforeDrop ? 2 : 0);
    const retry = () => { const next = [...timers.entries()].at(-1)!; timers.delete(next[0]); next[1](); };
    retry(); sockets[1]!.onopen?.();
    sockets[1]!.receive({ type: "Close", code: 1008, reason: "the server refused to resume the connection" });
    retry(); sockets[2]!.onopen?.(); sockets[2]!.receive(welcome());
    // The fresh writer needs output replay before typing, just as a resumed writer does.
    expect(frames.filter(({ frame }) => frame.type === "Resume")).toHaveLength(1);
    expect(frames.filter(({ socket, frame }) => socket === 2 && frame.type === "AttachTerm")).toHaveLength(1);
    terminal.resendRetainedInput(); // A tap before replay cannot release typing.
    expect(frames.filter(({ socket, frame }) => socket === 2 && frame.type === "Input")).toHaveLength(0);
    terminal.replayResponseFence = 0n;
    terminal.releaseReplayResponsesAfterPaint();
    expect(terminal.retainedInput?.byteLength).toBe(11);
    expect(retained.length).toBe(0);
    expect(notices).toBe(2);
    expect(frames.filter(({ socket, frame }) => socket === 2 && frame.type === "Input")).toHaveLength(0);
    // #244 chooses explicit consent: a new writer cannot prove prior delivery.
    terminal.resendRetainedInput();
    terminal.resendRetainedInput(); // A second tap cannot duplicate input.
    expect(terminal.retainedInput).toBeUndefined();
    expect(retained.length).toBe(11);
    const delivered = frames.filter(({ socket, frame }) => socket === 2 && frame.type === "Input")
      .map(({ frame }) => frame.type === "Input" ? new TextDecoder().decode(frame.bytes) : "").join("");
    expect(delivered).toBe("never-sent\n");
    const sent = frames.find(({ socket, frame }) => socket === 2 && frame.type === "Input")?.frame;
    expect(sent?.type === "Input" ? sent.inSeq : undefined).toBe(0n);
  } finally {
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
