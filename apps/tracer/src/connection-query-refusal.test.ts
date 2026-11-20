/** Exercises a pending renderer query across refusal, replay and explicit typing resend (#244, D307). */
import { expect, test } from "bun:test";
import { MuxConnection, type StreamHandler } from "./connection";
import { Osc52Scanner } from "./osc52";
import { TerminalClient } from "./terminal";
import { Ghostty } from "../vendor/ghostty-web";
import { QueryReplies } from "../test/query-replies-double";
import { encodeMuxedFrame, WebSocketFrameDecoder, type WireFrame } from "../../../packages/protocol/src/codec";

const engine = await Ghostty.load(new URL("../vendor/ghostty-web/dist/ghostty-vt.wasm", import.meta.url).pathname);
const encoder = new TextEncoder();

interface TerminalProbe {
  writeQueryResponses(bytes: Uint8Array, offset: bigint, callback: () => void): void;
  writeSuppressingTerminalResponses(bytes: Uint8Array, callback: () => void, offset?: bigint): void;
  parserReplies?: string[];
  parserReplyLength: number;
  suppressTerminalResponses: boolean;
  streamHandler(): StreamHandler;
  handleInput(text: string): void;
  resendRetainedInput(): void;
  releaseReplayResponsesAfterPaint(): void;
  retainedInput?: Uint8Array;
  attached: boolean;
  attachmentConfirmed: boolean;
  replayResponseFence: bigint | undefined;
}

for (const sentBeforeDrop of [false, true]) test(`pending query stays reply-marked through refusal and explicit resend (previously sent: ${sentBeforeDrop})`, () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, location: globals.location, WebSocket: globals.WebSocket, document: globals.document, performance: globals.performance };
  const sockets: Socket[] = [];
  const registry = new QueryReplies();
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
  let renderer = engine.createTerminal(80, 24);
  try {
    // A logical clock keeps protocol expiry independent of host scheduling.
    globals.performance = { now: () => 0 };
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
      terminal: {
        reset() { renderer.free(); renderer = engine.createTerminal(80, 24); },
        write(bytes: Uint8Array, callback: () => void) {
          renderer.write(bytes); drainReplies(); callback();
        },
        writeSlices(bytes: Uint8Array, slices: (write: (end: number) => void) => void, callback: () => void) {
          renderer.writeSlices(bytes, (write) => slices((end) => { write(end); drainReplies(); })); callback();
        },
      }, lastSize: { cols: 80, rows: 24, pxW: 0, pxH: 0 },
      showInputResendNotice() { notices += 1; }, cancelStreamRetry() {}, wakeTerminal() {}, setStatus() {}, sampleRoundTrip() {}, startPings() {},
      sendFrame: (stream: number, frame: WireFrame) => conn.send(stream, frame),
    }) as TerminalProbe;
    // Adapt only renderer event delivery; production methods own scanning, marking and suppression.
    function drainReplies(): void {
      for (let reply = renderer.readResponse(); reply !== null; reply = renderer.readResponse()) {
        if (terminal.suppressTerminalResponses) continue;
        if (terminal.parserReplies) { terminal.parserReplies = [...terminal.parserReplies, reply]; terminal.parserReplyLength += reply.length; }
        else terminal.handleInput(reply);
      }
    }
    conn.terminalQueryReplies = true;
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
    registry.output(100n, encoder.encode("\u001b[6"));
    terminal.writeQueryResponses(encoder.encode("\u001b[6"), 100n, () => {});
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
    // The pending control belongs to session output, not to the saved typing buffer.
    terminal.writeSuppressingTerminalResponses(encoder.encode("\u001b[6"), () => {}, 100n);
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
    registry.output(103n, encoder.encode("n"));
    terminal.writeQueryResponses(encoder.encode("n"), 103n, () => {});
    const replies = frames.filter(({ frame }) => frame.type === "Input" && frame.replyTo !== undefined);
    expect(replies).toHaveLength(1);
    const reply = replies[0]!.frame;
    if (reply.type !== "Input" || reply.replyTo === undefined) throw new Error("missing marked reply");
    expect(registry.accept(reply.replyTo, reply.bytes)).toBe(true);
    expect(registry.accept(reply.replyTo, reply.bytes)).toBe(false);
    expect(replies[0]?.frame).toMatchObject({ type: "Input", inSeq: 0n, replyTo: 100n });
    expect(replies[0]?.frame.type === "Input" ? new TextDecoder().decode(replies[0].frame.bytes) : "").toBe("\u001b[1;1R");
    terminal.resendRetainedInput();
    const freshTyping = frames.filter(({ socket, frame }) => socket === 2 && frame.type === "Input" && frame.replyTo === undefined);
    expect(freshTyping).toHaveLength(1);
    expect(freshTyping[0]?.frame.type === "Input" ? new TextDecoder().decode(freshTyping[0].frame.bytes) : "").toBe("never-sent\n");
    expect(retained.length).toBe(11);
  } finally {
    renderer.free();
    connection?.dispose();
    for (const [key, value] of Object.entries(original)) { if (value === undefined) delete globals[key]; else globals[key] = value; }
  }
});
