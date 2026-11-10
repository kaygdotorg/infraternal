/** Independent #244 retained-typing lifetime and consent controls; all input is synthetic. */
import { expect, test } from "bun:test";
import { Osc52Scanner } from "./osc52";
import { TerminalClient } from "./terminal";
import type { ToastMessage } from "../../../packages/ui/src/toast";
import type { WireFrame } from "../../../packages/protocol/src/codec";

interface Probe {
  inputNeedsResend: boolean;
  retainedInput?: Uint8Array;
  attachmentConfirmed: boolean;
  closed: boolean;
  nextInSeq: bigint;
  restartCursors(retain?: boolean): void;
  showInputResendNotice(): void;
  resendRetainedInput(): void;
  discardRetainedInput(): void;
  resendUnacknowledgedInput(): void;
  handleInput(text: string): void;
}

/** Keep transport and renderer out of these state-transition checks; execute production consent methods. */
function fixture() {
  const bytes: number[] = [];
  const sent: WireFrame[] = [];
  let notice: ToastMessage | undefined;
  let dismissals = 0;
  const queue = {
    get length() { return bytes.length; },
    get free() { return 1024 * 1024 - bytes.length; },
    clear() { bytes.fill(0); bytes.length = 0; },
    push(value: Uint8Array) { bytes.push(...value); return true; },
    copyOut(offset: number, target: Uint8Array) {
      const value = Uint8Array.from(bytes).subarray(offset, offset + target.length);
      target.set(value); return value.length;
    },
  };
  const client = Object.assign(Object.create(TerminalClient.prototype), {
    synchronizedOutput: { reset() {}, dispose() {} },
    // The constructor builds this private field, and Object.create skips it; a real scanner keeps the OSC 52 path honest (#440).
    clipboardWrites: new Osc52Scanner(),
    parsedOutputVersion: 0,
    closed: false, attachmentConfirmed: false, inputNeedsResend: false, retainedInput: undefined,
    inputQueue: queue, inputScratch: new Uint8Array(16 * 1024),
    inputModifiers: { ctrl: "off", alt: "off" }, cursorEpoch: 0,
    nextInSeq: 0n, ackedInSeq: 0n, sessionId: new Uint8Array(16),
    outputQueue: { clear() {} }, terminal: { reset() {} },
    config: { hooks: {} }, sampleRoundTrip() {},
    inputResendNotice: {
      show(value: ToastMessage) { notice = value; },
      dismiss() { dismissals += 1; },
    },
    sendFrame(_stream: number, frame: WireFrame) {
      sent.push(frame.type === "Input" ? { ...frame, bytes: frame.bytes.slice() } : frame);
    },
  }) as Probe;
  return { client, queue, sent, notice: () => notice!, dismissals: () => dismissals };
}

function waiting(text = "synthetic-old\n") {
  const f = fixture();
  f.client.handleInput(text);
  f.client.restartCursors(true);
  f.client.attachmentConfirmed = true;
  f.client.showInputResendNotice();
  return f;
}

test("review: saved typing can be declined without closing the live shell", () => {
  const f = waiting();
  const held = f.client.retainedInput!;
  expect(f.client.retainedInput?.byteLength).toBe(14);
  expect(f.queue.length).toBe(0);
  expect(f.sent).toHaveLength(0);
  // Declining must release only the retained bytes, then allow fresh typing at offset zero.
  expect(f.notice().secondaryAction?.label).toBe("Discard");
  f.notice().secondaryAction?.onSelect();
  expect(held.every((byte) => byte === 0)).toBe(true);
  expect(f.client.retainedInput).toBeUndefined();
  expect(f.client.inputNeedsResend).toBe(false);
  f.client.handleInput("fresh\n");
  expect(f.sent).toHaveLength(1);
  expect(f.sent[0]?.type === "Input" ? f.sent[0].inSeq : undefined).toBe(0n);
});

test("review: new typing reaches the fresh shell while saved typing stays pending", () => {
  const f = waiting();
  const saved = f.client.retainedInput?.slice();
  f.client.handleInput("fresh\n");

  expect(f.client.inputNeedsResend).toBe(true);
  expect(f.client.retainedInput).toEqual(saved);
  expect(f.sent).toHaveLength(1);
  expect(f.sent[0]?.type === "Input" ? new TextDecoder().decode(f.sent[0].bytes) : "").toBe("fresh\n");
  expect(f.notice().action?.label).toBe("Send again");

  f.notice().secondaryAction?.onSelect();
  expect(f.client.retainedInput).toBeUndefined();
  expect(f.queue.length).toBe(6);
  expect(f.sent).toHaveLength(1);
  f.client.handleInput("more\n");
  expect(f.sent).toHaveLength(2);
  expect(f.sent[1]?.type === "Input" ? f.sent[1].inSeq : undefined).toBe(6n);
});

test("review: retained input and consent are local to their terminal window", () => {
  // Distinct markers expose a swapped buffer; identical markers would conceal cross-window delivery.
  const first = waiting("window-one\n");
  const second = waiting("window-two\n");
  first.client.resendRetainedInput();
  first.client.resendRetainedInput();
  expect(first.sent).toHaveLength(1);
  expect(first.sent[0]?.type === "Input" ? new TextDecoder().decode(first.sent[0].bytes) : "").toBe("window-one\n");
  expect(second.sent).toHaveLength(0);
  expect(second.client.inputNeedsResend).toBe(true);
  expect(new TextDecoder().decode(second.client.retainedInput)).toBe("window-two\n");
  expect(second.queue.length).toBe(0);
  second.client.resendRetainedInput();
  expect(second.sent[0]?.type === "Input" ? new TextDecoder().decode(second.sent[0].bytes) : "").toBe("window-two\n");
  expect(first.sent).toHaveLength(1);
});

test("review: selecting a different session removes saved typing and its action", () => {
  const f = waiting();
  const held = f.client.retainedInput!;
  const staleAction = f.notice().action!;
  f.client.restartCursors();
  expect(held.every((byte) => byte === 0)).toBe(true);
  expect(f.client.retainedInput).toBeUndefined();
  expect(f.queue.length).toBe(0);
  expect(f.dismissals()).toBe(1);
  staleAction.onSelect();
  expect(f.sent).toHaveLength(0);
  f.client.handleInput("fresh\n");
  expect(f.sent).toHaveLength(1);
  expect(f.sent[0]?.type === "Input" ? f.sent[0].inSeq : undefined).toBe(0n);
});

test("review: another refused writer retains pending and unacknowledged fresh typing", () => {
  const f = waiting();
  f.client.handleInput("more\n");
  expect(f.sent).toHaveLength(1);
  expect(f.client.inputNeedsResend).toBe(true);

  f.client.attachmentConfirmed = false;
  f.client.restartCursors(true);
  expect(f.client.retainedInput?.byteLength).toBe(19);
  expect(f.queue.length).toBe(0);
  f.sent.length = 0;
  f.client.resendUnacknowledgedInput();
  expect(f.sent).toHaveLength(0);
  f.client.attachmentConfirmed = true;
  f.client.showInputResendNotice();
  f.notice().action!.onSelect();
  expect(f.sent).toHaveLength(1);
  expect(f.sent[0]?.type === "Input" ? new TextDecoder().decode(f.sent[0].bytes) : "").toBe("synthetic-old\nmore\n");
  expect(f.sent[0]?.type === "Input" ? f.sent[0].inSeq : undefined).toBe(0n);
});

test("review: window disposal clears held input and rejects a stale resend action", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { window: globals.window, document: globals.document };
  const f = waiting();
  const staleAction = f.notice().action!;
  const held = f.client.retainedInput!;
  let noticeDisposed = 0;
  let streamClosed = 0;
  Object.assign(f.client, {
    cancelStreamRetry() {}, pendingLinkRows: new Map(), forcedLinkRows: new Map(),
    disposeTouch() {}, pauseTerminal() {}, offRoundTrip() {},
    resizeObserver: { disconnect() {} },
    config: { host: { removeEventListener() {} } },
    terminal: { dispose() {} },
    conn: { streamAttached() {}, closeStream() { streamClosed += 1; } },
    inputResendNotice: { dispose() { noticeDisposed += 1; } },
  });
  try {
    globals.window = { removeEventListener() {} };
    globals.document = { removeEventListener() {} };
    (f.client as unknown as { dispose(): void }).dispose();
    expect(f.client.closed).toBe(true);
    expect(held.every((byte) => byte === 0)).toBe(true);
    expect(f.client.retainedInput).toBeUndefined();
    expect(f.queue.length).toBe(0);
    expect(noticeDisposed).toBe(1);
    expect(streamClosed).toBe(1);
    staleAction.onSelect();
    expect(f.sent).toHaveLength(0);
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete globals[key]; else globals[key] = value;
    }
  }
});
