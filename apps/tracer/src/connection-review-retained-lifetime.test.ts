/** Independent #244 retained-typing lifetime and consent controls; all input is synthetic. */
import { expect, test } from "bun:test";
import { TerminalClient } from "./terminal";
import type { ToastMessage } from "../../../packages/ui/src/toast";
import type { WireFrame } from "../../../packages/protocol/src/codec";

interface Probe {
  inputNeedsResend: boolean;
  attachmentConfirmed: boolean;
  closed: boolean;
  nextInSeq: bigint;
  restartCursors(retain?: boolean): void;
  showInputResendNotice(): void;
  resendRetainedInput(): void;
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
    closed: false, attachmentConfirmed: false, inputNeedsResend: false,
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

function waiting() {
  const f = fixture();
  f.client.handleInput("synthetic-old\n");
  f.client.restartCursors(true);
  f.client.attachmentConfirmed = true;
  f.client.showInputResendNotice();
  return f;
}

test("review: saved typing can be declined without closing the live shell", () => {
  const f = waiting();
  expect(f.queue.length).toBe(14);
  expect(f.sent).toHaveLength(0);
  // This shared surface offers one action plus an optional Dismiss control.
  // Declining must release the held bytes, then allow fresh typing at offset zero.
  expect(f.notice().dismissible).toBe(true);
  expect(typeof f.notice().onClose).toBe("function");
  f.notice().onClose?.();
  expect(f.queue.length).toBe(0);
  expect(f.client.inputNeedsResend).toBe(false);
  f.client.handleInput("fresh\n");
  expect(f.sent).toHaveLength(1);
  expect(f.sent[0]?.type === "Input" ? f.sent[0].inSeq : undefined).toBe(0n);
});

test("review: retained input and consent are local to their terminal window", () => {
  const first = waiting();
  const second = waiting();
  first.client.resendRetainedInput();
  first.client.resendRetainedInput();
  expect(first.sent).toHaveLength(1);
  expect(second.sent).toHaveLength(0);
  expect(second.client.inputNeedsResend).toBe(true);
  expect(second.queue.length).toBe(14);
});

test("review: selecting a different session removes saved typing and its action", () => {
  const f = waiting();
  const staleAction = f.notice().action!;
  f.client.restartCursors();
  expect(f.queue.length).toBe(0);
  expect(f.dismissals()).toBe(1);
  staleAction.onSelect();
  expect(f.sent).toHaveLength(0);
  f.client.handleInput("fresh\n");
  expect(f.sent).toHaveLength(1);
  expect(f.sent[0]?.type === "Input" ? f.sent[0].inSeq : undefined).toBe(0n);
});

test("review: another disconnect before consent keeps all typing behind consent", () => {
  const f = waiting();
  f.client.attachmentConfirmed = false;
  f.notice().action!.onSelect();
  f.client.handleInput("more\n");
  f.client.resendUnacknowledgedInput();
  expect(f.sent).toHaveLength(0);
  expect(f.queue.length).toBe(19);
  f.client.attachmentConfirmed = true;
  f.client.resendUnacknowledgedInput();
  expect(f.sent).toHaveLength(0);
  f.notice().action!.onSelect();
  expect(f.sent).toHaveLength(1);
  expect(f.sent[0]?.type === "Input" ? f.sent[0].bytes.length : undefined).toBe(19);
});
