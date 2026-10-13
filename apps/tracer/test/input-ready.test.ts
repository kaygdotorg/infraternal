/** Verifies that typing during a shim handshake is retained until real replay confirmation [D265, #199]. */
import { expect, test } from "bun:test";
import { TerminalClient } from "../src/terminal";
import type { WireFrame } from "../../../packages/protocol/src/codec";

test("an unconfirmed attachment buffers typing and flushes it once replay confirms readiness", () => {
  const retained: number[] = [];
  const sent: WireFrame[] = [];
  let confirmed = 0;
  // This adapter observes the queue boundary; the production ring is unchanged.
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
    closed: false, attached: true, attachmentConfirmed: false, sessionGone: false,
    inputModifiers: { ctrl: "off", alt: "off" }, inputQueue: queue,
    inputScratch: new Uint8Array(16 * 1024), nextInSeq: 0n, ackedInSeq: 0n,
    streamId: 1, lastOutSeq: 0n, replayResponseFence: 0n,
    config: { hooks: {}, status: { textContent: "Catching up…" } },
    conn: { streamAttached: () => { confirmed++; } },
    sampleRoundTrip: () => {}, startPings: () => {}, setStatus: () => {},
    sendFrame: (_stream: number, frame: WireFrame) => {
      sent.push(frame.type === "Input" ? { ...frame, bytes: frame.bytes.slice() } : frame);
    },
  }) as { handleInput(data: string): void; releaseReplayResponsesAfterPaint(): void; nextInSeq: bigint };
  client.handleInput("keep");
  expect(sent).toEqual([]);
  expect(new TextDecoder().decode(Uint8Array.from(retained))).toBe("keep");
  client.releaseReplayResponsesAfterPaint();
  expect(confirmed).toBe(1);
  expect(sent).toEqual([{ type: "Input", inSeq: 0n, bytes: new TextEncoder().encode("keep") }]);
  client.releaseReplayResponsesAfterPaint();
  expect(sent).toHaveLength(1);
  expect(client.nextInSeq).toBe(4n);
});
