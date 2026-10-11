/** Exercises unsolicited shell exits through the real browser notice handler (#87). */
import { expect, test } from "bun:test";
import { TerminalClient } from "../src/terminal";
import type { WireFrame } from "../../../packages/protocol/src/codec";

interface ExitProbe {
  attached: boolean;
  sessionId: Uint8Array;
  lastOutSeq: bigint;
  receivedOutSeq: bigint;
  pendingExit?: { status: number; finalSeq: bigint };
  exitReported: boolean;
  snapshotWriteInFlight: boolean;
  config: { hooks: { onExited(status: number): void } };
  setStatus(message: string): void;
  protocolFailure(message: string): void;
  handleTerminalFrame(frame: WireFrame, message: Uint8Array, at: number): void;
  finishExit(): void;
}

function probe(): { client: ExitProbe; statuses: number[] } {
  const statuses: number[] = [];
  const client = Object.assign(Object.create(TerminalClient.prototype), {
    attached: true, sessionId: new Uint8Array(16), lastOutSeq: 0n, receivedOutSeq: 0n,
    exitReported: false, outputWriteInFlight: false, snapshotWriteInFlight: false, outputQueue: { length: 0 }, config: { hooks: { onExited: (status: number) => statuses.push(status) } },
    cancelStreamRetry: () => {}, setStatus: () => {}, protocolFailure: (message: string) => { throw new Error(message); },
  }) as ExitProbe;
  return { client, statuses };
}

function exited(client: ExitProbe, status: number, finalSeq: number): void {
  const eventJson = new TextEncoder().encode(JSON.stringify({ type: "terminal.exited", session_id: "00000000-0000-0000-0000-000000000000", status, final_seq: finalSeq }));
  client.handleTerminalFrame({ type: "Event", subId: 0, eventJson }, new Uint8Array(), 0);
}

test("an unsolicited clean exit notifies the window without further input", () => {
  const { client, statuses } = probe();
  exited(client, 0, 0);
  expect(statuses).toEqual([0]);
  exited(client, 0, 0);
  expect(statuses).toEqual([0]);
});

test("an exit waits for the final output to paint and retains a nonzero status", () => {
  const { client, statuses } = probe();
  client.receivedOutSeq = 2n;
  exited(client, 7, 2);
  expect(statuses).toEqual([]);
  client.lastOutSeq = 2n;
  client.finishExit();
  expect(statuses).toEqual([7]);
});

test("an exit cannot discard bytes or wait for bytes the stream never sent", () => {
  const { client } = probe();
  expect(() => exited(client, 0, 1)).toThrow("invalid terminal notice");
  client.receivedOutSeq = 2n;
  expect(() => exited(client, 0, 0)).toThrow("invalid terminal notice");
});

test("an equal-cursor final snapshot paints before the window is notified", () => {
  const { client, statuses } = probe();
  client.snapshotWriteInFlight = true;
  exited(client, 0, 0);
  expect(statuses).toEqual([]);
  client.snapshotWriteInFlight = false;
  client.finishExit();
  expect(statuses).toEqual([0]);
});

test("a retired exit retains status without claiming missing final bytes painted", () => {
  const { client, statuses } = probe();
  const eventJson = new TextEncoder().encode(JSON.stringify({ type: "terminal.exited", session_id: "00000000-0000-0000-0000-000000000000", status: 7, final_seq: 42, retired: true }));
  client.handleTerminalFrame({ type: "Event", subId: 0, eventJson }, new Uint8Array(), 0);
  expect(statuses).toEqual([]);
  expect(client.receivedOutSeq).toBe(0n);
});

test("retired exits still reject a regressed cursor or malformed retirement flag", () => {
  const { client } = probe();
  client.receivedOutSeq = 43n;
  for (const retired of [true, "true"]) {
    const eventJson = new TextEncoder().encode(JSON.stringify({ type: "terminal.exited", session_id: "00000000-0000-0000-0000-000000000000", status: 7, final_seq: 42, retired }));
    expect(() => client.handleTerminalFrame({ type: "Event", subId: 0, eventJson }, new Uint8Array(), 0)).toThrow("invalid terminal notice");
  }
});
