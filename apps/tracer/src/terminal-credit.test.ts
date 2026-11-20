/** Checks that a terminal Snapshot can atomically replace queued raw output while staying inside its credit window. */
import { expect, test } from "bun:test";
import { TerminalClient } from "./terminal";

/** The production method and state observed by these Snapshot replacement checks. */
interface SnapshotReceiver {
  acceptSnapshot(sequence: bigint, bytes: Uint8Array): void;
  creditAvailable: number;
  receivedOutSeq: bigint;
  pendingSnapshot?: { outSeq: bigint; bytes: Uint8Array };
}

/** Build a real `acceptSnapshot` receiver with only its socket, renderer and byte ring replaced. */
function snapshotReceiver(creditAvailable: number, queuedOutput: number) {
  const failures: string[] = [];
  const outputQueue = {
    length: queuedOutput,
    discardAfter(keep: number): number {
      const dropped = this.length - keep;
      this.length = keep;
      return dropped;
    },
  };
  const client = Object.assign(Object.create(TerminalClient.prototype), {
    attached: false,
    creditAvailable,
    receivedOutSeq: 0n,
    streamId: 1,
    outputQueue,
    outputWriteInFlight: false,
    outputWriteLength: 0,
    snapshotWriteInFlight: false,
    pendingSnapshot: undefined,
    synchronizedOutput: { reset() {} },
    terminal: { reset() {} },
    protocolFailure(message: string) { failures.push(message); },
    requestSymbolsIfNeeded() {},
    traceRange() {},
    drainOutput() {},
  }) as SnapshotReceiver;
  return { client, failures, outputQueue };
}

test("a large Snapshot borrows credit only from raw output it replaces", () => {
  const fixture = snapshotReceiver(64 * 1024, 128 * 1024);
  const styledScreen = new Uint8Array(128 * 1024).fill(0x58);

  fixture.client.acceptSnapshot(1024n, styledScreen);

  expect(fixture.failures).toEqual([]);
  expect(fixture.client.receivedOutSeq).toBe(1024n);
  expect(fixture.client.pendingSnapshot?.bytes).toEqual(styledScreen);
  expect(fixture.outputQueue.length).toBe(0);
  expect(fixture.client.creditAvailable).toBe(64 * 1024);
});

test("the largest valid Snapshot fits when it replaces one raw credit window", () => {
  const fixture = snapshotReceiver(64 * 1024, 1024 * 1024);
  const maximumSnapshot = new Uint8Array(1024 * 1024 - 9).fill(0x58);

  fixture.client.acceptSnapshot(1024n, maximumSnapshot);

  expect(fixture.failures).toEqual([]);
  expect(fixture.client.pendingSnapshot?.bytes.byteLength).toBe(1024 * 1024 - 9);
  expect(fixture.outputQueue.length).toBe(0);
  expect(fixture.client.creditAvailable).toBe(64 * 1024 + 9);
});

test("a Snapshot without enough credit or replaceable output is rejected", () => {
  const fixture = snapshotReceiver(64 * 1024, 0);

  fixture.client.acceptSnapshot(1024n, new Uint8Array(128 * 1024));

  expect(fixture.failures).toEqual(["server sent a stale snapshot or exceeded output credit"]);
  expect(fixture.client.receivedOutSeq).toBe(0n);
  expect(fixture.client.pendingSnapshot).toBeUndefined();
  expect(fixture.client.creditAvailable).toBe(64 * 1024);
});
