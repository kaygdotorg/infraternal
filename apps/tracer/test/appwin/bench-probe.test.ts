/** Role: keep per-socket lifecycle receipts useful without retaining peer-provided close text (#146). */
import { expect, test } from "bun:test";
import { runInNewContext } from "node:vm";

async function lifecycle(reason: string): Promise<{ opened: number; closed: number; history: Array<{ event: string; reason?: string; socket: number }> }> {
  const result = await Bun.build({ entrypoints: [import.meta.dirname + "/bench-probe.ts"], target: "browser", format: "iife" });
  expect(result.success).toBe(true);
  type Event = { code?: number; reason?: string; wasClean?: boolean };
  const events = new Map<string, Array<(event: Event) => void>>();
  class Socket {
    addEventListener(name: string, listener: (event: Event) => void): void { events.set(name, [...(events.get(name) ?? []), listener]); }
    send(): void {}
    close(_code?: number, _reason?: string): void {}
  }
  const scope = { window: { addEventListener(): void {} }, WebSocket: Socket, Worker: class {}, TextDecoder, TextEncoder,
    performance: { timeOrigin: 1000, now: () => 1 }, Uint8Array, ArrayBuffer, setTimeout, clearTimeout };
  runInNewContext(await result.outputs[0]!.text(), scope);
  const socket = new scope.WebSocket();
  for (const listener of events.get("open") ?? []) listener({});
  socket.close(4000, reason);
  for (const listener of events.get("close") ?? []) listener({ code: 4000, reason, wasClean: true });
  return (scope.window as unknown as { __appWindowBench: { sockets: Awaited<ReturnType<typeof lifecycle>> } }).__appWindowBench.sockets;
}

test("unrecognized peer text never enters socket receipts", async () => {
  const rows = await lifecycle("unrecognized-private-text");
  expect(rows.opened).toBe(1); expect(rows.closed).toBe(1);
  expect(rows.history.map(row => row.event)).toEqual(["open", "client-close", "close"]);
  expect(rows.history.filter(row => row.reason).map(row => row.reason)).toEqual(["other", "other"]);
  expect(JSON.stringify(rows)).not.toContain("unrecognized-private-text");
});

test("a liveness retirement keeps its mapped reason and socket identity", async () => {
  const rows = await lifecycle("connection unresponsive");
  expect(rows.history[1]?.reason).toBe("The connection did not respond in time.");
  expect(rows.history.every(row => row.socket === 1)).toBe(true);
});
