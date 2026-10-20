/** Role: keep per-socket lifecycle receipts useful without retaining peer-provided close text (#146). */
import { expect, test } from "bun:test";
import { runInNewContext } from "node:vm";
import { encodeMuxedFrame } from "../../../../packages/protocol/src/codec";

async function lifecycle(reason: string, server = false, probes = false): Promise<{ opened: number; closed: number; history: Array<{ event: string; reason?: string; socket: number; probes?: { pending: Array<{ nonce: string; sentUs: string; ageMs: number }>; lastPongMs: number | null; lastInboundMs: number | null; bufferedBytes: number; hidden: boolean } }> }> {
  const result = await Bun.build({ entrypoints: [import.meta.dirname + "/bench-probe.ts"], target: "browser", format: "iife" });
  expect(result.success).toBe(true);
  type Event = { code?: number; reason?: string; wasClean?: boolean; data?: ArrayBuffer };
  const events = new Map<string, Array<(event: Event) => void>>();
  class Socket {
    bufferedAmount = 0;
    addEventListener(name: string, listener: (event: Event) => void): void { events.set(name, [...(events.get(name) ?? []), listener]); }
    send(_data: Uint8Array): void {}
    close(_code?: number, _reason?: string): void {}
  }
  let clock = 1;
  const scope = { window: { addEventListener(): void {} }, document: { hidden: false }, WebSocket: Socket, Worker: class {}, TextDecoder, TextEncoder,
    performance: { timeOrigin: 1000, now: () => clock }, Uint8Array, ArrayBuffer, setTimeout, clearTimeout };
  runInNewContext(await result.outputs[0]!.text(), scope);
  const socket = new scope.WebSocket();
  for (const listener of events.get("open") ?? []) listener({});
  if (probes) {
    socket.send(encodeMuxedFrame(0, { type: "Ping", nonce: 1n, sentUs: 1000n }));
    clock = 2;
    socket.send(encodeMuxedFrame(0, { type: "Ping", nonce: 2n, sentUs: 2000n }));
    clock = 10;
    const reply = encodeMuxedFrame(0, { type: "Pong", nonce: 2n, sentUs: 2000n });
    for (const listener of events.get("message") ?? []) listener({ data: reply.slice().buffer });
    clock = 11;
    socket.send(encodeMuxedFrame(0, { type: "Ping", nonce: 3n, sentUs: 11000n }));
    clock = 20;
    const unrelated = encodeMuxedFrame(0, { type: "Pong", nonce: 3n, sentUs: 11001n });
    for (const listener of events.get("message") ?? []) listener({ data: unrelated.slice().buffer });
    clock = 601;
  }
  if (server) {
    const frame = encodeMuxedFrame(0, { type: "Close", code: 1001, reason });
    for (const listener of events.get("message") ?? []) listener({ data: frame.slice().buffer });
  }
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

test("a retirement records unanswered probes without reviving cumulatively answered ones", async () => {
  const rows = await lifecycle("connection unresponsive", false, true);
  expect(rows.history.find(row => row.event === "client-close")?.probes).toEqual({
    pending: [{ nonce: "3", sentUs: "11000", ageMs: 590 }],
    lastPongMs: 591, lastInboundMs: 581, bufferedBytes: 0, hidden: false,
  });
});


test("a protocol close retains only its registered reason", async () => {
  const rows = await lifecycle("the server was too busy to confirm the session", true);
  expect(rows.history.find(row => row.event === "server-close")?.reason).toBe("The server was too busy to confirm your session.");
  const unknown = await lifecycle("unrecognized-private-text", true);
  expect(JSON.stringify(unknown)).not.toContain("unrecognized-private-text");
});
