/** Pending edits stay with their original authenticated lifetime across reconnects (D312, R250-02). */
import { expect, test } from "bun:test";
import { ServerCanvasStore, type LayoutTransport } from "./server-store";
import type { CanvasDocument } from "./schema";

const document = (name = "Saved"): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 1, views: [{ id: "console", kind: "console", name, cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
const emptyDocument = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 0, views: [] });
class Transport implements LayoutTransport {
  sessionIncarnation: string | undefined = "original";
  isWelcomed = true;
  calls: Record<string, unknown>[] = [];
  event: (event: Record<string, unknown>) => void = () => {};
  open = () => {};
  call(_action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> { this.calls.push(input); return new Promise(() => {}); }
  subscribe(_filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void) {
    this.event = event; this.open = open ?? (() => {}); this.open();
    return Object.assign(() => {}, { resync: () => this.open() });
  }
  snapshot(value = document()): void { this.event({ type: "canvas.layout.snapshot", revision: 1, document: value, initialized: true }); }
}
for (const replacement of ["original", "replacement"]) test(`reconnect ${replacement} fences unsent work before the snapshot pump`, async () => {
  const transport = new Transport(); let lost = 0;
  const store = new ServerCanvasStore(transport, "session-test", () => {}, (work) => { if (work === "unsent") lost++; });
  try {
    transport.snapshot(); transport.isWelcomed = false;
    const next = document(); next.views[0]!.name = "Unconfirmed"; await store.save(next);
    expect(store.pending).toBe(true); expect(transport.calls).toHaveLength(0);
    transport.sessionIncarnation = replacement; transport.isWelcomed = true; transport.open(); transport.snapshot();
    if (replacement === "original") {
      expect(transport.calls).toHaveLength(1); expect(transport.calls[0]!.session_incarnation).toBe("original"); expect(lost).toBe(0);
    } else {
      expect(transport.calls).toHaveLength(0); expect(store.pending).toBe(false); expect(lost).toBe(1); expect(store.current()).toEqual(emptyDocument());
      await store.save(next); expect(store.pending).toBe(false); expect(store.current()).toEqual(emptyDocument()); expect(transport.calls).toHaveLength(0);
    }
  } finally { store.dispose(); }
});

test("queued work with no original binding cannot adopt a later incarnation", async () => {
  const transport = new Transport(); transport.sessionIncarnation = undefined;
  let lost = 0;
  const store = new ServerCanvasStore(transport, "session-test", () => {}, (work) => { if (work === "unsent") lost++; });
  try {
    transport.snapshot(); transport.isWelcomed = false;
    const next = document(); next.views[0]!.name = "Unbound edit"; await store.save(next);
    transport.sessionIncarnation = "replacement"; transport.isWelcomed = true; transport.open(); transport.snapshot(document("Replacement account"));
    expect(transport.calls).toHaveLength(0); expect(store.pending).toBe(false); expect(lost).toBe(1);
    expect(store.current()).toEqual(emptyDocument());
  } finally { store.dispose(); }
});

test("a session-incarnation change ends the old canvas and refuses later edits", async () => {
  const transport = new Transport(); const lost: string[] = [];
  const store = new ServerCanvasStore(transport, "session-test", () => {}, (work) => { lost.push(work); });
  try {
    transport.snapshot();
    transport.sessionIncarnation = "replacement";
    transport.open();
    transport.snapshot(document("Replacement account"));
    expect(lost).toEqual(["none"]);
    expect(store.pending).toBe(false);
    expect(store.current()).toEqual(emptyDocument());
    await store.save(document("Late edit"));
    expect(store.pending).toBe(false);
    expect(store.current()).toEqual(emptyDocument());
    expect(transport.calls).toHaveLength(0);
  } finally { store.dispose(); }
});

test("a revoked store does not adopt a replacement account snapshot", () => {
  const transport = new Transport();
  const store = new ServerCanvasStore(transport, "session-test");
  try {
    transport.snapshot();
    transport.sessionIncarnation = "replacement";
    transport.open();
    transport.snapshot(document("Replacement account"));
    expect(store.current()).toEqual(emptyDocument());
  } finally { store.dispose(); }
});

class ReceiptTransport extends Transport {
  receipts: Array<(result: Record<string, unknown>) => void> = [];
  override call(_action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.calls.push(input); return new Promise((resolve) => { this.receipts.push(resolve); });
  }
}
const revokeAfter = async (receipt: boolean): Promise<string[]> => {
  const transport = new ReceiptTransport(); const work: string[] = [];
  const store = new ServerCanvasStore(transport, "session-test", () => {}, (value) => { work.push(value); });
  try {
    transport.snapshot();
    const next = document(); next.views[0]!.name = "Renamed"; await store.save(next);
    expect(transport.calls).toHaveLength(1);
    // R250-R3-01: the receipt arrives, its ordered event does not, then the sign-in is replaced.
    if (receipt) { transport.receipts[0]!({ revision: 2 }); await Promise.resolve(); await Promise.resolve(); }
    transport.sessionIncarnation = "replacement"; transport.open();
    return work;
  } finally { store.dispose(); }
};
test("R250-R3-01: a server-confirmed edit is never reported as lost on session replacement", async () => {
  expect(await revokeAfter(true)).toEqual(["none"]);
});
test("a sent edit without a receipt is reported as uncertain, not lost", async () => {
  expect(await revokeAfter(false)).toEqual(["unconfirmed"]);
});
