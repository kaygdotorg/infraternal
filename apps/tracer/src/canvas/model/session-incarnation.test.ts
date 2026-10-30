/** Pending edits stay with their original authenticated lifetime across reconnects (D312, R250-02). */
import { expect, test } from "bun:test";
import { ServerCanvasStore, type LayoutTransport } from "./server-store";
import type { CanvasDocument } from "./schema";

const document = (): CanvasDocument => ({ format: "infraternal.canvas", version: 1, revision: 1, views: [{ id: "console", kind: "console", name: "Saved", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [] } }] });
class Transport implements LayoutTransport {
  sessionIncarnation = "original";
  isWelcomed = true;
  calls: Record<string, unknown>[] = [];
  event: (event: Record<string, unknown>) => void = () => {};
  open = () => {};
  call(_action: string, input: Record<string, unknown>): Promise<Record<string, unknown>> { this.calls.push(input); return new Promise(() => {}); }
  subscribe(_filter: { topic: string }, event: (event: Record<string, unknown>) => void, open?: () => void) {
    this.event = event; this.open = open ?? (() => {}); this.open();
    return Object.assign(() => {}, { resync: () => this.open() });
  }
  snapshot(): void { this.event({ type: "canvas.layout.snapshot", revision: 1, document: document(), initialized: true }); }
}
for (const replacement of ["original", "replacement"]) test(`reconnect ${replacement} fences unsent work before the snapshot pump`, async () => {
  const transport = new Transport(); let lost = 0;
  const store = new ServerCanvasStore(transport, "session-test", (definitive) => { if (definitive) lost++; });
  try {
    transport.snapshot(); transport.isWelcomed = false;
    const next = document(); next.views[0]!.name = "Unconfirmed"; await store.save(next);
    expect(store.pending).toBe(true); expect(transport.calls).toHaveLength(0);
    transport.sessionIncarnation = replacement; transport.isWelcomed = true; transport.open(); transport.snapshot();
    if (replacement === "original") {
      expect(transport.calls).toHaveLength(1); expect(transport.calls[0]!.session_incarnation).toBe("original"); expect(lost).toBe(0);
    } else {
      expect(transport.calls).toHaveLength(0); expect(store.pending).toBe(false); expect(lost).toBe(1); expect(store.current()).toEqual(document());
      await store.save(next); expect(transport.calls).toHaveLength(0);
    }
  } finally { store.dispose(); }
});
