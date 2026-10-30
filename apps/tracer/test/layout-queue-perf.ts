/** Prebuilt browser-only queue probe for the approved locked-perf-VM matrix; never a production entry point (D312). */
import { LayoutJournal } from "../src/canvas/model/journal";
import type { CanvasDocument } from "../src/canvas/model/schema";
interface ProbeResult { windows: number; queued: number; captureMaxMs: number; captureP99Ms: number; rebaseMs: number; reconnectMs: number; retained: number }
const probe = globalThis as unknown as { layoutQueueProbe: { seed(windows: number, queued: number): ProbeResult; clear(): void } };
let journal: LayoutJournal | undefined;
probe.layoutQueueProbe = {
  seed(count, queued) {
    const canonical: CanvasDocument = { format: "infraternal.canvas", version: 1, revision: 1, views: [{ id: "console", kind: "console", name: "Console", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [{ id: "c", weight: 1, windows: Array.from({ length: count }, (_, n) => ({ id: `w${n}`, target: { type: "settings" as const, section: "appearance" } })) }] } }] };
    journal = new LayoutJournal();
    journal.accept({ type: "canvas.layout.snapshot", revision: 1, document: canonical, initialized: true });
    const captures: number[] = [];
    for (let n = 0; n < queued; n++) {
      const before = journal.current(), next = structuredClone(before);
      if (n % 2) next.views[0]!.cell.x = n % 1000; else next.views[0]!.name = `Queued ${n}`;
      const start = performance.now(); journal.capture(next, undefined, before); captures.push(performance.now() - start);
    }
    const newer = structuredClone(canonical); newer.revision = 2;
    let start = performance.now();
    journal.accept({ type: "canvas.layout.snapshot", revision: 2, document: newer, initialized: true }); journal.current();
    const rebaseMs = performance.now() - start;
    // Reserve the ordinary four-call pipeline, then reconnect without receipts. Inputs stay retained.
    for (let n = 0; n < 4; n++) journal.next();
    start = performance.now(); journal.restart();
    journal.accept({ type: "canvas.layout.snapshot", revision: 2, document: newer, initialized: true }); journal.current();
    for (let n = 0; n < 4; n++) journal.next();
    const reconnectMs = performance.now() - start;
    captures.sort((a, b) => a - b);
    return { windows: count, queued, captureMaxMs: captures.at(-1)!, captureP99Ms: captures[Math.floor(captures.length * 0.99)]!, rebaseMs, reconnectMs, retained: journal.pending.length };
  },
  clear() { journal?.clear(); journal = undefined; },
};
