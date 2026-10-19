/** Shared-layout receipts preserve this device's temporary app streams and their live bindings (#146, D208). */
import { expect, test } from "bun:test";
import type { Ctx, ViewRec, WinRec } from "../context";
import { metricsFor } from "../layout/geometry";
import { registerGroups, type Groups } from "../layout/groups-handle";
import { toDocument } from "./document";
import type { ViewModel, WindowModel } from "./types";

test("a canonical receipt keeps temporary streams without re-journaling them", async () => {
  const prior = globalThis.matchMedia;
  globalThis.matchMedia ??= (() => ({ matches: false })) as unknown as typeof matchMedia;
  const { reconcile } = await import("./reconcile");
  if (prior) globalThis.matchMedia = prior;
  let disposed = 0, changed = 0;
  const models: WindowModel[] = ["app", "screen", "flow"].map((kind) => ({ id: kind, kind: kind as WindowModel["kind"], host: "local" }));
  const metrics = metricsFor(1440, 900, false);
  const view: ViewModel = { id: "console", name: "Console", layout: "tiled", x: 0, y: 0, nodes: [], cols: [{ id: "local", w: metrics.colW, wins: models }] };
  const wins = new Map(models.map((model) => [model.id, {
    model, binding: { dispose: () => disposed++ }, card: { dispose: () => disposed++ },
  } as unknown as WinRec]));
  const record = { view, wins } as unknown as ViewRec;
  const cx = {
    views: new Map([[view.id, record]]), state: { metrics, activeWin: wins.get("app") },
    view: { geometry() {}, paintEmpty() {} }, win: { setActive() {} },
    visibility: { unwatch() {}, lodChanged() {} }, adapters: {},
    store: { reset() {}, changed: () => changed++ }, tree: { render() {} }, pill: { paint() {} }, toolbar: { update() {} },
  } as unknown as Ctx;
  registerGroups({ applyCols() {} } as unknown as Groups);
  try {
    await reconcile(cx, () => ({ document: toDocument([view], metrics, 0), protectedIds: new Set(), protectedViews: new Set() }), () => undefined, () => true);
    expect(disposed).toBe(0);
    expect([...record.wins.keys()]).toEqual(["app", "screen", "flow"]);
    expect(record.view.cols.flatMap((column) => column.wins)).toEqual(models);
    expect(changed).toBe(0);
  } finally {
    // Other suites may load the real grouped implementation after this test.
    const { groups } = await import("../layout/groups.on-demand");
    registerGroups(groups);
    if (!prior) Reflect.deleteProperty(globalThis, "matchMedia");
  }
});
