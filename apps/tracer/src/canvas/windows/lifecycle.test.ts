/** Closing a retained canvas record releases its binding once, even during feature withdrawal (#146). */
import { expect, test } from "bun:test";
import type { Ctx, ViewRec, WinRec } from "../context";

test("repeated immediate close retires a binding only once", async () => {
  const prior = globalThis.matchMedia;
  globalThis.matchMedia ??= (() => ({ matches: false })) as unknown as typeof matchMedia;
  const { createWindows } = await import("./lifecycle");
  let disposed = 0, cleaned = 0;
  const owner = { wins: new Map(), colsEl: {}, view: { id: "console" } } as unknown as ViewRec;
  const rec = {
    owner, model: { id: "app", kind: "app" },
    card: { root: { parentElement: null, offsetHeight: 10, remove() {}, style: {} } },
    binding: { dispose: () => disposed++ }, cleanup: () => cleaned++,
  } as unknown as WinRec;
  owner.wins.set(rec.model.id, rec);
  const cx = {
    state: {}, views: new Map(), camera: {}, inputLock: {}, adapters: {},
    flip: { targets: () => [], measure: () => [] }, visibility: { unwatch() {} },
    view: { geometry() {}, paintEmpty() {}, settle() {} }, tree: { render() {} }, store: { changed() {} },
  } as unknown as Ctx;
  try {
    const windows = createWindows(cx);
    windows.close(rec, true);
    windows.close(rec, true);
    expect(disposed).toBe(1);
    expect(cleaned).toBe(1);
    expect(owner.wins.size).toBe(0);
  } finally {
    if (prior) globalThis.matchMedia = prior;
    else Reflect.deleteProperty(globalThis, "matchMedia");
  }
});
