/** Shared-view reconciliation must leave camera state pointing at a surviving view (#243, D178, D248). */
import { expect, test } from "bun:test";
import type { Ctx, ViewRec } from "../context";

Object.defineProperty(globalThis, "matchMedia", {
  configurable: true,
  value: () => ({ matches: false, addEventListener() {}, removeEventListener() {} }),
});
const { reconcile } = await import("./reconcile");

test("review: removing the current shared view selects a surviving camera anchor", async () => {
  const consoleView = { view: { id: "console" } } as unknown as ViewRec;
  const settingsView = { view: { id: "settings" }, wins: new Map() } as unknown as ViewRec;
  const views = new Map<string, ViewRec>([["console", consoleView], ["settings", settingsView]]);
  const state = { currentView: "console", activeWin: undefined };
  let settledAnchor = "", flownTo = "";
  const cx = {
    views,
    state,
    nav: { flyView(id: string) { flownTo = id; state.currentView = id; } },
    view: {
      remove(view: ViewRec) { views.delete(view.view.id); },
      settle(id: string) { settledAnchor = id; },
    },
    win: { setActive() {} },
    visibility: { unwatch() {}, lodChanged() {} },
    store: { reset() {}, changed() {}, uncommittedWindows: () => new Set(), uncommittedViews: () => new Set() },
    adapters: {},
    tree: { render() {} },
    pill: { paint() {} },
    toolbar: { update() {} },
  } as unknown as Ctx;

  await reconcile(cx, () => ({
    document: { format: "infraternal.canvas", version: 1, revision: 2, views: [] },
    protectedIds: new Set(), protectedViews: new Set(),
  }), () => undefined, () => true);

  expect(flownTo).toBe("settings");
  expect(state.currentView).toBe("settings");
  expect(settledAnchor).toBe("settings");
  expect(views.has(state.currentView)).toBe(true);
});
