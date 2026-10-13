/** Keeps delayed palette selections attached to the window selected before the action chunk loads (#194). */
import { expect, test } from "bun:test";
import type { Ctx, WinRec } from "../context";
const previousMatchMedia = globalThis.matchMedia;
globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
const { dispatchCanvasAction } = await import("./palette-actions.on-demand");
if (previousMatchMedia) globalThis.matchMedia = previousMatchMedia;
else Reflect.deleteProperty(globalThis, "matchMedia");

test.each(["split:right", "new:below", "close"])("a deferred %s selection retains its original window", (action) => {
  const selected = { model: { id: "selected", kind: "terminal" }, owner: { wins: new Map() } } as unknown as WinRec;
  selected.owner.wins.set(selected.model.id, selected);
  const current = { model: { id: "current", kind: "terminal" } } as WinRec;
  const targets: WinRec[] = [];
  const cx = { state: { activeWin: current }, core: {}, views: new Map(), win: {
    split: (rec: WinRec) => targets.push(rec), newWindow: (rec: WinRec) => targets.push(rec), closeKey: (rec: WinRec) => targets.push(rec),
  } } as unknown as Ctx;
  // Passing the captured target reproduces a focus change during the pending chunk load.
  Reflect.apply(dispatchCanvasAction, undefined, [cx, { action: `canvas:${action}` }, selected]);
  expect(targets).toEqual([selected]);
  targets.length = 0;
  selected.owner.wins.delete(selected.model.id);
  dispatchCanvasAction(cx, { action: `canvas:${action}` }, selected);
  expect(targets).toEqual([]);
});
