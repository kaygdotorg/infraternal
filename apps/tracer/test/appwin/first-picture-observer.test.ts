/** Role: exercise first-picture timestamps independently of polling and later pictures (#146). */
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

test("each open uses the page clock and latches only its first live picture", () => {
  let now = 10;
  let changed = () => {};
  let disconnected = false;
  const cards = [{ live: false, dataset: { windowId: "canvas-a" }, querySelector() { return this.live ? {} : null; } },
    { live: false, dataset: { windowId: "canvas-b" }, querySelector() { return this.live ? {} : null; } }];
  const scope = { window: {} as { __firstPictures: { open(index: number): void; rows(): unknown; stop(): void } },
    document: { querySelectorAll: () => cards, documentElement: {} }, performance: { now: () => now },
    MutationObserver: class {
      constructor(callback: () => void) { changed = callback; }
      observe() {} disconnect() { disconnected = true; }
    } };
  runInNewContext(readFileSync(new URL("first-picture-observer.js", import.meta.url), "utf8"), scope);
  const clock = scope.window.__firstPictures;
  clock.open(0);
  now = 15; clock.open(1);
  expect(clock.rows()).toEqual([
    { fixture_index: 1, window_id: "canvas-a", open_ms: 10, first_picture_ms: null, elapsed_ms: null },
    { fixture_index: 2, window_id: "canvas-b", open_ms: 15, first_picture_ms: null, elapsed_ms: null },
  ]);
  now = 20; cards[1]!.live = true; changed();
  now = 30; cards[0]!.live = true; changed();
  now = 90; changed();
  expect(clock.rows()).toEqual([
    { fixture_index: 1, window_id: "canvas-a", open_ms: 10, first_picture_ms: 30, elapsed_ms: 20 },
    { fixture_index: 2, window_id: "canvas-b", open_ms: 15, first_picture_ms: 20, elapsed_ms: 5 },
  ]);
  clock.stop(); expect(disconnected).toBe(true);
});
