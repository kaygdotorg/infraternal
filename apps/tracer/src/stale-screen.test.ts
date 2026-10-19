/**
 * The stale-screen note (D309): a program that redraws after reattach never shows it, a shell that
 * stays silent does, and output arriving later takes it down.
 */
import { expect, test } from "bun:test";
import { STALE_WAIT_MAX_MS, STALE_WAIT_MIN_MS, StaleScreenWatch, staleWaitMs, type StaleScreenScheduler } from "./stale-screen";

function harness() {
  const timers = new Map<number, { at: number; run: () => void }>();
  let now = 0;
  let next = 1;
  const scheduler: StaleScreenScheduler = {
    after: (ms, run) => { const id = next++; timers.set(id, { at: now + ms, run }); return id; },
    cancel: (handle) => { timers.delete(handle as number); },
  };
  const changes: boolean[] = [];
  const watch = new StaleScreenWatch((shown) => changes.push(shown), scheduler);
  const advance = (ms: number): void => {
    now += ms;
    for (const [id, timer] of [...timers]) if (timer.at <= now) { timers.delete(id); timer.run(); }
  };
  return { watch, changes, advance };
}

test("a program that redraws after reattach never shows the note, not for a frame", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400);
  advance(120); // the repaint arrives inside the wait
  watch.output(180n);
  advance(2000);
  expect(changes).toEqual([]);
  expect(watch.shown).toBe(false);
});

test("a redraw that arrived before the replay painted needs no wait at all", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 150n, 400);
  advance(2000);
  expect(changes).toEqual([]);
  expect(watch.watching).toBe(false);
});

test("a shell that stays silent shows the note once the wait has run out", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400);
  advance(399);
  expect(changes).toEqual([]);
  advance(1);
  expect(changes).toEqual([true]);
  expect(watch.shown).toBe(true);
});

test("output that arrives later clears the note", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400);
  advance(400);
  watch.output(100n); // nothing new: still shown
  expect(changes).toEqual([true]);
  watch.output(101n);
  expect(changes).toEqual([true, false]);
  expect(watch.watching).toBe(false);
});

test("a dropped link takes the note down and cancels a wait that has not ended", () => {
  const first = harness();
  first.watch.begin(5n, 5n, 400);
  first.watch.reset();
  first.advance(2000);
  expect(first.changes).toEqual([]);
  const second = harness();
  second.watch.begin(5n, 5n, 400);
  second.advance(400);
  second.watch.reset();
  expect(second.changes).toEqual([true, false]);
});

test("the wait grows with the round trip and stays bounded", () => {
  expect(staleWaitMs(undefined)).toBe(STALE_WAIT_MIN_MS);
  expect(staleWaitMs(NaN)).toBe(STALE_WAIT_MIN_MS);
  expect(staleWaitMs(0)).toBe(STALE_WAIT_MIN_MS);
  expect(staleWaitMs(200)).toBe(800);
  expect(staleWaitMs(10_000)).toBe(STALE_WAIT_MAX_MS);
});
