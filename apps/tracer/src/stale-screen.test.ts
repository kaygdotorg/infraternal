/**
 * The stale-screen note (D309): a program that redraws after reattach never shows it, a shell that
 * stays silent does when the attach resized it, and output arriving later takes it down. A reattach
 * at the size the replay was captured at expects no repaint, so silence there is never a note (#257).
 */
import { expect, test } from "bun:test";
import { repaintExpected, replayedSize, STALE_WAIT_MAX_MS, STALE_WAIT_MIN_MS, StaleScreenWatch, staleWaitMs, type ScreenSize, type StaleScreenScheduler } from "./stale-screen";

const ATTACH: ScreenSize = { cols: 120, rows: 40 };
/** What an older server reports: no size, so the wait is decided as it always was. */
const UNREPORTED = undefined;
const SAME: ScreenSize = { cols: 120, rows: 40 };
const RESIZED: ScreenSize = { cols: 80, rows: 24 };

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
  watch.begin(100n, 100n, 400, UNREPORTED, ATTACH);
  advance(120); // the repaint arrives inside the wait
  watch.output(180n);
  advance(2000);
  expect(changes).toEqual([]);
  expect(watch.shown).toBe(false);
});

test("a redraw that arrived before the replay painted needs no wait at all", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 150n, 400, UNREPORTED, ATTACH);
  advance(2000);
  expect(changes).toEqual([]);
  expect(watch.watching).toBe(false);
});

test("a shell that stays silent shows the note once the wait has run out", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400, UNREPORTED, ATTACH);
  advance(399);
  expect(changes).toEqual([]);
  advance(1);
  expect(changes).toEqual([true]);
  expect(watch.shown).toBe(true);
});

test("output that arrives later clears the note", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400, UNREPORTED, ATTACH);
  advance(400);
  watch.output(100n); // nothing new: still shown
  expect(changes).toEqual([true]);
  watch.output(101n);
  expect(changes).toEqual([true, false]);
  expect(watch.watching).toBe(false);
});

test("an idle shell reattached at the same size is correctly silent and never shows the note", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400, SAME, ATTACH);
  expect(watch.watching).toBe(false);
  advance(5000);
  expect(changes).toEqual([]);
  expect(watch.shown).toBe(false);
});

test("a shell that stays silent after the attach resized it shows the note", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400, RESIZED, ATTACH);
  advance(399);
  expect(changes).toEqual([]);
  advance(1);
  expect(changes).toEqual([true]);
});

test("a resized program that repaints never shows the note, not for a frame", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400, RESIZED, ATTACH);
  advance(60);
  watch.output(220n);
  advance(5000);
  expect(changes).toEqual([]);
});

test("one changed dimension is a resize", () => {
  expect(repaintExpected({ cols: 120, rows: 41 }, ATTACH)).toBe(true);
  expect(repaintExpected({ cols: 121, rows: 40 }, ATTACH)).toBe(true);
  expect(repaintExpected(SAME, ATTACH)).toBe(false);
});

test("output after the note, on a resized reattach, clears it", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400, RESIZED, ATTACH);
  advance(400);
  expect(changes).toEqual([true]);
  watch.output(101n);
  expect(changes).toEqual([true, false]);
});

test("a server that reports no size keeps the wait", () => {
  const { watch, changes, advance } = harness();
  watch.begin(100n, 100n, 400, UNREPORTED, ATTACH);
  expect(watch.watching).toBe(true);
  advance(400);
  expect(changes).toEqual([true]);
});

test("the replay fence reports a size only when both fields are usable", () => {
  expect(replayedSize({ type: "terminal.replay_complete", out_seq: "0", cols: 80, rows: 24 })).toEqual({ cols: 80, rows: 24 });
  expect(replayedSize({ type: "terminal.replay_complete", out_seq: "0" })).toBeUndefined();
  expect(replayedSize({ cols: 80 })).toBeUndefined();
  expect(replayedSize({ rows: 24 })).toBeUndefined();
  for (const bad of [0, -1, 65536, 80.5, "80", null, NaN]) expect(replayedSize({ cols: bad, rows: 24 })).toBeUndefined();
});

test("a dropped link takes the note down and cancels a wait that has not ended", () => {
  const first = harness();
  first.watch.begin(5n, 5n, 400, UNREPORTED, ATTACH);
  first.watch.reset();
  first.advance(2000);
  expect(first.changes).toEqual([]);
  const second = harness();
  second.watch.begin(5n, 5n, 400, UNREPORTED, ATTACH);
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
