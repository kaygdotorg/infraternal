/** The "Not saved" notice waits about a second before it shows (D358, #395), and costs nothing at idle. */
import { expect, test } from "bun:test";
import { PENDING_NOTICE_DELAY_MS, watchPendingNotice } from "./pending-notice";

/** Hand-stepped timers: `advance(ms)` fires whatever is due; `armed` counts the timers still waiting. */
function fakeTimers() {
  let now = 0, serial = 0;
  const due = new Map<number, { at: number; run: () => void }>();
  return {
    timers: {
      set: (run: () => void, ms: number) => { due.set(++serial, { at: now + ms, run }); return serial; },
      clear: (id: number | undefined) => { if (id !== undefined) due.delete(id); },
    },
    advance(ms: number) {
      now += ms;
      for (const [id, entry] of [...due]) if (entry.at <= now) { due.delete(id); entry.run(); }
    },
    get armed() { return due.size; },
  };
}

/** A notice double that records what is on screen. */
function notice() {
  const state = { shown: false, shows: 0 };
  return { state, notice: { show: () => { state.shown = true; state.shows++; }, hide: () => { state.shown = false; } } };
}

test("the delay is about one second", () => {
  expect(PENDING_NOTICE_DELAY_MS).toBe(1000);
});

test("an edit confirmed before the delay never shows the notice, and nothing stays armed", () => {
  const clock = fakeTimers(), { state, notice: n } = notice();
  let pending = false;
  const watch = watchPendingNotice(() => pending, n, PENDING_NOTICE_DELAY_MS, clock.timers);
  expect(clock.armed).toBe(0);
  pending = true; watch.update();
  expect(clock.armed).toBe(1);
  clock.advance(400);
  pending = false; watch.update();
  expect(clock.armed).toBe(0);
  clock.advance(5000);
  expect(state.shows).toBe(0);
});

test("an edit still waiting after the delay shows the notice until every edit is saved", () => {
  const clock = fakeTimers(), { state, notice: n } = notice();
  let pending = true;
  const watch = watchPendingNotice(() => pending, n, PENDING_NOTICE_DELAY_MS, clock.timers);
  watch.update();
  clock.advance(999);
  expect(state.shown).toBe(false);
  clock.advance(1);
  expect(state.shown).toBe(true);
  // More edits arrive while it shows: it stays, once, with no new timer.
  watch.update(); watch.update();
  expect(state.shows).toBe(1); expect(clock.armed).toBe(0);
  clock.advance(10_000);
  expect(state.shown).toBe(true);
  pending = false; watch.update();
  expect(state.shown).toBe(false);
});

test("a stream of quick edits keeps one timer from the first waiting edit, not one per edit", () => {
  const clock = fakeTimers(), { state, notice: n } = notice();
  let pending = true;
  const watch = watchPendingNotice(() => pending, n, PENDING_NOTICE_DELAY_MS, clock.timers);
  for (let i = 0; i < 5; i++) { watch.update(); clock.advance(300); }
  // The queue never emptied, so the first waiting edit is now 1.5 s old.
  expect(state.shown).toBe(true); expect(clock.armed).toBe(0);
  pending = false; watch.update();
  pending = true; watch.update();
  // A new wait starts the clock again from zero.
  expect(state.shown).toBe(false); expect(clock.armed).toBe(1);
});

test("dispose hides the notice and disarms the timer", () => {
  const clock = fakeTimers(), { state, notice: n } = notice();
  const watch = watchPendingNotice(() => true, n, PENDING_NOTICE_DELAY_MS, clock.timers);
  watch.update(); watch.dispose();
  expect(clock.armed).toBe(0);
  clock.advance(5000);
  expect(state.shows).toBe(0);
});
