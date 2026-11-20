/** When a tab whose connection went to a newer tab says so, and when it stays quiet (#523, owner decision B). */
import { expect, test } from "bun:test";
import { CONNECTION_LIMIT_REASON } from "../close-reasons";
import { PAUSED_NOTICE_DELAY_MS, watchTakeover, type TakeoverProblem } from "./takeover-notice";

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

/** A page double: visibility the test flips, and a toast that records what is on screen. */
function page(hidden: boolean) {
  const state: { hidden: boolean; shown: TakeoverProblem | undefined; shows: number } = { hidden, shown: undefined, shows: 0 };
  const clock = fakeTimers();
  const watch = watchTakeover(
    { show: (problem) => { state.shown = problem; state.shows++; }, hide: () => { state.shown = undefined; } },
    () => state.hidden,
    PAUSED_NOTICE_DELAY_MS,
    clock.timers,
  );
  return { state, clock, watch };
}

test("a hidden tab that is taken over shows nothing, and arms no timer, while it stays hidden", () => {
  const { state, clock, watch } = page(true);
  watch.paused(true);
  clock.advance(60_000);
  expect(state.shows).toBe(0);
  expect(clock.armed).toBe(0);
});

test("a tab that comes back and reconnects quickly never shows the pause", () => {
  const { state, clock, watch } = page(true);
  watch.paused(true);
  state.hidden = false;
  watch.visibility();
  clock.advance(PAUSED_NOTICE_DELAY_MS - 1);
  watch.paused(false);
  watch.welcomed();
  clock.advance(10_000);
  expect(state.shows).toBe(0);
  expect(clock.armed).toBe(0);
});

test("a shown tab still paused after the wait says it is paused, until the welcome", () => {
  const { state, clock, watch } = page(true);
  watch.paused(true);
  state.hidden = false;
  watch.visibility();
  clock.advance(PAUSED_NOTICE_DELAY_MS);
  expect(state.shown).toBe("paused");
  watch.welcomed();
  expect(state.shown).toBeUndefined();
  expect(clock.armed).toBe(0);
});

test("going hidden again before the wait ends drops the wait", () => {
  const { state, clock, watch } = page(false);
  watch.paused(true);
  state.hidden = true;
  watch.visibility();
  clock.advance(PAUSED_NOTICE_DELAY_MS * 5);
  expect(state.shows).toBe(0);
  expect(clock.armed).toBe(0);
});

test("a reconnect refused for the account's limit names it at once; other refusals stay quiet", () => {
  const { state, clock, watch } = page(false);
  watch.refused("the server refused the terminal attachment");
  watch.refused(undefined);
  expect(state.shows).toBe(0);
  watch.paused(true);
  watch.refused(CONNECTION_LIMIT_REASON);
  expect(state.shown).toBe("limit");
  // The pause wait does not replace the limit with the softer words.
  clock.advance(PAUSED_NOTICE_DELAY_MS * 2);
  expect(state.shown).toBe("limit");
  expect(state.shows).toBe(1);
});

test("after the person presses the action, the next refusal shows again; a replaced toast does not clear the new one", () => {
  const { state, clock, watch } = page(false);
  watch.paused(true);
  clock.advance(PAUSED_NOTICE_DELAY_MS);
  expect(state.shown).toBe("paused");
  // The limit replaces the pause in place; the paused toast's close must not forget the limit is up.
  watch.refused(CONNECTION_LIMIT_REASON);
  watch.gone("paused");
  expect(state.shown).toBe("limit");
  watch.refused(CONNECTION_LIMIT_REASON);
  expect(state.shows).toBe(2);
  // The person pressed Try again: the toast left the screen by itself (assigned through Object.assign so the
  // compiler does not narrow `state.shown` to undefined for the checks below).
  Object.assign(state, { shown: undefined });
  watch.gone("limit");
  watch.refused(CONNECTION_LIMIT_REASON);
  expect(state.shown).toBe("limit");
  expect(state.shows).toBe(3);
});

test("dispose takes the toast down and ends everything", () => {
  const { state, clock, watch } = page(false);
  watch.paused(true);
  watch.dispose();
  clock.advance(PAUSED_NOTICE_DELAY_MS * 2);
  watch.refused(CONNECTION_LIMIT_REASON);
  expect(state.shows).toBe(0);
  expect(clock.armed).toBe(0);
});
