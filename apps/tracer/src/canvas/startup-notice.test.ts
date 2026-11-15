/** A page whose first connection fails says why (#523): the account limit at once, other trouble after a short wait. */
import { expect, test } from "bun:test";
import { CONNECTION_LIMIT_REASON, STARTUP_NOTICE_DELAY_MS, startupProblem, watchStartup, type StartupProblem } from "./startup-notice";

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
function surface() {
  const state: { shown: StartupProblem | undefined; shows: number } = { shown: undefined, shows: 0 };
  return { state, surface: { show: (problem: StartupProblem) => { state.shown = problem; state.shows++; }, hide: () => { state.shown = undefined; } } };
}

test("only the server's exact limit reason names the limit", () => {
  expect(startupProblem(CONNECTION_LIMIT_REASON)).toBe("limit");
  expect(startupProblem(` ${CONNECTION_LIMIT_REASON} `)).toBe("limit");
  expect(startupProblem("the server refused the terminal attachment")).toBe("unreachable");
  expect(startupProblem(undefined)).toBe("unreachable");
  expect(startupProblem("")).toBe("unreachable");
});

test("an ordinary load that is welcomed in time never shows anything, and nothing stays armed", () => {
  const clock = fakeTimers(), { state, surface: s } = surface();
  const watch = watchStartup(s, STARTUP_NOTICE_DELAY_MS, clock.timers);
  clock.advance(STARTUP_NOTICE_DELAY_MS - 1);
  watch.welcomed();
  clock.advance(10_000);
  expect(state.shows).toBe(0);
  expect(clock.armed).toBe(0);
});

test("the account limit shows at once and goes on the welcome", () => {
  const clock = fakeTimers(), { state, surface: s } = surface();
  const watch = watchStartup(s, STARTUP_NOTICE_DELAY_MS, clock.timers);
  watch.closed(CONNECTION_LIMIT_REASON);
  expect(state.shown).toBe("limit");
  expect(clock.armed).toBe(0);
  // Each refused retry repeats the same reason: the notice is not rebuilt.
  watch.closed(CONNECTION_LIMIT_REASON);
  expect(state.shows).toBe(1);
  watch.welcomed();
  expect(state.shown).toBeUndefined();
  // After the welcome, closes belong to the canvas: the startup notice never comes back.
  watch.closed(CONNECTION_LIMIT_REASON);
  expect(state.shown).toBeUndefined();
});

test("a brief blip waits; a page still not welcomed after the delay says it cannot reach the server", () => {
  const clock = fakeTimers(), { state, surface: s } = surface();
  const watch = watchStartup(s, STARTUP_NOTICE_DELAY_MS, clock.timers);
  watch.closed(undefined);
  expect(state.shown).toBeUndefined();
  clock.advance(STARTUP_NOTICE_DELAY_MS);
  expect(state.shown).toBe("unreachable");
  // The limit, seen later, replaces the generic words straight away.
  watch.closed(CONNECTION_LIMIT_REASON);
  expect(state.shown).toBe("limit");
  watch.dispose();
  expect(state.shown).toBeUndefined();
  expect(clock.armed).toBe(0);
});
