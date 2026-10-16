// SPDX-License-Identifier: AGPL-3.0-only
/** The terminal status relay never dresses a lost connection as good news (TASTE: the icon matches the news). */
import { expect, test } from "bun:test";
import { createStatusRelay } from "./status";

function relay() {
  const shown: Array<{ message: string; tone?: string; duration?: number }> = [];
  let dismissed = 0;
  const callbacks: Array<() => void> = [];
  const element = { hidden: false, textContent: "" };
  const globals = globalThis as unknown as Record<string, unknown>;
  // This fixture mounts no SVG paths; lazy mark completion can still query it.
  globals.document = { createElement: () => element, querySelectorAll: () => [] };
  globals.MutationObserver = class { constructor(callback: () => void) { callbacks.push(callback); } observe() {} disconnect() {} };
  createStatusRelay({ show: (value: { message: string; tone?: string; duration?: number }) => shown.push(value), dismiss() { dismissed += 1; }, dispose() {} } as never);
  const say = (text: string): void => { element.textContent = text; for (const callback of callbacks) callback(); };
  return { shown, say, get dismissed() { return dismissed; } };
}

test("a lost server connection is an error toast, never a success tick", () => {
  const { shown, say } = relay();
  say("The connection to the server ended.");
  expect(shown.map(({ message, tone, duration }) => ({ message, tone, duration }))).toEqual([{ message: "The connection to the server ended.", tone: "error", duration: 0 }]);
});

test("routine connection states stay out of the toast", () => {
  const { shown, say } = relay();
  say("Reconnecting…");
  say("Resumed");
  expect(shown).toEqual([]);
});

test("repeated connection closes do not reopen the persistent reason toast", () => {
  const originalNow = Date.now;
  let now = 1000;
  Date.now = () => now;
  try {
    const state = relay();
    state.say("The connection did not respond in time.");
    state.say("Connection lost. Reconnecting…");
    now += 6000;
    state.say("The connection did not respond in time.");
    expect(state.shown).toHaveLength(1);
  } finally {
    Date.now = originalNow;
  }
});

test("a close reason stays visible through a quick reconnect and clears after a stable attach", async () => {
  const state = relay();
  state.say("The connection to the server ended.");
  state.say("Connection lost. Reconnecting…");
  state.say("Catching up…");
  expect(state.shown.map(({ message, tone, duration }) => ({ message, tone, duration }))).toEqual([{ message: "The connection to the server ended.", tone: "error", duration: 0 }]);
  expect(state.dismissed).toBe(0);
  state.say("");
  await new Promise((resolve) => setTimeout(resolve, 150));
  state.say("The connection to the server ended.");
  await new Promise((resolve) => setTimeout(resolve, 200));
  expect(state.dismissed).toBe(0);
  state.say("");
  await new Promise((resolve) => setTimeout(resolve, 320));
  expect(state.dismissed).toBe(1);
});
