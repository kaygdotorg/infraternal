// SPDX-License-Identifier: AGPL-3.0-only
/** The terminal status relay never dresses a lost connection as good news (TASTE: the icon matches the news). */
import { afterEach, beforeEach, expect, test } from "bun:test";
import { createStatusRelay, endedStripText, exitStatusText } from "./status";

/** Each relay owns an observer and may leave a pending clear timer; release both after its test. */
const disposals: Array<() => void> = [];
/** Restore the DOM descriptors as well as their values so later suites see their own browser environment. */
const browserGlobals = new Map<string, PropertyDescriptor | undefined>();
beforeEach(() => {
  for (const name of ["document", "MutationObserver"]) browserGlobals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
});
afterEach(() => {
  for (const dispose of disposals.splice(0)) dispose();
  for (const [name, descriptor] of browserGlobals) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else Reflect.deleteProperty(globalThis, name);
  }
});

/** A real status relay with controlled text changes and no rendered DOM. */
function relay() {
  const shown: Array<{ message: string; tone?: string; duration?: number }> = [];
  let dismissed = 0;
  const callbacks: Array<() => void> = [];
  const element = { hidden: false, textContent: "" };
  const globals = globalThis as unknown as Record<string, unknown>;
  globals.document = { createElement: () => element };
  globals.MutationObserver = class { constructor(callback: () => void) { callbacks.push(callback); } observe() {} disconnect() {} };
  const status = createStatusRelay({ show: (value: { message: string; tone?: string; duration?: number }) => shown.push(value), dismiss() { dismissed += 1; }, dispose() {} } as never);
  disposals.push(status.dispose);
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

test("a repeated close does not retake the shared toast after a newer message replaces it", () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const original = { document: globals.document, MutationObserver: globals.MutationObserver };
  const callbacks: Array<() => void> = [];
  const shown: string[] = [];
  const element = { hidden: false, textContent: "" };
  let currentClose: (() => void) | undefined;
  globals.document = { createElement: () => element };
  globals.MutationObserver = class { constructor(callback: () => void) { callbacks.push(callback); } observe() {} disconnect() {} };
  const toast = {
    show(value: { message: string; onClose?: () => void }) {
      currentClose?.();
      shown.push(value.message);
      currentClose = value.onClose;
    },
    dismiss() { const close = currentClose; currentClose = undefined; close?.(); },
    dispose() {},
  };
  const relay = createStatusRelay(toast as never);
  const say = (message: string): void => { element.textContent = message; for (const callback of callbacks) callback(); };
  try {
    say("The connection to the server ended.");
    toast.show({ message: "A newer operation finished." });
    say("Connection lost. Reconnecting…");
    say("The connection to the server ended.");
    expect(shown).toEqual(["The connection to the server ended.", "A newer operation finished."]);
  } finally {
    relay.dispose();
    for (const key of ["document", "MutationObserver"] as const) {
      if (original[key] === undefined) delete globals[key]; else globals[key] = original[key];
    }
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

test("normal shell exits never produce error toasts", () => {
  const state = relay();
  for (const message of ["Shell exited.", "Shell exited with status 3. Open a new shell to continue.", "Shell exited with status 129. Open a new shell to continue."]) state.say(message);
  expect(state.shown).toEqual([]);
});

test("signed exit statuses distinguish shell codes from actual signals", () => {
  expect(exitStatusText(0)).toBe("Shell exited.");
  expect(exitStatusText(129)).toContain("status 129");
  expect(exitStatusText(-1)).toContain("signal 1");
  expect(exitStatusText(-9)).toContain("signal 9");
});

test("ended strips name actual signals and preserve recorded ordinary exit codes", () => {
  expect(endedStripText(undefined)).toBe("Session ended");
  expect(endedStripText(-1)).toBe("Stopped by signal 1");
  expect(endedStripText(-9)).toBe("Stopped by signal 9");
  expect(endedStripText(0)).toBe("Session ended · Exit 0");
  expect(endedStripText(3)).toBe("Session ended · Exit 3");
  expect(endedStripText(129)).toBe("Session ended · Exit 129");
});
