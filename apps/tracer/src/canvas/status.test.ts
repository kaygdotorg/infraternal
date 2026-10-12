// SPDX-License-Identifier: AGPL-3.0-only
/** The terminal status relay never dresses a lost connection as good news (TASTE: the icon matches the news). */
import { expect, test } from "bun:test";
import { createStatusRelay } from "./status";

function relay() {
  const shown: Array<{ message: string; tone?: string; duration?: number }> = [];
  const callbacks: Array<() => void> = [];
  const element = { hidden: false, textContent: "" };
  const globals = globalThis as unknown as Record<string, unknown>;
  globals.document = { createElement: () => element };
  globals.MutationObserver = class { constructor(callback: () => void) { callbacks.push(callback); } observe() {} disconnect() {} };
  createStatusRelay({ show: (value: { message: string; tone?: string; duration?: number }) => shown.push(value), dismiss() {}, dispose() {} } as never);
  const say = (text: string): void => { element.textContent = text; for (const callback of callbacks) callback(); };
  return { shown, say };
}

test("a lost server connection is an error toast, never a success tick", () => {
  const { shown, say } = relay();
  say("The connection to the server ended.");
  expect(shown).toEqual([{ message: "The connection to the server ended.", tone: "error", duration: 5000 }]);
});

test("routine connection states stay out of the toast", () => {
  const { shown, say } = relay();
  say("Reconnecting…");
  say("Resumed");
  expect(shown).toEqual([]);
});
