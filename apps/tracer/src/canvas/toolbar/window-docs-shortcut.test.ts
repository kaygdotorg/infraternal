// SPDX-License-Identifier: AGPL-3.0-only
/** The "read about this window" keys collide with nothing: not the shortcuts panel, not the terminal, not AltGr (D222). */
import { expect, test } from "bun:test";
import { sameCombo, terminalNeeds, type Combo } from "../../../../../packages/ui/src/shortcuts";
import { WINDOW_DOCS_KEYS } from "./window-docs-keys";

// The shortcuts panel's own defaults (core-screen.ts), and the other window bindings that use a slash-adjacent chord.
const PANEL: { mac: Combo; other: Combo } = { mac: { code: "Slash", key: "/", mod: true, shift: false }, other: { code: "Slash", key: "/", mod: true, shift: true } };

test("neither chord is the shortcuts panel's, on either platform", () => {
  expect(sameCombo(WINDOW_DOCS_KEYS.mac, PANEL.mac)).toBe(false);
  expect(sameCombo(WINDOW_DOCS_KEYS.other, PANEL.other)).toBe(false);
  expect(sameCombo(WINDOW_DOCS_KEYS.mac, PANEL.other)).toBe(false);
  expect(sameCombo(WINDOW_DOCS_KEYS.other, PANEL.mac)).toBe(false);
});

test("the terminal does not need either chord, and a plain Ctrl+/ would be refused as a shortcut by its own rule only for letters (so it is avoided by design)", () => {
  expect(terminalNeeds(WINDOW_DOCS_KEYS.mac)).toBeUndefined();
  expect(terminalNeeds(WINDOW_DOCS_KEYS.other)).toBeUndefined();
  // The PC chord carries Shift as well as Control and Alt, so it is never AltGr (Ctrl+Alt alone is) and never a plain shell key.
  expect(WINDOW_DOCS_KEYS.other.shift).toBe(true);
  expect(WINDOW_DOCS_KEYS.other.mod).toBe(true);
  expect(WINDOW_DOCS_KEYS.other.alt).toBe(true);
});
