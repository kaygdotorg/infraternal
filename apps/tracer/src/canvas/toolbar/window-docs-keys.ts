// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The keys of "read about this window" (#304), on their own so a test can read them without loading the canvas.
 *
 * ⌥⌘/ on a Mac, Ctrl+Shift+Alt+/ on a PC. D222's rule maps a Mac chord to the PC one (⌘ becomes Ctrl+Shift, Option stays Alt), the way
 * ⌘⇧↩ is Ctrl+Shift+Alt+Enter. The keys the owner first proposed are taken: ⌘/ and Ctrl+Shift+/ are the shortcuts panel, and plain
 * Ctrl+/ is the terminal's (^_, undo in readline and emacs). Matched by the physical key, because Option rewrites what "/" types.
 */
import type { Combo } from "../../../../../packages/ui/src/shortcuts";

export const WINDOW_DOCS_KEYS: { mac: Combo; other: Combo } = { mac: { code: "Slash", mod: true, alt: true }, other: { code: "Slash", mod: true, shift: true, alt: true } };
