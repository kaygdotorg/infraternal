// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The one bound the themes and the canvas document share, kept in a module of its own so that the themes (on the critical path) do not pull the document decoder
 * (`model/schema.ts`, loaded with the canvas) in with them: both read it from here.
 */

/**
 * The most themes one account may keep. The canvas document holds the whole list in one `look.set` edit, and the server bounds an edit at 8 KiB (a full list of 16
 * measured well under it, `model/look.test.ts`), so the same number is the server's own bound (`MAX_THEMES` in the canvas plugin).
 */
export const MAX_THEMES = 16;
