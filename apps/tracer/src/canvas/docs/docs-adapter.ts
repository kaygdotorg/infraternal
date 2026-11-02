// SPDX-License-Identifier: AGPL-3.0-only
/**
 * "Read about this window" (issue #304): the one place a window learns which docs heading explains it.
 *
 * A window that has a docs link gets a "?" as the FIRST button of its action group (before split, sessions and close), the
 * same action is the shortcut `⌥⌘/` (`Ctrl+Shift+Alt+/` on a PC) and a ⌘K row, and all three open the heading as a window in the
 * Docs cluster. The canvas does not know which window has which page: an adapter says. An adapter that is absent (the
 * product today) means no window shows the button and the shortcut is not registered, so nothing is offered that does
 * nothing. A window the adapter knows but has no page for yet still shows the button and says so in plain words.
 */
import type { WindowModel } from "../model/types";

/** A docs page (slug) and one of its headings (id); the page alone opens at its top. */
export interface DocsLink { page: string; heading?: string }

export interface DocsAdapter {
  /** `undefined`: this window has no "?". An object without `link`: it has one, but no page is written yet. */
  for(model: WindowModel): { link?: DocsLink } | undefined;
  /** Opens the page in the Docs cluster; resolves false when there is no such page. */
  open(link: DocsLink): Promise<boolean>;
}
