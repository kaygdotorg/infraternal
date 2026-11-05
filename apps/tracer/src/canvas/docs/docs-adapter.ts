// SPDX-License-Identifier: AGPL-3.0-only
/**
 * "Read about this window" (issue #304): the one place a window learns which docs heading explains it.
 *
 * A window that has a docs link gets a "?" as the FIRST button of its action group (before split, sessions and close), the
 * same action is the shortcut `⌥⌘/` (`Ctrl+Shift+Alt+/` on a PC) and a ⌘K row. All three open a POPOVER anchored to the button (a bottom
 * sheet on a phone) with the most helpful few lines about the window, from the docs index; its expand icon, at the top right, opens
 * the heading as a window in the Docs cluster. The canvas does not know which window has which page: an adapter says. An adapter that is absent (the
 * product today) means no window shows the button and the shortcut is not registered, so nothing is offered that does
 * nothing. A window the adapter knows but has no page for yet still shows the button and says so in plain words.
 */
import type { WindowModel } from "../model/types";
import type { DocsPreviewContent } from "./docs-excerpt";

/** A docs page (slug) and one of its headings (id); the page alone opens at its top. */
export interface DocsLink { page: string; heading?: string }

export interface DocsAdapter {
  /** `undefined`: this window has no "?". An object without `link`: it has one, but no page is written yet. */
  for(model: WindowModel): { link?: DocsLink } | undefined;
  /** Opens the page in the Docs cluster, scrolled to the heading; resolves false when there is no such page. */
  open(link: DocsLink): Promise<boolean>;
  /** The excerpt for the popover; undefined when there is no such page. */
  preview(link: DocsLink): Promise<DocsPreviewContent | undefined>;
  /** Fetches what `preview` needs ahead of the first press. */
  warm?(): void;
}
