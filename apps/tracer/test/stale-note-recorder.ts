/**
 * Shared by the stale-screen specs (D309, #257): records every moment the "screen may be out of date" note
 * has been up, from the first frame, so a one-frame flash cannot slip past a poll.
 */
import type { Page } from "playwright/test";

export const NOTE = ".ui-terminal-note";

/** Start recording on this page; read the count with `everShown`. Reloading the page stops it, so call it again after a reload. */
export async function recordNote(page: Page): Promise<void> {
  await page.evaluate((selector) => {
    const w = window as unknown as { __noteShown: number };
    w.__noteShown = 0;
    const seen = (el: Element): void => { if (el.hasAttribute("data-shown") || !(el as HTMLElement).hidden) w.__noteShown += 1; };
    new MutationObserver((records) => {
      for (const record of records) {
        const target = record.target as Element;
        if (target.matches?.(selector)) seen(target);
        for (const node of record.addedNodes) if (node instanceof Element && node.matches(selector)) seen(node);
      }
    }).observe(document.body, { subtree: true, childList: true, attributes: true });
  }, NOTE);
}

/** How many times the note has been up since `recordNote`. */
export const everShown = (page: Page): Promise<number> => page.evaluate(() => (window as unknown as { __noteShown: number }).__noteShown);
