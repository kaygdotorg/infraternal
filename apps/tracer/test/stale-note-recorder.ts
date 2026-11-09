/**
 * Shared by the stale-screen specs (D309, #257): records every moment the window's connection indicator has shown
 * the "stale" state (the "screen may be out of date" icon in the machine pill), from the first frame, so a
 * one-frame flash cannot slip past a poll. The old floating note (`.ui-terminal-note`) must never exist.
 */
import type { Page } from "playwright/test";

/** The window pill's indicator while it shows the stale state. */
export const NOTE = '.ui-window-conn[data-state="stale"]';
/** The window pill's indicator in any state: it carries the tooltip and the accessible name. */
export const ICON = ".ui-window-conn";
/** The retired floating note: no document may ever contain it. */
export const FLOATING_NOTE = ".ui-terminal-note";

/** Counts the moments the stale state is shown in this document; runs in the page, in the current document and in every later one. It observes the document itself because an init script runs before the root element exists. */
function install(selector: string): void {
  const w = window as unknown as { __noteShown: number };
  w.__noteShown = 0;
  const seen = (el: Element): void => { if (el.matches(selector)) w.__noteShown += 1; };
  new MutationObserver((records) => {
    for (const record of records) {
      const target = record.target as Element;
      if (record.type === "attributes") seen(target);
      for (const node of record.addedNodes) if (node instanceof Element) { seen(node); for (const inner of node.querySelectorAll(selector)) seen(inner); }
    }
  }).observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: ["data-state"] });
}

/**
 * Start recording on this page and keep recording across reloads (each new document starts at zero, from its first
 * frame, so a state that appears while the page loads is counted). Read the count with `everShown`.
 */
export async function recordNote(page: Page): Promise<void> {
  await page.addInitScript(install, NOTE);
  await page.evaluate(install, NOTE);
}

/** How many times the stale state has been shown since `recordNote`. */
export const everShown = (page: Page): Promise<number> => page.evaluate(() => (window as unknown as { __noteShown: number }).__noteShown);
