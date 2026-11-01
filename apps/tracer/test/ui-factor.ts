/**
 * The UI size's factor as the page shows it (#283): the root font size over 16 px, so 1.1 at the desktop default (the base) and 1
 * on a touch screen. A spec that asserts a length the stylesheets draw in rem multiplies its expectation by it, instead of
 * hard-coding the pixels of the standard size.
 */
import type { Page } from "playwright/test";

export const uiFactor = (page: Page): Promise<number> => page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize) / 16);
