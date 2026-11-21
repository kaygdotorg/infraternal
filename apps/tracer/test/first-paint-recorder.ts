/**
 * An in-page recorder for "when did the person see it" first-paint rows (#569 finding 2, #573, D375).
 *
 * Two things went wrong with the old first-paint row. It read `first-contentful-paint`, which Chromium never reports
 * for the sign-in page (a plain `data:` page does report it, so the browser is fine; the sign-in page's first
 * paint holds nothing Chromium counts as contentful), so every sample fell back to a bound and `fcp_missing_n` was 20
 * of 20. And that bound was taken from Node after Playwright saw the button, so a slow Node round trip was
 * counted as page time. The recorder runs inside the page before any script: when the sign-in button (or a connected
 * terminal indicator) appears it waits two animation frames and takes `performance.now()`. Zero is the
 * navigation start, as in a browser's own paint entries.
 */
import type { Page } from "playwright/test";

/** What the recorder collected, in milliseconds from navigation start; a mark is undefined until it happened. */
export interface FirstPaintMarks {
  /** The sign-in button was on screen (two frames after it appeared). */
  signin: number | undefined;
  /** A terminal's connection indicator said connected or resumed (two frames after). */
  connected: number | undefined;
  /** Chromium's own `first-paint` entry, when it exists. */
  firstPaint: number | undefined;
  /** Chromium's `first-contentful-paint` entry, when it exists (it does not for the sign-in page). */
  firstContentfulPaint: number | undefined;
}

/** Installs the recorder on `page`; call before `goto`. */
export async function installFirstPaintRecorder(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const marks: Record<string, number> = {};
    (window as unknown as { __firstPaintMarks: Record<string, number> }).__firstPaintMarks = marks;
    /** Records `name` two animation frames from now, the first frame that can show what just appeared. */
    const markAfterFrames = (name: string): void => {
      if (name in marks) return;
      marks[name] = -1;
      requestAnimationFrame(() => requestAnimationFrame(() => { marks[name] = performance.now(); }));
    };
    const look = (): void => {
      if (!("signin" in marks) && document.querySelector("#login-passkey")) markAfterFrames("signin");
      if (!("connected" in marks) && document.querySelector('.ui-conn[data-state="connected"], .ui-conn[data-state="resumed"]')) markAfterFrames("connected");
    };
    new MutationObserver(look).observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: ["data-state"] });
  });
}

/** Waits until `mark` was recorded (up to `timeoutMs`) and returns every mark. */
export async function readFirstPaintMarks(page: Page, mark: "signin" | "connected", timeoutMs: number): Promise<FirstPaintMarks> {
  await page.waitForFunction((name) => ((window as unknown as { __firstPaintMarks?: Record<string, number> }).__firstPaintMarks?.[name] ?? -1) >= 0, mark, { timeout: timeoutMs, polling: 50 });
  return page.evaluate(() => {
    const marks = (window as unknown as { __firstPaintMarks: Record<string, number> }).__firstPaintMarks;
    const entry = (name: string): number | undefined => performance.getEntriesByName(name)[0]?.startTime;
    const known = (value: number | undefined): number | undefined => (value !== undefined && value >= 0 ? value : undefined);
    return {
      signin: known(marks.signin),
      connected: known(marks.connected),
      firstPaint: entry("first-paint"),
      firstContentfulPaint: entry("first-contentful-paint"),
    };
  });
}
