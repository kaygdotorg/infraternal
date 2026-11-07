/**
 * The scene the host-removal specs share: the clusters mockup with a dense `ls -la` listing in every terminal, one
 * card transparency level chosen, and "Remove host" started from the palette for a host other than the focused window's.
 */
import { expect, type Page } from "playwright/test";

/** The three review viewports. `touch` runs them as a phone (coarse pointer, 44 px targets). */
export const SIZES = [
  { id: "desktop", width: 1440, height: 900, touch: false },
  { id: "phone", width: 393, height: 852, touch: true },
  { id: "small-phone", width: 375, height: 667, touch: true },
] as const;
/** Both card themes the owner reviews. */
export const THEMES = ["ink", "paper"] as const;
/** The card transparency levels the user can pick (`data-card` on the root): Solid is the lowest transparency, Frosted the highest. */
export const LEVELS = ["solid", "tinted", "clear", "frosted"] as const;
/** One card transparency level, as the root's `data-card` value. */
export type Level = (typeof LEVELS)[number];

/** A dense directory listing, long enough to fill a window on every viewport and wide enough to run under the whole card. */
export function listing(): string[] {
  const names = [".bash_history", ".bashrc", ".bashrc.bak-20261102T061545", "10-lan-links.conf", "authorized_keys", "infraternal", "infraternal.toml", ".profile", "notes.md", "build.log"];
  return Array.from({ length: 80 }, (_, i) => `-rw-r--r--. ${1 + (i % 4)} root root ${String(100 + i * 137).padStart(6)} Nov ${String(1 + (i % 6)).padStart(2)} 1${i % 10}:${String(10 + (i % 50))} ${names[i % names.length]}-${i}`);
}

/**
 * Opens the clusters mockup in `theme` at card transparency `level`, flies into the Console view, and fills every
 * terminal with the dense listing. The live terminal is where a person would be typing.
 */
export async function openDenseConsole(page: Page, theme: string, level: Level): Promise<void> {
  await page.context().request.post("/__mock/reset").catch(() => undefined);
  await page.goto(`/?mock=1&proto=clusters&scene=1&bg=none&removal=1&theme=${theme}`);
  await expect(page.locator(".ui-window").nth(1)).toBeVisible({ timeout: 30_000 });
  await page.evaluate((name) => { document.documentElement.dataset.card = name; }, level);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.locator("#palette-input").fill("Console");
  await page.locator('.palette .result[data-action^="canvas:view"]').first().click();
  // sleep: the camera flight into the Console view must land before text is written and the palette opens again
  await page.waitForTimeout(1500);
  // The hook appears once the live terminal has connected.
  await page.waitForFunction(() => (window as unknown as { __tracerTestDouble?: unknown }).__tracerTestDouble !== undefined, undefined, { timeout: 30_000 });
  const lines = listing();
  await page.evaluate(async (rows) => {
    const hook = (window as unknown as { __tracerTestDouble?: { writeText(text: string): Promise<void> } }).__tracerTestDouble;
    if (!hook) throw new Error("the test double's terminal hook is missing");
    await hook.writeText(`${rows.join("\r\n")}\r\n`);
    for (const pre of document.querySelectorAll<HTMLElement>(".cl-preview")) pre.textContent = rows.join("\n");
  }, lines);
}

/**
 * Starts "Remove host" from the palette for a host other than the focused window's and returns its name. The card
 * opens centred, because the palette is not the removed host's own row or pill.
 */
export async function startRemovalFromPalette(page: Page): Promise<string> {
  const focusedPill = (await page.locator(".ui-window").first().locator(".ui-window-pill").innerText()).toLowerCase();
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.locator("#palette-input").fill("Remove host");
  const rows = page.locator(".palette .result");
  await expect(rows.filter({ hasText: "Remove host:" }).first()).toBeVisible();
  // The palette redraws its rows while it filters, so read the names until one that is not the focused window's shows.
  let other: string | undefined;
  await expect.poll(async () => {
    const labels = await rows.allInnerTexts();
    other = labels.map((text) => /Remove host:\s*([^\s\n]+)/.exec(text)?.[1]).find((name) => name && !focusedPill.includes(name.toLowerCase()));
    return other;
  }, { message: `a host other than the focused window's is offered (focused pill: ${focusedPill})` }).toBeTruthy();
  await page.locator("#palette-input").fill(`Remove host: ${other}`);
  await page.keyboard.press("Enter");
  return other!;
}

/** The scene most cases want: a dense Console, then "Remove host" started from the palette. Returns the removed host's name. */
export async function openRemovalOverDenseTerminal(page: Page, theme: string, level: Level): Promise<string> {
  await openDenseConsole(page, theme, level);
  return await startRemovalFromPalette(page);
}
