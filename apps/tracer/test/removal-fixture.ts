/**
 * The scene the host-removal specs share: the clusters mockup with a dense `ls -la` listing in every terminal, one
 * card transparency level chosen, and "Remove host" started from the palette for a host other than the focused window's.
 */
import { expect, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { measureColour, measureLegibility, type Legibility } from "./glyph-legibility";

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

/** Waits two frames, so a style change has been painted before a screenshot. */
async function settled(page: Page): Promise<void> {
  await page.evaluate(() => new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done()))));
}

/** Hides or shows the card and the glass bed under it, so a screenshot shows the unblurred page behind both. */
async function setCardHidden(page: Page, hidden: boolean): Promise<void> {
  await page.evaluate((hide) => { for (const element of document.querySelectorAll<HTMLElement>(".ui-confirm-tip, .ui-glass-bed")) element.style.visibility = hide ? "hidden" : "visible"; }, hidden);
  await settled(page);
}

/** What the two pixel measures say about one open card. */
export interface CardPixels { text: Legibility; colour: Legibility }

/**
 * Measures the open `.ui-confirm-tip` twice, at rest. First over the dense text: the card as shown against the same page
 * with the card and its bed hidden (`measureLegibility`). Then over a coloured block placed just under the card's glass
 * (`measureColour`): glass shows its colours and shapes, an opaque card does not. The shot of the card as shown over the
 * text is saved as `removal-confirm/<name>.png`, and the coloured one as `removal-confirm/<name>-colour.png`.
 */
export async function measureOpenCard(page: Page, name: string): Promise<CardPixels> {
  const withCard = await page.screenshot({ path: tracerEvidencePath("removal-confirm", `${name}.png`), animations: "disabled" });
  await setCardHidden(page, true);
  const withoutCard = await page.screenshot({ animations: "disabled" });
  const text = await measureLegibility(page, withCard, withoutCard);
  await setCardHidden(page, false);
  // Three hard-edged colour bands behind the card (under the card, over the terminal), far past the card on every side.
  await page.evaluate(() => {
    const box = document.querySelector<HTMLElement>(".ui-confirm-tip")!.getBoundingClientRect();
    const block = document.createElement("div");
    block.id = "j300-colour-block";
    Object.assign(block.style, {
      position: "fixed", zIndex: "65", pointerEvents: "none", left: `${box.left - 160}px`, top: `${box.top - 160}px`, width: `${box.width + 320}px`, height: `${box.height + 320}px`,
      background: "linear-gradient(90deg, #e03030 0 30%, #2060e0 30% 55%, #e0c020 55% 80%, #20a060 80%)",
    });
    document.body.append(block);
  });
  await settled(page);
  const colourWith = await page.screenshot({ path: tracerEvidencePath("removal-confirm", `${name}-colour.png`), animations: "disabled" });
  await setCardHidden(page, true);
  const colourWithout = await page.screenshot({ animations: "disabled" });
  const colour = await measureColour(page, colourWith, colourWithout);
  await page.evaluate(() => document.getElementById("j300-colour-block")?.remove());
  await setCardHidden(page, false);
  return { text, colour };
}

/**
 * Starts "Remove host" for edge-arm from the sidebar's host caption (Delete), over the dense Console. The card is
 * anchored to that caption, the host's own row. Returns once the card is open.
 */
export async function startRemovalFromSidebar(page: Page): Promise<void> {
  await page.click("#sidebar-toggle");
  await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
  // sleep: the sidebar's own open animation
  await page.waitForTimeout(700);
  await page.locator('#tree li.bm-subhead[data-id="h:edge-arm"]').focus();
  await page.keyboard.press("Delete");
  await expect(page.locator(".ui-confirm-tip[data-open='true']")).toBeVisible();
}
