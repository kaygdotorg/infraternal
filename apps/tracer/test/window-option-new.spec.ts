/**
 * Option (macOS) or Alt (Windows, Linux) on a window's split buttons (#280, D212): holding the key with the
 * pointer near the header's split right / split down buttons morphs their icons into "new window right / below", the
 * warm tooltip and the accessible name change with them, and a click runs the new-window action. Releasing the key turns
 * them back; far from the buttons the key does nothing; reduced motion swaps at once.
 *
 * The icons' geometry is read back from the morphing <rect> (the frame is 16 wide as "split", 8 wide as "new window").
 */
import { expect, test, type Page } from "playwright/test";

const VIEW = '.cl[data-view="console"]';
const ACTIVE = `${VIEW} .ui-window[data-active]`;

async function boot(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
  await page.locator(`${VIEW} .ui-window .ui-window-body`).first().click({ position: { x: 20, y: 40 } });
  await page.waitForTimeout(500);
}

const layout = (page: Page) => page.evaluate((view) => {
  const cols = [...document.querySelectorAll<HTMLElement>(`${view} .cl-col`)];
  const widths = cols.map((c) => Number(c.dataset.w) || 0);
  return { widths, total: widths.reduce((a, b) => a + b, 0) + 12 * Math.max(0, widths.length - 1), windows: document.querySelectorAll(`${view} .ui-window`).length, heights: cols.map((c) => [...c.querySelectorAll<HTMLElement>(":scope > .ui-window")].map((w) => w.offsetHeight)) };
}, VIEW);

const button = (page: Page, id: "split-right" | "split-down") => page.locator(`${ACTIVE} [data-action="${id}"]`);
const frameWidth = async (page: Page, id: "split-right" | "split-down"): Promise<number> => Number(await button(page, id).locator("svg rect").getAttribute("width"));
const frameHeight = async (page: Page, id: "split-right" | "split-down"): Promise<number> => Number(await button(page, id).locator("svg rect").getAttribute("height"));
const hover = async (page: Page, id: "split-right" | "split-down"): Promise<void> => {
  const box = (await button(page, id).boundingBox())!;
  await page.mouse.move(box.x + box.width / 2 - 6, box.y + box.height / 2 - 4);
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 4 });
};
const tipText = (page: Page): Promise<string> => page.evaluate(() => (document.querySelector(".tip-pos[style*='visible'] .tip-label:not(.is-leaving)") as HTMLElement | null)?.textContent ?? "");

test.describe("Option on the split buttons", () => {
  test.setTimeout(120_000);

  test("holding Option near the buttons morphs both icons, the tooltip and the name; releasing turns them back", async ({ page }) => {
    await boot(page);
    await hover(page, "split-right");
    await expect.poll(() => tipText(page), { timeout: 3000 }).toBe("Split right");
    expect(await frameWidth(page, "split-right")).toBe(16);
    await page.keyboard.down("Alt");
    await expect.poll(() => frameWidth(page, "split-right"), { timeout: 2000 }).toBeCloseTo(8, 0);
    await expect.poll(() => tipText(page), { timeout: 2000 }).toBe("New window right");
    await expect(button(page, "split-right")).toHaveAttribute("aria-label", "New window right");
    // The pair morphs together: split down turns into "new window below" (a wide, short frame) while the pointer is near.
    await expect(button(page, "split-down")).toHaveAttribute("aria-label", "New window below");
    expect(await frameHeight(page, "split-down")).toBeCloseTo(8, 0);
    await page.keyboard.up("Alt");
    await expect.poll(() => frameWidth(page, "split-right"), { timeout: 2000 }).toBeCloseTo(16, 0);
    await expect(button(page, "split-right")).toHaveAttribute("aria-label", "Split right");
    await expect.poll(() => tipText(page), { timeout: 2000 }).toBe("Split right");
    await expect(button(page, "split-down")).toHaveAttribute("aria-label", "Split down");
  });

  test("the morph is a continuous motion, not a swap: the frame passes through the sizes in between", async ({ page }) => {
    await boot(page);
    await hover(page, "split-right");
    const samples = page.evaluate(() => new Promise<number[]>((done) => {
      const rect = document.querySelector('.ui-window[data-active] [data-action="split-right"] svg rect')!;
      const out: number[] = [];
      const t0 = performance.now();
      const loop = (): void => { out.push(Number(rect.getAttribute("width"))); if (performance.now() - t0 < 700) requestAnimationFrame(loop); else done(out); };
      requestAnimationFrame(loop);
    }));
    await page.keyboard.down("Alt");
    const widths = await samples;
    const between = widths.filter((w) => w > 8.5 && w < 15.5);
    expect(between.length, `frames between the two sizes: ${widths.map((w) => w.toFixed(1)).join(" ")}`).toBeGreaterThanOrEqual(4);
    // It settles within about 300 ms and never goes below the new size by more than the spring's small overshoot.
    expect(Math.min(...widths)).toBeGreaterThan(7);
    expect(widths.at(-1)).toBeCloseTo(8, 0);
    await page.keyboard.up("Alt");
  });

  test("far from the buttons the key changes nothing", async ({ page }) => {
    await boot(page);
    const body = (await page.locator(`${ACTIVE} .ui-window-body`).boundingBox())!;
    await page.mouse.move(body.x + 60, body.y + body.height - 60);
    await page.keyboard.down("Alt");
    await page.waitForTimeout(500);
    expect(await frameWidth(page, "split-right")).toBe(16);
    await expect(button(page, "split-right")).toHaveAttribute("aria-label", "Split right");
    // Moving in while it is held morphs; moving out turns back.
    await hover(page, "split-right");
    await expect.poll(() => frameWidth(page, "split-right"), { timeout: 2000 }).toBeCloseTo(8, 0);
    await page.mouse.move(body.x + 60, body.y + body.height - 60, { steps: 6 });
    await expect.poll(() => frameWidth(page, "split-right"), { timeout: 2000 }).toBeCloseTo(16, 0);
    await page.keyboard.up("Alt");
  });

  test("Option-click opens a full-size window beside (the first keeps its size); a plain click divides", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    await hover(page, "split-right");
    await page.keyboard.down("Alt");
    await page.waitForTimeout(400);
    await button(page, "split-right").click();
    await page.keyboard.up("Alt");
    await page.waitForTimeout(1500);
    const added = await layout(page);
    expect(added.windows).toBe(before.windows + 1);
    expect(added.widths.length).toBe(before.widths.length + 1);
    expect(added.total, "a new window grows the footprint by a full column").toBe(before.total + Math.max(...before.widths) + 12);
    // Plain click on the (new) active window's split right: the footprint stays.
    await hover(page, "split-right");
    await button(page, "split-right").click();
    await page.waitForTimeout(1500);
    const split = await layout(page);
    expect(split.windows).toBe(added.windows + 1);
    expect(split.total).toBe(added.total);
  });

  test("Option-click on split down opens a full-size window below", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    await hover(page, "split-down");
    await page.keyboard.down("Alt");
    await page.waitForTimeout(400);
    await button(page, "split-down").click();
    await page.keyboard.up("Alt");
    await page.waitForTimeout(1500);
    const after = await layout(page);
    expect(after.widths).toEqual(before.widths);
    expect(after.windows).toBe(before.windows + 1);
  });
});

/** Emulates a keyboard family before the page loads: the platform decides only the words (⌥ or Alt), never the behaviour. */
async function asPlatform(page: Page, platform: "Win32" | "Linux x86_64" | "MacIntel"): Promise<void> {
  await page.addInitScript((value) => { Object.defineProperty(navigator, "platform", { get: () => value }); }, platform);
}

for (const platform of ["Win32", "Linux x86_64", "MacIntel"] as const) {
  test.describe(`on ${platform}`, () => {
    test.setTimeout(120_000);

    test("Alt (Option) near the buttons morphs them, and a bare Alt press near them is claimed so the browser menu stays shut", async ({ page }) => {
      await asPlatform(page, platform);
      await boot(page);
      await hover(page, "split-right");
      // The probe is registered after the card's own listeners, so it sees whether they claimed the key.
      await page.evaluate(() => {
        const seen = { down: false, up: false };
        (window as unknown as { __alt: typeof seen }).__alt = seen;
        window.addEventListener("keydown", (e) => { if (e.key === "Alt") seen.down = e.defaultPrevented; });
        window.addEventListener("keyup", (e) => { if (e.key === "Alt") seen.up = e.defaultPrevented; });
      });
      await page.keyboard.down("Alt");
      await expect.poll(() => frameWidth(page, "split-right"), { timeout: 2000 }).toBeCloseTo(8, 0);
      await expect.poll(() => tipText(page), { timeout: 2000 }).toBe("New window right");
      await page.keyboard.up("Alt");
      await expect.poll(() => frameWidth(page, "split-right"), { timeout: 2000 }).toBeCloseTo(16, 0);
      expect(await page.evaluate(() => (window as unknown as { __alt: { down: boolean; up: boolean } }).__alt)).toEqual({ down: true, up: true });
      // Far from the buttons the key is not ours: it goes on to the browser (and to the shell) untouched.
      const body = (await page.locator(`${ACTIVE} .ui-window-body`).boundingBox())!;
      await page.mouse.move(body.x + 60, body.y + body.height - 60, { steps: 4 });
      await page.keyboard.down("Alt");
      await page.keyboard.up("Alt");
      expect(await page.evaluate(() => (window as unknown as { __alt: { down: boolean; up: boolean } }).__alt)).toEqual({ down: false, up: false });
    });

    test("the shortcuts panel names the modifier in this platform's words", async ({ page }) => {
      await asPlatform(page, platform);
      await boot(page);
      await page.mouse.click(720, 880); // the canvas background: a press outside any field, so "?" is not typed into the shell
      await page.waitForTimeout(300);
      await page.keyboard.press("?");
      await expect(page.locator(".ui-shortcuts")).toBeVisible({ timeout: 5000 });
      const row = page.locator(".ui-shortcuts-row", { hasText: "Split buttons: new window instead" });
      await expect(row).toBeVisible();
      const text = await row.innerText();
      if (platform === "MacIntel") { expect(text).toContain("⌥"); expect(text).not.toContain("Alt+"); }
      else { expect(text).toContain("Alt"); expect(text).not.toMatch(/[⌘⌥⌃⇧]/); }
    });
  });
}

test.describe("keyboard", () => {
  test.setTimeout(120_000);

  test("Tab to a split button, hold Alt: it turns into the new-window button; the pointer can be far away", async ({ page }) => {
    await boot(page);
    const body = (await page.locator(`${ACTIVE} .ui-window-body`).boundingBox())!;
    await page.mouse.move(body.x + 60, body.y + body.height - 60);
    await button(page, "split-right").focus();
    await page.keyboard.press("Shift+Tab");
    await page.keyboard.press("Tab"); // a real Tab arrival, so the focus ring is on
    await expect(button(page, "split-right")).toBeFocused();
    await page.keyboard.down("Alt");
    await expect.poll(() => frameWidth(page, "split-right"), { timeout: 2000 }).toBeCloseTo(8, 0);
    await expect(button(page, "split-right")).toHaveAttribute("aria-label", "New window right");
    await page.keyboard.up("Alt");
    await expect.poll(() => frameWidth(page, "split-right"), { timeout: 2000 }).toBeCloseTo(16, 0);
  });

  test("a click with the pointer's button focused leaves nothing stuck: Alt far from the buttons still does nothing", async ({ page }) => {
    await boot(page);
    await hover(page, "split-right");
    await page.mouse.down(); await page.mouse.up();
    await page.waitForTimeout(1500);
    const body = (await page.locator(`${ACTIVE} .ui-window-body`).boundingBox())!;
    await page.mouse.move(body.x + 60, body.y + body.height - 60, { steps: 4 });
    await page.keyboard.down("Alt");
    await page.waitForTimeout(500);
    expect(await frameWidth(page, "split-right")).toBe(16);
    await page.keyboard.up("Alt");
  });
});

test.describe("reduced motion", () => {
  test("the icons and the words swap at once", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await boot(page);
    expect(await page.evaluate(() => matchMedia("(prefers-reduced-motion: reduce)").matches)).toBe(true);
    await hover(page, "split-right");
    await page.keyboard.down("Alt");
    // The very next frame already shows the new icon.
    const width = await page.evaluate(() => new Promise<number>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done(Number(document.querySelector('.ui-window[data-active] [data-action="split-right"] svg rect')!.getAttribute("width")))))));
    expect(width).toBeCloseTo(8, 0);
    await expect(button(page, "split-right")).toHaveAttribute("aria-label", "New window right");
    await page.keyboard.up("Alt");
  });
});
