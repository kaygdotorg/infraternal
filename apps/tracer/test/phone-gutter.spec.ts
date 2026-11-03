/**
 * Phone gutter and the palette's top bar (#121, TASTE: "Windows keep the gutter on phones", "The palette owns the top bar
 * while it is open"). Runs against the test double's mockup canvas, which mounts the product canvas (create.ts), so the
 * geometry is the same code the product runs. Phones use a touch profile at 393x852 and 375x667; desktop at 1440x900.
 */
import { tracerEvidencePath } from "./evidence-path";
import { devices, expect, test, type Browser, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const captures = tracerEvidencePath("phone-gutter");
const URL = "/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft";

async function phone(browser: Browser, width: number, height: number): Promise<{ page: Page; close(): Promise<void> }> {
  const context = await browser.newContext({ ...devices["iPhone 15"], baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width, height }, deviceScaleFactor: 2 });
  // The 16 px gutter belongs to the "Comfortable" phone size. Since 2026-10-12 (owner: "edge to edge (the default) should allow
  // peeking of the neighbour windows"; TASTE "Full width means full width; edge to edge peeks", D191) the default is "Edge to
  // edge", where the canvas runs to the safe areas and a lone window is the screen width. This spec picks the size that keeps
  // the gutter, as the person who wants it would (Settings, Window Sizes); phone-window-width.spec.ts holds the other two sizes.
  await context.addInitScript(() => localStorage.setItem("tracer.window-size.phone", "comfortable"));
  const page = await context.newPage();
  await page.goto(URL);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(900);
  return { page, close: () => context.close() };
}

/** The resting window of the current view: the one whose centre is nearest the screen's centre. Its gaps to the screen edges. */
const resting = (page: Page) => page.evaluate(() => {
  const view = document.querySelector<HTMLElement>(".cl[data-view]:not([data-view=''])")?.dataset.view;
  const wins = [...document.querySelectorAll<HTMLElement>(`.cl[data-view="${view}"] .ui-window`)].filter((n) => n.offsetParent);
  const mid = innerWidth / 2;
  const best = wins.map((n) => ({ n, r: n.getBoundingClientRect() })).sort((a, b) => Math.abs((a.r.left + a.r.right) / 2 - mid) - Math.abs((b.r.left + b.r.right) / 2 - mid))[0];
  return { view, id: best?.n.dataset.windowId, left: best ? Math.round(best.r.left) : -1, right: best ? Math.round(innerWidth - best.r.right) : -1 };
});

const view = async (page: Page, name: string) => {
  // D222: off a Mac the palette is Ctrl+Shift+K; plain Ctrl+K belongs to the terminal.
      await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type(`Go to ${name}`);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(900);
};

for (const [w, h] of [[393, 852], [375, 667]] as const) {
  test(`phone ${w}x${h}: a resting window keeps the gutter in every view, after a split and after a close`, async ({ browser }) => {
    test.setTimeout(120_000);
    const { page, close } = await phone(browser, w, h);
    try {
      // The panes' inset is the top bar's gutter (style.css --gutter): read it from the element, not the max() token.
      const gutter = await page.evaluate(() => parseFloat(getComputedStyle(document.querySelector("#panes")!).left));
      expect(gutter).toBeGreaterThanOrEqual(16);
      const check = async (label: string) => {
        const r = await resting(page);
        expect(r.left, `${label}: left gap (${r.view} ${r.id})`).toBeGreaterThanOrEqual(gutter);
        expect(r.right, `${label}: right gap (${r.view} ${r.id})`).toBeGreaterThanOrEqual(gutter);
      };
      await check("console at load");
      await view(page, "Settings");
      await check("settings");
      await view(page, "Mesh");
      await check("mesh");
      await view(page, "Console");
      await check("console again");
      // A split of the active window (D212), then a close: the resting window keeps the gutter both times.
      // D222: off a Mac the palette is Ctrl+Shift+K; plain Ctrl+K belongs to the terminal.
      await page.keyboard.press("Control+Shift+K");
      await page.keyboard.type("Split right");
      await page.keyboard.press("Enter");
      await page.waitForTimeout(900);
      await check("after split");
      // D222: off a Mac the palette is Ctrl+Shift+K; plain Ctrl+K belongs to the terminal.
      await page.keyboard.press("Control+Shift+K");
      await page.keyboard.type("Close window");
      await page.keyboard.press("Enter");
      await page.waitForTimeout(900);
      await check("after close");
    } finally {
      await close();
    }
  });

  test(`phone ${w}x${h}: opening the palette hides the sidebar toggle and +, closing it brings them back`, async ({ browser }) => {
    const { page, close } = await phone(browser, w, h);
    try {
      const state = () => page.evaluate(() => ["#sidebar-toggle", "#capsule", ".top > .tabs > .tab-add"].map((s) => ({ s, op: getComputedStyle(document.querySelector(s)!).opacity, pe: getComputedStyle(document.querySelector(s)!).pointerEvents })));
      const rest = (await state()).map((c) => c.op);
      expect(rest).toEqual(["1", "1", "0.8"]); // the "+" rests at its own 0.8 opacity (style.css .tab)
      // D222: off a Mac the palette is Ctrl+Shift+K; plain Ctrl+K belongs to the terminal.
      await page.keyboard.press("Control+Shift+K");
      // Every control the palette covers on a phone: all three (the palette grows from the top pill over the bar).
      await expect.poll(async () => (await state()).map((c) => c.op), { timeout: 2000 }).toEqual(["0", "0", "0"]);
      for (const c of await state()) expect(c.pe, c.s).toBe("none");
      await page.keyboard.press("Escape");
      await expect.poll(async () => (await state()).map((c) => c.op), { timeout: 2000 }).toEqual(rest);
    } finally {
      await close();
    }
  });
}

test("desktop 1440x900: opening the palette leaves the buttons it does not cover visible", async ({ browser }) => {
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  await page.goto(URL);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(900);
  // D222: off a Mac the palette is Ctrl+Shift+K; plain Ctrl+K belongs to the terminal.
      await page.keyboard.press("Control+Shift+K");
  await page.waitForTimeout(600);
  const baseline = await page.evaluate(() => ["#sidebar-toggle", "#capsule", ".top > .tabs > .tab-add"].map((s) => getComputedStyle(document.querySelector(s)!).opacity));
  expect(baseline).toEqual(["1", "1", "0.8"]);
  const result = await page.evaluate(() => {
    const box = document.querySelector("#palette")!.getBoundingClientRect();
    return ["#sidebar-toggle", "#capsule", ".top > .tabs > .tab-add"].map((s) => {
      const n = document.querySelector(s)!;
      const r = n.getBoundingClientRect();
      return { s, overlaps: r.left < box.right && box.left < r.right && r.top < box.bottom && box.top < r.bottom, op: getComputedStyle(n).opacity };
    });
  });
  // Desktop: the centred palette covers none of the corner controls, so each keeps its resting opacity.
  result.forEach((c, i) => {
    expect(c.overlaps, c.s).toBe(false);
    expect(c.op, c.s).toBe(baseline[i]);
  });
  await mkdir(captures, { recursive: true });
  await page.screenshot({ path: `${captures}/palette-1440x900.png` });
  await context.close();
});

test("phone 393x852 ink: Settings at rest, and the palette open on the phone, are captured", async ({ browser }) => {
  const { page, close } = await phone(browser, 393, 852);
  try {
    await mkdir(captures, { recursive: true });
    await view(page, "Settings");
    await page.waitForTimeout(700);
    await page.screenshot({ path: `${captures}/phone-393x852-ink-settings-rest.png` });
    // D222: off a Mac the palette is Ctrl+Shift+K; plain Ctrl+K belongs to the terminal.
      await page.keyboard.press("Control+Shift+K");
    await page.waitForTimeout(600);
    await page.screenshot({ path: `${captures}/phone-393x852-ink-palette-open.png` });
  } finally {
    await close();
  }
});
