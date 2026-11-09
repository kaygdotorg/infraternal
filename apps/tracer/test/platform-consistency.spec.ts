/**
 * Cross-platform consistency (TASTE §6 "Every platform sees its own conventions", #121). A Windows browser
 * never shows the Apple modifier glyphs and gets Ctrl keycaps; a Mac shows the glyphs. The palette draws no
 * scroll bar at rest, gets the scrolling state during a wheel scroll and keeps keyboard scrolling working.
 * Platforms are emulated in the page before it loads (navigator.platform and userAgentData).
 */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Browser, type BrowserContext, type Page } from "playwright/test";

// Headless Chromium hides scroll bars unless told otherwise; the bar behaviour is what this file checks.
test.use({ launchOptions: { args: ["--disable-renderer-backgrounding"], ignoreDefaultArgs: ["--hide-scrollbars"] } });

const APPLE_GLYPHS = /[⌘⌥⌃⇧]/;
const WINDOWS = { platform: "Win32", uaPlatform: "Windows", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36" };
const MAC = { platform: "MacIntel", uaPlatform: "macOS", userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36" };

async function platformContext(browser: Browser, env: typeof WINDOWS): Promise<BrowserContext> {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}` });
  await context.addInitScript((spec: typeof WINDOWS & { uaPlatform: string }) => {
    Object.defineProperty(navigator, "platform", { get: () => spec.platform });
    Object.defineProperty(navigator, "userAgent", { get: () => spec.userAgent });
    Object.defineProperty(navigator, "userAgentData", { get: () => ({ platform: spec.uaPlatform, mobile: false }) });
  }, env);
  return context;
}

async function openTerminal(context: BrowserContext): Promise<Page> {
  // The reset closes the previous test's sockets; a pooled keep-alive connection through the proxy can be among them, so one retry absorbs that.
  await context.request.post("/__mock/reset").catch(() => context.request.post("/__mock/reset"));
  await context.request.post("/__mock/open-terminal");
  const page = await context.newPage();
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  return page;
}

/** The text a person can read: every visible element's text, the top pill and the palette included. */
const visibleText = (page: Page): Promise<string> => page.evaluate(() => document.body.innerText);

const scrollState = (page: Page) => page.evaluate(() => {
  const list = document.querySelector<HTMLElement>("#palette-results")!;
  return {
    scrolling: list.hasAttribute("data-scrolling"),
    overflows: list.scrollHeight > list.clientHeight,
    top: list.scrollTop,
  };
});

/**
 * The pixels of the list's scroll track: the strip inside the right edge, where a bar would be drawn. The
 * screenshot is decoded in the page, so the check is the same for every engine.
 *
 * The result is the largest brightness step between two neighbouring rows of the strip. A bar is a thumb with
 * edges, so it shows as an abrupt step; with no bar the strip only drifts smoothly, because the glass lets the
 * page's own gradient through. (The first version measured the spread from the darkest to the brightest row.
 * That grows with the list's height and with the gradient behind it, so it failed on tall lists and on the paper theme.)
 * The strip stops short of the palette's rounded bottom corner: the list ends at the palette's edge, and the corner
 * and the page outside it would read as a step too (#430).
 *
 * The palette fades and scales in over 180 to 240 ms. Measuring while it moves puts the strip over the page outside the
 * palette, so the palette's own animations finish first (waiting for them, not for a fixed time).
 */
async function trackSpread(page: Page): Promise<number> {
  await page.locator("#palette").evaluate((element) => Promise.all(element.getAnimations({ subtree: true }).map((animation) => animation.finished.catch(() => undefined))));
  const box = await page.locator("#palette-results").boundingBox();
  if (!box) throw new Error("palette list is not laid out");
  const radius = await page.locator("#palette").evaluate((element) => Number.parseFloat(getComputedStyle(element).borderBottomRightRadius) || 0);
  const clip = { x: box.x + box.width - 8, y: box.y + 4, width: 6, height: box.height - 8 - Math.ceil(radius) };
  const png = (await page.screenshot({ clip })).toString("base64");
  return page.evaluate(async (data: string) => {
    const image = new Image();
    image.src = `data:image/png;base64,${data}`;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.width;
    canvas.height = image.height;
    const context = canvas.getContext("2d")!;
    context.drawImage(image, 0, 0);
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
    let step = 0;
    let previous: number | undefined;
    for (let y = 0; y < canvas.height; y++) {
      let row = 0;
      for (let x = 0; x < canvas.width; x++) {
        const i = (y * canvas.width + x) * 4;
        row += pixels[i]! + pixels[i + 1]! + pixels[i + 2]!;
      }
      row /= canvas.width;
      if (previous !== undefined) step = Math.max(step, Math.abs(row - previous));
      previous = row;
    }
    return step;
  }, png);
}

test("Windows: the top pill shows Ctrl+Shift+K keycaps and no Apple glyph is visible anywhere", async ({ browser }) => {
  const context = await platformContext(browser, WINDOWS);
  const page = await openTerminal(context);
  await expect(page.locator("#capsule kbd")).toHaveText(["Ctrl", "Shift", "K"]);
  expect(await visibleText(page)).not.toMatch(APPLE_GLYPHS);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  expect(await visibleText(page)).not.toMatch(APPLE_GLYPHS);
  await page.keyboard.press("Escape");
  await context.close();
});

test("Windows: the palette shows no scroll bar at rest, the scrolling state during a wheel scroll, and it fades out", async ({ browser }) => {
  const context = await platformContext(browser, WINDOWS);
  const page = await openTerminal(context);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  await expect.poll(async () => (await scrollState(page)).overflows).toBe(true);

  // At rest: no scrolling state, and the thumb colour is fully transparent (no bar is drawn).
  const rest = await scrollState(page);
  expect(rest.scrolling).toBe(false);
  expect(await trackSpread(page)).toBeLessThan(6);

  // A wheel scroll turns the thumb on at once.
  await page.locator("#palette-results").hover();
  await page.mouse.wheel(0, 240);
  // The clock starts at the wheel, not after the pixel check below: capturing the strip takes a variable time that
  // would otherwise be taken off the 800 ms the bar is meant to stay (#430).
  const stoppedAt = Date.now();
  await expect.poll(async () => (await scrollState(page)).scrolling).toBe(true);
  const during = await scrollState(page);
  expect(during.top).toBeGreaterThan(0);
  expect(await trackSpread(page)).toBeGreaterThan(20);

  // The bar stays about 800 ms after the last scroll, then the attribute clears.
  await expect.poll(async () => (await scrollState(page)).scrolling, { timeout: 4000, intervals: [50] }).toBe(false);
  const hideAfter = Date.now() - stoppedAt;
  expect(hideAfter).toBeGreaterThan(300);
  // The thumb fades over a short transition after the attribute clears; the track must be flat again.
  await expect.poll(() => trackSpread(page), { timeout: 1000 }).toBeLessThan(6);
  await context.close();
});

test("keyboard scrolling in the palette still moves the selection and the list, and focus stays in the search field", async ({ browser }) => {
  const context = await platformContext(browser, WINDOWS);
  const page = await openTerminal(context);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  const input = page.locator("#palette-input");
  await expect(input).toBeFocused();
  for (let i = 0; i < 25; i++) await page.keyboard.press("ArrowDown");
  await expect.poll(async () => (await scrollState(page)).top).toBeGreaterThan(0);
  await expect(input).toBeFocused();
  await context.close();
});

test("Mac: the top pill shows the Command and K glyphs", async ({ browser }) => {
  const context = await platformContext(browser, MAC);
  const page = await openTerminal(context);
  await expect(page.locator("#capsule kbd")).toHaveText(["⌘", "K"]);
  await context.close();
});

test("captures: Windows and Mac, ink, 1440x900: the top pill, the palette and the palette mid-scroll", async ({ browser }) => {
  const dir = tracerEvidencePath("platform");
  for (const [name, env] of [["windows", WINDOWS], ["mac", MAC]] as const) {
    const context = await platformContext(browser, env);
    const page = await openTerminal(context);
    await page.waitForTimeout(300);
    await page.locator("#capsule").screenshot({ path: `${dir}/${name}-pill-ink-1440x900.png` });
    await page.screenshot({ path: `${dir}/${name}-top-ink-1440x900.png` });
    await page.keyboard.press(name === "mac" ? "Meta+k" : "Control+Shift+K");
    await expect(page.locator("#palette")).toBeVisible();
    await expect.poll(async () => (await scrollState(page)).overflows).toBe(true);
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${dir}/${name}-palette-ink-1440x900.png` });
    if (name === "windows") {
      await page.locator("#palette-results").hover();
      await page.mouse.wheel(0, 160);
      await expect.poll(async () => (await scrollState(page)).scrolling).toBe(true);
      await page.waitForTimeout(150);
      await page.screenshot({ path: `${dir}/windows-palette-midscroll-ink-1440x900.png` });
    }
    await context.close();
  }
});

test("Windows: the shortcuts panel names every key in words, with no Apple glyph", async ({ browser }) => {
  // The `?` key opens the panel in the window canvas (proto=windows), where the canvas registers its shortcuts.
  const context = await platformContext(browser, WINDOWS);
  await context.request.post("/__mock/reset").catch(() => context.request.post("/__mock/reset"));
  const page = await context.newPage();
  await page.goto("/?mock=1&proto=windows&theme=ink&bg=none&fixture=none");
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0), { timeout: 30_000 }).toBeGreaterThan(2);
  await page.keyboard.press("?");
  const panel = page.locator(".ui-shortcuts");
  await expect(panel).toBeVisible();
  await expect(panel.locator(".ui-shortcuts-row", { hasText: "Lock or unlock" }).locator("kbd")).toHaveText(["Ctrl", "Shift", "L"]);
  expect(await panel.innerText()).not.toMatch(APPLE_GLYPHS);
  await page.keyboard.press("Escape");
  await context.close();
});

// Phone widths and the paper theme: the palette still scrolls with a thin bar, and the captures are kept for review.
for (const [width, height, theme] of [[393, 852, "paper"], [375, 667, "ink"]] as const) {
  test(`captures: Windows palette at ${width}x${height}, ${theme}: no bar at rest, a thin bar while scrolling`, async ({ browser }) => {
    const context = await platformContext(browser, WINDOWS);
    // Same one retry as `openTerminal`: a pooled keep-alive connection through the proxy can be among the sockets the reset closes.
    await context.request.post("/__mock/reset").catch(() => context.request.post("/__mock/reset"));
    await context.request.post("/__mock/open-terminal");
    const page = await context.newPage();
    await page.setViewportSize({ width, height });
    await page.goto(`/?mock=1&theme=${theme}&bg=none`);
    await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
    await page.keyboard.press("Control+Shift+K");
    await expect(page.locator("#palette")).toBeVisible();
    await expect.poll(async () => (await scrollState(page)).overflows).toBe(true);
    expect(await trackSpread(page)).toBeLessThan(6);
    await page.locator("#palette-results").hover();
    await page.mouse.wheel(0, 160);
    await expect.poll(async () => (await scrollState(page)).scrolling).toBe(true);
    await page.waitForTimeout(150);
    expect(await trackSpread(page)).toBeGreaterThan(20);
    await page.screenshot({ path: tracerEvidencePath("platform", `windows-palette-midscroll-${theme}-${width}x${height}.png`) });
    await context.close();
  });
}
