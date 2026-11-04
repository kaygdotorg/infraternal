/**
 * Scrolling in a focused terminal belongs to the terminal (#113, TASTE). Three windows stacked in one column, the
 * middle one focused and input-locked: the wheel scrolls that terminal's scrollback and nothing else, wherever the
 * pointer is. The strip (the column's scroll offset and the canvas transform) does not move by a pixel, also when the
 * terminal is at its top or bottom (no scroll chaining) and for a burst of wheel events like trackpad momentum.
 * Production server binary, real PTYs.
 */
import { expect, test, type Page } from "playwright/test";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
let server: RealServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("scroll_real"));
  await page.locator("#setup-display-name").fill("Scroll real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

const windows = () => page.locator('.cl[data-view="console"] .ui-window');
const strip = () => page.evaluate(() => {
  const col = document.querySelector<HTMLElement>('.cl[data-view="console"] .cl-col')!;
  return `${col.scrollTop}|${col.scrollLeft}|${document.querySelector<HTMLElement>(".cl-world")!.style.transform}`;
});
const scrolled = (index: number) => windows().nth(index).locator(".terminal-host").getAttribute("data-scrolled");
/** A point on the terminal that is on screen (the strip shows only part of a tall window). */
const centre = async (index: number) => {
  const b = (await windows().nth(index).locator(".terminal-host").boundingBox())!;
  const top = Math.max(b.y, 70), bottom = Math.min(b.y + b.height, 880);
  return { x: b.x + b.width / 2, y: (top + bottom) / 2 };
};

test("three stacked windows, the middle focused and locked", async () => {
  await windows().first().locator('[data-action="split-down"]').evaluate((b) => (b as HTMLElement).click());
  await expect(windows()).toHaveCount(2);
  await windows().nth(1).locator('[data-action="split-down"]').evaluate((b) => (b as HTMLElement).click());
  await expect(windows()).toHaveCount(3);
  // A mounted canvas can precede its real attachment. Wait for output from all
  // three live streams before focusing: a late initial attach focuses its input.
  await expect.poll(() => server.bridges.filter((bridge) => !bridge.closed).some((bridge) =>
    [...bridge.attached.keys()].filter((id) => (bridge.output.get(id)?.length ?? 0) > 0).length === 3,
  )).toBe(true);
  // Tall windows, so the column is a strip that scrolls (as when the person has stacked and resized them).
  await page.evaluate(() => { for (const w of document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')) { w.style.height = "560px"; w.style.flex = "none"; } });
  await expect.poll(() => page.evaluate(() => { const c = document.querySelector<HTMLElement>('.cl[data-view="console"] .cl-col')!; return c.scrollHeight - c.clientHeight; })).toBeGreaterThan(200);
  await windows().nth(1).locator(".terminal-host").click({ position: { x: 60, y: 60 } });
  await expect(windows().nth(1).locator(".terminal-host")).toBeFocused();
  await page.keyboard.press("Control+Shift+L");
  await expect(windows().nth(1)).toHaveAttribute("data-locked", "");
  await expect(page.locator(".cl-viewport")).toHaveAttribute("data-input-lock", "");
  await page.waitForTimeout(1200);
});

test("no scrollback and no mouse input: nothing moves, anywhere the pointer is", async () => {
  const before = await strip();
  for (const at of [await centre(1), await centre(0), await centre(2)]) {
    await page.mouse.move(at.x, at.y);
    for (let i = 0; i < 6; i++) await page.mouse.wheel(0, i % 2 ? 120 : -120);
    await page.waitForTimeout(300);
  }
  // The header strip of another window and the gap between windows.
  const head = (await windows().nth(0).locator(".ui-window-head").boundingBox())!;
  await page.mouse.move(head.x + head.width - 4, head.y + head.height / 2);
  await page.mouse.wheel(0, 240);
  await page.waitForTimeout(300);
  expect(await strip()).toBe(before);
  expect(await scrolled(1)).toBe("false");
});

test("with scrollback: the locked terminal scrolls, the strip never does, also at its top and bottom", async () => {
  await windows().nth(1).locator(".terminal-host").click({ position: { x: 60, y: 60 } });
  await page.keyboard.type("seq 1 400\n", { delay: 5 });
  await expect.poll(async () => (await windows().nth(1).locator(".terminal-host canvas").count()) > 0).toBe(true);
  await page.waitForTimeout(1500);
  const before = await strip();
  await expect.poll(scrolled.bind(null, 1)).toBe("false");
  // Over the locked terminal.
  const mid = await centre(1);
  await page.mouse.move(mid.x, mid.y);
  await page.mouse.wheel(0, -300);
  await expect.poll(scrolled.bind(null, 1)).toBe("true");
  expect(await strip()).toBe(before);
  // To the very top and beyond: a long burst, like trackpad momentum, must not chain into the strip.
  for (let i = 0; i < 80; i++) await page.mouse.wheel(0, -200);
  await page.waitForTimeout(500);
  expect(await strip()).toBe(before);
  // Back to the bottom and beyond.
  for (let i = 0; i < 120; i++) await page.mouse.wheel(0, 200);
  await page.waitForTimeout(500);
  expect(await scrolled(1)).toBe("false");
  expect(await strip()).toBe(before);
  // Pointer over another window: the wheel is handed to the locked terminal, the other one does not move.
  const top = await centre(0);
  await page.mouse.move(top.x, top.y);
  await page.mouse.wheel(0, -300);
  await expect.poll(scrolled.bind(null, 1)).toBe("true");
  expect(await scrolled(0)).not.toBe("true");
  expect(await strip()).toBe(before);
  // Pointer over a header of the locked window itself.
  const head = (await windows().nth(1).locator(".ui-window-head").boundingBox())!;
  await page.mouse.move(head.x + head.width - 4, head.y + head.height / 2);
  for (let i = 0; i < 40; i++) await page.mouse.wheel(0, 200);
  await page.waitForTimeout(400);
  expect(await scrolled(1)).toBe("false");
  expect(await strip()).toBe(before);
});

test("unlocked, today's behaviour stays: the wheel over the strip's gap still pans the canvas", async () => {
  await page.keyboard.press("Control+Shift+L");
  await expect(page.locator(".cl-viewport")).not.toHaveAttribute("data-input-lock", "");
  const before = await strip();
  const head = (await windows().nth(0).locator(".ui-window-head").boundingBox())!;
  await page.mouse.move(head.x + head.width - 4, head.y + head.height / 2);
  await page.mouse.wheel(0, 240);
  await page.waitForTimeout(800);
  expect(await strip()).not.toBe(before);
});

test("handler cost: a wheel event held back and forwarded to the locked terminal costs under 1 ms", async () => {
  await windows().nth(1).locator(".terminal-host").click({ position: { x: 60, y: 60 } });
  await page.keyboard.press("Control+Shift+L");
  await expect(page.locator(".cl-viewport")).toHaveAttribute("data-input-lock", "");
  const cost = await page.evaluate(() => {
    const target = document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')[0]!.querySelector<HTMLElement>(".ui-window-head")!;
    // The cost of the canvas's own capture handler: dispatch to a target outside the locked terminal, with the
    // terminal's forwarded dispatch replaced by a no-op listener, so only the viewport handler is timed.
    const host = document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')[1]!.querySelector<HTMLElement>(".terminal-host")!;
    const sink = (e: Event): void => e.stopImmediatePropagation();
    host.addEventListener("wheel", sink, { capture: true });
    const times: number[] = [];
    for (let i = 0; i < 400; i++) {
      const t0 = performance.now();
      target.dispatchEvent(new WheelEvent("wheel", { deltaY: 100, bubbles: true, cancelable: true }));
      times.push(performance.now() - t0);
    }
    host.removeEventListener("wheel", sink, { capture: true });
    times.sort((a, b) => a - b);
    return { mean: times.reduce((a, b) => a + b, 0) / times.length, median: times[200]!, p95: times[380]!, max: times[399]! };
  });
  console.log(`WHEEL handler ${JSON.stringify(cost)} ms per event`);
  // Mean and p95: a rare long tick on this shared, loaded machine (load average 15 or more on 8 cores) is not the handler.
  expect(cost.mean).toBeLessThan(1);
  expect(cost.p95).toBeLessThan(1);
});
