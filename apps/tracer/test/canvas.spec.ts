/**
 * Window canvas prototype (`?proto=windows`, D158–D159, D171): activation without focus,
 * trackpad and two-finger panning, crisp resting offset, copyable key/value cells and the
 * live terminal's cursor staying on its text inside a window card.
 */
import { expect, test, type BrowserContext, type Page } from "playwright/test";

type CanvasOffset = { x: number; y: number; minX: number; moving: boolean; transform: string };

async function openCanvas(page: Page): Promise<void> {
  // The reset closes the previous test's sockets; a pooled keep-alive connection through the
  // latency proxy can be among them, so one retry absorbs that hang-up.
  await page.context().request.post("/__mock/reset").catch(() => page.context().request.post("/__mock/reset"));
  await page.goto("/?mock=1&proto=windows&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0)).toBeGreaterThan(2);
}

const offset = (page: Page): Promise<CanvasOffset> => page.evaluate(() =>
  (window as unknown as { __tracerCanvas: { offset(): CanvasOffset } }).__tracerCanvas.offset());
const activeWindow = (page: Page): Promise<string | undefined> => page.evaluate(() =>
  (window as unknown as { __tracerCanvas: { active(): string | undefined } }).__tracerCanvas.active());

async function touchContext(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.setViewportSize({ width: 393, height: 852 });
  return page;
}

test("desktop: horizontal trackpad scrolling pans the canvas over a terminal and rests on whole pixels", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const terminal = await page.locator(".ui-window").first().locator(".terminal-host").boundingBox();
  await page.mouse.move(terminal!.x + 200, terminal!.y + 200);
  for (let index = 0; index < 10; index++) await page.mouse.wheel(48, 0);
  await expect.poll(async () => (await offset(page)).moving).toBe(false);
  const rest = await offset(page);
  expect(rest.x).toBeLessThan(-200);
  expect(rest.x).toBeGreaterThanOrEqual(rest.minX);
  // Whole device pixels at rest: crisp text (TASTE §5).
  const dpr = await page.evaluate(() => devicePixelRatio);
  expect(Math.abs(rest.x * dpr - Math.round(rest.x * dpr))).toBeLessThan(1e-6);
  expect(rest.transform).toMatch(/^translate3d\(-?\d+(\.\d+)?px, 0px, 0px\)$/);
  // Vertical scrolling over the terminal stays with the terminal, not the canvas.
  const before = (await offset(page)).x;
  await page.mouse.wheel(0, 120);
  expect((await offset(page)).x).toBe(before);
});

test("desktop: a click on an inactive window activates it without moving focus into it", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const second = page.locator(".ui-window").nth(1);
  await second.locator(".ui-window-body").click();
  await expect(second).toHaveAttribute("aria-current", "true");
  // Focus neither moves into the clicked window nor stays in the live terminal behind it.
  expect(await page.evaluate(() => document.activeElement?.closest(".ui-window")?.getAttribute("data-window-id") ?? null)).toBeNull();
  await expect(page.locator("#capsule-host")).toHaveText(/build-01/);
  // No focus ring after a pointer action (TASTE §1).
  expect(await page.evaluate(() => document.documentElement.dataset.focusRing ?? "off")).toBe("off");
});

test("touch: a tap activates without the keyboard, two fingers pan the canvas", async ({ browser }) => {
  const context = await browser.newContext({ hasTouch: true, isMobile: true, deviceScaleFactor: 3, viewport: { width: 393, height: 852 } });
  const page = await touchContext(context);
  await openCanvas(page);
  const cdp = await context.newCDPSession(page);
  const touch = (type: "touchStart" | "touchMove" | "touchEnd", points: Array<{ x: number; y: number; id: number }>) =>
    cdp.send("Input.dispatchTouchEvent", { type, touchPoints: points });
  const box = (await page.locator(".canvas-viewport").boundingBox())!;
  const y = box.y + box.height / 2;
  // Two-finger pan to the left by 240 px.
  await touch("touchStart", [{ x: 260, y, id: 1 }, { x: 320, y, id: 2 }]);
  for (let step = 1; step <= 12; step++) {
    await touch("touchMove", [{ x: 260 - step * 20, y, id: 1 }, { x: 320 - step * 20, y, id: 2 }]);
  }
  await touch("touchEnd", []);
  await expect.poll(async () => (await offset(page)).moving, { timeout: 4_000 }).toBe(false);
  expect((await offset(page)).x).toBeLessThan(-150);
  // A tap on the now visible second window activates it and opens no keyboard.
  const second = page.locator(".ui-window").nth(1).locator(".ui-window-body");
  await second.tap();
  await expect.poll(() => activeWindow(page)).toMatch(/^build-01:/);
  expect(await page.evaluate(() => document.activeElement?.tagName ?? "")).not.toBe("TEXTAREA");
  await context.close();
});

test("details popover: keys left, values right, each cell copies with a tick", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  const popover = page.locator(".canvas-popover");
  await expect(popover).toBeVisible();
  const row = popover.locator(".ui-kv-row").first();
  const [key, value] = await Promise.all([row.locator(".ui-kv-key").boundingBox(), row.locator(".ui-kv-value").boundingBox()]);
  const rowBox = (await row.boundingBox())!;
  expect(key!.x).toBeLessThan(rowBox.x + 8);
  expect(Math.abs(value!.x + value!.width - (rowBox.x + rowBox.width))).toBeLessThan(8);
  await row.locator(".ui-kv-value").click();
  await expect(row.locator(".ui-kv-value")).toHaveAttribute("data-copied", "");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("6.8.0-58-generic");
  await row.locator(".ui-kv-key").click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("Kernel");
  // No ellipsis anywhere in the popover.
  expect(await popover.evaluate((node) => [...node.querySelectorAll("*")].some((element) => getComputedStyle(element).textOverflow === "ellipsis"))).toBe(false);
  await page.keyboard.press("Escape");
  await expect(popover).toHaveCount(0);
});

test("live terminal: the cursor stays on its text inside the window card", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.locator(".ui-window").first().locator(".terminal-host").click();
  const text = "echo abcdefghijklmnopqrstuvwxyz0123456789";
  await page.keyboard.type(text);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX)).toBe(text.length);
  const metrics = await page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!);
  // UI tracking must not reach the renderer: the measured advance equals the cell width.
  expect(Math.abs(metrics.naturalCellWidth - metrics.cellWidth)).toBeLessThan(0.51);
});

for (const dpr of [1, 2]) {
  test(`live terminal: an 86-character line puts the cursor at column 86 with 8 px cells at DPR ${dpr} (a window wide enough for 87 columns)`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1920, height: 900 }, deviceScaleFactor: dpr });
    const page = await context.newPage();
    try {
      await openCanvas(page);
      await page.locator(".ui-window").first().locator(".terminal-host").click();
      const text = "x".repeat(86);
      await page.keyboard.type(text);
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX)).toBe(86);
      const metrics = await page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!);
      expect(metrics.cellWidth).toBe(8);
    } finally {
      await context.close();
    }
  });
}

// ---- floating cards stay inside their window (TASTE §4) --------------------------------
for (const viewport of [{ width: 1440, height: 900, touch: false }, { width: 393, height: 852, touch: true }, { width: 375, height: 667, touch: true }]) {
  test(`details popover stays inside its window with an equal inset at ${viewport.width}×${viewport.height}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport, hasTouch: viewport.touch, isMobile: viewport.touch });
    const page = await context.newPage();
    try {
      await openCanvas(page);
      const pill = page.locator(".ui-window").first().locator(".ui-window-pill");
      if (viewport.touch) await pill.tap(); else await pill.click();
      await expect(page.locator(".canvas-popover")).toBeVisible();
      await page.waitForTimeout(300);
      const box = await page.evaluate(() => {
        const p = document.querySelector(".canvas-popover")!.getBoundingClientRect();
        const w = document.querySelector(".ui-window")!.getBoundingClientRect();
        return { left: p.left - w.left, right: w.right - p.right, bottom: w.bottom - p.bottom, top: p.top - w.top };
      });
      // Never past the window; the left and right gaps are the same 9 px (8 px padding + 1 px frame).
      expect(box.left).toBeGreaterThanOrEqual(8);
      expect(box.right).toBeGreaterThanOrEqual(8);
      expect(box.bottom).toBeGreaterThanOrEqual(8);
      if (viewport.touch) {
        expect(Math.abs(box.left - box.right)).toBeLessThan(1.5);
        // On a phone the content is taller than the window, so the bottom gap is the same inset.
        expect(Math.abs(box.bottom - box.left)).toBeLessThan(1.5);
      }
    } finally {
      await context.close();
    }
  });
}

test("every floating card uses the one overlay material", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  const material = await page.evaluate(() => {
    const read = (el: Element) => { const s = getComputedStyle(el); return { background: s.backgroundColor, filter: s.backdropFilter }; };
    const popover = read(document.querySelector(".canvas-popover")!);
    const probe = document.createElement("div");
    probe.className = "ui-overlay-surface";
    document.body.append(probe);
    const shared = read(probe);
    probe.remove();
    return { popover, shared };
  });
  expect(material.popover).toEqual(material.shared);
  expect(material.shared.filter).toContain("blur(14px)");
});

// ---- the connection line is never a second toast ---------------------------------------
test("a connection failure shows in the shared toast, never as a floating status box", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.evaluate(() => { document.querySelector("#connection-status")!.textContent = "The request could not be completed. Try again."; });
  const toast = page.locator(".ui-toast");
  await expect(toast).toBeVisible();
  await expect(toast).toContainText("could not be completed");
  expect(await page.locator("#connection-status").evaluate((node) => getComputedStyle(node).display)).toBe("none");
  // Progress text ("Connecting…") raises nothing.
  await page.evaluate(() => { document.querySelector("#connection-status")!.textContent = "Connecting…"; });
  await expect(toast).toContainText("could not be completed");
});

// ---- resizing windows -------------------------------------------------------------------
const windowBox = (page: Page, index: number): Promise<{ x: number; y: number; width: number; height: number }> =>
  page.locator(".ui-window").nth(index).evaluate((node) => { const r = node.getBoundingClientRect(); return { x: r.x, y: r.y, width: r.width, height: r.height }; });

test("desktop: edges and corners resize with the right cursors, neighbours shift and never overlap", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const cursors = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll(".ui-window")[1]!.querySelectorAll<HTMLElement>(".ui-window-resize")].map((node) => [node.dataset.edge, getComputedStyle(node).cursor])));
  expect(cursors).toEqual({ n: "ns-resize", s: "ns-resize", e: "ew-resize", w: "ew-resize", ne: "nesw-resize", sw: "nesw-resize", nw: "nwse-resize", se: "nwse-resize" });
  const first = await windowBox(page, 0);
  const second = await windowBox(page, 1);
  // The east edge of the first window drags 150 px narrower; the second window follows it.
  await page.mouse.move(first.x + first.width - 2, first.y + first.height / 2);
  await page.mouse.down();
  await page.mouse.move(first.x + first.width - 152, first.y + first.height / 2, { steps: 12 });
  await page.mouse.up();
  const after = await windowBox(page, 0);
  expect(Math.abs(after.width - (first.width - 150))).toBeLessThan(2);
  const moved = await windowBox(page, 1);
  expect(moved.x - (after.x + after.width)).toBeCloseTo(12, 0);
  expect(moved.x).toBeLessThan(second.x);
  // A south-east corner drag on the second window changes both dimensions.
  await page.mouse.move(moved.x + moved.width - 3, moved.y + moved.height - 3);
  await page.mouse.down();
  await page.mouse.move(moved.x + moved.width - 103, moved.y + moved.height - 203, { steps: 12 });
  await page.mouse.up();
  const corner = await windowBox(page, 1);
  expect(Math.abs(corner.width - (moved.width - 100))).toBeLessThan(2);
  expect(Math.abs(corner.height - (moved.height - 200))).toBeLessThan(2);
  // A north edge drag moves the top down and keeps the bottom where it was.
  const bottom = corner.y + corner.height;
  await page.mouse.move(corner.x + corner.width / 2, corner.y + 2);
  await page.mouse.down();
  await page.mouse.move(corner.x + corner.width / 2, corner.y + 82, { steps: 8 });
  await page.mouse.up();
  const north = await windowBox(page, 1);
  expect(Math.abs(north.y + north.height - bottom)).toBeLessThan(1);
  expect(Math.abs(north.height - (corner.height - 80))).toBeLessThan(2);
  // Windows never overlap: each starts one gap after the previous one ends.
  const boxes = await Promise.all([0, 1, 2].map((index) => windowBox(page, index)));
  for (let index = 1; index < boxes.length; index++) expect(boxes[index]!.x).toBeGreaterThanOrEqual(boxes[index - 1]!.x + boxes[index - 1]!.width + 11);
  // Whole device pixels at rest, so text stays crisp.
  expect(Number.isInteger(after.width) && Number.isInteger(corner.height)).toBe(true);
});

test("desktop: a window cannot shrink below about 40 columns by 10 rows", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const box = await windowBox(page, 1);
  await page.mouse.move(box.x + box.width - 3, box.y + box.height - 3);
  await page.mouse.down();
  await page.mouse.move(box.x + 20, box.y + 20, { steps: 20 });
  await page.mouse.up();
  const small = await windowBox(page, 1);
  expect(small.width).toBeGreaterThanOrEqual(340);
  expect(small.width).toBeLessThan(400);
  expect(small.height).toBeGreaterThanOrEqual(240);
  expect(small.height).toBeLessThan(300);
});

test("desktop: the live terminal refits once on release, not on every frame, and each frame costs under 16 ms", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.evaluate(() => {
    const host = document.querySelector(".terminal-host")!;
    const state = { fits: 0, down: false, costs: [] as number[], pending: 0 };
    (window as unknown as { __rz: typeof state }).__rz = state;
    new ResizeObserver(() => { state.fits++; }).observe(host);
    // Cost of a frame: from the first rAF of the frame to a forced layout after the engine's frame.
    window.addEventListener("pointermove", () => { if (state.down) requestAnimationFrame(() => { state.pending = performance.now(); }); }, { capture: true });
    document.addEventListener("pointermove", () => {
      if (!state.down) return;
      requestAnimationFrame(() => { void document.body.offsetHeight; state.costs.push(performance.now() - state.pending); });
    });
  });
  const box = await windowBox(page, 0);
  await page.mouse.move(box.x + box.width - 2, box.y + box.height - 2);
  await page.evaluate(() => { (window as unknown as { __rz: { down: boolean; fits: number } }).__rz.down = true; (window as unknown as { __rz: { fits: number } }).__rz.fits = 0; });
  await page.mouse.down();
  for (let step = 1; step <= 40; step++) {
    await page.mouse.move(box.x + box.width - 2 - step * 6, box.y + box.height - 2 - step * 8);
    await page.waitForTimeout(16);
  }
  const during = await page.evaluate(() => (window as unknown as { __rz: { fits: number } }).__rz.fits);
  await page.mouse.up();
  await page.waitForTimeout(400);
  const stats = await page.evaluate(() => { const s = (window as unknown as { __rz: { fits: number; costs: number[] } }).__rz; return { fits: s.fits, costs: s.costs }; });
  // Nothing refits while the pointer is down; the one refit happens on release.
  expect(during).toBe(0);
  expect(stats.fits).toBe(1);
  const sorted = [...stats.costs].sort((a, b) => a - b);
  const p95 = sorted[Math.floor(sorted.length * 0.95)]!;
  console.log(`resize frame cost over ${sorted.length} frames: median ${sorted[Math.floor(sorted.length / 2)]!.toFixed(2)} ms, p95 ${p95.toFixed(2)} ms, max ${sorted.at(-1)!.toFixed(2)} ms`);
  expect(p95).toBeLessThan(16);
});

test("touch: press and hold on a header reveals corner handles; a handle resizes; a tap outside ends it", async ({ browser }) => {
  const context = await browser.newContext({ hasTouch: true, isMobile: true, deviceScaleFactor: 3, viewport: { width: 393, height: 852 } });
  const page = await touchContext(context);
  await openCanvas(page);
  const cdp = await context.newCDPSession(page);
  const touch = (type: "touchStart" | "touchMove" | "touchEnd", points: Array<{ x: number; y: number; id: number }>) =>
    cdp.send("Input.dispatchTouchEvent", { type, touchPoints: points });
  const window0 = page.locator(".ui-window").first();
  // No handles at rest, and a quick tap on the header does not start the mode.
  expect(await window0.evaluate((node) => getComputedStyle(node.querySelector(".ui-window-resize")!).display)).toBe("none");
  const head = (await window0.locator(".ui-window-head").boundingBox())!;
  const holdPoint = { x: head.x + head.width - 20, y: head.y + head.height / 2, id: 1 };
  await touch("touchStart", [holdPoint]);
  await page.waitForTimeout(150);
  await touch("touchEnd", []);
  await expect(window0).not.toHaveAttribute("data-resize", "touch");
  // A 450 ms hold does.
  await touch("touchStart", [holdPoint]);
  await page.waitForTimeout(650);
  await expect(window0).toHaveAttribute("data-resize", "touch");
  await touch("touchEnd", []);
  const before = await windowBox(page, 0);
  const grip = (await window0.locator(".ui-window-resize[data-edge='se']").boundingBox())!;
  expect(grip.width).toBeGreaterThanOrEqual(44);
  const from = { x: grip.x + grip.width - 12, y: grip.y + grip.height - 12, id: 2 };
  await touch("touchStart", [from]);
  for (let step = 1; step <= 10; step++) await touch("touchMove", [{ ...from, x: from.x - step * 6, y: from.y - step * 20 }]);
  await touch("touchEnd", []);
  await page.waitForTimeout(300);
  const after = await windowBox(page, 0);
  expect(after.height).toBeLessThan(before.height - 150);
  expect(after.width).toBeLessThan(before.width - 40);
  // The mode stays until a tap lands outside the handles.
  await expect(window0).toHaveAttribute("data-resize", "touch");
  await page.touchscreen.tap(200, after.y + after.height + 40 > 840 ? 800 : after.y + after.height + 40);
  await expect(window0).not.toHaveAttribute("data-resize", "touch");
  await context.close();
});
