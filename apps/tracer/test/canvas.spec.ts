/**
 * Window canvas prototype (`?proto=windows`, D158–D159, D171): activation without focus,
 * trackpad and two-finger panning, crisp resting offset, copyable key/value cells and the
 * live terminal's cursor staying on its text inside a window card.
 */
import { chromium, expect, test, type BrowserContext, type Page } from "playwright/test";
import { uiFactor } from "./ui-factor";

type CanvasOffset = { x: number; y: number; minX: number; moving: boolean; transform: string };

async function openCanvas(page: Page, query = ""): Promise<void> {
  // The reset closes the previous test's sockets; a pooled keep-alive connection through the
  // latency proxy can be among them, so one retry absorbs that hang-up.
  await page.context().request.post("/__mock/reset").catch(() => page.context().request.post("/__mock/reset"));
  await page.goto(`/?mock=1&proto=windows&bg=none&fixture=none${query}`);
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
  expect(material.shared.filter).toContain("blur(8px)"); // the default card level, Tinted
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
  // Off-centre: the middle of the top edge belongs to the window's lock.
  await page.mouse.move(corner.x + 60, corner.y + 2);
  await page.mouse.down();
  await page.mouse.move(corner.x + 60, corner.y + 82, { steps: 8 });
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
  // The preview's frame meter rests in the bottom-right corner, which on a phone is where the first window's lower-right grip is,
  // and takes the touch that is meant for the grip. This spec is about the grips, so it runs without the meter (`fps=0`).
  await openCanvas(page, "&fps=0");
  const cdp = await context.newCDPSession(page);
  const touch = (type: "touchStart" | "touchMove" | "touchEnd", points: Array<{ x: number; y: number; id: number }>) =>
    cdp.send("Input.dispatchTouchEvent", { type, touchPoints: points });
  const window0 = page.locator(".ui-window").first();
  // No handles at rest, and a quick tap on the header does not start the mode.
  expect(await window0.evaluate((node) => getComputedStyle(node.querySelector(".ui-window-resize")!).display)).toBe("none");
  const head = (await window0.locator(".ui-window-head").boundingBox())!;
  // On the title pill: the lock icon takes the free end of the header, so a hold there would lock instead.
  const holdPoint = { x: head.x + 60, y: head.y + head.height / 2, id: 1 };
  await touch("touchStart", [holdPoint]);
  await page.waitForTimeout(150);
  await touch("touchEnd", []);
  await expect(window0).not.toHaveAttribute("data-resize", "touch");
  await page.keyboard.press("Escape"); // the quick tap opened the details popover
  await expect(page.locator(".canvas-popover")).toHaveCount(0);
  // A 450 ms hold does.
  await touch("touchStart", [holdPoint]);
  await page.waitForTimeout(650);
  await expect(window0).toHaveAttribute("data-resize", "touch");
  await touch("touchEnd", []);
  // The hold ends with a 220 ms settle from scale(0.985) back to rest (window-resize.ts). A rect read inside it is still scaled
  // (a 44 px grip measures 43.99994), so wait for the state, no running animation on the window, not for a time.
  await expect.poll(() => window0.evaluate((node) => node.getAnimations().length)).toBe(0);
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

// ---- the sidebar footer ------------------------------------------------------------------
test("sidebar footer: the person and settings pills line up, press, and open Settings with About; no version pill", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(500); // the open spring settles before sizes are read
  const foot = page.locator(".ui-sidebar-foot");
  await expect(foot).toBeVisible();
  await expect(foot.locator(".ui-sidebar-version")).toHaveCount(0);
  await expect(foot.locator(".ui-sidebar-name")).not.toBeEmpty();
  await expect(foot.locator(".ui-sidebar-settings")).toHaveAttribute("aria-label", "Settings");
  // Same height, centres on one line, pinned at the sidebar's bottom.
  const geometry = await page.evaluate(() => {
    const box = (selector: string) => document.querySelector(selector)!.getBoundingClientRect();
    const user = box(".ui-sidebar-user"), gear = box(".ui-sidebar-settings"), sidebar = box("#sidebar"), foot = box(".ui-sidebar-foot");
    return { userH: user.height, gearH: gear.height, centre: Math.abs((user.top + user.height / 2) - (gear.top + gear.height / 2)), gap: sidebar.bottom - foot.bottom };
  });
  expect(geometry.userH).toBeCloseTo(geometry.gearH, 0);
  // The person's pill hugs its content (avatar, name, padding); the gear stays at the right edge.
  const hug = await page.evaluate(() => {
    const user = document.querySelector(".ui-sidebar-user")!.getBoundingClientRect();
    const gear = document.querySelector(".ui-sidebar-settings")!.getBoundingClientRect();
    const foot = document.querySelector(".ui-sidebar-foot")!.getBoundingClientRect();
    const names = document.querySelector(".ui-sidebar-names")!.getBoundingClientRect();
    return { userRight: user.right, gearLeft: gear.left, gearRight: gear.right, footRight: foot.right, trailing: user.right - names.right };
  });
  expect(hug.gearRight).toBeCloseTo(hug.footRight, 0);
  expect(hug.gearLeft - hug.userRight).toBeGreaterThan(40);
  expect(hug.trailing).toBeLessThan(20);
  expect(geometry.centre).toBeLessThan(0.5);
  expect(geometry.gap).toBeLessThan(12);
  // Both are real buttons: pressing scales them (nothing is inert).
  const user = foot.locator(".ui-sidebar-user");
  const ubox = (await user.boundingBox())!;
  await page.mouse.move(ubox.x + 20, ubox.y + 10);
  await page.mouse.down();
  await expect.poll(() => user.evaluate((node) => getComputedStyle(node).transform)).not.toBe("none");
  await page.mouse.up();
  // The person's pill is their account menu (#171, TASTE "You can always sign yourself out"): Settings and Sign out. Its Settings row opens Settings.
  const accountMenu = page.locator(".ui-anchored-popover[aria-label='Account']");
  await expect(accountMenu.getByRole("menuitem")).toHaveText(["Settings", "Sign out"]);
  await accountMenu.getByRole("menuitem", { name: "Settings" }).click();
  await expect(page.locator(".ui-settings")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator(".ui-settings")).toHaveCount(0);
  // Settings, About: the gear opens it; a value copies and confirms in place (clipboard icon and "Copied").
  await foot.locator(".ui-sidebar-settings").click();
  const about = page.locator(".ui-settings");
  await expect(about.locator(".ui-settings-nav-row[aria-current='true']")).toHaveText("About");
  const commit = about.locator(".ui-kv-row", { hasText: "Commit" }).locator(".ui-kv-value");
  await commit.click();
  await expect(commit).toHaveAttribute("data-copied", "");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^[0-9a-f]{40}$|^dev$/);
  await expect(commit.locator(".ui-copied")).toHaveText("Copied");
  const version = about.locator(".ui-kv-row", { hasText: "Version" }).locator(".ui-kv-value");
  await version.click();
  expect((await page.evaluate(() => navigator.clipboard.readText())).length).toBeGreaterThanOrEqual(3);
  expect(await page.evaluate(() => document.documentElement.dataset.focusRing ?? "off")).toBe("off");
  await page.keyboard.press("Escape");
});

test("palette: About infraternal opens Settings, About, and is found by version, build and commit", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  for (const alias of ["about", "version", "build", "commit"]) {
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill(alias);
    await expect(page.locator(".result[data-action='settings:about']")).toBeVisible();
    if (alias === "commit") {
      // "commit" also finds the Commit Mono font row, so pick About by name.
      await page.locator(".result[data-action='settings:about']").click();
      await expect(page.locator(".ui-settings")).toBeVisible();
      await page.keyboard.press("Escape");
    } else await page.keyboard.press("Escape");
  }
});

// ---- the window lock ----------------------------------------------------------------------
test("lock: the icon appears near a window's top edge, locks with a click, stays, and unlocks with Ctrl+Shift+L", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const window0 = page.locator(".ui-window").first();
  const lock = window0.locator(".ui-window-lock");
  const box = (await window0.boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + 400);
  await expect(lock).toHaveCSS("opacity", "0");
  await page.mouse.move(box.x + box.width / 2, box.y + 30);
  await expect(lock).toHaveCSS("opacity", "0.35");
  // Never covered by the title pill.
  const geometry = await page.evaluate(() => {
    const l = document.querySelector(".ui-window-lock")!.getBoundingClientRect();
    const p = document.querySelector(".ui-window-pill")!.getBoundingClientRect();
    return { lockLeft: l.left, pillRight: p.right, size: l.width };
  });
  expect(geometry.lockLeft).toBeGreaterThanOrEqual(geometry.pillRight);
  // The glyph itself sits on the frame: the shackle above the window's top line, the body below it.
  const frame = await page.evaluate(() => {
    const w = document.querySelector(".ui-window")!.getBoundingClientRect();
    const body = document.querySelector(".ui-lock-body")!.getBoundingClientRect();
    const shackle = document.querySelector(".ui-lock-shackle")!.getBoundingClientRect();
    const button = document.querySelector(".ui-window-lock")!.getBoundingClientRect();
    return { shackleBottom: shackle.bottom - w.top, shackleTop: shackle.top - w.top, bodyTop: body.top - w.top, hit: [button.width, button.height], bg: getComputedStyle(document.querySelector(".ui-window-lock")!).backgroundColor, border: getComputedStyle(document.querySelector(".ui-window-lock")!).borderTopWidth };
  });
  // The glyph and its hit area are drawn in rem, the frame is a 1 px hairline: the glyph's offsets from the frame grow with the UI size's
  // factor, and the button's own offset grows with it too, so the shackle's distance grows with its square (measured: 1.17 px at a
  // factor of 1, 1.43 at 1.1, 2.01 at 1.32). The glyph's design is the same at every size (#283).
  const factor = await uiFactor(page);
  expect(frame.shackleTop).toBeLessThan(-3);
  expect(Math.abs(frame.bodyTop)).toBeLessThan(1.2 * factor);
  expect(Math.abs(frame.shackleBottom)).toBeLessThan(1.2 * factor * factor);
  for (const side of frame.hit as number[]) expect(Math.abs(side - 44 * factor), "the lock's hit area is 44 px at the standard factor").toBeLessThan(0.1);
  expect(frame.bg).toBe("rgba(0, 0, 0, 0)");
  expect(frame.border).toBe("0px");
  await expect(lock).toHaveAttribute("data-tip", "Lock input");
  await lock.click();
  await expect(window0).toHaveAttribute("data-locked", "");
  await expect(lock).toHaveAttribute("aria-pressed", "true");
  await expect(lock).toHaveAttribute("data-tip", "Unlock input");
  // Persistent: it stays visible with the pointer far away.
  await page.mouse.move(box.x + box.width / 2, box.y + 500);
  await expect(lock).toHaveCSS("opacity", "0.9");
  // The shackle has closed: its transform settles to none.
  await expect.poll(() => lock.locator(".ui-lock-shackle").evaluate((node) => getComputedStyle(node).transform)).toMatch(/^(none|matrix\(1, 0, 0, 1, 0, 0\))$/);
  await page.keyboard.press("Control+Shift+KeyL");
  await expect(window0).not.toHaveAttribute("data-locked", "");
  await expect(lock.locator(".ui-lock-shackle")).toHaveCSS("transform", /matrix/);
});

test("lock: wheel and canvas gestures inside the locked window never pan; outside it still does; other windows are ignored", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const window0 = page.locator(".ui-window").first();
  await page.keyboard.press("Control+Shift+KeyL");
  await expect(window0).toHaveAttribute("data-locked", "");
  const box = (await window0.boundingBox())!;
  await page.mouse.move(box.x + 200, box.y + 300);
  for (let index = 0; index < 8; index++) await page.mouse.wheel(60, 0);
  await page.waitForTimeout(400);
  expect((await offset(page)).x).toBe(0);
  // A middle-button drag that starts inside the window is ignored too.
  await page.mouse.move(box.x + 200, box.y + 300);
  await page.mouse.down({ button: "middle" });
  await page.mouse.move(box.x + 20, box.y + 300, { steps: 6 });
  await page.mouse.up({ button: "middle" });
  expect((await offset(page)).x).toBe(0);
  // Over another window the canvas still pans.
  const second = (await page.locator(".ui-window").nth(1).boundingBox())!;
  await page.mouse.move(second.x + 200, second.y + 300);
  for (let index = 0; index < 8; index++) await page.mouse.wheel(60, 0);
  await expect.poll(async () => (await offset(page)).x).toBeLessThan(-100);
  // A click on another window does not take the input: the locked window stays the active one.
  const other = page.locator(".ui-window").nth(1);
  const otherBox = (await other.boundingBox())!;
  await page.mouse.click(otherBox.x + 100, otherBox.y + 200);
  expect(await activeWindow(page)).toMatch(/^live:/);
  await expect(window0).toHaveAttribute("data-locked", "");
});

test("lock: Ctrl+K reaches the terminal on Linux and Windows while locked, and opens the palette when unlocked", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.evaluate(() => {
    (window as unknown as { __keys: string[] }).__keys = [];
    document.querySelector(".terminal-host")!.addEventListener("keydown", (event) => {
      const key = event as KeyboardEvent;
      if (key.ctrlKey && key.key.toLowerCase() === "k") (window as unknown as { __keys: string[] }).__keys.push("ctrl+k");
    }, true);
  });
  await page.keyboard.press("Control+Shift+KeyL");
  await expect(page.locator(".ui-window").first()).toHaveAttribute("data-locked", "");
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeHidden();
  expect(await page.evaluate(() => (window as unknown as { __keys: string[] }).__keys)).toEqual(["ctrl+k"]);
  await page.keyboard.press("Control+Shift+KeyL");
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  // The palette offers the action that fits the state, with the shortcut shown.
  await expect(page.locator(".result[data-action='proto:lock'] .result-label")).toHaveText("Lock window");
  await expect(page.locator(".result[data-action='proto:lock'] .result-hint")).toHaveText("Ctrl+Shift+L");
  await page.keyboard.press("Enter");
  await expect(page.locator(".ui-window").first()).toHaveAttribute("data-locked", "");
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.keyboard.press("Meta+k"); // not a macOS page: ⌘K does not open the palette while locked
  await expect(page.locator("#palette")).toBeHidden();
});

test("lock: on macOS, ⌘K still opens the palette while locked and offers Unlock window", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await context.addInitScript(() => Object.defineProperty(navigator, "platform", { get: () => "MacIntel" }));
  const page = await context.newPage();
  await openCanvas(page);
  await page.keyboard.press("Control+Shift+KeyL");
  await expect(page.locator(".ui-window").first()).toHaveAttribute("data-locked", "");
  await expect(page.locator(".ui-window-lock").first()).toHaveAttribute("data-tip", "Unlock input");
  // Ctrl+K belongs to the terminal on a Mac too (kill-line); ⌘K is the palette.
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeHidden();
  await page.keyboard.press("Meta+k");
  await expect(page.locator("#palette")).toBeVisible();
  await expect(page.locator(".result[data-action='proto:unlock'] .result-label")).toHaveText("Unlock window");
  await page.keyboard.press("Enter");
  await expect(page.locator(".ui-window").first()).not.toHaveAttribute("data-locked", "");
  await context.close();
});

test("lock (touch): there is no frame lock on a phone; the palette locks", async ({ browser }) => {
  const context = await browser.newContext({ hasTouch: true, isMobile: true, deviceScaleFactor: 3, viewport: { width: 393, height: 852 } });
  const page = await touchContext(context);
  await openCanvas(page);
  const window0 = page.locator(".ui-window").first();
  expect(await window0.locator(".ui-window-lock").evaluate((node) => getComputedStyle(node).display)).toBe("none");
  await page.keyboard.press("Control+Shift+KeyL");
  await expect(window0).toHaveAttribute("data-locked", "");
  await context.close();
});

test("lock: one click on an unfocused window's lock focuses that window and locks it", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const second = page.locator(".ui-window").nth(1);
  expect(await activeWindow(page)).toMatch(/^live:/);
  const box = (await second.boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + 20);
  await expect(second).toHaveAttribute("data-lock-near", "");
  await second.locator(".ui-window-lock").click();
  await expect(second).toHaveAttribute("data-locked", "");
  expect(await activeWindow(page)).toMatch(/^build-01:/);
  await expect(page.locator(".ui-window[data-locked]")).toHaveCount(1);
  // Locking another window moves the lock.
  const first = page.locator(".ui-window").first();
  const firstBox = (await first.boundingBox())!;
  await page.mouse.move(firstBox.x + firstBox.width / 2, firstBox.y + 20);
  await first.locator(".ui-window-lock").click();
  await expect(first).toHaveAttribute("data-locked", "");
  await expect(second).not.toHaveAttribute("data-locked", "");
});

// ---- the `?` shortcuts view ---------------------------------------------------------------
const blurTerminal = (page: Page): Promise<void> => page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());

test("shortcuts: ? morphs the capsule into the list, current area first, one shortcut per action; Esc, ? and a click outside morph it back", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  // Typing into the terminal is never hijacked.
  await page.locator(".ui-window").first().locator(".terminal-host").click();
  await page.keyboard.press("?");
  await expect(page.locator(".ui-shortcuts")).toHaveCount(0);
  await blurTerminal(page);
  const pillBox = (await page.locator("#capsule").boundingBox())!;
  await page.keyboard.press("?");
  const panel = page.locator(".ui-shortcuts");
  await expect(panel).toBeVisible();
  // Mid-morph: the shape is clipped to part of the panel and the pill is fading out.
  const mid = await panel.evaluate((node) => ({ clip: getComputedStyle(node).clipPath, pill: getComputedStyle(document.querySelector("#capsule")!).opacity }));
  expect(mid.clip === "none" || mid.clip.startsWith("inset(")).toBe(true);
  await expect.poll(() => panel.evaluate((node) => getComputedStyle(node).clipPath)).toBe("none");
  // The panel starts where the pill is and is the same material as every floating card.
  const box = (await panel.boundingBox())!;
  expect(Math.abs(box.y - pillBox.y)).toBeLessThan(1.5);
  expect(box.width).toBeGreaterThan(pillBox.width);
  const titles = await panel.locator(".ui-shortcuts-title").allTextContents();
  expect(titles).toEqual(["Canvas", "Terminal", "Everywhere"]);
  const labels = await panel.locator(".ui-shortcuts-label").allTextContents();
  expect(new Set(labels).size).toBe(labels.length);
  // One shortcut per action: the palette shows Ctrl+K here, never ⌘K as well.
  const palette = await panel.locator(".ui-shortcuts-row", { hasText: "command palette" }).locator("kbd").allTextContents();
  expect(palette).toEqual(["Ctrl", "Shift", "K", "Ctrl", "Shift", "P"]); // the primary, then the alternate (dimmed) on the same row
  const material = await panel.evaluate((node) => { const s = getComputedStyle(node); return { filter: s.backdropFilter, bg: s.backgroundColor }; });
  expect(material.filter).toContain("blur(8px)"); // the default card level, Tinted
  // At rest nothing is left animating: no transform, no opacity on the content.
  expect(await panel.evaluate((node) => [getComputedStyle(node).transform, getComputedStyle(node.querySelector(".ui-shortcuts-body")!).opacity])).toEqual(["none", "1"]);
  await page.keyboard.press("Escape");
  await expect(panel).toHaveCount(0);
  await expect(page.locator("#capsule")).toHaveCSS("opacity", "1");
  // ? again toggles; a press outside closes.
  await page.keyboard.press("?");
  await expect(panel).toBeVisible();
  await page.keyboard.press("?");
  await expect(panel).toHaveCount(0);
  await page.keyboard.press("?");
  await expect(panel).toBeVisible();
  await page.mouse.click(300, 700);
  await expect(panel).toHaveCount(0);
});

test("shortcuts: the palette offers Keyboard shortcuts, lock shortcuts are listed, and a Mac sees ⌘K", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await context.addInitScript(() => Object.defineProperty(navigator, "platform", { get: () => "MacIntel" }));
  const page = await context.newPage();
  await openCanvas(page);
  await page.keyboard.press("Meta+k");
  await page.locator("#palette-input").fill("shortcuts");
  await page.keyboard.press("Enter");
  const panel = page.locator(".ui-shortcuts");
  await expect(panel).toBeVisible();
  // Key labels follow the platform (#121, TASTE "Every platform sees its own conventions"): on an Apple keyboard the written
  // "Ctrl+Shift+L" is drawn as the glyphs ⌃ ⇧ L, one cap each; the words stay on Windows and Linux (the next test).
  await expect(panel.locator(".ui-shortcuts-row", { hasText: "Lock or unlock" }).locator("kbd")).toHaveText(["⌃", "⇧", "L"]);
  await expect(panel.locator(".ui-shortcuts-row", { hasText: "command palette" }).locator("kbd")).toHaveText(["⌘", "K", "⌘", "⇧", "P"]);
  await page.keyboard.press("Escape");
  await expect(panel).toHaveCount(0);
  await context.close();
});

test("shortcuts (reduced motion): the panel crossfades without any shape travel", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
  const page = await context.newPage();
  await openCanvas(page);
  await blurTerminal(page);
  await page.keyboard.press("?");
  const panel = page.locator(".ui-shortcuts");
  await expect(panel).toBeVisible();
  expect(await panel.evaluate((node) => getComputedStyle(node).clipPath)).toBe("none");
  await page.keyboard.press("Escape");
  await expect(panel).toHaveCount(0);
  await context.close();
});

// ---- empty canvas ---------------------------------------------------------------------------
test("empty canvas: a click in the gap clears the active window and its highlight; keys go to canvas navigation", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.locator(".ui-window").first().locator(".terminal-host").click();
  await expect(page.locator(".ui-window[data-active]")).toHaveCount(1);
  const first = (await page.locator(".ui-window").first().boundingBox())!;
  await page.mouse.click(first.x + first.width + 6, first.y + 300); // the 12 px gap between two windows
  await expect(page.locator(".ui-window[data-active]")).toHaveCount(0);
  await expect(page.locator(".ui-window[aria-current]")).toHaveCount(0);
  expect(await activeWindow(page)).toBeUndefined();
  expect(await page.evaluate(() => document.activeElement?.closest(".terminal-host") ?? null)).toBeNull();
  // Keys now navigate the canvas: Ctrl+Shift+→ activates a window again.
  await page.keyboard.press("Control+Shift+ArrowRight");
  await expect.poll(() => activeWindow(page)).toBeDefined();
  // A drag that starts in the gap (a pan) is not a tap.
  await page.mouse.move(first.x + first.width + 6, first.y + 300);
  await page.keyboard.down("Space");
  await page.mouse.down();
  await page.mouse.move(first.x + first.width - 60, first.y + 300, { steps: 6 });
  await page.mouse.up();
  await page.keyboard.up("Space");
  expect(await activeWindow(page)).toBeDefined();
});

test("empty canvas (touch): a tap in the gap clears the active window", async ({ browser }) => {
  const context = await browser.newContext({ hasTouch: true, isMobile: true, deviceScaleFactor: 3, viewport: { width: 393, height: 852 } });
  const page = await touchContext(context);
  await openCanvas(page);
  await expect(page.locator(".ui-window[data-active]")).toHaveCount(1);
  await page.waitForTimeout(600);
  // The next window peeks past the 12 px gap; tap the middle of the gap itself.
  const gap = await page.evaluate(() => {
    const [a, b] = [...document.querySelectorAll(".ui-window")].slice(0, 2).map((node) => node.getBoundingClientRect());
    return { x: (a!.right + b!.left) / 2, y: a!.top + 300, gap: b!.left - a!.right };
  });
  expect(gap.gap).toBeGreaterThan(8);
  await page.touchscreen.tap(gap.x, gap.y);
  await expect(page.locator(".ui-window[data-active]")).toHaveCount(0);
  await context.close();
});

// ---- the info popover's tabs use the shared gliding capsule -----------------------------------
test("details popover tabs: the selected capsule glides (does not jump) and the keyboard moves it instantly", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  await expect(page.locator(".canvas-popover .ui-tabs")).toBeVisible();
  await page.waitForTimeout(400);
  // The only tab implementation is the shared one.
  expect(await page.evaluate(() => document.querySelectorAll(".canvas-popover [role='tab']:not(.ui-tab)").length)).toBe(0);
  await page.evaluate(() => {
    const capsule = document.querySelector<HTMLElement>(".ui-tabs-capsule")!;
    const samples: number[] = [];
    (window as unknown as { __tabs: number[] }).__tabs = samples;
    const t0 = performance.now();
    const frame = (): void => {
      samples.push(new DOMMatrix(getComputedStyle(capsule).transform).m41);
      if (performance.now() - t0 < 450) requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  });
  await page.locator(".canvas-popover .ui-tab[data-tab='connection']").click();
  await page.waitForTimeout(500);
  const samples = await page.evaluate(() => (window as unknown as { __tabs: number[] }).__tabs);
  const start = samples[0]!, end = samples.at(-1)!;
  expect(end).toBeGreaterThan(start + 20);
  // At least two frames sit strictly between the start and the end: a glide, not a jump.
  expect(samples.filter((value) => value > start + 1 && value < end - 1).length).toBeGreaterThanOrEqual(2);
  // Arrow keys move it without animation.
  await page.locator(".canvas-popover .ui-tab[data-tab='connection']").focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.locator(".canvas-popover .ui-tab[data-tab='session']")).toHaveAttribute("aria-selected", "true");
  expect(await page.locator(".ui-tabs-capsule").evaluate((node) => node.style.transition)).toBe("none");
});

test("copyable values: the highlight hugs the text with even padding, on keys and right-aligned values", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  await page.waitForTimeout(500); // the popover's scale-in settles before it is measured
  const measure = (kind: "key" | "value") => page.evaluate((which) => {
    const row = [...document.querySelectorAll(".canvas-popover .ui-kv-row")].find((node) => node.textContent!.includes("Virtualization"))!;
    const span = row.querySelector(`.ui-kv-${which} .ui-kv-text`)!;
    const text = document.createRange();
    text.selectNodeContents([...span.childNodes].find((node) => node.nodeType === 3)!);
    const box = span.getBoundingClientRect(), glyphs = text.getBoundingClientRect();
    return { left: glyphs.left - box.left, right: box.right - glyphs.right };
  }, kind);
  for (const kind of ["key", "value"] as const) {
    const pad = await measure(kind);
    expect(Math.abs(pad.left - 6)).toBeLessThan(0.6);
    expect(Math.abs(pad.right - 6)).toBeLessThan(0.6);
  }
  // Wrapped values keep a highlight per line: the decoration is cloned across the lines.
  expect(await page.evaluate(() => getComputedStyle(document.querySelector(".ui-kv-text")!).getPropertyValue("box-decoration-break"))).toBe("clone");
});

// ---- nothing in the bottom-left corner -------------------------------------------------------
test("a normal preview session never writes text bottom left: reload, a failing session check, state messages", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const cornerText = (): Promise<string[]> => page.evaluate(() => {
    const found: string[] = [];
    for (const node of document.querySelectorAll<HTMLElement>("body *")) {
      if (node.children.length || !node.textContent?.trim()) continue;
      const box = node.getBoundingClientRect(), style = getComputedStyle(node);
      if (box.width === 0 || box.height === 0 || style.visibility === "hidden" || style.display === "none" || Number(style.opacity) === 0) continue;
      if (node.closest(".ui-window, .sidebar, .palette")) continue; // windows own their own content
      if (box.left < 320 && box.bottom > innerHeight - 140) found.push(node.textContent.trim());
    }
    return found;
  });
  await openCanvas(page);
  // The very first frames after a reload: the status line's "Starting terminal…" is never drawn.
  await page.reload();
  for (let frame = 0; frame < 10; frame++) {
    expect(await page.locator("#connection-status").evaluate((node) => getComputedStyle(node).display)).toBe("none");
    await page.waitForTimeout(60);
  }
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  // The server goes away while the tab is in the background, then the person returns.
  await page.route("**/auth/session", (route) => route.abort("connectionrefused"));
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
    document.dispatchEvent(new Event("visibilitychange"));
    Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await page.waitForTimeout(1200);
  await page.unroute("**/auth/session");
  // Routine connection states raise no toast and no text, in any corner.
  for (const message of ["Connecting…", "Connection lost. Reconnecting…", "Connection interrupted. Reconnecting…", "Reconnected. The screen may be slightly out of date.", "Starting terminal…"]) {
    await page.evaluate((text) => { document.querySelector("#connection-status")!.textContent = text; }, message);
    await page.waitForTimeout(150);
    await expect(page.locator(".ui-toast")).toBeHidden();
  }
  await page.evaluate(() => { document.querySelector("#connection-status")!.textContent = ""; });
  expect(await cornerText()).toEqual([]);
  // The shared toast sits bottom centre and takes the theme's material (light on paper).
  await page.evaluate(() => { document.querySelector("#connection-status")!.textContent = "The server could not open this terminal."; });
  await expect(page.locator(".ui-toast")).toBeVisible();
  const toast = await page.locator(".ui-toast").evaluate((node) => { const r = node.getBoundingClientRect(); return { centre: r.left + r.width / 2, bottom: innerHeight - r.bottom }; });
  expect(Math.abs(toast.centre - 720)).toBeLessThan(4);
  expect(toast.bottom).toBeLessThan(40);
});

// ---- copying from an insecure origin ---------------------------------------------------------
test("copy works from a plain-http, non-localhost origin: no async clipboard, the fallback copies and the feedback plays", async () => {
  // `insecure.test` resolves to the loopback proxy, but the browser treats it as a non-secure
  // origin (as the LAN address of the preview is), so `navigator.clipboard` is undefined there.
  const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
  const browser = await chromium.launch({ args: [`--host-resolver-rules=MAP insecure.test 127.0.0.1`] });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.goto(`http://insecure.test:${port}/?mock=1&proto=windows&bg=none`);
    await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0), { timeout: 30_000 }).toBeGreaterThan(2);
    expect(await page.evaluate(() => ({ secure: isSecureContext, clipboard: typeof navigator.clipboard }))).toEqual({ secure: false, clipboard: "undefined" });
    // Record what execCommand("copy") is asked to copy, then let it succeed.
    await page.evaluate(() => {
      const copied: string[] = [];
      (window as unknown as { __copied: string[] }).__copied = copied;
      document.execCommand = (command: string): boolean => {
        if (command === "copy") copied.push((document.activeElement as HTMLTextAreaElement).value);
        return true;
      };
    });
    await page.locator(".ui-window").first().locator(".ui-window-pill").click();
    const value = page.locator(".canvas-popover .ui-kv-value").first();
    await value.click();
    await expect(value).toHaveAttribute("data-copied", "");
    expect(await page.evaluate(() => (window as unknown as { __copied: string[] }).__copied)).toEqual(["6.8.0-58-generic"]);
    // The text fades out and the clipboard icon with "Copied" takes its place; there is no tooltip.
    await expect(value.locator(".ui-copied")).toHaveCSS("opacity", "1");
    await expect(value.locator(".ui-kv-text")).toHaveCSS("opacity", "0");
    await expect(value.locator(".ui-copied svg")).toHaveCount(1);
    expect((await page.locator(".tip").allInnerTexts()).join(" ")).not.toContain("Copied");
    // The cursor over a copyable value is the pointer, never the green plus of `copy`.
    expect(await value.evaluate((node) => getComputedStyle(node).cursor)).toBe("pointer");
    // If both paths fail, the same slot says so.
    await page.evaluate(() => { document.execCommand = () => false; });
    const key = page.locator(".canvas-popover .ui-kv-key").first();
    await key.click();
    await expect(key.locator(".ui-copied")).toHaveText("Couldn't copy");
    await expect(key.locator(".ui-copied svg")).toHaveCount(0);
  } finally {
    await browser.close();
  }
});

test("top pill: the host's operating-system icon replaces the connection dot and follows the active window", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const pill = page.locator("#capsule");
  await expect(pill.locator("#connection-dot")).toBeHidden();
  await expect(pill.locator("#capsule-os svg")).toBeVisible();
  const first = await pill.locator("#capsule-os").innerHTML();
  await page.locator(".ui-window").nth(2).locator(".ui-window-body").click(); // an Arch/Debian-family host, not the first
  await expect.poll(() => pill.locator("#capsule-os").innerHTML()).not.toBe(first);
});

// ---- the palette: centred and sized by its results ---------------------------------------------
test("palette (desktop): centred, as tall as its results, never closer than a quarter of the viewport to the top or bottom", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const palette = page.locator("#palette");
  const box = async () => (await palette.boundingBox())!;
  await page.keyboard.press("Control+Shift+K");
  await expect(palette).toBeVisible();
  await page.waitForTimeout(300);
  // No query: the default sections up to the cap (50 % of the viewport), centred both ways.
  let b = await box();
  expect(Math.abs(b.x + b.width / 2 - 720)).toBeLessThan(1);
  expect(b.height).toBeLessThanOrEqual(450.5);
  expect(b.y).toBeGreaterThanOrEqual(224);
  expect(900 - (b.y + b.height)).toBeGreaterThanOrEqual(224);
  expect(Math.abs(b.y + b.height / 2 - 450)).toBeLessThan(1);
  const sizes: number[] = [b.height];
  for (const [query, expectRows] of [["ink", 1], ["theme", 10], ["zzzz", 0]] as const) {
    await page.locator("#palette-input").fill(query);
    await page.waitForTimeout(60);
    b = await box();
    sizes.push(b.height);
    // Symmetric growth: the middle never moves; the height follows the rows and is never animated.
    expect(Math.abs(b.y + b.height / 2 - 450)).toBeLessThan(1);
    expect(await page.locator(".palette-results .result").count()).toBeGreaterThanOrEqual(Math.min(expectRows, 1));
    expect(await palette.evaluate((node) => getComputedStyle(node).transitionProperty)).not.toContain("height");
  }
  const [none, one, many, empty] = sizes as [number, number, number, number];
  expect(one).toBeLessThan(many);
  expect(many).toBeLessThanOrEqual(none);
  expect(empty).toBeLessThan(none);
  expect(one).toBeLessThan(200);
  // The selected row keeps its inset highlight.
  await page.locator("#palette-input").fill("theme");
  const inset = await page.locator(".result[aria-selected='true']").first().evaluate((node) => getComputedStyle(node, "::before").top);
  expect(parseFloat(inset)).toBeCloseTo(3 * (await uiFactor(page)), 1);
  await page.keyboard.press("Escape");
});

test("palette (phone): keeps its placement under the top bar, inside the safe area", async ({ browser }) => {
  const context = await browser.newContext({ hasTouch: true, isMobile: true, deviceScaleFactor: 3, viewport: { width: 393, height: 852 } });
  const page = await touchContext(context);
  await openCanvas(page);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  await page.waitForTimeout(300);
  const b = (await page.locator("#palette").boundingBox())!;
  expect(b.y).toBeLessThan(100);
  expect(b.y + b.height).toBeLessThanOrEqual(852);
  await context.close();
});

// ---- animation never gets in the way ----------------------------------------------------------
test("palette: Ctrl+K then typing within 20 ms lands every character; arrow selection has no transition", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  // The open animates (a short fade), yet the field is focused at once and takes the first keystrokes.
  await page.keyboard.press("Control+Shift+K");
  await page.waitForTimeout(20);
  await page.keyboard.type("thm", { delay: 0 });
  await expect(page.locator("#palette-input")).toHaveValue("thm");
  expect(await page.evaluate(() => getComputedStyle(document.querySelector("#palette")!).pointerEvents)).not.toBe("none");
  await page.locator("#palette-input").fill("theme");
  const before = await page.locator(".result[aria-selected='true']").getAttribute("data-action");
  await page.keyboard.press("ArrowDown");
  expect(await page.locator(".result[aria-selected='true']").getAttribute("data-action")).not.toBe(before);
  const transitions = await page.evaluate(() => [...document.querySelectorAll(".result")].slice(0, 4).map((row) => getComputedStyle(row, "::before").transitionDuration));
  expect(transitions.every((duration) => duration === "0s")).toBe(true);
  // The key-triggered open is short (about 180 ms) and the pointer one longer.
  expect(await page.evaluate(() => getComputedStyle(document.querySelector("#palette")!).transitionDuration)).toBe("0.18s");
});

// ---- text behind glass is never legible through it --------------------------------------------
test("clear and frosted cards blur what is behind them by more than a line of text, so letters never read through", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page, "&card=3");
  await page.locator("#sidebar-toggle").click();
  await page.keyboard.press("Control+Shift+K");
  await page.waitForTimeout(400);
  const blurs = await page.evaluate(() => Object.fromEntries(["#palette", "#sidebar"].map((selector) => [selector, parseFloat(/blur\(([\d.]+)px\)/.exec(getComputedStyle(document.querySelector(selector)!).backdropFilter)?.[1] ?? "0")])));
  await page.keyboard.press("Escape");
  await page.locator(".ui-window-pill").nth(1).click();
  const popover = await page.evaluate(() => parseFloat(/blur\(([\d.]+)px\)/.exec(getComputedStyle(document.querySelector(".canvas-popover")!).backdropFilter)?.[1] ?? "0"));
  // A terminal line is about 18 px tall: the blur radius is at least that, measured from captures over dense text.
  for (const value of [...Object.values(blurs), popover]) expect(value).toBeGreaterThanOrEqual(24);
});
