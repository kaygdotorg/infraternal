/**
 * The window shortcuts and the `?` panel (TASTE: every window action has a key, and the shortcuts panel shows them all).
 *
 * - Close window: one press closes one window, quick presses each close one, auto-repeat does nothing, the session keeps
 *   running (D178), and nothing animates (a keyboard action is instant).
 * - The panel shows the alternates on the same row, quieter, and keeps its order: the area it was opened in comes first.
 * - ⌘/ (Ctrl+Shift+/ here) opens the panel from inside a focused terminal, where "?" is typed into the shell.
 */
import { expect, test, type Page } from "playwright/test";

const VIEW = '.cl[data-view="console"]';

async function boot(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none&sessions=1");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
}

/** Opens `count` new windows to the right, so the view holds that many (each one becomes the active window). */
async function fill(page: Page, count: number): Promise<void> {
  await page.evaluate((n) => {
    for (let i = 0; i < n; i++) window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:new:right", source: "pointer" } }));
  }, count);
  await page.waitForTimeout(900);
}

const windows = (page: Page): Promise<number> => page.evaluate((v) => document.querySelectorAll(`${v} .ui-window`).length, VIEW);
const activeId = (page: Page): Promise<string | null> => page.evaluate((v) => document.querySelector<HTMLElement>(`${v} .ui-window[data-active]`)?.dataset.windowId ?? null, VIEW);
const sessionStates = (page: Page): Promise<string[]> => page.evaluate(() => {
  const probe = (window as unknown as { __tracerClusters: { sessions(): { hosts: Array<{ sessions: Array<{ state: string }> }> } } }).__tracerClusters;
  return probe.sessions().hosts.flatMap((h) => h.sessions.map((s) => s.state));
});

/** Presses a key chord, with no wait between the keys, the way a quick press lands. */
async function chord(page: Page, keys: string[]): Promise<void> {
  for (const k of keys) await page.keyboard.down(k);
  for (const k of [...keys].reverse()) await page.keyboard.up(k);
}

test.describe("Close window", () => {
  test.setTimeout(180_000);

  test("ten quick presses close exactly ten windows, the sessions stay alive, and nothing animates", async ({ page }) => {
    await boot(page);
    await fill(page, 10);
    const n0 = await windows(page);
    expect(n0).toBeGreaterThanOrEqual(11);
    const states0 = await sessionStates(page);
    for (let i = 0; i < 10; i++) {
      await chord(page, ["Control", "Alt", "KeyW"]);
      // Read at once, with no wait: an instant close has no motion, so the count is already the count after the press.
      expect(await windows(page)).toBe(n0 - (i + 1));
    }
    // The sessions stay alive, detached: none has ended, and the number of sessions is unchanged.
    await page.waitForTimeout(300);
    const states1 = await sessionStates(page);
    // Nothing ended: the exited sessions of the scene are the same, the list is the same length, and the windows that
    // closed are detached, not gone.
    expect(states1.length).toBe(states0.length);
    expect(states1.filter((x) => x === "exited").length).toBe(states0.filter((x) => x === "exited").length);
    expect(states1.filter((x) => x === "detached").length).toBeGreaterThan(states0.filter((x) => x === "detached").length);
    // No window is left mid-animation: the one still standing carries no transform.
    const transform = await page.evaluate((v) => [...document.querySelectorAll<HTMLElement>(`${v} .ui-window`)].filter((w) => w.style.transform).length, VIEW);
    expect(transform).toBe(0);
  });

  test("auto-repeat is ignored: holding the key closes one window", async ({ page }) => {
    await boot(page);
    await fill(page, 3);
    const n0 = await windows(page);
    await page.keyboard.down("Control"); await page.keyboard.down("Alt");
    await page.keyboard.down("KeyW");
    for (let i = 0; i < 6; i++) await page.keyboard.down("KeyW");
    await page.keyboard.up("KeyW"); await page.keyboard.up("Alt"); await page.keyboard.up("Control");
    await page.waitForTimeout(300);
    expect(await windows(page)).toBe(n0 - 1);
  });

  test("focus moves to the neighbour at once, so the next press closes that one", async ({ page }) => {
    await boot(page);
    await fill(page, 2);
    const first = await activeId(page);
    await chord(page, ["Control", "Alt", "KeyW"]);
    const next = await activeId(page);
    expect(next).not.toBe(first);
    expect(next, "a neighbour takes the focus").not.toBeNull();
    await chord(page, ["Control", "Alt", "KeyW"]);
    expect(await page.locator(`${VIEW} .ui-window[data-window-id="${next}"]`).count()).toBe(0);
  });

  test("Close window is in ⌘K with its label", async ({ page }) => {
    await boot(page);
    await page.keyboard.press("Control+k");
    await expect(page.locator("#palette")).toBeVisible();
    await page.locator("#palette-input").fill("Close window");
    await expect(page.locator("#palette-results .result", { hasText: "Close window" }).first()).toBeVisible();
    await page.keyboard.press("Escape");
  });
});

test.describe("the shortcuts panel (?)", () => {
  test.setTimeout(120_000);

  test("it shows the alternates on the same row, quieter, and Close window with its chord", async ({ page }) => {
    await boot(page);
    await page.mouse.click(720, 880); // the canvas background: a press outside any field
    await page.waitForTimeout(300);
    await page.keyboard.press("Shift+Slash");
    await expect(page.locator(".ui-shortcuts")).toBeVisible({ timeout: 5000 });
    // "Show these shortcuts" has ⌘/ or Ctrl+Shift+/ as its primary, and "?" as its alternate on the same row.
    const row = page.locator(".ui-shortcuts-row", { hasText: "Show these shortcuts" });
    await expect(row).toHaveCount(1);
    await expect(row.locator("kbd.ui-shortcuts-alt")).toHaveText("?");
    await expect(row.locator("kbd:not(.ui-shortcuts-alt)").first()).toHaveText("Ctrl");
    // The alternate is quieter than the primary keycap.
    const opacity = await row.locator("kbd.ui-shortcuts-alt").evaluate((k) => Number(getComputedStyle(k).opacity));
    expect(opacity).toBeLessThan(1);
    const close = page.locator(".ui-shortcuts-row", { hasText: "Close window" });
    await expect(close.locator("kbd").first()).toHaveText("Ctrl");
    await expect(close.locator("kbd:not(.ui-shortcuts-alt)")).toHaveText(["Ctrl", "Alt", "W"]);
    await page.keyboard.press("Escape");
  });

  test("opened on the canvas, Canvas is first; opened inside a focused terminal, Terminal is first", async ({ page }) => {
    await boot(page);
    await page.mouse.click(720, 880);
    await page.waitForTimeout(300);
    await page.keyboard.press("Shift+Slash");
    await expect(page.locator(".ui-shortcuts")).toBeVisible({ timeout: 5000 });
    const titles = () => page.locator(".ui-shortcuts-title").allTextContents();
    expect((await titles())[0]).toBe("Canvas");
    await page.keyboard.press("Escape");
    await page.waitForTimeout(400);
    // ⌘/ from a focused terminal (on Linux the chord is Ctrl+Shift+/): the panel leads with Terminal, and the terminal
    // receives no "/" in its screen.
    // A first press activates the window; a second press on the active one focuses its terminal (D159).
    // The mock's live terminal is w-build-01 (the others show previews, which take no focus).
    const body = page.locator(`${VIEW} .ui-window[data-window-id="w-build-01"] .ui-window-body`).first();
    await body.click({ position: { x: 20, y: 40 }, timeout: 3000 }).catch(() => undefined);
    await page.waitForTimeout(200);
    await body.click({ position: { x: 20, y: 40 }, timeout: 3000 }).catch(() => undefined);
    await page.waitForTimeout(300);
    // The terminal takes the focus, as a person's tap or click on it does: the keystroke must come from inside it.
    const focused = await page.evaluate(() => {
      const host = document.querySelector<HTMLElement>(".terminal-host");
      (host?.querySelector("textarea") ?? host)?.focus({ preventScroll: true });
      return !!document.activeElement?.closest(".terminal-host");
    });
    expect(focused, "the terminal has the focus").toBe(true);
    const before = await page.locator(`${VIEW} .ui-window[data-active]`).innerText({ timeout: 3000 }).catch(() => "");
    await chord(page, ["Control", "Shift", "Slash"]);
    await expect(page.locator(".ui-shortcuts")).toBeVisible({ timeout: 5000 });
    expect((await titles())[0]).toBe("Terminal");
    const after = await page.locator(`${VIEW} .ui-window[data-active]`).innerText({ timeout: 3000 }).catch(() => "");
    expect(after.includes("/") && !before.includes("/")).toBe(false);
    await page.keyboard.press("Escape");
  });
});
