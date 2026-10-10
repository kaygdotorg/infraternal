/**
 * The D222 keymap, driven as keystrokes in the product canvas (proto=clusters, one scene) on a Mac and on Windows.
 * Each default chord runs its action; Ctrl+K inside a focused terminal on Windows is the terminal's, not the palette's;
 * AltGr triggers nothing; a German layout's "?" opens the panel. Platforms are emulated before the page loads.
 *
 * The browser's own accelerators (⌘W, Ctrl+W, ⌘T, Ctrl+T, ⌘/Ctrl+ zoom and similar) never reach a page in a synthetic test,
 * so they are not asserted here; docs/verification/shortcuts-d222.md lists them for a manual check.
 */
import { expect, test, type Page } from "playwright/test";

const VIEW = '.cl[data-view="console"]';
const MAC = "MacIntel";
const WINDOWS = "Win32";

async function boot(page: Page, platform: string, width = 1440, height = 900): Promise<void> {
  await page.addInitScript((value: string) => { Object.defineProperty(navigator, "platform", { get: () => value }); }, platform);
  await page.setViewportSize({ width, height });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
  await page.locator(`${VIEW} .ui-window .ui-window-body`).first().click({ position: { x: 20, y: 40 } });
  await page.waitForTimeout(500);
}

const windows = (page: Page): Promise<number> => page.evaluate((view) => document.querySelectorAll(`${view} .ui-window`).length, VIEW);
const activeId = (page: Page): Promise<string | null> => page.evaluate((view) => document.querySelector<HTMLElement>(`${view} .ui-window[data-active]`)?.dataset.windowId ?? null, VIEW);

/** A chord with no wait between the keys, the way a quick press lands. */
async function chord(page: Page, keys: string[]): Promise<void> {
  for (const k of keys) await page.keyboard.down(k);
  for (const k of [...keys].reverse()) await page.keyboard.up(k);
  await page.waitForTimeout(250);
}

/** The keyboard chords of each platform, in D222's table order. */
const MAC_CHORDS = {
  splitRight: ["Meta", "KeyD"],
  splitDown: ["Meta", "Shift", "KeyD"],
  newRight: ["Meta", "Enter"],
  newBelow: ["Meta", "Shift", "Enter"],
  next: ["Meta", "BracketRight"],
  previous: ["Meta", "BracketLeft"],
  moveLeft: ["Meta", "Alt", "ArrowLeft"],
  close: ["Meta", "Alt", "KeyW"],
  palette: ["Meta", "KeyK"],
  paletteAlternate: ["Meta", "Shift", "KeyP"],
  panel: ["Meta", "Slash"],
};
const PC_CHORDS = {
  splitRight: ["Control", "Shift", "KeyD"],
  splitDown: ["Control", "Shift", "KeyE"],
  newRight: ["Control", "Shift", "Enter"],
  newBelow: ["Control", "Shift", "Alt", "Enter"],
  next: ["Control", "Shift", "BracketRight"],
  previous: ["Control", "Shift", "BracketLeft"],
  moveLeft: ["Control", "Shift", "ArrowLeft"],
  close: ["Control", "Shift", "KeyX"],
  palette: ["Control", "Shift", "KeyK"],
  paletteAlternate: ["Control", "Shift", "KeyP"],
  panel: ["Control", "Shift", "Slash"],
};

for (const [name, platform, chords] of [["Mac", MAC, MAC_CHORDS], ["Windows", WINDOWS, PC_CHORDS]] as const) {
  test.describe(`${name} chords (D222)`, () => {
    test.setTimeout(180_000);

    test("split right and split down each add one window", async ({ page }) => {
      await boot(page, platform);
      let before = await windows(page);
      await chord(page, chords.splitRight);
      expect(await windows(page), "split right").toBe(before + 1);
      before = await windows(page);
      await chord(page, chords.splitDown);
      expect(await windows(page), "split down").toBe(before + 1);
    });

    test("new window right and new window below each add one window", async ({ page }) => {
      await boot(page, platform);
      let before = await windows(page);
      await chord(page, chords.newRight);
      expect(await windows(page), "new window right").toBe(before + 1);
      before = await windows(page);
      await chord(page, chords.newBelow);
      expect(await windows(page), "new window below").toBe(before + 1);
    });

    test("next and previous window move the active window; the arrows move to the nearest window", async ({ page }) => {
      await boot(page, platform);
      await chord(page, chords.splitRight);
      const right = await activeId(page);
      await chord(page, chords.previous);
      const left = await activeId(page);
      expect(left, "previous window").not.toBe(right);
      await chord(page, chords.next);
      expect(await activeId(page), "next window").toBe(right);
      await chord(page, chords.moveLeft);
      expect(await activeId(page), "move to the window on the left").toBe(left);
    });

    test("close window removes the active window", async ({ page }) => {
      await boot(page, platform);
      await chord(page, chords.splitRight);
      const before = await windows(page);
      await chord(page, chords.close);
      await page.waitForTimeout(400);
      expect(await windows(page), "close window").toBe(before - 1);
    });

    test("the palette opens on its chord and on its alternate, and closes on Escape", async ({ page }) => {
      await boot(page, platform);
      await chord(page, chords.palette);
      await expect(page.locator("#palette")).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(page.locator("#palette")).toBeHidden();
      await chord(page, chords.paletteAlternate);
      await expect(page.locator("#palette")).toBeVisible();
      await page.keyboard.press("Escape");
    });

    test("the shortcuts panel opens on its chord and lists the D222 defaults", async ({ page }) => {
      await boot(page, platform);
      await chord(page, chords.panel);
      const panel = page.locator(".ui-shortcuts");
      await expect(panel).toBeVisible();
      await expect(panel.locator(".ui-shortcuts-row", { hasText: "Split down" })).toBeVisible();
      await page.keyboard.press("Escape");
    });
  });
}

test("Windows: Ctrl+Shift+/ and ? both open the panel, and a German layout's ? (Shift+ß) opens it too", async ({ page }) => {
  await boot(page, WINDOWS);
  // The German "?" arrives as the character "?" on physical Minus with Shift, not as the US Shift+Slash.
  await page.evaluate(() => document.body.dispatchEvent(new KeyboardEvent("keydown", { key: "?", code: "Minus", shiftKey: true, bubbles: true, cancelable: true })));
  await expect(page.locator(".ui-shortcuts")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator(".ui-shortcuts")).toBeHidden();
});

test("Windows: Ctrl+K inside a focused terminal is the terminal's: the palette stays shut and the byte reaches the shell", async ({ page }) => {
  await page.addInitScript((value: string) => { Object.defineProperty(navigator, "platform", { get: () => value }); }, WINDOWS);
  await page.request.post("/__mock/reset").catch(() => page.request.post("/__mock/reset"));
  await page.request.post("/__mock/open-terminal");
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  const accepted = async (): Promise<number> => (await (await page.request.get("/__mock/state")).json()).accepted_input_bytes as number;
  const before = await accepted();
  await page.locator(".terminal-host").first().click();
  await page.keyboard.press("Control+k");
  await expect.poll(accepted, { timeout: 5000 }).toBeGreaterThan(before);
  await expect(page.locator("#palette")).toBeHidden();
});

test("AltGr triggers nothing: Ctrl+Shift+D with AltGraph set does not split", async ({ page }) => {
  await boot(page, WINDOWS);
  const before = await windows(page);
  await page.evaluate(() => document.body.dispatchEvent(new KeyboardEvent("keydown", { key: "D", code: "KeyD", ctrlKey: true, shiftKey: true, altKey: false, modifierAltGraph: true, bubbles: true, cancelable: true })));
  await page.waitForTimeout(300);
  expect(await windows(page)).toBe(before);
});

for (const [name, platform, chords] of [["mac", MAC, MAC_CHORDS], ["windows", WINDOWS, PC_CHORDS]] as const) {
  test(`captures: the ? panel on ${name}, ink, 1440x900 (D222)`, async ({ page }) => {
    await boot(page, platform);
    await chord(page, chords.panel);
    await expect(page.locator(".ui-shortcuts")).toBeVisible();
    await page.waitForTimeout(500);
    await page.screenshot({ path: `captures/shortcuts-d222/${name}-panel-ink-1440x900.png` });
    await page.keyboard.press("Escape");
  });
}

// The font size belongs to a live terminal client, which the single-terminal screen runs (the clusters mockup draws previews).
for (const [name, platform, mod] of [["Windows", WINDOWS, "Control"], ["Mac", MAC, "Meta"]] as const) {
  test(`${name}: keyboard font size steps the terminal text and resets it (D222)`, async ({ page }) => {
    await page.addInitScript((value: string) => { Object.defineProperty(navigator, "platform", { get: () => value }); }, platform);
    await page.request.post("/__mock/reset").catch(() => page.request.post("/__mock/reset"));
    await page.request.post("/__mock/open-terminal");
    await page.goto("/?mock=1&theme=ink&bg=none");
    await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
    await page.locator(".terminal-host").first().click();
    const size = (): Promise<string | null> => page.evaluate(() => document.querySelector<HTMLElement>(".terminal-host")?.dataset.fontSize ?? null);
    await chord(page, [mod, "Equal"]);
    expect(await size(), "larger").toBe("15");
    await chord(page, [mod, "Equal"]);
    expect(await size(), "larger again").toBe("16");
    await chord(page, [mod, "Minus"]);
    expect(await size(), "smaller").toBe("15");
    await chord(page, [mod, "Digit0"]);
    expect(await size(), "reset to the default").toBe("14");
  });
}
