/**
 * Settings › Appearance › Themes (issue #323, D322, D338, D341, D329), against the production build of the product canvas.
 *
 * What is checked: the strip (Solid, Tinted, Frosted and the add card; Tinted selected for a new person), that the light and dark circles of a Colour choose the
 * version and do not move on a press, that the add card copies the selected theme, that the Windows heading sits over Tint, Blur and Grain, that grain lies on the
 * windows and not on the canvas behind them, that every colour scheme of D329 is in the list, that a font is fetched only when chosen, and that the left edges and
 * centre lines line up within 0.5 px (the owner's alignment rule). Against the product canvas and the real layout store: the look is the account's, saved in the
 * canvas document (a theme chosen on one device is the look on another, a font picked in the palette reaches the document, a damaged first-paint cache is mended, and
 * `?look=` is a preview that saves nothing). `THEMES_SHOTS=<dir>` also writes the review captures at 1440x900, 393x852 and 375x667, dark and light.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Browser, type Page } from "playwright/test";
import { paletteOpen } from "./settings-palette";
import { createThemeStore } from "../src/canvas/themes/model";

/** Optional directory for the review screenshots written by the capture cases. */
const SHOTS = process.env.THEMES_SHOTS;
/** Selector for the Themes settings window in both test canvases. */
const WINDOW = '[data-window-id="s-appearance-themes"]';
/** Maximum accepted geometry difference, in CSS pixels, for alignment assertions. */
const HALF = 0.5;
/** Asserts that two measured CSS positions differ by at most half a pixel. */
const near = (a: number, b: number, what: string): void => { expect(Math.abs(a - b), `${what}: ${a.toFixed(2)} vs ${b.toFixed(2)}`).toBeLessThanOrEqual(HALF); };

/** Opens the product canvas on the Themes window. `theme` is the colour scheme the page starts in (a new person starts Tinted over it). */
async function open(page: Page, theme = "mocha"): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&docs=1&scene=3&theme=${theme}&at=appearance.themes`);
  await expect(page.locator(`${WINDOW} .ui-theme-strip`)).toBeVisible({ timeout: 25_000 });
  await expect(page.locator(`${WINDOW} .ui-theme[data-id="tinted"]`)).toBeVisible();
  // sleep: let the opening camera and panel transitions settle before geometry assertions.
  await page.waitForTimeout(1500);
}
/** The numbers the page is showing for the selected theme. */
const look = (page: Page) => page.evaluate(() => {
  const r = document.documentElement;
  return { id: r.dataset.look, tint: r.style.getPropertyValue("--look-tint"), blur: r.style.getPropertyValue("--look-blur"), scheme: r.dataset.scheme, theme: r.dataset.theme, grain: r.hasAttribute("data-look-grain"), font: r.dataset.font };
});

test.describe("the Themes window", () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test("lists Solid, Tinted and Frosted and the add card; a new person starts on Tinted with the owner's numbers", async ({ page }) => {
    await open(page);
    const cards = page.locator(`${WINDOW} .ui-theme`);
    await expect(cards).toHaveCount(3);
    expect(await cards.locator(".ui-theme-name").allTextContents()).toEqual(["Solid", "Tinted", "Frosted"]);
    expect(await cards.locator(".ui-theme-meta").allTextContents()).toEqual(["100% tint · 0% blur", "75% tint · 25% blur", "50% tint · 50% blur"]);
    await expect(page.locator(`${WINDOW} .ui-theme-add`)).toBeVisible();
    await expect(page.locator(`${WINDOW} .ui-theme[data-id="tinted"] .ui-theme-pick`)).toHaveAttribute("aria-checked", "true");
    expect(await look(page)).toMatchObject({ id: "tinted", tint: "0.75", blur: "6px", scheme: "dark", theme: "mocha", grain: false });
  });

  test("a prototype-named saved Colour leaves the Themes window usable", async ({ page }) => {
    const saved = createThemeStore({ colors: "mocha", font: "maple-mono-nf", uiSize: 100 }).snapshot();
    saved.themes.find((theme) => theme.id === "tinted")!.colors = "__proto__";
    await page.addInitScript((look) => localStorage.setItem("tracer.look", JSON.stringify(look)), saved);
    await open(page);
    await expect(page.locator(`${WINDOW} .ui-theme-strip`)).toBeVisible();
    await expect(page.locator(`${WINDOW} .cl-colour-row[data-id="catppuccin"]`)).toBeVisible();
    expect(await look(page)).toMatchObject({ theme: "mocha", id: "tinted" });
  });

  test("the plus card makes a copy of the selected theme, selects it and lets its name change", async ({ page }) => {
    await open(page);
    await page.locator(`${WINDOW} .ui-theme[data-id="frosted"] .ui-theme-pick`).click();
    await page.locator(`${WINDOW} .ui-theme-add`).click();
    const made = page.locator(`${WINDOW} .ui-theme[data-selected]`);
    await expect(made.locator(".ui-theme-name")).toHaveText("Theme 4");
    await expect(made.locator(".ui-theme-meta")).toHaveText("50% tint · 50% blur");
    expect(await page.locator(`${WINDOW} .ui-theme`).count()).toBe(4);
    const name = page.locator(`${WINDOW} .cl-theme-name-input`);
    await name.fill("Night");
    await expect(made.locator(".ui-theme-name")).toHaveText("Night");
    // A built-in theme's name is not editable: its row is closed.
    await page.locator(`${WINDOW} .ui-theme[data-id="solid"] .ui-theme-pick`).click();
    await expect(page.locator(`${WINDOW} .cl-theme-name`)).not.toHaveAttribute("data-open", "");
  });

  test("the selected theme tick does not cover preview text", async ({ page }) => {
    await open(page);
    const covered = await page.locator(`${WINDOW} .ui-theme[data-selected]`).evaluate((card) => {
      const tick = card.querySelector(".ui-theme-tick")!.getBoundingClientRect();
      const samples = [...card.querySelectorAll(".ui-theme-term > span, .ui-theme-aa, .ui-theme-prompt")];
      return samples.flatMap((sample) => {
        const range = document.createRange();
        range.selectNodeContents(sample);
        return [...range.getClientRects()].filter((rect) =>
          tick.left < rect.right && tick.right > rect.left && tick.top < rect.bottom && tick.bottom > rect.top,
        ).map(() => sample.textContent);
      });
    });
    expect(covered, "the selection marker stays clear of the preview's rendered text").toEqual([]);
  });

  test("the light and dark circles of a Colour choose the version, and a press does not move the circle", async ({ page }) => {
    await open(page);
    const row = page.locator(`${WINDOW} .cl-colour-row[data-id="catppuccin"]`);
    await row.scrollIntoViewIfNeeded();
    const light = row.locator('.cl-colour-dot[data-mode="light"]'), dark = row.locator('.cl-colour-dot[data-mode="dark"]');
    await expect(dark).toHaveAttribute("aria-checked", "true");
    const before = await light.boundingBox();
    // Hold the pointer down: nothing moves, scales or jolts under it (D338 round 4: no bounce on press).
    await light.hover();
    await page.mouse.down();
    const held = await light.boundingBox();
    const rowHeld = await row.evaluate((r) => getComputedStyle(r).transform);
    await page.mouse.up();
    expect(held, "the circle is where it was while pressed").toEqual(before);
    expect(rowHeld).toBe("none");
    await expect.poll(() => look(page)).toMatchObject({ theme: "latte", scheme: "light" });
    await expect(light).toHaveAttribute("aria-checked", "true");
    await dark.click();
    await expect.poll(() => look(page)).toMatchObject({ theme: "mocha", scheme: "dark" });
  });

  test("Tint, Blur and Grain sit under one Windows heading: stacked in a narrow window, three columns in a wide one", async ({ page }) => {
    await open(page);
    // The controls, in the owner's order (D338); the Name of a theme the person made sits above them and is closed for a built-in theme.
    const heads = await page.locator(`${WINDOW} .ui-sp > section > .ui-ts-title`).allTextContents();
    expect(heads).toEqual(["UI size", "Colour", "Backgrounds", "Windows", "Fonts", "Interface font"]);
    const windows = page.locator(`${WINDOW} section:has(> .ui-ts-title:text-is("Windows"))`);
    await windows.scrollIntoViewIfNeeded();
    const labels = await windows.locator(".cl-field-label").allTextContents();
    expect(labels).toEqual(["Tint", "Blur", "Grain"]);
    const where = (): Promise<Array<{ x: number; y: number }>> => windows.locator(".cl-field").evaluateAll((fields) => fields.map((f) => { const r = f.getBoundingClientRect(); return { x: r.left, y: r.top }; }));
    // At the window's default width the three sit in one column, each slider under its own label (a very wide slider is hard to use, D338 asks for columns only when the window is wide).
    const narrow = await where();
    near(narrow[0]!.x, narrow[1]!.x, "stacked: Tint and Blur share a left edge");
    expect(narrow[1]!.y).toBeGreaterThan(narrow[0]!.y + 20);
    // Pulling the window's east edge out makes it wide enough: one row of three.
    const edge = (await page.locator(`${WINDOW} .ui-window-resize[data-edge="e"]`).boundingBox())!;
    const x = edge.x + edge.width / 2, y = edge.y + edge.height / 2 + 100;
    await page.mouse.move(x, y); await page.mouse.down();
    for (let k = 1; k <= 12; k++) {
      await page.mouse.move(x + k * 40, y);
      // sleep: pace pointer movement so each resize sample can be rendered during the drag.
      await page.waitForTimeout(25);
    }
    await page.mouse.up();
    // sleep: let the window resize spring settle before comparing the new column positions.
    await page.waitForTimeout(600);
    await windows.scrollIntoViewIfNeeded();
    await expect.poll(async () => { const w = await where(); return Math.abs(w[0]!.y - w[1]!.y) < HALF && Math.abs(w[1]!.y - w[2]!.y) < HALF && w[0]!.x < w[1]!.x; }, { timeout: 5000 }).toBe(true);
  });

  test("the interface font can be changed from Appearance and is saved with the account look", async ({ page, browser }) => {
    await openProduct(page);
    await openThemes(page);
    const control = page.locator(`${WINDOW} section[data-kind="ui-font"]`);
    await expect(control).toBeVisible();
    await control.locator('button[data-id="sans"]').click();
    await expect(page.locator("html")).toHaveAttribute("data-ui-font", "sans");
    await expect.poll(async () => (await accountLook(page))?.uiFont).toBe("sans");

    const other = await browser.newContext({ baseURL: baseURL(), viewport: { width: 1440, height: 900 } });
    try {
      const second = await other.newPage();
      await openProduct(second, "", false);
      await expect(second.locator("html")).toHaveAttribute("data-ui-font", "sans");
      await second.reload();
      await expect(second.locator('.cl[data-view="console"] .ui-window')).toHaveCount(1, { timeout: 30_000 });
      await expect(second.locator("html")).toHaveAttribute("data-ui-font", "sans");
    } finally {
      await other.close();
    }
  });

  test("grain lies on the windows and the floating cards, never on the canvas behind them; 0% is none", async ({ page }) => {
    await open(page);
    expect((await look(page)).grain).toBe(false);
    const grain = page.locator(`${WINDOW} input[aria-label="Grain"]`);
    await grain.scrollIntoViewIfNeeded();
    await grain.fill("60");
    await expect.poll(async () => (await look(page)).grain).toBe(true);
    // The tile is drawn by code that loads on demand the first time, so it arrives a moment after the attribute does.
    await expect.poll(() => page.evaluate(() => getComputedStyle(document.querySelector('[data-window-id="s-appearance-themes"]')!).backgroundImage), { timeout: 10_000 }).toContain("data:image/png");
    const seen = await page.evaluate(() => {
      const image = (sel: string): string => { const n = document.querySelector(sel); return n ? getComputedStyle(n).backgroundImage : "missing"; };
      return { win: image('[data-window-id="s-appearance-themes"]'), backdrop: image(".ui-canvas-backdrop"), size: document.documentElement.style.getPropertyValue("--look-grain-size") };
    });
    expect(seen.win, "the window carries the tile").toContain("data:image/png");
    expect(seen.backdrop, "the canvas backdrop does not").not.toContain("data:image/png");
    await grain.fill("0");
    await expect.poll(async () => (await look(page)).grain).toBe(false);
  });

  test("every colour scheme of D329 is in the Colour list once, light and dark in one row", async ({ page }) => {
    await open(page);
    const rows = await page.locator(`${WINDOW} .cl-colour-row .cl-colour-label`).allTextContents();
    for (const name of ["Solarized", "Everforest", "Kanagawa", "Ayu", "GitHub", "Flexoki", "Gruvbox", "Tokyo Night", "Catppuccin", "Catppuccin Frappé", "Catppuccin Macchiato", "Night Owl"]) expect(rows, name).toContain(name);
    expect(new Set(rows).size, "no scheme is listed twice").toBe(rows.length);
    const circles = await page.locator(`${WINDOW} .cl-colour-row[data-id="kanagawa"] .cl-colour-dot`).evaluateAll((d) => d.map((x) => (x as HTMLElement).getAttribute("aria-label")));
    expect(circles).toEqual(["Kanagawa, light", "Kanagawa, dark"]);
    // A scheme in the list works: choosing Solarized Light makes the page light and keeps Tinted's numbers.
    await page.locator(`${WINDOW} .cl-colour-dot[data-id="solarized-light"]`).click();
    await expect.poll(() => look(page)).toMatchObject({ theme: "solarized-light", scheme: "light", id: "tinted" });
  });

  test("a font is fetched only when it is chosen, and then it is the font of the page", async ({ page }) => {
    const fetched: string[] = [];
    page.on("request", (r) => { const m = /\/fonts\/([^/]+)\//.exec(r.url()); if (m) fetched.push(m[1]!); });
    await open(page);
    expect(fetched, "no extra family on first load").not.toContain("iosevka");
    expect(fetched).not.toContain("victor-mono");
    const row = page.locator(`${WINDOW} .ui-sp-row[data-id="iosevka"]`);
    await row.scrollIntoViewIfNeeded();
    await row.click();
    await expect.poll(() => fetched.includes("iosevka"), { timeout: 10_000 }).toBe(true);
    await expect.poll(async () => (await look(page)).font).toBe("iosevka");
    expect(await page.evaluate(() => document.fonts.check('14px "Iosevka"'))).toBe(true);
    expect(fetched, "only the chosen family").not.toContain("victor-mono");
  });

  test("the Themes are in ⌘K, and the card and window transparency rows are gone", async ({ page }) => {
    await open(page);
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill("Theme: ");
    await expect(page.locator('#palette-results .result[data-action="themes:frosted"]')).toBeVisible();
    await page.locator("#palette-input").fill("transparency");
    // sleep: allow the debounced palette search to finish before reading its rows.
    await page.waitForTimeout(500);
    const rows = await page.locator("#palette-results .result").allTextContents();
    expect(rows.filter((r) => /(card|window) transparency/i.test(r)), "no Card or Window transparency rows").toEqual([]);
    await page.locator("#palette-input").fill("Theme: Frosted");
    await page.locator('#palette-results .result[data-action="themes:frosted"]').click();
    await expect.poll(() => look(page)).toMatchObject({ id: "frosted" });
  });

  test("alignment: sections, rows and circles share left edges and centre lines within half a pixel", async ({ page }) => {
    await open(page);
    const edges = await page.evaluate((win) => {
      const w = document.querySelector(win)!;
      const left = (n: Element | null): number => n!.getBoundingClientRect().left;
      const titles = [...w.querySelectorAll(".ui-ts-title")].map(left);
      const names = [...w.querySelectorAll(".cl-colour-label")].map(left);
      const fonts = [...w.querySelectorAll('section:has(> .ui-ts-title) .ui-sp-row .ui-sp-label')].map(left);
      const dots = (mode: string): number[] => [...w.querySelectorAll(`.cl-colour-dot[data-mode="${mode}"]`)].map((d) => { const r = d.getBoundingClientRect(); return (r.left + r.right) / 2; });
      const centres = [...w.querySelectorAll(".cl-colour-row")].map((r) => { const label = r.querySelector(".cl-colour-label")!.getBoundingClientRect(), dot = r.querySelector(".cl-colour-dot")!.getBoundingClientRect(); return [(label.top + label.bottom) / 2, (dot.top + dot.bottom) / 2]; });
      // What the first row is made of, for the message when a centre line is off.
      const first = w.querySelector(".cl-colour-row")!;
      const box = (n: Element): string => { const r = n.getBoundingClientRect(), c = getComputedStyle(n); return `${n.className.toString().split(" ")[0]} top=${r.top.toFixed(2)} h=${r.height.toFixed(2)} lh=${c.lineHeight} fs=${c.fontSize} align=${c.alignItems}/${c.alignSelf}`; };
      const debug = [first, first.querySelector(".cl-colour-name")!, first.querySelector(".cl-colour-label")!, first.querySelector(".cl-colour-modes")!, first.querySelector(".cl-colour-dot")!].map(box).join(" | ");
      return { titles, names, fonts, light: dots("light"), dark: dots("dark"), centres, debug };
    }, WINDOW);
    for (const x of edges.names) near(x, edges.names[0]!, "Colour names share a left edge");
    for (const x of edges.light) near(x, edges.light[0]!, "light circles share a column");
    for (const x of edges.dark) near(x, edges.dark[0]!, "dark circles share a column");
    for (const [label, dot] of edges.centres) near(label!, dot!, `a Colour name and its circle share a centre line (${edges.debug})`);
    for (const x of edges.titles) near(x, edges.titles[0]!, "section headings share a left edge");
    near(edges.names[0]!, edges.titles[0]!, "Colour names start at the headings' edge");
  });
});

test.describe("the Colour picker on a phone", () => {
  test.use({ viewport: { width: 393, height: 852 }, hasTouch: true, isMobile: true });

  test("each light and dark Colour circle has a 44 px touch target", async ({ page }) => {
    await open(page);
    expect(await page.evaluate(() => matchMedia("(pointer: coarse)").matches)).toBe(true);
    const targets = await page.locator(`${WINDOW} .cl-colour-dot`).evaluateAll((dots) => dots.map((dot) => {
      const rect = dot.getBoundingClientRect();
      return { label: dot.getAttribute("aria-label"), width: rect.width, height: rect.height };
    }));
    expect(targets.length).toBeGreaterThan(0);
    for (const target of targets) {
      expect(target.width, `${target.label} target width`).toBeGreaterThanOrEqual(44);
      expect(target.height, `${target.label} target height`).toBeGreaterThanOrEqual(44);
    }
    const centres = await page.locator(`${WINDOW} .cl-colour-row`).evaluateAll((rows) => rows.map((row) => {
      const label = row.querySelector(".cl-colour-label")!.getBoundingClientRect();
      const dot = row.querySelector(".cl-colour-dot")!.getBoundingClientRect();
      return { label: (label.top + label.bottom) / 2, dot: (dot.top + dot.bottom) / 2 };
    }));
    for (const centre of centres) near(centre.label, centre.dot, "phone Colour labels and touch targets share a centre line");
  });
});

test.describe("custom background controls on a phone", () => {
  test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });

  test("Solid, Gradient, Add and Remove have 44 px touch targets", async ({ page }) => {
    await open(page);
    expect(await page.evaluate(() => matchMedia("(pointer: coarse)").matches)).toBe(true);
    const tabs = page.locator(`${WINDOW} [role="tablist"][aria-label="Background"] .ui-tab`);
    await expect(tabs).toHaveCount(2);
    await tabs.filter({ hasText: "Gradient" }).click();
    const gradientBlock = page.locator(`${WINDOW} .cl-bg-block`).nth(1);
    await gradientBlock.locator('.cl-bg-swatch[data-custom]').click();
    const add = gradientBlock.locator('button[aria-label="Add a colour"]');
    const remove = gradientBlock.locator('button[aria-label="Remove the last colour"]');
    await expect(add).toBeVisible();
    await expect(remove).toBeVisible();

    const controls = [
      ...await tabs.evaluateAll((items) => items.map((item) => ({ label: item.textContent?.trim() ?? "tab", rect: item.getBoundingClientRect().toJSON() }))),
      ...await Promise.all([add, remove].map(async (item) => ({ label: await item.getAttribute("aria-label"), rect: await item.boundingBox() }))),
    ];
    for (const control of controls) {
      expect(control.rect?.width ?? 0, `${control.label} touch target width`).toBeGreaterThanOrEqual(44);
      expect(control.rect?.height ?? 0, `${control.label} touch target height`).toBeGreaterThanOrEqual(44);
    }
  });
});

// ---- in the product: the look is the account's, in the canvas document (D322, D178, D180) ----------------------------------------------------------------
// Against the real layout store (`layout=server`) and the test double's server, which applies the same edits as the real one: a look chosen on one device is the
// look of the account on every other; the browser keeps only a first-paint cache of the selected theme.
/** Product-canvas route backed by the real per-account layout adapter. */
const PRODUCT = "/?mock=1&proto=product&layout=server&theme=mocha&bg=none";
/** The account-look fields this real-server spec reads back from its test double. */
interface DocLookLike { selected: string; uiFont?: "mono" | "sans"; themes: Array<{ id: string; name: string; tint: number; blur: number; font: string }> }
/** Base URL for the local real-server fixture used by product-canvas cases. */
const baseURL = (): string => `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`;
/** The look the account's document holds right now, as the test double has it (null: none yet). */
const accountLook = (page: Page): Promise<DocLookLike | null> => page.evaluate(() => fetch("/__mock/layout").then((r) => r.json()).then((d: { document: { look?: unknown } }) => (d.document.look ?? null) as never));

/** Opens one product-canvas page and optionally preserves its account document. */
async function openProduct(page: Page, query = "", reset = true): Promise<void> {
  if (reset) {
    expect((await page.context().request.post("/__mock/reset")).ok()).toBe(true);
    expect((await page.context().request.post("/__mock/open-terminal")).ok()).toBe(true);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${PRODUCT}${query}`);
  await expect(page.locator('.cl[data-view="console"] .ui-window')).toHaveCount(1, { timeout: 30_000 });
}
/** Navigates the active product page to the Themes settings window. */
async function openThemes(page: Page): Promise<void> {
  await paletteOpen(page, "Appearance › Themes", "appearance.themes");
  await expect(page.locator(`${WINDOW} .ui-theme-strip`)).toBeVisible({ timeout: 25_000 });
}

test.describe("the look is the account's, saved in the canvas document", () => {
  test("an account with no look yet gets this page's, once; a new person is on Tinted", async ({ page }) => {
    await openProduct(page);
    await expect.poll(() => accountLook(page), { timeout: 10_000 }).toMatchObject({ selected: "tinted" });
    expect((await accountLook(page))!.themes.map((t) => t.id)).toEqual(["solid", "tinted", "frosted"]);
    expect(await look(page)).toMatchObject({ id: "tinted", tint: "0.75", blur: "6px" });
  });

  test("a theme chosen on one device is the look on another, and survives a reload", async ({ page, browser }: { page: Page; browser: Browser }) => {
    await openProduct(page);
    await openThemes(page);
    await page.locator(`${WINDOW} .ui-theme[data-id="frosted"] .ui-theme-pick`).click();
    await expect.poll(() => look(page)).toMatchObject({ id: "frosted", tint: "0.5", blur: "12px" });
    // The edit goes to the document a moment after the last change.
    await expect.poll(async () => (await accountLook(page))?.selected, { timeout: 8000 }).toBe("frosted");
    // Another device: a browser with nothing of ours (no first-paint cache), signed in to the same account, shows the same look.
    const other = await browser.newContext({ baseURL: baseURL(), viewport: { width: 1440, height: 900 } });
    const second = await other.newPage();
    await openProduct(second, "", false);
    await expect.poll(async () => (await look(second)).id, { timeout: 15_000 }).toBe("frosted");
    expect(await look(second)).toMatchObject({ tint: "0.5", blur: "12px" });
    await other.close();
    // Reload on this device: the same look from the document.
    await page.reload();
    await expect(page.locator('.cl[data-view="console"] .ui-window')).toHaveCount(1, { timeout: 30_000 });
    await expect.poll(async () => (await look(page)).id, { timeout: 15_000 }).toBe("frosted");
  });

  test("the plus card's theme and its name reach the account's document", async ({ page }) => {
    await openProduct(page);
    await openThemes(page);
    await page.locator(`${WINDOW} .ui-theme-add`).click();
    await page.locator(`${WINDOW} .cl-theme-name-input`).fill("Night");
    await expect.poll(async () => (await accountLook(page))?.themes.map((t) => t.name), { timeout: 8000 }).toEqual(["Solid", "Tinted", "Frosted", "Night"]);
  });

  test("a damaged first-paint cache never breaks the page: the numbers are mended", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("tracer.look", JSON.stringify({ v: 1, selected: "tinted", basics: { colors: "mocha", font: "maple-mono-nf", uiSize: 100 }, themes: [{ id: "tinted", tint: 900, blur: -4, grain: "lots" }] })));
    await openProduct(page);
    expect(await look(page)).toMatchObject({ id: "tinted", tint: "1", blur: "0px" });
  });

  test("a font picked in ⌘K is a change to the selected theme, so it reaches the document and survives a reload", async ({ page }) => {
    await openProduct(page);
    await page.keyboard.press("Control+Shift+K");
    await page.keyboard.type("Hack");
    await page.locator('#palette-results .result[data-action="font:hack"]').click();
    await expect.poll(async () => (await look(page)).font, { timeout: 15_000 }).toBe("hack");
    await expect.poll(async () => (await accountLook(page))?.themes.find((t) => t.id === "tinted")?.font, { timeout: 8000 }).toBe("hack");
    await page.reload();
    await expect(page.locator('.cl[data-view="console"] .ui-window')).toHaveCount(1, { timeout: 30_000 });
    await expect.poll(async () => (await look(page)).font, { timeout: 15_000 }).toBe("hack");
  });

  test("?look= previews a theme for one page load: it saves nothing, even after edits, and the next load is the account's own", async ({ page }) => {
    await openProduct(page);
    await openThemes(page);
    await page.locator(`${WINDOW} .ui-theme[data-id="frosted"] .ui-theme-pick`).click();
    await expect.poll(async () => (await accountLook(page))?.selected, { timeout: 8000 }).toBe("frosted");
    const cache = await page.evaluate(() => localStorage.getItem("tracer.look"));
    // A link that asks for Solid: that page shows Solid, ignores the account's choice, and an edit made on it is saved nowhere.
    await openProduct(page, "&look=solid", false);
    await expect.poll(async () => (await look(page)).id).toBe("solid");
    expect(await look(page)).toMatchObject({ tint: "1", blur: "0px" });
    await openThemes(page);
    const tint = page.locator(`${WINDOW} input[aria-label="Tint"]`);
    await tint.scrollIntoViewIfNeeded();
    await tint.fill("30");
    await page.locator(`${WINDOW} .ui-theme[data-id="tinted"] .ui-theme-pick`).click();
    // sleep: exceed the account-edit debounce window so any erroneous preview save becomes visible.
    await page.waitForTimeout(2000);
    expect(await page.evaluate(() => localStorage.getItem("tracer.look")), "the first-paint cache is exactly what it was").toBe(cache);
    expect((await accountLook(page))?.selected, "the account still has the person's own choice").toBe("frosted");
    // The next load, without the parameter, is the account's look; an id that is not a theme is ignored.
    await openProduct(page, "&look=nonsense", false);
    await expect.poll(async () => (await look(page)).id, { timeout: 15_000 }).toBe("frosted");
    expect(await look(page)).toMatchObject({ tint: "0.5" });
  });
});

// The review captures: written only when THEMES_SHOTS is set.
/** Desktop and phone viewports used for the review captures. */
const SIZES = [
  { name: "desktop-1440x900", viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, isMobile: false, hasTouch: false },
  { name: "phone-393x852", viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true },
  { name: "phone-375x667", viewport: { width: 375, height: 667 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true },
] as const;
/** Representative dark and light schemes for the capture set. */
const MODES = { dark: "mocha", light: "latte" } as const;
for (const size of SIZES) for (const [mode, theme] of Object.entries(MODES)) {
  test.describe(`captures ${size.name} ${mode}`, () => {
    test.skip(!SHOTS, "set THEMES_SHOTS=<dir> to write the review captures");
    test.use({ viewport: size.viewport, deviceScaleFactor: size.deviceScaleFactor, isMobile: size.isMobile, hasTouch: size.hasTouch });
    test("themes, then the lower sections of the window", async ({ page }) => {
      mkdirSync(SHOTS!, { recursive: true });
      await open(page, theme);
      await page.screenshot({ path: `${SHOTS}/${size.name}-${mode}-themes.png` });
      const pane = page.locator(`${WINDOW} .ui-settings-pane`);
      for (const [n, title] of ["Colour", "Backgrounds", "Windows", "Fonts", "Interface font"].entries()) {
        await page.locator(`${WINDOW} .ui-ts-title:text-is("${title}")`).scrollIntoViewIfNeeded();
        await pane.evaluate((el, t) => { const h = [...el.querySelectorAll(".ui-ts-title")].find((x) => x.textContent === t)!; (el as HTMLElement).scrollTop += h.getBoundingClientRect().top - el.getBoundingClientRect().top - 8; }, title);
        // sleep: let the scrolled settings section settle before capturing it.
        await page.waitForTimeout(250);
        await page.screenshot({ path: `${SHOTS}/${size.name}-${mode}-${n + 1}-${title.toLowerCase()}.png` });
      }
    });
  });
}
