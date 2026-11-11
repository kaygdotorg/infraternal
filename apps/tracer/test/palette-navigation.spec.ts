/** Checks palette keyboard navigation and measures its production handlers. */
import { cpus, hostname, loadavg } from "node:os";
import { expect, test, type Browser, type Page } from "playwright/test";

interface PaletteState {
  count: number;
  selectedIndex: number;
  selectedId: string;
  activeDescendant: string | null;
  selectedCount: number;
  rowVisible: boolean;
  firstInGroup: boolean;
  headingVisible: boolean;
  visibleOptions: number;
}

async function openPalette(page: Page, width: number, height: number): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto("/?mock=1");
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
}

async function trackPaletteRows(page: Page): Promise<void> {
  await page.evaluate(() => {
    const trackedWindow = window as Window & { __paletteRows?: Element[] };
    trackedWindow.__paletteRows = [...document.querySelectorAll("#palette-results .result")];
  });
}

async function paletteState(page: Page): Promise<PaletteState> {
  return page.evaluate(() => {
    const results = document.querySelector<HTMLElement>("#palette-results");
    const input = document.querySelector<HTMLInputElement>("#palette-input");
    if (!results || !input) throw new Error("Palette results or input are missing");
    const options = [...results.querySelectorAll<HTMLElement>(".result")];
    const selected = options.find((option) => option.getAttribute("aria-selected") === "true");
    if (!selected) throw new Error("Palette has no selected option");
    // Rows are 28 x the UI size's factor tall (30.8 px at the default), and a scroll lands on a whole pixel: an edge may sit up to a pixel off.
    const EDGE = 1;
    const port = results.getBoundingClientRect();
    const top = port.top + results.clientTop;
    const bottom = top + results.clientHeight;
    const selectedRect = selected.getBoundingClientRect();
    const previous = selected.previousElementSibling;
    const heading = previous instanceof HTMLElement && previous.classList.contains("group-label") ? previous : undefined;
    const headingRect = heading?.getBoundingClientRect();
    const visibleOptions = options.filter((option) => {
      const rect = option.getBoundingClientRect();
      return rect.top >= top - EDGE && rect.bottom <= bottom + EDGE;
    }).length;
    return {
      count: options.length,
      selectedIndex: options.indexOf(selected),
      selectedId: selected.id,
      activeDescendant: input.getAttribute("aria-activedescendant"),
      selectedCount: options.filter((option) => option.getAttribute("aria-selected") === "true").length,
      rowVisible: selectedRect.top >= top - EDGE && selectedRect.bottom <= bottom + EDGE,
      firstInGroup: heading !== undefined,
      headingVisible: Boolean(headingRect && headingRect.top >= top - EDGE && headingRect.bottom <= bottom + EDGE),
      visibleOptions,
    };
  });
}

async function expectSelectedVisible(page: Page, expectedIndex?: number): Promise<PaletteState> {
  const state = await paletteState(page);
  expect(state.rowVisible, `selected option ${state.selectedIndex} must be fully visible`).toBe(true);
  expect(state.activeDescendant).toBe(state.selectedId);
  expect(state.selectedCount).toBe(1);
  if (state.firstInGroup) expect(state.headingVisible, "the first option's group heading must stay visible").toBe(true);
  if (expectedIndex !== undefined) expect(state.selectedIndex).toBe(expectedIndex);
  const retainedNodes = await page.evaluate(() => {
    const trackedWindow = window as Window & { __paletteRows?: Element[] };
    const previous = trackedWindow.__paletteRows;
    const current = [...document.querySelectorAll("#palette-results .result")];
    return Boolean(previous && previous.length === current.length && previous.every((node, index) => node === current[index]));
  });
  expect(retainedNodes, "keyboard navigation must retain the rendered option nodes").toBe(true);
  return state;
}

async function measureHandlers(page: Page): Promise<void> {
  const millisecondsPerArrow = await page.evaluate(() => {
    const input = document.querySelector<HTMLInputElement>("#palette-input");
    const rows = document.querySelectorAll("#palette-results .result");
    if (!input || rows.length < 2) throw new Error("Palette has too few options to benchmark");
    let selected = 0;
    let direction = 1;
    const started = performance.now();
    for (let press = 0; press < 100; press += 1) {
      if (selected === 0) direction = 1;
      else if (selected === rows.length - 1) direction = -1;
      input.dispatchEvent(new KeyboardEvent("keydown", {
        key: direction === 1 ? "ArrowDown" : "ArrowUp",
        bubbles: true,
        cancelable: true,
      }));
      selected += direction;
    }
    return (performance.now() - started) / 100;
  });
  const measuredFilter = await page.evaluate(() => {
    const input = document.querySelector<HTMLInputElement>("#palette-input");
    if (!input) throw new Error("Palette input is missing");
    const started = performance.now();
    // Two queries that both match many rows: the palette's theme rows are in the "Colour" group (the old "theme" word now matches one row, and
    // "theme t" none, which left the palette with no options for the checks that follow).
    for (let press = 0; press < 100; press += 1) {
      input.value = press % 2 === 0 ? "colour" : "colour p";
      input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" }));
    }
    const elapsed = (performance.now() - started) / 100;
    const matches = document.querySelectorAll("#palette-results .result").length;
    // Leave the palette as it was found: unfiltered, so the rest of the test starts from the whole list.
    input.value = "";
    input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "deleteContentBackward" }));
    return { elapsed, matches };
  });
  expect(measuredFilter.matches, "the benchmark's last query still matches rows, so the filter did real work").toBeGreaterThan(0);
  const load = loadavg().map((value) => value.toFixed(2)).join(",");
  console.log(`ENVIRONMENT machine=${hostname()} cores=${cpus().length} load_1_5_15=${load}`);
  console.log(`METRIC name=palette_arrow_handler_ms_per_press value=${millisecondsPerArrow.toFixed(4)} presses=100 viewport=1440x900`);
  console.log(`METRIC name=palette_filter_handler_ms_per_input value=${measuredFilter.elapsed.toFixed(4)} inputs=100 viewport=1440x900`);
  expect(millisecondsPerArrow).toBeGreaterThanOrEqual(0);
  expect(measuredFilter.elapsed).toBeLessThanOrEqual(0.13);
}

async function walkDownAndUp(page: Page): Promise<void> {
  let state = await expectSelectedVisible(page, 0);
  expect(await page.locator("#palette-results").evaluate((element) => element.scrollHeight > element.clientHeight)).toBe(true);
  for (let index = 1; index < state.count; index += 1) {
    await page.locator("#palette-input").press("ArrowDown");
    state = await expectSelectedVisible(page, index);
  }
  for (let index = state.count - 2; index >= 0; index -= 1) {
    await page.locator("#palette-input").press("ArrowUp");
    state = await expectSelectedVisible(page, index);
  }
}

async function exercisePageKeys(page: Page): Promise<void> {
  let state = await expectSelectedVisible(page, 0);
  await page.locator("#palette-input").press("PageDown");
  state = await expectSelectedVisible(page, Math.min(state.count - 1, state.visibleOptions));
  const pageIndex = state.selectedIndex;
  await page.locator("#palette-input").press("PageUp");
  state = await expectSelectedVisible(page, Math.max(0, pageIndex - state.visibleOptions));
  await page.locator("#palette-input").press("End");
  state = await expectSelectedVisible(page, state.count - 1);
  await page.locator("#palette-input").press("Home");
  await expectSelectedVisible(page, 0);
}

async function openMobilePalette(browser: Browser, page: Page): Promise<{ context: Awaited<ReturnType<Browser["newContext"]>>; page: Page }> {
  const context = await browser.newContext({
    baseURL: new URL(page.url()).origin,
    viewport: { width: 393, height: 852 },
    deviceScaleFactor: 1,
    isMobile: true,
    hasTouch: true,
    storageState: await page.context().storageState(),
  });
  const mobilePage = await context.newPage();
  await mobilePage.goto("/?mock=1");
  await expect.poll(() => mobilePage.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  await mobilePage.keyboard.press("Control+Shift+K");
  await expect(mobilePage.locator("#palette")).toBeVisible();
  await trackPaletteRows(mobilePage);
  return { context, page: mobilePage };
}

test("palette keyboard navigation stays visible and accessible on desktop and mobile", async ({ browser, page }) => {
  test.setTimeout(120_000);
  await openPalette(page, 1440, 900);
  await measureHandlers(page);

  const beforeFilter = await paletteState(page);
  await page.locator("#palette-input").fill("dracula");
  const filtered = await paletteState(page);
  expect(filtered.count).toBe(1);
  expect(filtered.selectedId).not.toBe(beforeFilter.selectedId);
  expect(filtered.activeDescendant).toBe(filtered.selectedId);
  expect(filtered.rowVisible).toBe(true);
  await page.locator("#palette-input").fill("");
  await trackPaletteRows(page);

  await walkDownAndUp(page);
  await exercisePageKeys(page);

  const mobile = await openMobilePalette(browser, page);
  try {
    await walkDownAndUp(mobile.page);
  } finally {
    await mobile.context.close();
  }
});
