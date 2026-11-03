/**
 * Every row of every Settings section shares two edges (owner, 2026-11-02, #306: "align the switch and status rows too
 * ... and every other non-option row type in Settings"). Each row's first mark sits on the section's left edge, the
 * heading's own left edge (or, for a section with no heading such as Devices, the pane's content edge); each row's last
 * mark (a switch, a button, key caps, a value, a slider readout) sits on the right edge the option descriptions end at:
 * before the tick column in a window that has option lists, at the pane's far right edge where there is none. All within
 * 0.5 px, at desktop and phone size, in the ink and paper themes. A "mark" is what you see (a glyph, a text run, a
 * switch), not the hit box that holds it: icon buttons keep their 44 px targets and still show their glyph on the edge.
 * Review screenshots land in the external job evidence directory.
 */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const captures = tracerEvidencePath("settings-edges");
const SIZES = [{ w: 1440, h: 900, touch: false, dpr: 2 }, { w: 393, h: 852, touch: true, dpr: 3 }] as const;
/** Section id (the window is `s-<id>`), the palette words that open it. */
const SECTIONS = [
  { id: "appearance", words: "settings: appearance" },
  { id: "windows", words: "settings: window sizes" },
  { id: "hosts", words: "settings: hosts" },
  { id: "toolbar", words: "settings: toolbar" },
  { id: "shortcuts", words: "settings: shortcuts" },
  { id: "devices", words: "settings: devices" },
  { id: "account", words: "settings: account" },
  { id: "about", words: "settings: about" },
] as const;

/** The row types each section must show, so a section that renders nothing cannot pass. */
const EXPECTED: Record<string, string[]> = {
  appearance: ["slider", "tabs"], windows: [], hosts: ["switch", "status"], toolbar: ["toolbar"], shortcuts: ["shortcut"],
  devices: ["device"], account: ["fact", "status"], about: ["fact"],
};

interface Mark { left: number; right: number }
interface RowEdges { section: string; type: string; name: string; firstLeft: number; lastRight: number; lastKind: string }
interface SectionEdges { section: string; left: number; right: number; ticks: boolean; headingLeft?: number | undefined; overflow: number; rows: RowEdges[] }

/** Measures every row of one Settings window in the page, in CSS pixels. */
const measure = (page: Page, id: string): Promise<SectionEdges | undefined> => page.evaluate((sectionId) => {
  const win = document.querySelector<HTMLElement>(`.ui-window[data-window-id="s-${sectionId}"]`);
  const pane = win?.querySelector<HTMLElement>(".ui-settings-pane");
  if (!win || !pane) return undefined;
  const cs = getComputedStyle(pane), pr = pane.getBoundingClientRect();
  const padL = parseFloat(cs.paddingLeft), padR = parseFloat(cs.paddingRight);
  const left = pr.left + padL, farRight = pr.left + padL + (pane.clientWidth - padL - padR);
  const rect = (el: Element | null | undefined): Mark => { const r = el!.getBoundingClientRect(); return { left: r.left, right: r.right }; };
  // The visible extent of a run of text: its glyph boxes, not the (padded, highlight-sized) element around them.
  const text = (el: Element | null | undefined): Mark => {
    const walker = document.createTreeWalker(el!, NodeFilter.SHOW_TEXT);
    let l = Infinity, r = -Infinity;
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (!n.textContent!.trim()) continue;
      const range = document.createRange();
      range.selectNodeContents(n);
      for (const q of range.getClientRects()) { l = Math.min(l, q.left); r = Math.max(r, q.right); }
    }
    return { left: l, right: r };
  };
  // A switch's visible track is its ::before, not the input's box.
  const track = (el: Element | null | undefined): Mark => {
    const r = el!.getBoundingClientRect(), b = getComputedStyle(el!, "::before");
    const borders = b.boxSizing === "border-box" ? 0 : parseFloat(b.borderLeftWidth) + parseFloat(b.borderRightWidth);
    const left = r.left + parseFloat(b.left);
    return { left, right: left + parseFloat(b.width) + borders };
  };
  const tick = pane.querySelector<HTMLElement>(".ui-sp-text");
  const ticks = pane.querySelector(".ui-sp-tick") !== null && tick !== null;
  // Where an option's description ends: the right edge every other row's last mark shares in a window with ticks.
  const right = ticks ? tick!.getBoundingClientRect().right : farRight;
  const heading = pane.querySelector(".ui-ts-title, .ui-kv-group");
  const rows: RowEdges[] = [];
  const add = (type: string, row: Element, name: string, first: Mark | null, last: { m: Mark; kind: string } | null): void => {
    rows.push({ section: sectionId, type, name, firstLeft: first?.left ?? NaN, lastRight: last?.m.right ?? NaN, lastKind: last?.kind ?? "" });
  };
  for (const row of pane.querySelectorAll(".ui-sp-switch")) add("switch", row, row.querySelector(".ui-sp-label")!.textContent!, text(row.querySelector(".ui-sp-label")), { m: track(row.querySelector(".ui-switch")), kind: "switch" });
  for (const row of pane.querySelectorAll(".ui-sp-status")) {
    const action = row.querySelector<HTMLElement>(".ui-sp-status-action, .ui-window-action");
    const icon = action?.querySelector("svg");
    add("status", row, row.querySelector(".ui-sp-label")!.textContent!, text(row.querySelector(".ui-sp-label")), action ? { m: rect(icon ?? action), kind: icon ? "glyph" : "button" } : null);
  }
  for (const row of pane.querySelectorAll(".ui-ts-item")) add("toolbar", row, row.querySelector(".ui-ts-label")!.textContent!, rect(row.querySelector(".ui-ts-grip svg")), { m: track(row.querySelector(".ui-ts-switch")), kind: "switch" });
  // A changed row keeps its caps on the edge too (its mark is a dot on the caps, not a button beside them); "Reset all" has no caps.
  for (const row of pane.querySelectorAll(".ui-ss-row:not([data-reset-all])")) {
    const caps = row.querySelectorAll("kbd");
    add("shortcut", row, row.querySelector(".ui-ss-label")!.textContent!, text(row.querySelector(".ui-ss-label")), { m: caps.length ? rect(caps[caps.length - 1]) : text(row.querySelector(".ui-ss-keys")), kind: "keys" });
  }
  for (const row of pane.querySelectorAll(".ui-sp-device")) {
    const buttons = row.querySelectorAll(".ui-window-action svg");
    add("device", row, (row.querySelector(".ui-sp-name") as HTMLInputElement).value, rect(row.querySelector(".ui-sp-kind svg")), { m: rect(buttons[buttons.length - 1]), kind: "glyph" });
  }
  for (const row of pane.querySelectorAll(".ui-kv-row")) add("fact", row, row.querySelector(".ui-kv-key")?.textContent ?? "", text(row.querySelector(".ui-kv-key")), { m: text(row.querySelector(".ui-kv-value")), kind: "value" });
  for (const row of pane.querySelectorAll(".ui-slider")) add("slider", row, "slider", rect(row.querySelector(".ui-slider-input")), { m: text(row.querySelector(".ui-slider-value")), kind: "value" });
  for (const row of pane.querySelectorAll(".ui-tabs")) add("tabs", row, row.getAttribute("aria-label") ?? "tabs", rect(row), { m: rect(row), kind: "tabs" });
  return { section: sectionId, left, right, ticks, headingLeft: heading ? heading.getBoundingClientRect().left : undefined, overflow: pane.scrollWidth - pane.clientWidth, rows };
}, id);

async function open(page: Page, theme: string): Promise<void> {
  for (let attempt = 0; attempt < 3; attempt++) {
    await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none&sessions=0`);
    if (await page.locator("[data-view='console'] .ui-window").nth(3).waitFor({ timeout: 15_000 }).then(() => true, () => false)) break;
  }
  await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
  await page.addStyleTag({ content: ".test-double-badge, .cl-mockup, .perf-hud, .ui-toast { display: none !important; }" });
  await page.waitForTimeout(1000);
}

/** Opens a section through the palette and waits until its window is the one on screen and has rows. */
async function show(page: Page, section: (typeof SECTIONS)[number]): Promise<void> {
  for (let attempt = 0; attempt < 4; attempt++) {
    await page.keyboard.press("Control+Shift+K");
    await page.keyboard.type(section.words);
    await page.keyboard.press("Enter");
    const ok = await expect.poll(() => page.evaluate((id) => {
      const win = document.querySelector(`.ui-window[data-window-id="s-${id}"]`);
      if (!win || !win.querySelector(".ui-settings-pane")) return false;
      // The camera may still be flying to the window: every measurement is relative to the pane, so only its rows must exist.
      return win.querySelectorAll("li, .ui-sp-row, .ui-kv-row, .ui-tabs").length > 0;
    }, section.id), { timeout: 5000 }).toBe(true).then(() => true, () => false);
    if (ok) return;
  }
  throw new Error(`could not open ${section.id}`);
}

for (const theme of ["ink", "paper"]) for (const { w, h, touch, dpr } of SIZES) test(`settings edges ${theme} ${w}x${h}`, async ({ browser }) => {
  test.setTimeout(240_000);
  await mkdir(captures, { recursive: true });
  const context = await browser.newContext({ viewport: { width: w, height: h }, hasTouch: touch, isMobile: touch, deviceScaleFactor: dpr });
  const page = await context.newPage();
  try {
    await open(page, theme);
    for (const section of SECTIONS) {
      await show(page, section);
      await page.waitForTimeout(900);
      const m = (await measure(page, section.id))!;
      const where = `${section.id} ${theme} ${w}`;
      expect.soft(m.overflow, `${where}: the pane never scrolls sideways`).toBeLessThanOrEqual(1);
      if (m.headingLeft !== undefined) expect.soft(Math.abs(m.headingLeft - m.left), `${where}: the heading is on the content edge`).toBeLessThanOrEqual(0.5);
      for (const type of EXPECTED[section.id] ?? []) expect.soft(m.rows.filter((r) => r.type === type).length, `${where}: has ${type} rows to measure`).toBeGreaterThan(0);
      for (const r of m.rows) {
        expect.soft(Math.abs(r.firstLeft - m.left), `${where}: ${r.type} "${r.name}" starts on the left edge`).toBeLessThanOrEqual(0.5);
        // A segmented control is a control, not a value: only its left edge belongs to the shared edges.
        if (r.type !== "tabs") expect.soft(Math.abs(r.lastRight - m.right), `${where}: ${r.type} "${r.name}" (${r.lastKind}) ends on the right edge`).toBeLessThanOrEqual(0.5);
      }
      await page.locator(`.ui-window[data-window-id="s-${section.id}"]`).screenshot({ path: resolve(captures, `${section.id}-${theme}-${w}x${h}.png`) }).catch(() => undefined);
    }
  } finally { await context.close(); }
});
