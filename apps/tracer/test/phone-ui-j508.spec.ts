// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Three bugs the owner hit on an iPhone (J508, #499), checked at 393 px in a production build:
 *
 * 1. The machine pill's details panel keeps its scroll position while the facts poll repaints it (Machine and Connection tabs).
 * 2. A mesh card grows to fit its status line, so nothing is clipped; a host that cannot clear restored peers says so in plain
 *    words ("needs an update"), not "unsafe after restore".
 * 3. Phone text is 15 px or larger everywhere except true labels (D372, D383, TASTE "Text sizes follow Apple's guidelines"):
 *    a census of the sidebar, palette, details panel, mesh cards, toasts and toolbar lists every visible text under 15 px.
 *
 * `J508_CAPTURES=<label>` writes dark and light screenshots to the external evidence directory (`phone-ui-j508/<label>/`).
 */
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { decodeMuxedFrame, encodeMuxedFrame } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "./evidence-path";

/** The phone under test: an iPhone-sized viewport with touch. */
const PHONE = { width: 393, height: 852 };
/** The smallest size a row of text may have on a phone; true labels (eyebrows, captions, field labels) may go to 13 px. */
const ROW_PX = 15;
/** Set to a folder name to take the review screenshots. */
const CAPTURES = process.env.J508_CAPTURES;
/** The facts the intercepted server answers with, enough rows for the panel to overflow a short phone. */
const FACTS = { os: "AlmaLinux", version: "10.2", kernel: "6.12.0-124", architecture: "x86_64", cpuModel: "Intel N100", logicalCpus: 4, executionUid: 0, mode: "embedded", engines: [] };

test.use({ viewport: PHONE, hasTouch: true, isMobile: true, deviceScaleFactor: 3 });

/** Takes a review capture when `J508_CAPTURES` is set. */
async function capture(page: Page, name: string, theme: string): Promise<void> {
  if (!CAPTURES) return;
  await page.screenshot({ path: tracerEvidencePath("phone-ui-j508", CAPTURES, `${name}-${theme}.png`) });
}

/** Answers the machine-facts read from the page's own socket, counting how many times it was asked. */
async function serveFacts(page: Page): Promise<{ reads: () => number }> {
  let reads = 0;
  await page.routeWebSocket(/\/v1\/ws(?:\?|$)/, (socket) => {
    const server = socket.connectToServer();
    socket.onMessage((message) => {
      if (typeof message === "string") { server.send(message); return; }
      const { frame } = decodeMuxedFrame(message);
      if (frame.type === "Call" && frame.actionId === "host.facts.read") {
        reads += 1;
        socket.send(Buffer.from(encodeMuxedFrame(0, { type: "Result", callId: frame.callId, ok: true, json: new TextEncoder().encode(JSON.stringify(FACTS)) })));
        return;
      }
      server.send(message);
    });
    server.onMessage((message) => socket.send(message));
  });
  return { reads: () => reads };
}

for (const theme of ["ink", "paper"] as const) {
  test(`the details panel keeps its scroll position through facts refreshes: ${theme}`, async ({ page }) => {
    test.setTimeout(90_000);
    const asked = await serveFacts(page);
    // Short enough that both tabs overflow, whatever rows a machine reports.
    await page.setViewportSize({ width: PHONE.width, height: 560 });
    await page.request.post("/__mock/reset");
    await page.goto(`/?mock=1&proto=product&fresh=1&bg=none&theme=${theme}`);
    const pill = page.locator(".ui-window .ui-window-pill").first();
    await expect(pill).toBeVisible({ timeout: 30_000 });
    await pill.click();
    const scroll = page.locator(".canvas-popover-scroll");
    await expect(page.locator(".canvas-popover .ui-kv-key", { hasText: /^System$/ })).toBeVisible({ timeout: 40_000 });
    for (const tab of ["Machine", "Connection"]) {
      await page.locator(".canvas-popover").getByRole("tab", { name: tab }).click();
      const overflow = await scroll.evaluate((el) => el.scrollHeight - el.clientHeight);
      expect(overflow, `${tab} tab overflows the short phone`).toBeGreaterThan(20);
      // A real scroll, so the panel's own scroll listener sees it.
      await scroll.evaluate((el) => { el.scrollTop = 40; });
      await expect.poll(() => scroll.evaluate((el) => el.scrollTop)).toBeGreaterThan(20);
      const held = await scroll.evaluate((el) => el.scrollTop);
      const readsBefore = asked.reads();
      // sleep: two facts-poll intervals (1 s each), so at least two refreshes repaint the panel while it is scrolled
      await page.waitForTimeout(2_600);
      expect(asked.reads() - readsBefore, "the facts poll ran again").toBeGreaterThanOrEqual(2);
      expect(await scroll.evaluate((el) => el.scrollTop)).toBe(held);
    }
    // Choosing another tab is a new page: it starts from the top.
    await scroll.evaluate((el) => { el.scrollTop = 40; });
    await page.locator(".canvas-popover").getByRole("tab", { name: "Machine" }).click();
    expect(await scroll.evaluate((el) => el.scrollTop)).toBe(0);
    await capture(page, "details-panel", theme);
  });
}

/** The mesh view on the fake mesh server, on a phone. */
async function openMesh(page: Page, theme: string): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=6&theme=${theme}&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: { views(): unknown[] } }).__tracerClusters?.views().length);
  await page.keyboard.press("Control+Shift+Digit3");
  // sleep: the view flies to the mesh and its cards mount
  await page.waitForTimeout(1_400);
}
/** Runs `fn` against the mesh test server (the same hook the mesh spec uses). */
const meshServer = (page: Page, fn: (s: { patchNode(name: string, patch: Record<string, unknown>): void }) => void) =>
  page.evaluate((source) => (new Function("s", `return (${source})(s)`) as (s: unknown) => unknown)((window as unknown as { __tracerClusters: { mesh: { server(): unknown } } }).__tracerClusters.mesh.server()), fn.toString());

for (const theme of ["ink", "paper"] as const) {
  test(`mesh cards fit their status line and say restore trouble in plain words: ${theme}`, async ({ page }) => {
    await openMesh(page, theme);
    await meshServer(page, (s) => {
      s.patchNode("build-01", { restoreSafe: false });
      s.patchNode("nix-cache", { path: "relay", via: "fra-relay", restoreSafe: false });
    });
    await expect.poll(() => page.locator('.ui-window[data-window-id="n-build-01"] .cl-node-sub').innerText()).toMatch(/needs an update/);
    const text = await page.locator('.cl-node-sub').allInnerTexts();
    expect(text.join("\n")).not.toMatch(/unsafe after restore/);
    // Every card: its text ends inside its card (no clipped line, no hidden overflow).
    const clipped = await page.locator('.ui-window[data-kind="node"]').evaluateAll((cards) => cards.map((card) => {
      const box = card.getBoundingClientRect();
      const bottoms = Array.from(card.querySelectorAll<HTMLElement>(".cl-node-detail, .cl-node-sub")).map((el) => {
        const range = document.createRange();
        range.selectNodeContents(el);
        return { overflow: el.scrollHeight - el.clientHeight, bottom: range.getBoundingClientRect().bottom };
      });
      return { id: (card as HTMLElement).dataset.windowId, overflow: Math.max(...bottoms.map((b) => b.overflow)), spill: Math.max(...bottoms.map((b) => b.bottom)) - box.bottom };
    }));
    expect(clipped.filter((c) => c.overflow > 0 || c.spill > 0.5), JSON.stringify(clipped)).toEqual([]);
    await capture(page, "mesh-cards", theme);
  });
}

/** One visible text that is smaller than a row may be, with where it is. */
interface Small { selector: string; text: string; px: number; weight: string; transform: string }

/** Lists the visible text under `root` whose computed size is below `ROW_PX`, with enough to tell a label from a row. */
async function small(page: Page, root: string): Promise<Small[]> {
  return page.evaluate(({ selector, min }) => {
    const base = document.querySelector(selector) ?? document.body;
    const out: Small[] = [];
    for (const el of [base, ...Array.from(base.querySelectorAll("*"))]) {
      const box = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      if (box.width === 0 || box.height === 0 || cs.visibility === "hidden" || cs.display === "none" || Number(cs.opacity) === 0) continue;
      const own = Array.from(el.childNodes).filter((n) => n.nodeType === 3).map((n) => (n.textContent ?? "").trim()).join(" ").trim();
      if (!own) continue;
      // Text drawn in the canvas's own coordinates (an arrow's "via" name) is scaled by the camera, so its size is the camera's, not the stylesheet's.
      if (el.closest("svg.cl-graph-arrows")) continue;
      const px = parseFloat(cs.fontSize);
      if (px >= min - 0.01) continue;
      const cls = (el.getAttribute("class") ?? "").trim().split(/\s+/).slice(0, 2).join(".");
      const inKey = el.closest(".ui-kv-key") ? " in .ui-kv-key" : "";
      out.push({ selector: `${el.tagName.toLowerCase()}${cls ? "." + cls : ""}${inKey}`, text: own.slice(0, 40), px: Math.round(px * 100) / 100, weight: cs.fontWeight, transform: cs.textTransform });
    }
    return out;
  }, { selector: root, min: ROW_PX });
}

/**
 * Selectors of true labels: eyebrows (section headings), captions and tags may be 13 px on a phone (D383). Everything else
 * that is text a person reads in a row must be 15 px or larger.
 */
const LABELS = [
  /\.group-label/, /ui-kv-group/, /canvas-popover-sub/, /ui-kv-key/, /ui-sidebar-secondary/, /cl-node-sub/, /cl-arrow-label/, /\.result-hint/, /\.bm-meta/, /\.glyph/, /\.ui-setting-caption/, /\.ui-eyebrow/, /\.ui-kv-hint/, /caption/, /eyebrow/, /\.ui-chip/, /\.ui-tag/, /\.ui-badge/, /kbd/,
];
/** True when the text is one of the true labels above, which may be 13 px. */
const isLabel = (s: Small): boolean => LABELS.some((re) => re.test(s.selector));

/** The surfaces the owner named, each opened on a phone. */
const SURFACES: Array<{ name: string; root: string; open: (page: Page, theme: string) => Promise<void> }> = [
  { name: "sidebar", root: "#sidebar", open: async (page, theme) => {
    await openCanvasScene(page, theme, 1);
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
    // sleep: the sidebar slides in and settles
    await page.waitForTimeout(900);
  } },
  { name: "palette", root: "#palette", open: async (page, theme) => {
    await openCanvasScene(page, theme, 1);
    await page.keyboard.press("Control+Shift+K");
    await expect(page.locator("#palette")).toBeVisible();
    // sleep: the palette grows to its results
    await page.waitForTimeout(500);
  } },
  { name: "details", root: ".canvas-popover", open: async (page, theme) => {
    await serveFacts(page);
    await page.request.post("/__mock/reset");
    await page.goto(`/?mock=1&proto=product&fresh=1&bg=none&theme=${theme}`);
    const pill = page.locator(".ui-window .ui-window-pill").first();
    await expect(pill).toBeVisible({ timeout: 30_000 });
    await pill.click();
    await expect(page.locator(".canvas-popover .ui-kv-key", { hasText: /^System$/ })).toBeVisible({ timeout: 40_000 });
    // sleep: the popover finishes growing from its pill
    await page.waitForTimeout(500);
  } },
  { name: "mesh", root: '.cl[data-view="mesh"]', open: async (page, theme) => {
    await openMesh(page, theme);
    await meshServer(page, (s) => s.patchNode("build-01", { restoreSafe: false }));
    // sleep: the card text updates
    await page.waitForTimeout(300);
  } },
  { name: "toast", root: ".ui-toast", open: async (page, theme) => {
    await openCanvasScene(page, theme, 3);
    await page.waitForFunction(() => Boolean((window as unknown as { __toast?: unknown }).__toast));
    await page.evaluate(() => { const t = (window as unknown as { __toast: { dismiss(): void; show(v: Record<string, unknown>): string } }).__toast; t.dismiss(); t.show({ title: "Copied from the terminal", message: "The program asked to copy this." }); });
    await expect(page.locator(".ui-toast").first()).toBeVisible();
    // sleep: the toast slides in
    await page.waitForTimeout(500);
  } },
  { name: "toolbar", root: "#keybar", open: async (page, theme) => {
    await openCanvasScene(page, theme, 1);
    // sleep: the toolbar rows settle
    await page.waitForTimeout(500);
  } },
];

/** Opens the mock canvas at `scene` in `theme`, flown to the console. */
async function openCanvasScene(page: Page, theme: string, scene: number): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=${theme}&bg=none`);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  // sleep: the scene mounts before the camera flies
  await page.waitForTimeout(700);
}

for (const theme of ["ink", "paper"] as const) {
  for (const surface of SURFACES) {
    test(`phone text is 15 px or larger except true labels: ${surface.name} ${theme}`, async ({ page }) => {
      await surface.open(page, theme);
      const found = await small(page, surface.root);
      // A label may be 13 px, never smaller; anything else is a row and must be 15 px.
      const rows = found.filter((s) => !isLabel(s) || s.px < 13);
      const tally = (list: Small[]) => Object.fromEntries([...new Set(list.map((x) => `${x.selector} ${x.px}`))].map((k) => [k, list.filter((x) => `${x.selector} ${x.px}` === k).length]));
      console.log(`J508_SMALL ${surface.name} ${theme} labels=${JSON.stringify(tally(found.filter(isLabel)))} rows=${JSON.stringify(tally(rows))}`);
      await capture(page, surface.name, theme);
      expect(rows, `${surface.name}: text under ${ROW_PX} px that is not a label`).toEqual([]);
    });
  }
}
