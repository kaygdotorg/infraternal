/**
 * Settings as rows of windows (issue #304, `?mock=1&proto=clusters`): the table drives the rows and
 * windows, the top breadcrumb, the sidebar nesting, the "?" docs buttons and ⌘K; a setting shows its default and range, refuses
 * a value out of range inline, and resets. Alignment is measured, not looked at: text and icons on one centre line, one left
 * edge per column, every window at the layout's size, everything within 0.5 px (the owner's rule, 2026-11-01). `SETTINGS_SHOTS=<dir>`
 * also writes the review captures (1440x900 at DPR 2 and 393x852 at DPR 3).
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";

const SHOTS = process.env.SETTINGS_SHOTS;
/** `SETTINGS_THEME=latte` writes the light captures (the default is the dark `mocha`). */
const URL = `/?mock=1&proto=clusters&docs=1&scene=3&theme=${process.env.SETTINGS_THEME ?? "mocha"}&bg=none`;
const SIZES = {
  desktop: { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, isMobile: false, hasTouch: false },
  phone: { viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true },
} as const;
const HALF = 0.5;
const near = (a: number, b: number, what: string): void => { expect(Math.abs(a - b), `${what}: ${a.toFixed(2)} vs ${b.toFixed(2)}`).toBeLessThanOrEqual(HALF); };
/** The Settings windows the docs have no page for yet: they show no "?" (a button that opens nothing is not offered). */
const WITHOUT_DOCS = ["s-appearance-themes", "s-appearance-layout", "s-terminal-typing", "s-terminal-hosts", "s-terminal-scrollback", "s-you-profile", "s-machines-updates", "s-mesh-names", "s-mesh-access", "s-mesh-connections", "s-sharing-published-services", "s-sharing-certificates", "s-about-version", "s-about-licences"];
const ROWS = ["appearance", "terminal", "you", "machines", "mesh", "sharing", "about"];

async function open(page: Page, extra = ""): Promise<void> {
  await page.goto(`${URL}${extra.includes("&at=") ? extra : `&at=appearance${extra}`}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect(page.locator(".cl-crumbs:not([hidden])")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1800);
}
const shot = async (page: Page, name: string): Promise<void> => {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: `${SHOTS}/${name}.png` });
};
const crumbs = (page: Page): Promise<string[]> => page.locator(".cl-crumb .cl-crumb-name").allTextContents();
/** ⌘K as a Windows or Linux keyboard sends it; the phone shows the same sheet. */
const palette = async (page: Page, text: string): Promise<void> => {
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeVisible();
  await page.locator("#palette-input").fill(text);
  await page.waitForTimeout(400);
};
const active = (page: Page): Promise<string | undefined> => page.evaluate(() => document.querySelector<HTMLElement>('.cl[data-view="settings"] .ui-window[data-active]')?.dataset.windowId);

/** Rows inside one window: the name, help, control and range share one left edge; the control and its Reset share a centre line. */
async function checkRows(page: Page, windowId: string): Promise<number> {
  const rows = await page.evaluate((id) => [...document.querySelectorAll(`[data-window-id="${id}"] .ui-setting`)].map((r) => {
    const q = (s: string): DOMRect => r.querySelector(s)!.getBoundingClientRect();
    const t = q(".ui-setting-title"), e = q(".ui-setting-explain"), c = q(".ui-setting-caption"), i = q(".ui-setting-field"), b = q(".ui-setting-reset");
    return { tl: t.left, el: e.left, cl: c.left, il: i.left, im: (i.top + i.bottom) / 2, bm: (b.top + b.bottom) / 2, ir: i.right, bl: b.left, order: [t.top, e.top, i.top, c.top] };
  }), windowId);
  for (const [n, r] of rows.entries()) {
    near(r.el, r.tl, `row ${n} explain left edge`);
    near(r.il, r.tl, `row ${n} control left edge`);
    near(r.cl, r.tl, `row ${n} caption left edge`);
    near(r.bm, r.im, `row ${n} reset/control centre`);
    near(r.bl - r.ir, rows[0]!.bl - rows[0]!.ir, `row ${n} control-to-reset gap`);
    near(r.tl, rows[0]!.tl, `row ${n} left edge`);
    expect(r.order, `row ${n} reads top to bottom`).toEqual([...r.order].sort((a, b) => a - b));
  }
  return rows.length;
}

/** Self-contained (it runs in the page): the action group of every window matching `selector`, measured. */
function measureActions(selector: string) {
  return [...document.querySelectorAll<HTMLElement>(selector)].map((w) => {
    const rect = (n: Element): DOMRect => n.getBoundingClientRect();
    const pill = w.querySelector<HTMLElement>(".ui-window-pill");
    const group = w.querySelector<HTMLElement>(".ui-window-actions");
    const buttons = [...(group?.querySelectorAll<HTMLElement>(".ui-window-action") ?? [])].filter((b) => b.getBoundingClientRect().width > 0 && !b.classList.contains("ui-window-more"));
    const g = group ? rect(group) : undefined;
    return {
      id: w.dataset.windowId ?? "", ids: buttons.map((b) => b.dataset.action ?? ""),
      boxes: buttons.map((b) => { const r = rect(b), svg = b.querySelector("svg"), sr = svg ? rect(svg) : r; return { w: r.width, h: r.height, cx: (r.left + r.right) / 2, cy: (r.top + r.bottom) / 2, icx: (sr.left + sr.right) / 2, icy: (sr.top + sr.bottom) / 2, left: r.left, right: r.right }; }),
      group: g ? { cy: (g.top + g.bottom) / 2, h: g.height } : undefined,
      pill: pill ? { cy: (rect(pill).top + rect(pill).bottom) / 2, h: rect(pill).height } : undefined,
      inset: g ? rect(w).right - g.right : 0,
    };
  });
}
type Measured = ReturnType<typeof measureActions>;

/** The action-group rules (owner, 2026-11-01): the first button is `first`; buttons are one size on one centre line with equal gaps,
 *  every icon sits dead centre in its button, the group is as tall as the title pill and on its centre line, and every group ends the same
 *  distance from its window's edge. */
function checkGroups(list: Measured, first: string, insetOf?: number): number {
  const inset = insetOf ?? list.find((m) => m.group)?.inset ?? 0;
  for (const m of list) {
    expect(m.ids[0], `${m.id} first button`).toBe(first);
    for (const [i, b] of m.boxes.entries()) {
      near(b.w, m.boxes[0]!.w, `${m.id} button ${i} width`); near(b.h, m.boxes[0]!.h, `${m.id} button ${i} height`);
      near(b.cy, m.boxes[0]!.cy, `${m.id} button ${i} centre line`);
      near(b.icx, b.cx, `${m.id} button ${i} icon centre x`); near(b.icy, b.cy, `${m.id} button ${i} icon centre y`);
      if (i > 0) near(b.left - m.boxes[i - 1]!.right, m.boxes[1]!.left - m.boxes[0]!.right, `${m.id} gap ${i}`);
    }
    if (m.group && m.pill) { near(m.group.cy, m.pill.cy, `${m.id} group/pill centre line`); near(m.group.h, m.pill.h, `${m.id} group/pill height`); }
    near(m.inset, inset, `${m.id} distance from the window's edge`);
  }
  return inset;
}

/** The preview's rules: the expand icon is at the top right on the title's centre line and dead centre in its button; title, lead, bullets and table
 *  share one left edge; a popover stays inside its window with the same inset on its right as the shared popover keeps, a sheet is on screen with equal gutters. */
async function checkPreview(page: Page, kind: "popover" | "sheet", windowId?: string): Promise<void> {
  const m = await page.evaluate(([k, id]) => {
    const rect = (n: Element | null | undefined): DOMRect | undefined => n?.getBoundingClientRect();
    const root = document.querySelector<HTMLElement>(k === "popover" ? ".ui-dp-pop" : ".ui-sheet")!;
    const head = rect(root.querySelector(".ui-dp-head"))!, expand = rect(root.querySelector(".ui-dp-expand")), svg = rect(root.querySelector(".ui-dp-expand svg"));
    const title = rect(root.querySelector(".ui-dp-title"))!, r = root.getBoundingClientRect();
    const lefts = [".ui-dp-title", ".ui-dp-lead", ".ui-dp-bullets", ".ui-dp-table-wrap", ".ui-dp-empty"].map((s) => rect(root.querySelector(s))?.left).filter((v): v is number => v !== undefined);
    const win = id ? rect(document.querySelector(`[data-window-id="${id}"]`)) : undefined;
    const anchor = id ? rect(document.querySelector(`[data-window-id="${id}"] .ui-window-action[data-action="docs"]`)) : undefined;
    const border = win && id ? parseFloat(getComputedStyle(document.querySelector(`[data-window-id="${id}"]`)!).borderLeftWidth) || 0 : 0;
    return {
      root: { left: r.left, right: r.right, top: r.top, bottom: r.bottom, height: r.height },
      head: { cy: (head.top + head.bottom) / 2 }, title: { cy: (title.top + title.bottom) / 2, right: title.right },
      expand: expand ? { cx: (expand.left + expand.right) / 2, cy: (expand.top + expand.bottom) / 2, left: expand.left, right: expand.right, top: expand.top, w: expand.width, h: expand.height } : undefined,
      svg: svg ? { cx: (svg.left + svg.right) / 2, cy: (svg.top + svg.bottom) / 2 } : undefined,
      lefts, win: win ? { left: win.left, right: win.right, top: win.top, bottom: win.bottom } : undefined, border, anchorRight: anchor?.right,
      vw: innerWidth, vh: innerHeight,
    };
  }, [kind, windowId ?? ""] as const);
  expect(m.lefts.length).toBeGreaterThan(1);
  for (const left of m.lefts) near(left, m.lefts[0]!, "preview content shares one left edge");
  if (m.expand && m.svg) {
    near(m.expand.cy, m.head.cy, "expand icon is on the heading row's centre line");
    near(m.svg.cx, m.expand.cx, "expand icon is dead centre in its button (x)"); near(m.svg.cy, m.expand.cy, "expand icon is dead centre in its button (y)");
    expect(m.expand.right, "the expand icon is the right-most thing in the heading row").toBeGreaterThanOrEqual(m.title.right - 0.5);
    expect(m.root.right - m.expand.right, "the expand icon is at the top right").toBeLessThan(20);
    expect(m.expand.top - m.root.top, "the expand icon is at the top").toBeLessThan(kind === "sheet" ? 48 : 20);
    expect(m.expand.w).toBeGreaterThanOrEqual(kind === "sheet" ? 28 : 24);
  }
  if (kind === "popover") {
    expect(m.win, "a popover belongs to a window").toBeDefined();
    expect(m.root.left).toBeGreaterThanOrEqual(m.win!.left); expect(m.root.right).toBeLessThanOrEqual(m.win!.right); expect(m.root.bottom).toBeLessThanOrEqual(m.win!.bottom);
    // It lines up with the "?" it grew from (its right edges meet), or, in a window too narrow for that, sits at the window's own inset on the left;
    // either way it keeps the header's inset from the window's edges.
    const inset = 8 + m.border, atButton = Math.abs(m.root.right - m.anchorRight!) <= 0.5, atEdge = Math.abs(m.root.left - (m.win!.left + inset)) <= 0.5;
    expect(atButton || atEdge, `the popover meets the "?" at its right edge (${m.root.right} vs ${m.anchorRight}) or the window's inset on the left`).toBe(true);
    expect(m.root.left).toBeGreaterThanOrEqual(m.win!.left + inset - 0.5); expect(m.root.right).toBeLessThanOrEqual(m.win!.right - inset + 0.5);
  } else {
    near(m.root.left, m.vw - m.root.right, "the sheet has equal gutters left and right");
    expect(m.root.bottom).toBeLessThanOrEqual(m.vh); expect(m.root.height).toBeLessThanOrEqual(m.vh * 0.7 + 1);
  }
}
/** Brings one window into view the way ⌘K does, then waits for the camera. */
const goTo = async (page: Page, action: string): Promise<void> => {
  await page.evaluate((a) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: a, source: "keyboard" } })), action);
  await page.waitForTimeout(1300);
};

test("desktop: a row of windows for each component, breadcrumb, sidebar, \"?\", ⌘K, refusal and Reset", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ ...SIZES.desktop, baseURL: process.env.J92_URL ?? `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}` });
  const page = await context.newPage();
  await open(page, "&at=mesh.keys");

  // The breadcrumb names the focused window, and the three pills sit on the screen's centre line.
  expect(await crumbs(page)).toEqual(["Settings", "Mesh", "Keys"]);
  expect(await active(page)).toBe("s-mesh-keys");
  const bar = await page.locator(".cl-crumbs").evaluate((n) => { const r = n.getBoundingClientRect(); return { cx: (r.left + r.right) / 2 }; });
  expect(Math.abs(bar.cx - 720)).toBeLessThanOrEqual(1);
  const pills = await page.locator(".cl-crumb").evaluateAll((ns) => ns.map((n) => { const r = n.getBoundingClientRect(); return (r.top + r.bottom) / 2; }));
  for (const mid of pills) near(mid, pills[0]!, "breadcrumb pills share a centre line");

  // Every window starts at the layout's size (TASTE): the width a terminal window has (Settings -> Window Sizes) and the layout's height, one screen. A component is ONE ROW of
  // its windows (D212, Settings rows): the windows of a row are level (the row is one band), side by side with equal gaps, the rows are one band under the other, tracks line up
  // from row to row, no window spans, none is over another, and the view is wider than the screen (a row's further windows are reached by scrolling sideways).
  const wins = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="settings"] .ui-window')].map((n) => {
    const r = n.getBoundingClientRect();
    return { id: n.dataset.windowId!, left: r.left, right: r.right, top: r.top, bottom: r.bottom, w: n.offsetWidth, h: n.offsetHeight, span: n.dataset.span ?? "" };
  }));
  expect(wins.length).toBe(21);
  const layout = await page.evaluate(() => ({ clh: parseFloat((document.querySelector(".cl-world") as HTMLElement).style.getPropertyValue("--clh")), terminalW: document.querySelector<HTMLElement>('.cl[data-view="console"] .ui-window')?.offsetWidth ?? 0 }));
  expect(layout.terminalW, "a terminal window gives the default width").toBeGreaterThan(300);
  expect(layout.clh, "the layout's height is known").toBeGreaterThan(500);
  const byRow = new Map<string, typeof wins>();
  for (const w of wins) { const key = w.id.split("-")[1]!; byRow.set(key, [...(byRow.get(key) ?? []), w]); }
  expect([...byRow.keys()]).toEqual(ROWS);
  expect([...byRow.values()].map((r) => r.length)).toEqual([2, 4, 5, 2, 4, 2, 2]);
  for (const w of wins) {
    near(w.w, layout.terminalW, `${w.id} has the layout's width`);
    near(w.h, layout.clh, `${w.id} has the layout's height: it does not grow to its content`);
    expect(w.span, `${w.id} spans no column`).toBe("");
  }
  const rows = [...byRow.values()];
  const longest = rows.reduce((a, b) => (b.length > a.length ? b : a));
  for (const [i, row] of rows.entries()) {
    for (const [k, w] of row.entries()) {
      near(w.top, row[0]!.top, `${w.id} is level with its row`); near(w.bottom, row[0]!.bottom, `${w.id} ends level with its row`);
      near(w.left, longest[k]!.left, `${w.id} is at the track of the same window of the longest row`);
      if (k > 0) near(w.left - row[k - 1]!.right, 12, `${w.id} sits one gap from the window before it`);
    }
    if (i > 0) near(row[0]!.top - rows[i - 1]![0]!.bottom, 12, `row ${i} sits one gap under row ${i - 1}`);
  }
  expect(Math.max(...wins.map((w) => w.right)) - Math.min(...wins.map((w) => w.left)), "a row is wider than the screen: the canvas scrolls sideways").toBeGreaterThan(1440);
  for (let i = 0; i < wins.length; i++) for (let j = i + 1; j < wins.length; j++) {
    const a = wins[i]!, b = wins[j]!;
    expect(a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1, `${a.id} overlaps ${b.id}`).toBe(false);
  }

  // A window the docs have a page for has "?" as the first button of its action group, and the group obeys the alignment rules. A window without a page has no "?".
  const groups = await page.evaluate(measureActions, '.cl[data-view="settings"] .ui-window');
  expect(groups.length).toBe(21);
  expect(groups.filter((g) => g.ids.length === 0).map((g) => g.id).sort(), "windows without a docs page offer no button").toEqual([...WITHOUT_DOCS].sort());
  const settingsInset = checkGroups(groups.filter((g) => g.ids.length > 0), "docs");
  // No window's name is ever cut short, even with five windows to a row.
  const cut = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="settings"] .ui-window')].map((w) => { const h = w.querySelector<HTMLElement>(".ui-window-host")!; return h.scrollWidth > h.clientWidth + 0.5 ? `${w.dataset.windowId}: ${h.textContent}` : ""; }).filter(Boolean));
  expect(cut).toEqual([]);
  expect(await checkRows(page, "s-mesh-keys")).toBe(3);
  await expect(page.locator('[data-window-id="s-mesh-keys"] .ui-setting[data-setting="connection-keys"] .ui-setting-caption')).toHaveText("Default 7 d · allowed 1 to 30 days");
  // The certificate lock state is read only: a fact, not a field.
  await expect(page.locator('[data-window-id="s-mesh-keys"]')).toContainText("locked until an administrator confirms with a passkey");
  await shot(page, "01-mesh-keys");

  // Out of range is refused inline, nothing is saved, and Escape puts the saved value back.
  const row = page.locator('[data-window-id="s-mesh-keys"] .ui-setting[data-setting="connection-keys"]');
  const input = row.locator(".ui-setting-input");
  await input.click();
  await input.fill("400");
  await expect(row).toHaveAttribute("data-invalid", "");
  await expect(row.locator(".ui-setting-refusal p")).toHaveText("Pick 1 to 30 days. Still using 7 d.");
  await page.waitForTimeout(400);
  await shot(page, "02-refusal");
  await input.press("Escape");
  await expect(input).toHaveValue("7 d");
  await expect(row).not.toHaveAttribute("data-invalid", "");
  // Another unit is understood; a saved value shows Reset, which puts the default back.
  await input.fill("336 h");
  await input.press("Enter");
  await expect(input).toHaveValue("14 d");
  await expect(row.locator(".ui-setting-reset")).toHaveAttribute("data-shown", "true");
  await shot(page, "03-changed-reset");
  const reset = row.locator(".ui-setting-reset");
  await expect(reset).toHaveAttribute("aria-label", "Reset to 7 d");
  await reset.click();
  await expect(input).toHaveValue("7 d");
  await expect(reset).toHaveAttribute("data-shown", "false");
  expect(await checkRows(page, "s-mesh-keys")).toBe(3);

  // A choice and a switch: picked, saved at once, with their own Reset, on the same edges.
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:machines.new-machines", source: "keyboard" } })));
  await page.waitForTimeout(1200);
  expect(await crumbs(page)).toEqual(["Settings", "Machines", "New Machines"]);
  expect(await checkRows(page, "s-machines-new-machines")).toBe(5);
  const mode = page.locator('[data-window-id="s-machines-new-machines"] .ui-setting[data-setting="install-mode"]');
  await mode.locator(".ui-tab", { hasText: "User" }).click();
  await expect(mode.locator(".ui-tab[aria-selected='true']")).toHaveText("User");
  await expect(mode.locator(".ui-setting-reset")).toHaveAttribute("data-shown", "true");
  await mode.locator(".ui-setting-reset").click();
  await expect(mode.locator(".ui-tab[aria-selected='true']")).toHaveText("System");
  const mesh = page.locator('[data-window-id="s-machines-new-machines"] .ui-setting[data-setting="join-mesh"]');
  await mesh.locator(".ui-switch").click();
  await expect(mesh.locator(".ui-setting-reset")).toHaveAttribute("data-shown", "true");
  await page.waitForTimeout(450); // the switch has finished moving: captures are taken at rest
  await shot(page, "04-new-machines");
  await mesh.locator(".ui-setting-reset").click();
  await expect(mesh.locator(".ui-switch")).toBeChecked();
  expect(await checkRows(page, "s-machines-new-machines")).toBe(5);

  // The breadcrumb navigates: Machines lists the components, New Machines the groups of this one.
  await page.locator('.cl-crumb[data-level="row"]').click();
  const items = page.locator(".cl-crumb-menu .cl-crumb-item");
  await expect(items).toHaveCount(7);
  await page.waitForTimeout(450);
  await shot(page, "05-breadcrumb-menu");
  await items.filter({ hasText: "Sharing" }).click();
  await page.waitForTimeout(1200);
  expect(await crumbs(page)).toEqual(["Settings", "Sharing", "Published Services"]);
  await page.locator('.cl-crumb[data-level="group"]').click();
  await expect(page.locator(".cl-crumb-menu .cl-crumb-item")).toHaveText(["Published Services", "Certificates"]);
  await page.keyboard.press("Escape");
  await expect(page.locator(".cl-crumb-menu")).toHaveCount(0);

  // The sidebar shows the same nesting, with the group's glyph under its parent's name.
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#sidebar")).toBeVisible();
  await page.waitForTimeout(600);
  await page.evaluate(() => document.querySelector<HTMLElement>("#tree .bm-leaf[data-id='st:mesh']")?.click());
  await page.waitForTimeout(1200);
  expect(await crumbs(page)).toEqual(["Settings", "Mesh", "Keys"]);
  const tree = await page.evaluate(() => {
    const leaves = [...document.querySelectorAll<HTMLElement>('#tree .bm-sec[data-id="view:settings"] .bm-leaf')];
    const rect = (n: Element | null | undefined): DOMRect | undefined => n?.getBoundingClientRect();
    const mesh = leaves.find((l) => l.dataset.id === "st:mesh");
    const nested = leaves.filter((l) => l.dataset.depth === "1");
    return {
      labels: leaves.map((l) => (l.dataset.depth ? "  " : "") + l.querySelector(".bm-label")!.textContent),
      meshLabelLeft: rect(mesh?.querySelector(".bm-label"))?.left, nestedGlyphLeft: nested.map((l) => rect(l.querySelector(".glyph"))!.left),
      mids: leaves.map((l) => { const g = rect(l.querySelector(".glyph"))!, t = rect(l.querySelector(".bm-label"))!; return [(g.top + g.bottom) / 2, (t.top + t.bottom) / 2]; }),
    };
  });
  const at = tree.labels.indexOf("Mesh");
  expect(tree.labels.slice(0, 5)).toEqual(["Appearance", "Terminal", "You", "Machines", "Mesh"]);
  expect(tree.labels.slice(at, at + 6)).toEqual(["Mesh", "  Keys", "  Names", "  Access", "  Connections", "Sharing"]);
  for (const left of tree.nestedGlyphLeft) near(left, tree.meshLabelLeft!, "nested glyph under the parent's name");
  for (const [g, t] of tree.mids) near(g!, t!, "sidebar glyph/label centre");
  await page.evaluate(() => document.querySelector('#tree .bm-sec[data-id="view:settings"]')?.scrollIntoView({ block: "start" }));
  await page.waitForTimeout(300);
  await shot(page, "06-sidebar-nested");
  await page.locator("#sidebar-toggle").click();

  // "?" opens a preview anchored to the button: the heading, a lead, bullets, a small table, and the expand icon at the top right. A press outside
  // or Escape closes it, and the expand icon opens the whole page as a window in the Docs cluster.
  const questionMark = page.locator('[data-window-id="s-mesh-keys"] .ui-window-action[data-action="docs"]');
  await questionMark.click();
  const preview = page.locator(".ui-dp-pop");
  await expect(preview).toBeVisible();
  await page.waitForTimeout(450);
  // Connection Keys is the 7-day key (D317): its quick facts come from the docs index as the docs wrote them.
  await expect(preview.locator(".ui-dp-title")).toHaveText("Connection Keys");
  await expect(preview.locator(".ui-dp-lead")).toContainText("Default every 7 days");
  await expect(preview.locator(".ui-dp-bullet")).toHaveCount(1);
  expect(await docsOnScreen(page), "the preview alone does not open the page").toBe(false);
  await expect(page.locator(".tip:visible"), "the button's tooltip does not sit over the preview it opened").toHaveCount(0);
  await checkPreview(page, "popover", "s-mesh-keys");
  await shot(page, "07-preview");
  await page.keyboard.press("Escape");
  await expect(preview).toHaveCount(0);
  expect(await page.evaluate(() => document.activeElement?.getAttribute("data-action")), "Escape puts focus back on the ?").toBe("docs");
  await questionMark.click();
  await expect(preview).toBeVisible();
  await page.mouse.click(8, 450); // a press outside
  await expect(preview).toHaveCount(0);
  await questionMark.click();
  await expect(preview).toBeVisible();
  await questionMark.click(); // the button again closes it
  await expect(preview).toHaveCount(0);
  await questionMark.click();
  await page.waitForTimeout(450);
  await preview.locator(".ui-dp-expand").click();
  await expect.poll(() => docsOnScreen(page), { timeout: 90_000 }).toBe(true);
  await expect(preview).toHaveCount(0);
  await page.waitForTimeout(1500);
  expect(await docsOnScreen(page)).toBe(true);
  await expect(page.locator('.cl[data-view="docs"] .ui-window[data-window-id="d-reference/keys"]'), "the page of the heading is the active window").toHaveAttribute("data-active", "");
  await shot(page, "07b-docs-cluster");
  await goTo(page, "canvas:settings:mesh.names");
  // A window the docs have no page for has no "?" at all, and its shortcut opens nothing: a button that leads nowhere is not offered.
  await expect(page.locator('[data-window-id="s-mesh-names"] .ui-window-action[data-action="docs"]')).toHaveCount(0);
  await page.keyboard.press("Control+Shift+Alt+Slash");
  await page.waitForTimeout(500);
  await expect(page.locator(".ui-dp-pop")).toHaveCount(0);
  await shot(page, "08-no-page-yet");

  // ⌘K goes straight to one setting: its window comes into view, the breadcrumb follows, the row is shown.
  await palette(page, "wireguard");
  const found = page.locator('.result[data-action^="canvas:settings:"]', { has: page.locator(".result-label", { hasText: /^Connection Keys$/ }) });
  await expect(found).toBeVisible();
  await shot(page, "09-palette-wireguard");
  await found.click();
  await page.waitForTimeout(1200);
  expect(await active(page)).toBe("s-mesh-keys");
  expect(await crumbs(page)).toEqual(["Settings", "Mesh", "Keys"]);
  await palette(page, "browsers stay");
  const browserRow = page.locator('.result[data-action^="canvas:settings:"]', { has: page.locator(".result-label", { hasText: /^Browsers Stay Signed In For$/ }) });
  await expect(browserRow).toBeVisible();
  await browserRow.click();
  await page.waitForTimeout(500);
  await expect(page.locator('[data-window-id="s-you-devices"] .ui-setting[data-setting="browser-session"]')).toHaveAttribute("data-found", "");
  await page.waitForTimeout(900);
  expect(await crumbs(page)).toEqual(["Settings", "You", "Devices"]);
  expect(await checkRows(page, "s-you-devices")).toBe(1);
  await shot(page, "10-you-devices");
  // The Appearance row has the Themes window (a theme holds Colour, backgrounds, windows, font and size, so one window edits all of them) and Layout.
  for (const [at, titles] of [["appearance.themes", ["UI size", "Colour", "Backgrounds", "Windows", "Fonts"]], ["appearance.layout", ["Phones", "Desktop"]]] as const) {
    await page.evaluate((target) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: `canvas:settings:${target}`, source: "keyboard" } })), at);
    await page.waitForTimeout(700);
    await expect.poll(() => page.locator(`[data-window-id="s-${at.replace(".", "-")}"] .ui-sp > section .ui-ts-title`).allTextContents()).toEqual(titles);
    if (at === "appearance.themes") await shot(page, "12-appearance-themes");
  }
  // Apps lists the keys with Revoke (asking first); Devices lists the browsers with Sign out.
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:you.apps", source: "keyboard" } })));
  await page.waitForTimeout(1200);
  expect(await crumbs(page)).toEqual(["Settings", "You", "Apps"]);
  expect(await checkRows(page, "s-you-apps")).toBe(1);
  const keys = page.locator('[data-window-id="s-you-apps"] .cl-keys .ui-sp-device');
  await expect(keys).toHaveCount(3);
  await keys.first().locator('button[aria-label^="Revoke"]').click();
  await page.waitForTimeout(500);
  await shot(page, "13-you-apps-revoke");
  await page.getByRole("button", { name: "Revoke key" }).click();
  await expect(keys).toHaveCount(2);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:you.devices", source: "keyboard" } })));
  await page.waitForTimeout(1200);
  expect(await page.locator('[data-window-id="s-you-devices"] .ui-sp-device button[aria-label^="Sign out"]').count()).toBeGreaterThan(0);
  await shot(page, "14-you-devices");
  // The old way in still lands somewhere: "About" opens its window.
  await palette(page, "about");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(1200);
  expect(await crumbs(page)).toEqual(["Settings", "About", "Version"]);
  await shot(page, "11-about");
  await context.close();
});

test("phone: a row for each component, the breadcrumb fits, rows align, \"?\" opens docs", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ ...SIZES.phone, baseURL: process.env.J92_URL ?? `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}` });
  const page = await context.newPage();
  await open(page, "&at=mesh.keys");
  expect(await crumbs(page)).toEqual(["Settings", "Mesh", "Keys"]);
  const bar = await page.locator(".cl-crumbs").evaluate((n) => { const r = n.getBoundingClientRect(); return { left: r.left, right: r.right, cx: (r.left + r.right) / 2 }; });
  expect(bar.left).toBeGreaterThanOrEqual(0);
  expect(bar.right).toBeLessThanOrEqual(393);
  expect(Math.abs(bar.cx - 196.5)).toBeLessThanOrEqual(1);
  const pills = await page.locator(".cl-crumb").evaluateAll((ns) => ns.map((n) => { const r = n.getBoundingClientRect(); return { mid: (r.top + r.bottom) / 2, h: r.height, left: r.left, right: r.right }; }));
  for (const p of pills) { near(p.mid, pills[0]!.mid, "phone breadcrumb centre line"); expect(p.h).toBeGreaterThanOrEqual(43.5); }
  for (let i = 1; i < pills.length; i++) expect(pills[i]!.left).toBeGreaterThanOrEqual(pills[i - 1]!.right - 0.5);
  // The phone has the same model as a desktop (D212): one grid, a row of windows for each component, a column for each window of the longest row; the neighbours peek in.
  const geo = await page.evaluate(() => ({ groups: document.querySelectorAll('.cl[data-view="settings"] .cl-group').length, cols: document.querySelectorAll('.cl[data-view="settings"] .cl-col').length, w: document.querySelector<HTMLElement>('[data-window-id="s-mesh-keys"]')!.getBoundingClientRect().width }));
  expect(geo.groups).toBe(1);
  expect(geo.cols).toBe(5);
  expect(geo.w).toBeGreaterThan(393 * 0.85);
  expect(await checkRows(page, "s-mesh-keys")).toBe(3);
  const touch = await page.locator('[data-window-id="s-mesh-keys"] .ui-setting-reset').first().boundingBox();
  expect(touch!.width).toBeGreaterThanOrEqual(43.5);
  expect(touch!.height).toBeGreaterThanOrEqual(43.5);
  const field = await page.locator('[data-window-id="s-mesh-keys"] .ui-setting-input').first().boundingBox();
  expect(field!.height).toBeGreaterThanOrEqual(43.5);
  // The "?" is the first button of the action group, the group obeys the alignment rules on a phone too, and the title still shows.
  const phoneGroups = await page.evaluate(measureActions, '.cl[data-view="settings"] .ui-window');
  expect(phoneGroups.length).toBe(21);
  checkGroups(phoneGroups.filter((g) => g.ids.length > 0), "docs");
  const hit = await page.locator('[data-window-id="s-mesh-keys"] .ui-window-action[data-action="docs"]').boundingBox();
  expect(hit!.width).toBeGreaterThanOrEqual(28);
  const title = await page.evaluate(() => document.querySelector('[data-window-id="s-mesh-keys"] .ui-window-host')!.getBoundingClientRect().width);
  expect(title).toBeGreaterThan(20);
  await shot(page, "p01-mesh-keys");
  const row = page.locator('[data-window-id="s-mesh-keys"] .ui-setting[data-setting="machine-identity"]');
  await row.locator(".ui-setting-input").fill("0");
  await expect(row).toHaveAttribute("data-invalid", "");
  await page.waitForTimeout(400);
  await shot(page, "p02-refusal");
  await row.locator(".ui-setting-input").press("Escape");
  // On a phone "?" lifts a bottom sheet with the same content; a drag down or a press on the dim area closes it; its expand icon opens the page.
  const phoneQuestion = page.locator('[data-window-id="s-mesh-keys"] .ui-window-action[data-action="docs"]');
  await phoneQuestion.click();
  await expect(page.locator(".ui-sheet")).toBeVisible();
  await page.waitForTimeout(500);
  await expect(page.locator(".ui-sheet .ui-dp-title")).toHaveText("Connection Keys");
  await checkPreview(page, "sheet");
  await shot(page, "p03-preview");
  await page.evaluate(() => {
    const grab = document.querySelector<HTMLElement>(".ui-sheet-grab")!, r = grab.getBoundingClientRect(), x = r.left + r.width / 2;
    const fire = (type: string, y: number, t: number) => grab.dispatchEvent(new PointerEvent(type, { pointerId: 7, pointerType: "touch", clientX: x, clientY: y, bubbles: true, cancelable: true }));
    fire("pointerdown", r.top + 8, 0);
    for (let i = 1; i <= 6; i++) fire("pointermove", r.top + 8 + i * 30, i * 16);
    fire("pointerup", r.top + 8 + 180, 120);
  });
  await expect(page.locator(".ui-sheet")).toHaveCount(0, { timeout: 5000 });
  await phoneQuestion.click();
  await expect(page.locator(".ui-sheet")).toBeVisible();
  await page.waitForTimeout(450);
  await page.mouse.click(196, 60); // the dim area above the sheet
  await expect(page.locator(".ui-sheet")).toHaveCount(0, { timeout: 5000 });
  await phoneQuestion.click();
  await page.waitForTimeout(450);
  await page.locator(".ui-sheet .ui-dp-expand").click();
  await expect.poll(() => docsOnScreen(page), { timeout: 90_000 }).toBe(true);
  await expect(page.locator(".ui-sheet")).toHaveCount(0);
  await page.waitForTimeout(1500);
  await shot(page, "p03b-docs");
  await palette(page, "machine names");
  await shot(page, "p04-palette");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(1500);
  expect(await crumbs(page)).toEqual(["Settings", "Mesh", "Names"]);
  await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(700);
  await page.evaluate(() => document.querySelector('#tree .bm-sec[data-id="view:settings"]')?.scrollIntoView({ block: "start" }));
  await page.waitForTimeout(300);
  await shot(page, "p05-sidebar");
  await context.close();
});

const baseURL = (): string => process.env.J92_URL ?? `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`;
const ids = (page: Page, selector: string): Promise<string[]> => page.evaluate((sel) => [...document.querySelectorAll<HTMLElement>(sel)].map((n) => n.dataset.windowId ?? ""), selector);
const TERMINAL = '.cl[data-view="console"] .ui-window[data-kind="terminal"]';
/** The first terminal window that is not a "No access" card, and the card. */
const terminalId = (page: Page): Promise<string> => page.evaluate((sel) => [...document.querySelectorAll<HTMLElement>(sel)].find((w) => !w.querySelector(".cl-noaccess"))!.dataset.windowId!, TERMINAL);
const cardId = (page: Page): Promise<string> => page.evaluate((sel) => [...document.querySelectorAll<HTMLElement>(sel)].find((w) => w.querySelector(".cl-noaccess"))!.dataset.windowId!, TERMINAL);
const flyConsole = async (page: Page): Promise<void> => { await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console")); await page.waitForTimeout(1500); };
/** A docs window is on screen: a page that is already open is brought into view, not made active. */
const docsOnScreen = (page: Page): Promise<boolean> => page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="docs"] .ui-window')].some((w) => { const r = w.getBoundingClientRect(); return r.left >= -1 && r.right <= innerWidth + 1 && r.top >= 0 && r.width > 100; }));
/** Opens the add-host dialog from ⌘K and returns its window's id. */
async function openAddHost(page: Page): Promise<string> {
  const button = page.locator('.ui-window[data-kind="flow"] .ui-window-action[data-action="docs"]');
  // The dialog's code loads on demand; on a busy machine the first try can take long, so try once more before failing.
  for (const attempt of [1, 2]) {
    await palette(page, "add host");
    await page.locator(".result .result-label", { hasText: /add host/i }).first().click();
    if (await button.count().then((n) => n === 1, () => false) || await button.first().waitFor({ timeout: attempt === 1 ? 45_000 : 90_000 }).then(() => true, () => false)) break;
  }
  await expect(button).toHaveCount(1);
  await page.waitForTimeout(1500);
  return page.evaluate(() => document.querySelector<HTMLElement>('.ui-window[data-kind="flow"]:has(.ui-window-action[data-action="docs"])')!.dataset.windowId!);
}

test("\"?\": the first button on a terminal, the add-host dialog and an error card; its shortcut, its panel row and its ⌘K row", async ({ browser }) => {
  test.setTimeout(300_000);
  const context = await browser.newContext({ ...SIZES.desktop, baseURL: baseURL() });
  const page = await context.newPage();
  await open(page, "&at=mesh.keys&noaccess=1");
  const settingsInset = checkGroups(await page.evaluate(measureActions, '[data-window-id="s-mesh-keys"]'), "docs");

  // The shortcut opens the preview for the focused window (Ctrl+Shift+Alt+/ here, ⌥⌘/ on a Mac), with focus on the expand icon; pressing it again closes
  // it, Escape closes it and puts focus back on the "?", and Enter on the expand icon opens the page in the Docs cluster.
  await page.keyboard.press("Control+Shift+Alt+Slash");
  await expect(page.locator(".ui-dp-pop")).toBeVisible();
  await page.waitForTimeout(450);
  expect(await page.evaluate(() => document.activeElement?.className ?? ""), "a keyboard open puts focus on the expand icon").toContain("ui-dp-expand");
  await page.keyboard.press("Control+Shift+Alt+Slash");
  await expect(page.locator(".ui-dp-pop")).toHaveCount(0);
  await page.keyboard.press("Control+Shift+Alt+Slash");
  await expect(page.locator(".ui-dp-pop")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator(".ui-dp-pop")).toHaveCount(0);
  expect(await page.evaluate(() => document.activeElement?.getAttribute("data-action"))).toBe("docs");
  await page.keyboard.press("Control+Shift+Alt+Slash");
  await expect(page.locator(".ui-dp-pop")).toBeVisible();
  await page.waitForTimeout(450);
  await page.keyboard.press("Enter");
  await expect.poll(() => docsOnScreen(page), { timeout: 90_000 }).toBe(true);
  await expect(page.locator(".ui-dp-pop")).toHaveCount(0);
  await page.waitForTimeout(1200);
  expect(await page.locator('.cl[data-view="docs"] .ui-window-action[data-action="docs"]').count()).toBe(0); // a docs page has no "?" of its own
  // The shortcuts panel lists it, with its keys.
  await goTo(page, "canvas:settings:mesh.keys");
  await page.keyboard.press("Control+Shift+Slash"); // the panel's own chord, which works wherever the focus is
  const panelRows = page.locator(".ui-shortcuts-row", { has: page.locator(".ui-shortcuts-label", { hasText: /^Read about this window$/ }) });
  await expect(panelRows).toHaveCount(1);
  await expect(panelRows.first()).toBeVisible();
  const caps = await panelRows.first().locator(".ui-shortcuts-keys").evaluate((n) => [...n.querySelectorAll("kbd")].map((k) => k.textContent));
  expect(caps).toEqual(["Ctrl", "Shift", "Alt", "/"]); // no Mac glyph on a PC (TASTE: platform conventions)
  await page.waitForTimeout(700); // the panel has finished morphing open: captures are taken at rest
  await shot(page, "15-shortcuts-panel");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(400);
  // ⌘K lists it for the focused window, with the keys in its hint.
  await palette(page, "read about");
  const rowK = page.locator(".result", { has: page.locator(".result-label", { hasText: /^Read about this window$/ }) });
  await expect(rowK).toBeVisible();
  await expect(rowK).toContainText("Ctrl+Shift+Alt+/");
  await page.keyboard.press("Escape");

  // A terminal: "?" comes before the splits, the sessions button and Close, on the same rules.
  await flyConsole(page);
  const terminal = await terminalId(page);
  const terminals = await page.evaluate(measureActions, `[data-window-id="${terminal}"]`);
  expect(terminals[0]!.ids).toEqual(["docs", "split-right", "split-down", "sessions", "close"]);
  checkGroups(terminals, "docs", settingsInset);
  // An error card ("No access"): "?" and Close.
  const card = await cardId(page);
  await expect(page.locator(`[data-window-id="${card}"] .cl-noaccess`)).toBeVisible();
  const cards = await page.evaluate(measureActions, `[data-window-id="${card}"]`);
  expect(cards[0]!.ids).toEqual(["docs", "close"]);
  checkGroups(cards, "docs", settingsInset);
  await goTo(page, `canvas:win:${card}`); // bring the card into view, as a person would before pressing its button
  await page.locator(`[data-window-id="${card}"] .ui-window-action[data-action="docs"]`).click({ timeout: 15_000 });
  await expect(page.locator(".ui-dp-pop")).toBeVisible();
  await page.waitForTimeout(450);
  await expect(page.locator(".ui-dp-pop .ui-dp-title")).toHaveText("All keys at a glance");
  await checkPreview(page, "popover", card);
  await page.locator(".ui-dp-pop .ui-dp-expand").click();
  await page.waitForTimeout(1500);
  expect(await docsOnScreen(page)).toBe(true);
  // The add-host dialog: "?" and its own controls; its preview is the host join token, and its expand icon opens that heading.
  await goTo(page, `canvas:win:${terminal}`);
  const dialog = await openAddHost(page);
  checkGroups(await page.evaluate(measureActions, `[data-window-id="${dialog}"]`), "docs", settingsInset);
  await page.locator(`[data-window-id="${dialog}"] .ui-window-action[data-action="docs"]`).click({ timeout: 15_000 });
  await expect(page.locator(".ui-dp-pop")).toBeVisible();
  await page.waitForTimeout(450);
  await expect(page.locator(".ui-dp-pop .ui-dp-title")).toHaveText("Host join token");
  await checkPreview(page, "popover", dialog);
  await page.locator(".ui-dp-pop .ui-dp-expand").click();
  await page.waitForTimeout(1500);
  expect(await docsOnScreen(page)).toBe(true);
  await context.close();
});

test("close-ups of the action group at DPR 2 and 3 (desktop and phone), alignment measured at each", async ({ browser }) => {
  test.setTimeout(480_000);
  for (const [tag, size, dsf] of [["d2", SIZES.desktop, 2], ["d3", SIZES.desktop, 3], ["p2", SIZES.phone, 2], ["p3", SIZES.phone, 3]] as const) {
    const context = await browser.newContext({ ...size, deviceScaleFactor: dsf, baseURL: baseURL() });
    const page = await context.newPage();
    await open(page, "&at=mesh.keys&noaccess=1");
    const closeUp = async (name: string, windowId: string): Promise<void> => {
      if (!SHOTS) return;
      mkdirSync(SHOTS, { recursive: true });
      const head = (await page.locator(`[data-window-id="${windowId}"] .ui-window-head`).boundingBox())!;
      const group = (await page.locator(`[data-window-id="${windowId}"] .ui-window-actions`).boundingBox())!;
      const fit = (b: { x: number; y: number; width: number; height: number }, pad: number) => { const x = Math.max(0, b.x - pad), y = Math.max(0, b.y - pad); return { x, y, width: Math.min(size.viewport.width - x, b.width + 2 * pad), height: b.height + 2 * pad }; };
      await page.screenshot({ path: `${SHOTS}/closeup-${tag}-${name}-header.png`, clip: fit(head, 8) });
      await page.screenshot({ path: `${SHOTS}/closeup-${tag}-${name}-actions.png`, clip: fit(group, 10) });
    };
    const checkOne = async (windowId: string, expected: string[] | undefined): Promise<void> => {
      const m = await page.evaluate(measureActions, `[data-window-id="${windowId}"]`);
      if (expected && size === SIZES.desktop) expect(m[0]!.ids).toEqual(expected);
      checkGroups(m, "docs");
    };
    // The preview itself: a popover on a desktop, a bottom sheet on a phone, with its alignment measured at this pixel ratio.
    const kind = size === SIZES.phone ? "sheet" : "popover";
    const previewShot = async (name: string, windowId: string): Promise<void> => {
      await page.locator(`[data-window-id="${windowId}"] .ui-window-action[data-action="docs"]`).click({ timeout: 15_000 });
      // The preview's code loads on the first press (D188): wait for it, not for a fixed time.
      await expect(page.locator(kind === "popover" ? ".ui-dp-pop" : ".ui-sheet")).toBeVisible({ timeout: 15_000 });
      await page.waitForTimeout(550);
      await checkPreview(page, kind, windowId);
      expect(await page.locator(".tip:visible").count(), `no tooltip over the ${name} preview`).toBe(0);
      if (SHOTS) {
        mkdirSync(SHOTS, { recursive: true });
        const b = (await page.locator(kind === "popover" ? ".ui-dp-pop" : ".ui-sheet").boundingBox())!;
        const head = (await page.locator(`[data-window-id="${windowId}"] .ui-window-head`).boundingBox())!;
        const vw = size.viewport.width;
        const clip = kind === "sheet"
          ? { x: 0, y: Math.max(0, b.y - 14), width: vw, height: size.viewport.height - Math.max(0, b.y - 14) }
          : (() => { const x = Math.max(0, Math.min(b.x, head.x) - 12), y = Math.max(0, head.y - 12); return { x, y, width: Math.min(vw - x, Math.max(b.x + b.width, head.x + head.width) + 12 - x), height: b.y + b.height + 12 - y }; })();
        await page.screenshot({ path: `${SHOTS}/closeup-${tag}-preview-${name}.png`, clip });
      }
      await page.keyboard.press("Escape");
      await page.waitForTimeout(350);
    };
    await closeUp("settings", "s-mesh-keys");
    await previewShot("settings", "s-mesh-keys");
    expect(await page.locator(".tip:visible").count(), "no tooltip over a preview").toBe(0);
    await checkOne("s-mesh-keys", ["docs"]);
    await flyConsole(page);
    const terminal = await terminalId(page);
    await goTo(page, `canvas:win:${terminal}`);
    await closeUp("terminal", terminal);
    await previewShot("terminal", terminal);
    await checkOne(terminal, ["docs", "split-right", "split-down", "sessions", "close"]);
    const card = await cardId(page);
    await goTo(page, `canvas:win:${card}`);
    await closeUp("no-access", card);
    await previewShot("no-access", card);
    await checkOne(card, ["docs", "close"]);
    await goTo(page, `canvas:win:${terminal}`);
    const dialog = await openAddHost(page);
    await closeUp("add-host", dialog);
    await previewShot("add-host", dialog);
    await checkOne(dialog, undefined);
    await context.close();
  }
});


/** Samples a panel that grows out of the top pill on every animation frame while `run` opens it: where the panel is and how faded the breadcrumb is. */
async function recordMorph(page: Page, selector: string, run: () => Promise<void>, ms = 900, from = ".cl-crumbs", faded = ".cl-crumbs"): Promise<Array<{ p: { cx: number; top: number; w: number } | null; c: { cx: number; top: number }; o: number }>> {
  await page.evaluate(([sel, span, anchor, fade]) => {
    const frames: unknown[] = [];
    (window as unknown as { __morph: unknown[] }).__morph = frames;
    const end = performance.now() + Number(span);
    const tick = (): void => {
      const panel = document.querySelector(String(sel)), crumbs = document.querySelector(String(anchor))!;
      const pr = panel?.getBoundingClientRect(), cr = crumbs.getBoundingClientRect();
      frames.push({ p: pr ? { cx: (pr.left + pr.right) / 2, top: pr.top, w: pr.width } : null, c: { cx: (cr.left + cr.right) / 2, top: cr.top }, o: Number(getComputedStyle(document.querySelector(String(fade))!).opacity) });
      if (performance.now() < end) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [selector, ms, from, faded] as const);
  await run();
  await page.waitForTimeout(ms + 150);
  return page.evaluate(() => (window as unknown as { __morph: Array<{ p: { cx: number; top: number; w: number } | null; c: { cx: number; top: number }; o: number }> }).__morph);
}

for (const [tag, size] of [["desktop", SIZES.desktop], ["phone", SIZES.phone]] as const) {
  test(`${tag}: the breadcrumb is the main pill's size, centred, and what grows out of the top pill grows out of it, in place`, async ({ browser }) => {
    test.setTimeout(240_000);
    const context = await browser.newContext({ ...size, baseURL: baseURL() });
    const page = await context.newPage();
    const centre = size.viewport.width / 2;
    await open(page, "&at=appearance.themes");
    expect(await crumbs(page)).toEqual(["Settings", "Appearance", "Themes"]);
    // The breadcrumb as measured, and the main pill (the capsule in Console) as measured, by the same function.
    const measure = (sel: string) => page.evaluate((selector) => {
      const n = document.querySelector<HTMLElement>(selector)!, s = getComputedStyle(n), r = n.getBoundingClientRect();
      return { h: r.height, font: parseFloat(s.fontSize), weight: s.fontWeight, color: s.color };
    }, sel);
    const pillsNow = await page.evaluate(() => {
      const rects = [...document.querySelectorAll<HTMLElement>(".cl-crumbs > *")].map((n) => n.getBoundingClientRect());
      const box = document.querySelector(".cl-crumbs")!.getBoundingClientRect(), ghost = document.querySelector("#capsule")!.getBoundingClientRect();
      return { left: Math.min(...rects.map((r) => r.left)), right: Math.max(...rects.map((r) => r.right)), top: Math.min(...rects.map((r) => r.top)), bottom: Math.max(...rects.map((r) => r.bottom)), box: { left: box.left, right: box.right, top: box.top, bottom: box.bottom }, ghost: { left: ghost.left, right: ghost.right, top: ghost.top, bottom: ghost.bottom } };
    });
    // Centred on the screen's centre line, and the invisible capsule has exactly the breadcrumb's rectangle.
    expect(Math.abs((pillsNow.left + pillsNow.right) / 2 - centre)).toBeLessThanOrEqual(1);
    for (const k of ["left", "right", "top", "bottom"] as const) near(pillsNow.ghost[k], pillsNow.box[k], `the ghost capsule's ${k} is the breadcrumb's`);
    const crumb = await measure('.cl-crumb[data-level="row"]'), name = await measure('.cl-crumb[data-level="row"] .cl-crumb-name');
    const icon = await page.evaluate(() => document.querySelector<HTMLElement>(".cl-crumb-icon")!.getBoundingClientRect().width);
    const ancestors = await page.locator(".cl-crumb .cl-crumb-name").evaluateAll((ns) => ns.map((n) => getComputedStyle(n).color));
    await flyConsole(page);
    const main = await measure("#capsule"), mainName = await measure("#capsule-host");
    const mainIcon = await page.evaluate(() => document.querySelector<HTMLElement>("#capsule-os")!.getBoundingClientRect().width);
    near(crumb.h, main.h, "breadcrumb pill height is the main pill's");
    expect(crumb.font).toBeGreaterThanOrEqual(main.font - 0.01);
    expect(crumb.font).toBeLessThanOrEqual(main.font * 1.1);
    expect(name.weight).toBe(mainName.weight);
    near(icon, mainIcon, "breadcrumb icon is the main pill's icon");
    for (const colour of ancestors) expect(colour, "every name in the breadcrumb is full colour, like the main pill").toBe(mainName.color);
    await shot(page, `${tag === "desktop" ? "" : "p"}16-main-pill`);
    await goTo(page, "canvas:settings:appearance.themes");
    await page.waitForTimeout(500);
    await shot(page, `${tag === "desktop" ? "" : "p"}17-breadcrumb`);

    // The views menu: pressing Settings grows the list out of that pill, centred on it (shifted only as far as the screen's inset needs), never at the top left.
    const frames = await recordMorph(page, ".cl-viewlist", async () => { await page.locator('.cl-crumb[data-level="view"]').click(); }, 900, '.cl-crumb[data-level="view"]', '.cl-crumb[data-level="group"]');
    const withPanel = frames.filter((f) => f.p);
    expect(withPanel.length).toBeGreaterThan(8);
    for (const f of withPanel) {
      const half = f.p!.w / 2, wanted = Math.max(12 + half, Math.min(f.c.cx, size.viewport.width - 12 - half));
      near(f.p!.cx, wanted, "the list is centred on the Settings pill (or at the screen's inset)"); near(f.p!.top, f.c.top, "the list starts at the pill's top");
    }
    expect(frames.at(-1)!.o, "the rest of the breadcrumb has faded while the list is open").toBe(0);
    await shot(page, `${tag === "desktop" ? "" : "p"}18-views-open`);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(900);
    // Closed again: the breadcrumb is fully visible and takes presses (what the morph wrote on the capsule is not left as a fade).
    expect(await page.evaluate(() => { const c = getComputedStyle(document.querySelector(".cl-crumbs")!); return { opacity: c.opacity, events: c.pointerEvents, expanded: document.querySelector("#capsule")!.hasAttribute("aria-expanded") }; })).toEqual({ opacity: "1", events: "auto", expanded: false });
    // Choosing Settings in the list keeps the breadcrumb where it is.
    await page.locator('.cl-crumb[data-level="view"]').click();
    await page.waitForTimeout(700);
    await page.locator('.cl-viewrow[data-view="settings"]').click({ timeout: 15_000 });
    await page.waitForTimeout(1200);
    // Choosing Settings flies to the view's first stop, so the row in view is Theme, not the window that was focused last (D323).
    expect(await crumbs(page)).toEqual(["Settings", "Appearance", "Themes"]);
    const after = await page.evaluate(() => { const r = document.querySelector(".cl-crumbs")!.getBoundingClientRect(); return { cx: (r.left + r.right) / 2, top: r.top, opacity: getComputedStyle(document.querySelector(".cl-crumbs")!).opacity }; });
    near(after.cx, centre, "the breadcrumb is still on the centre line after choosing Settings");
    expect(after.opacity).toBe("1");

    // The shortcuts panel is made from the same pill, so it opens from the breadcrumb too.
    if (tag === "desktop") {
      const panelFrames = await recordMorph(page, ".ui-shortcuts", async () => { await page.keyboard.press("Control+Shift+Slash"); });
      for (const f of panelFrames.filter((x) => x.p)) { near(f.p!.cx, f.c.cx, "the shortcuts panel is centred on the breadcrumb"); near(f.p!.top, f.c.top, "the shortcuts panel starts at the breadcrumb's top"); }
      await shot(page, "19-shortcuts-from-breadcrumb");
      await page.keyboard.press("Escape");
    }
    await context.close();
  });
}

test("close-ups of the breadcrumb beside the main pill at DPR 2 and 3 (desktop and phone)", async ({ browser }) => {
  test.setTimeout(300_000);
  if (!SHOTS) return;
  for (const [tag, size, dsf] of [["d2", SIZES.desktop, 2], ["d3", SIZES.desktop, 3], ["p2", SIZES.phone, 2], ["p3", SIZES.phone, 3]] as const) {
    const context = await browser.newContext({ ...size, deviceScaleFactor: dsf, baseURL: baseURL() });
    const page = await context.newPage();
    await open(page, "&at=appearance.themes");
    mkdirSync(SHOTS, { recursive: true });
    const strip = async (name: string, selector: string): Promise<void> => {
      const b = (await page.locator(selector).first().boundingBox())!;
      const x = Math.max(0, b.x - 10), y = Math.max(0, b.y - 10);
      await page.screenshot({ path: `${SHOTS}/closeup-${tag}-${name}.png`, clip: { x, y, width: Math.min(size.viewport.width - x, b.width + 20), height: b.height + 20 } });
    };
    await strip("breadcrumb", ".cl-crumbs");
    // The morph, frame by frame: the breadcrumb at rest, then 60, 140 and 320 ms after Settings is pressed.
    await page.locator('.cl-crumb[data-level="view"]').click();
    for (const [i, wait] of [60, 80, 180].entries()) { await page.waitForTimeout(wait); await page.screenshot({ path: `${SHOTS}/morph-${tag}-${i + 1}.png`, clip: { x: 0, y: 0, width: size.viewport.width, height: 360 } }); }
    await page.waitForTimeout(500);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(700);
    await flyConsole(page);
    await strip("main-pill", "#capsule");
    await context.close();
  }
});

/** Self-contained (it runs in the page): every control of one window with the boxes that could clip it, and, when `focus` is set, the focus ring it shows. */
function measureEdges([id, focus]: readonly [string, boolean]) {
  const w = document.querySelector<HTMLElement>(`[data-window-id="${id}"]`)!;
  const head = w.querySelector<HTMLElement>(".ui-window-head")!;
  const box = (r: DOMRect) => ({ left: r.left, right: r.right, top: r.top, bottom: r.bottom });
  const controls = [...w.querySelectorAll<HTMLElement>("button, input, select, textarea, [role=tab], [role=switch], .ui-window-pill")]
    .filter((c) => { const r = c.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(c).visibility !== "hidden"; })
    // The strip of theme cards scrolls sideways by design: a card past its edge is reached by scrolling or by Tab, which brings it into view, so it is not "cut".
    .filter((c) => !c.closest(".ui-theme-strip"));
  return {
    window: box(w.getBoundingClientRect()),
    controls: controls.map((c) => {
      // Whatever between the control and its window cuts what sticks out of it: the window itself and any scroller or clipping box.
      const clips: Array<ReturnType<typeof box> & { y: boolean }> = [];
      for (let n: HTMLElement | null = c.parentElement; n; n = n.parentElement) {
        const cs = getComputedStyle(n);
        if (n === w || cs.overflowX !== "visible") clips.push({ ...box(n.getBoundingClientRect()), y: n === w || cs.overflowY !== "visible" });
        if (n === w) break;
      }
      let ring = 0;
      if (focus) {
        c.focus({ preventScroll: true });
        const cs = getComputedStyle(c);
        ring = cs.outlineStyle !== "none" ? (parseFloat(cs.outlineWidth) || 0) + (parseFloat(cs.outlineOffset) || 0) : 0;
        c.blur();
      }
      return { name: c.getAttribute("aria-label") ?? c.dataset.action ?? c.className.split(" ")[0] ?? c.tagName, inHead: head.contains(c), rect: box(c.getBoundingClientRect()), clips, ring };
    }),
  };
}

const flyTo = async (page: Page, id: string): Promise<void> => {
  const row = ROWS.find((r) => id.startsWith(`s-${r}-`))!;
  await page.evaluate((a) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: a, source: "keyboard" } })), `canvas:settings:${row}.${id.slice(`s-${row}-`.length)}`);
  await page.waitForTimeout(1000);
};

/** Nothing at a side of a window or of the screen is cut (TASTE: "Windows keep their natural width; the canvas scrolls", which means: never shrunk to fit the screen): at each size, every window is flown into
 *  view and every control's box, with its focus ring, is inside its window and inside every box that clips it, and the top bar's controls are inside the screen. */
for (const [label, size] of [["1440x900", SIZES.desktop], ["393x852", SIZES.phone], ["1024x768", { viewport: { width: 1024, height: 768 }, deviceScaleFactor: 2, isMobile: false, hasTouch: false }]] as const) {
  test(`no side is clipped at ${label}: header and body controls, focus rings and the top bar`, async ({ browser }) => {
    test.setTimeout(300_000);
    const context = await browser.newContext({ ...size, baseURL: baseURL() });
    const page = await context.newPage();
    await open(page, "&at=mesh.keys");
    await page.evaluate(() => { document.documentElement.dataset.focusRing = "on"; });
    const vw = size.viewport.width, vh = size.viewport.height;
    const problems: string[] = [];
    const ids = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="settings"] .ui-window')].map((n) => n.dataset.windowId!));
    expect(ids.length).toBe(21);
    let rings = 0;
    for (const id of ids) {
      await flyTo(page, id);
      const m = await page.evaluate(measureEdges, [id, true] as const);
      // The window is whole on screen (a window is never wider than the screen), so its sides are visible.
      if (m.window.left < -HALF || m.window.right > vw + HALF) problems.push(`${id} is not whole on screen: ${m.window.left.toFixed(1)}..${m.window.right.toFixed(1)} of ${vw}`);
      for (const c of m.controls) {
        const pad = c.ring;
        const inside = (outer: { left: number; right: number; top: number; bottom: number }, y: boolean): boolean =>
          c.rect.left - pad >= outer.left - HALF && c.rect.right + pad <= outer.right + HALF && (!y || (c.rect.top - pad >= outer.top - HALF && c.rect.bottom + pad <= outer.bottom + HALF));
        // The header sits inside its window on all four sides; the body scrolls up and down, so only its sides count.
        if (!inside(m.window, c.inHead)) problems.push(`${id} ${c.name} (ring ${pad}) leaves the window: ${JSON.stringify(c.rect)} in ${JSON.stringify(m.window)}`);
        for (const clip of c.clips) if (!inside(clip, c.inHead && clip.y)) problems.push(`${id} ${c.name} (ring ${pad}) is cut by a clipping box: ${JSON.stringify(c.rect)} in ${JSON.stringify(clip)}`);
        if (c.inHead && c.ring > 0) rings++;
      }
    }
    expect(rings, "the focus ring was measured on the header controls").toBeGreaterThan(ids.length);
    // The top bar: the controls and the breadcrumb pills are whole inside the screen, rings included.
    const top = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>("header.top button, header.top .cl-crumb, .cl-mockup, .cl-crumbs")].filter((n) => { const r = n.getBoundingClientRect(); return r.width > 0 && getComputedStyle(n).visibility !== "hidden"; }).map((n) => {
      const r = n.getBoundingClientRect();
      n.focus({ preventScroll: true });
      const f = getComputedStyle(n), ring = f.outlineStyle !== "none" ? (parseFloat(f.outlineWidth) || 0) + (parseFloat(f.outlineOffset) || 0) : 0;
      n.blur();
      return { name: n.getAttribute("aria-label") ?? n.className.split(" ")[0] ?? n.tagName, left: r.left, right: r.right, top: r.top, bottom: r.bottom, ring };
    }));
    expect(top.length).toBeGreaterThan(3);
    for (const t of top) if (t.left - t.ring < -HALF || t.right + t.ring > vw + HALF || t.top - t.ring < -HALF || t.bottom + t.ring > vh + HALF) problems.push(`top bar ${t.name} (ring ${t.ring}) leaves the screen: ${t.left.toFixed(1)}..${t.right.toFixed(1)} of ${vw}`);
    expect(problems, problems.join("\n")).toEqual([]);

    if (SHOTS) {
      // Close-ups of both edges: the right edge of a window (its action group), the left edge of a window at the screen's left, and the top bar's right edge.
      const tag = `${size.deviceScaleFactor}x-${label}`;
      await flyTo(page, "s-mesh-keys");
      const w = await page.evaluate(measureEdges, ["s-mesh-keys", false] as const);
      const clip = (x: number, y: number, width: number, height: number) => ({ x: Math.max(0, x), y: Math.max(0, y), width: Math.min(width, vw - Math.max(0, x)), height: Math.min(height, vh - Math.max(0, y)) });
      mkdirSync(SHOTS, { recursive: true });
      await page.screenshot({ path: `${SHOTS}/edge-${tag}-window-right.png`, clip: clip(w.window.right - 260, w.window.top - 6, 266, 150) });
      await page.screenshot({ path: `${SHOTS}/edge-${tag}-window-left.png`, clip: clip(Math.max(0, w.window.left - 6), w.window.top - 6, 266, 150) });
      await page.screenshot({ path: `${SHOTS}/edge-${tag}-topbar-right.png`, clip: clip(vw - 300, 0, 300, 84) });
      await page.screenshot({ path: `${SHOTS}/edge-${tag}-topbar-left.png`, clip: clip(0, 0, 300, 84) });
      await page.screenshot({ path: `${SHOTS}/edge-${tag}-screen.png` });
    }
    await context.close();
  });
}

/** An anchored popover follows its anchor (TASTE: "Anchored popovers move with their anchor"): the "?" preview is opened, the canvas is panned, and on every frame
 *  its offset from the "?" is the same within 0.5 px; it closes once the "?" has left the screen. */
test("the \"?\" preview keeps its place against its button while the canvas pans, and closes when the button leaves the screen", async ({ browser }) => {
  test.setTimeout(120_000);
  const context = await browser.newContext({ ...SIZES.desktop, baseURL: baseURL() });
  const page = await context.newPage();
  await open(page, "&at=mesh.keys");
  const button = page.locator('[data-window-id="s-mesh-keys"] .ui-window-action[data-action="docs"]');
  await button.click();
  await expect(page.locator(".ui-dp-pop")).toBeVisible();
  await page.waitForTimeout(500);

  // Every frame of a pan: where the popover and the button are. `step(t)` moves the camera for t in 0..1.
  const record = (frames: number, dx: number) => page.evaluate(async ([n, d]) => {
    const probe = (window as unknown as { __tracerClusters: { camera(): { cx: number; cy: number; z: number }; setCamera(x: number, y: number, z: number): void } }).__tracerClusters;
    const from = probe.camera(), out: Array<{ dx: number; dy: number; ax: number }> = [];
    for (let i = 0; i <= n; i++) {
      probe.setCamera(from.cx + (d * i) / n, from.cy, from.z);
      await new Promise<void>((r) => requestAnimationFrame(() => r()));
      const pop = document.querySelector(".ui-dp-pop")?.getBoundingClientRect(), a = document.querySelector('[data-window-id="s-mesh-keys"] .ui-window-action[data-action="docs"]')?.getBoundingClientRect();
      if (!pop || !a) { out.push({ dx: NaN, dy: NaN, ax: NaN }); continue; }
      out.push({ dx: pop.left - a.left, dy: pop.top - a.top, ax: a.left });
    }
    return out;
  }, [frames, dx] as const);

  const there = await record(40, 300);
  const back = await record(40, -300);
  for (const f of [...there, ...back]) {
    expect(Number.isNaN(f.dx), "the popover stays open while its button is on screen").toBe(false);
    near(f.dx, there[0]!.dx, "popover offset from its button (x)"); near(f.dy, there[0]!.dy, "popover offset from its button (y)");
  }
  expect(Math.abs(there.at(-1)!.ax - there[0]!.ax), "the pan really moved the button").toBeGreaterThan(250);

  // A wheel pan, the way a trackpad does it: the offset holds on every frame.
  await page.mouse.move(420, 600);
  const seen: Array<{ dx: number; dy: number; ax: number }> = [];
  await page.evaluate(() => {
    const w = window as unknown as { __frames: Array<{ dx: number; dy: number; ax: number }>; __stop: boolean };
    w.__frames = []; w.__stop = false;
    const tick = (): void => {
      const pop = document.querySelector(".ui-dp-pop")?.getBoundingClientRect(), a = document.querySelector('[data-window-id="s-mesh-keys"] .ui-window-action[data-action="docs"]')?.getBoundingClientRect();
      if (pop && a) w.__frames.push({ dx: pop.left - a.left, dy: pop.top - a.top, ax: a.left });
      if (!w.__stop) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  for (let i = 0; i < 6; i++) { await page.mouse.wheel(40, 0); await page.waitForTimeout(40); }
  await page.waitForTimeout(300);
  seen.push(...await page.evaluate(() => { const w = window as unknown as { __frames: Array<{ dx: number; dy: number; ax: number }>; __stop: boolean }; w.__stop = true; return w.__frames; }));
  expect(seen.length).toBeGreaterThan(5);
  for (const f of seen) { near(f.dx, there[0]!.dx, "popover offset during a wheel pan (x)"); near(f.dy, there[0]!.dy, "popover offset during a wheel pan (y)"); }
  const moved = Math.abs(seen.at(-1)!.ax - seen[0]!.ax);
  expect(moved, "the wheel moved the canvas").toBeGreaterThan(20);

  if (SHOTS) {
    // A frame strip: the same preview at four places of one pan, cropped around the button.
    mkdirSync(SHOTS, { recursive: true });
    for (let i = 0; i < 4; i++) {
      await page.evaluate((k) => { const p = (window as unknown as { __tracerClusters: { camera(): { cx: number; cy: number; z: number }; setCamera(x: number, y: number, z: number): void } }).__tracerClusters; const c = p.camera(); p.setCamera(c.cx + (k === 0 ? 0 : 140), c.cy, c.z); }, i);
      await page.waitForTimeout(250);
      const a = (await button.boundingBox())!;
      await page.screenshot({ path: `${SHOTS}/pan-strip-${i + 1}.png`, clip: { x: Math.max(0, a.x - 380), y: Math.max(0, a.y - 30), width: 520, height: 430 } });
    }
  }

  // Past the screen's edge the button is gone, and the preview with it.
  await page.evaluate(() => { const p = (window as unknown as { __tracerClusters: { camera(): { cx: number; cy: number; z: number }; setCamera(x: number, y: number, z: number): void } }).__tracerClusters; const c = p.camera(); p.setCamera(c.cx + 2600, c.cy, c.z); });
  await expect(page.locator(".ui-dp-pop")).toHaveCount(0, { timeout: 3000 });
  await context.close();
});

/** A menu opened from a pill is centred on that pill (TASTE): the breadcrumb's three pills each open one, and every menu's centre is its pill's centre, unless the
 *  screen's inset holds it back. The menus still grow from their pill (the transform origin is the pill's centre). */
for (const [tag, size] of [["desktop", SIZES.desktop], ["phone", SIZES.phone]] as const) {
  test(`${tag}: every breadcrumb pill's menu is centred on its pill`, async ({ browser }) => {
    test.setTimeout(120_000);
    const context = await browser.newContext({ ...size, baseURL: baseURL() });
    const page = await context.newPage();
    await open(page, "&at=appearance.themes");
    const vw = size.viewport.width;
    for (const [level, menu, inset] of [["view", ".cl-viewlist", 12], ["row", ".cl-crumb-menu", 8], ["group", ".cl-crumb-menu", 8]] as const) {
      await page.locator(`.cl-crumb[data-level="${level}"]`).click();
      await page.waitForTimeout(900);
      const m = await page.evaluate(([pillSel, menuSel]) => {
        const pill = document.querySelector(pillSel)!.getBoundingClientRect(), node = document.querySelector<HTMLElement>(menuSel)!, r = node.getBoundingClientRect();
        return { pill: { cx: (pill.left + pill.right) / 2, left: pill.left, w: pill.width }, menu: { cx: (r.left + r.right) / 2, w: r.width, left: r.left, top: r.top }, origin: node.style.transformOrigin };
      }, [`.cl-crumb[data-level="${level}"]`, menu] as const);
      const half = m.menu.w / 2, wanted = Math.max(inset + half, Math.min(m.pill.cx, vw - inset - half));
      near(m.menu.cx, wanted, `the ${level} menu is centred on its pill (or at the screen's inset)`);
      if (level !== "view" && Math.abs(wanted - m.pill.cx) < 0.5) near(m.menu.cx, m.pill.cx, `the ${level} menu's centre is the pill's centre`);
      // It still grows from the pill: the origin of the grow is the pill's centre, in the menu's own coordinates.
      if (level !== "view") near(parseFloat(m.origin), m.pill.cx - m.menu.left, `the ${level} menu grows from the pill's centre`);
      await shot(page, `${tag === "desktop" ? "" : "p"}20-menu-${level}`);
      await page.keyboard.press("Escape");
      await page.waitForTimeout(500);
    }
    await context.close();
  });
}

test("the round Views button is gone from the top bar, and every button left in it does something", async ({ browser }) => {
  test.setTimeout(90_000);
  const context = await browser.newContext({ ...SIZES.desktop, baseURL: baseURL() });
  const page = await context.newPage();
  await open(page, "&at=mesh.keys");
  await expect(page.locator(".cl-viewsbtn")).toHaveCount(0);
  // The buttons beside the pill: canvas lock changes state, the plus opens a window.
  const lock = page.locator(".cl-snap");
  const before = await lock.getAttribute("aria-pressed");
  await lock.click();
  expect(await lock.getAttribute("aria-pressed")).not.toBe(before);
  await lock.click();
  expect(await lock.getAttribute("aria-pressed")).toBe(before);
  await context.close();
});

/** Where the windows of the Settings view are and what scrolls inside each (page.evaluate, self-contained). */
function windowBoxes() {
  return [...document.querySelectorAll<HTMLElement>('.cl[data-view="settings"] .ui-window')].map((w) => {
    const r = w.getBoundingClientRect(), pane = w.querySelector<HTMLElement>(".ui-window-body > .ui-settings-pane");
    return { id: w.dataset.windowId!, top: r.top, left: r.left, height: r.height, paneTop: pane?.scrollTop ?? 0, paneMax: pane ? pane.scrollHeight - pane.clientHeight : 0 };
  });
}
type Boxes = ReturnType<typeof windowBoxes>;
const topOf = (list: Boxes, id: string): number => list.find((w) => w.id === id)!.top;
/** Every window moved by the same offset between two readings (the canvas moved the whole view together, a row at a time), and that offset. */
function movedTogether(before: Boxes, after: Boxes, what: string): number {
  const dy = after[0]!.top - before[0]!.top;
  for (const [k, w] of after.entries()) { near(w.top - before[k]!.top, dy, `${w.id} moved by the same offset as every other window (${what})`); expect(w.paneTop, `${w.id} did not scroll its content (${what})`).toBe(before[k]!.paneTop); }
  return dy;
}

/** Settings rows move as a whole; windows scroll their own content (TASTE, D212, D275). One wheel over content that can scroll scrolls only that window's content, and no
 *  window moves. A wheel over something that cannot (a window's pill, or content at its end) moves the canvas: the whole view by one offset, onto the next row, with
 *  the snap. Sideways it moves to the next window of the row. */
test("desktop: a wheel over content scrolls that window, a wheel over nothing to scroll moves the canvas a row at a time", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ ...SIZES.desktop, baseURL: baseURL() });
  const page = await context.newPage();
  await open(page, "&at=terminal.typing");
  const clh = await page.evaluate(() => parseFloat((document.querySelector(".cl-world") as HTMLElement).style.getPropertyValue("--clh")));
  const first = await page.evaluate(windowBoxes);
  for (const w of first) near(w.height, clh, `${w.id} keeps the layout's height whatever its content`);
  const typing = first.find((w) => w.id === "s-terminal-typing")!;
  expect(typing.paneMax, "Typing's content is longer than the window: it scrolls inside").toBeGreaterThan(100);
  const centreOf = async (id: string, part: string): Promise<{ x: number; y: number }> => { const b = (await page.locator(`[data-window-id="${id}"] ${part}`).boundingBox())!; return { x: b.x + b.width / 2, y: b.y + b.height / 2 }; };

  // Over Typing's content: its own content scrolls, nothing else moves.
  const content = await centreOf("s-terminal-typing", ".ui-window-body > .ui-settings-pane");
  await page.mouse.move(content.x, content.y);
  await page.mouse.wheel(0, 200);
  await page.waitForTimeout(500);
  const scrolled = await page.evaluate(windowBoxes);
  expect(scrolled.find((w) => w.id === "s-terminal-typing")!.paneTop, "the wheel scrolled the content under it").toBeGreaterThan(50);
  for (const [k, w] of scrolled.entries()) near(w.top, first[k]!.top, `${w.id} did not move: the wheel was the content's`);
  for (const w of scrolled.filter((x) => x.id !== "s-terminal-typing")) expect(w.paneTop, `${w.id} did not scroll`).toBe(0);

  // Over the window's pill (nothing there scrolls): the canvas moves one row, every window of the view by the same offset, the next row lands where this one was.
  const pill = await centreOf("s-terminal-typing", ".ui-window-pill");
  await page.mouse.move(pill.x, pill.y);
  await page.mouse.wheel(0, 200);
  await page.waitForTimeout(1000);
  const next = await page.evaluate(windowBoxes);
  const dy = movedTogether(scrolled, next, "a row down");
  expect(dy, "the canvas moved up by a row").toBeLessThan(-clh * 0.8);
  near(topOf(next, "s-you-profile"), topOf(scrolled, "s-terminal-typing"), "the next row (You) lands where Terminal was: row to row with the snap");
  near(topOf(next, "s-you-passkeys"), topOf(next, "s-you-profile"), "and its windows are level");
  if (SHOTS) { mkdirSync(SHOTS, { recursive: true }); await page.screenshot({ path: `${SHOTS}/rows-d2-next-row.png` }); }

  // And back: up one row, the same way.
  const pill2 = await centreOf("s-you-profile", ".ui-window-pill");
  await page.mouse.move(pill2.x, pill2.y);
  await page.mouse.wheel(0, -200);
  await page.waitForTimeout(1000);
  const back = await page.evaluate(windowBoxes);
  expect(movedTogether(next, back, "a row up"), "the canvas moved down by a row").toBeGreaterThan(clh * 0.8);
  near(topOf(back, "s-terminal-typing"), topOf(scrolled, "s-terminal-typing"), "back on the first row");

  // Sideways: one window of the row, the canvas lock's stop for the next column, and again nothing shifts on its own.
  const idx = () => page.evaluate(() => (window as unknown as { __tracerClusters: { canvasLock(): { index: number } } }).__tracerClusters.canvasLock().index);
  const i0 = await idx(), l0 = await page.evaluate(windowBoxes);
  await page.mouse.move(pill.x, pill.y);
  await page.mouse.wheel(300, 0);
  await page.waitForTimeout(1000);
  expect(await idx(), "a sideways wheel moved to the next window of the row").toBe(i0 + 1);
  const l1 = await page.evaluate(windowBoxes);
  const dx = l1[0]!.left - l0[0]!.left;
  expect(dx, "the canvas moved sideways, to the next stop").toBeLessThan(-30);
  for (const [k, w] of l1.entries()) { near(w.left - l0[k]!.left, dx, `${w.id} moved sideways with the rest`); near(w.top, l0[k]!.top, `${w.id} did not move vertically`); }
  await context.close();
});

/** Jumping to a setting (⌘K) shows it: the pane of its window scrolls to it, and the canvas goes to its window. */
test("desktop: ⌘K to a setting low in a window shows that setting", async ({ browser }) => {
  test.setTimeout(120_000);
  const context = await browser.newContext({ ...SIZES.desktop, baseURL: baseURL() });
  const page = await context.newPage();
  await open(page, "&at=appearance.themes");
  const settingIds = await page.evaluate(() => [...document.querySelectorAll('[data-window-id="s-machines-new-machines"] .ui-setting')].map((n) => (n as HTMLElement).dataset.setting!));
  expect(settingIds.length).toBeGreaterThan(3);
  await goTo(page, `canvas:settings:machines.new-machines.${settingIds.at(-1)}`);
  await page.waitForTimeout(600);
  const r = await page.evaluate((id) => { const b = document.querySelector(`[data-window-id="s-machines-new-machines"] .ui-setting[data-setting="${id}"]`)!.getBoundingClientRect(); return { top: b.top, bottom: b.bottom }; }, settingIds.at(-1)!);
  expect(r.top).toBeGreaterThanOrEqual(0); expect(r.bottom).toBeLessThanOrEqual(900);
  await context.close();
});

/** On a phone, the same model (D212): one finger scrolls the content of the window under it and nothing else moves (D159); two fingers move the canvas, a row at a time up and
 *  down and a window at a time sideways, with the snap, the whole view together. */
test("phone: one finger scrolls the window under it, two fingers move the canvas a row or a window at a time", async ({ browser }) => {
  test.setTimeout(180_000);
  const context = await browser.newContext({ ...SIZES.phone, baseURL: baseURL() });
  const page = await context.newPage();
  await open(page, "&at=terminal.typing");
  const cdp = await context.newCDPSession(page);
  const clh = await page.evaluate(() => parseFloat((document.querySelector(".cl-world") as HTMLElement).style.getPropertyValue("--clh")));
  const first = await page.evaluate(windowBoxes);
  for (const w of first) near(w.height, clh, `${w.id} has the layout's height on a phone`);
  expect(first.find((w) => w.id === "s-terminal-typing")!.paneMax, "Typing is longer than the screen: it scrolls inside").toBeGreaterThan(100);

  // One finger, up: the pane of the window under it scrolls; no window moves.
  const finger = (type: "touchStart" | "touchMove" | "touchEnd", y: number) => cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x: 196, y, id: 1 }] });
  await finger("touchStart", 600);
  for (const y of [590, 570, 540, 500, 460, 420, 380]) { await finger("touchMove", y); await page.waitForTimeout(16); }
  await finger("touchEnd", 380);
  await page.waitForTimeout(1200);
  const scrolled = await page.evaluate(windowBoxes);
  expect(scrolled.find((w) => w.id === "s-terminal-typing")!.paneTop, "one finger scrolled the content of the window under it").toBeGreaterThan(100);
  for (const [k, w] of scrolled.entries()) near(w.top, first[k]!.top, `${w.id} did not move: one finger does not move the canvas`);

  // Two fingers, vertical: the canvas goes to the next row; every window of the view moves by the same offset and the next row lands where this one was.
  const two = async (type: "touchStart" | "touchMove" | "touchEnd", x: number, y: number): Promise<void> => { await cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x: x - 50, y, id: 1 }, { x: x + 50, y, id: 2 }] }); };
  await two("touchStart", 196, 600);
  for (const y of [580, 550, 520, 480]) { await two("touchMove", 196, y); await page.waitForTimeout(30); }
  await two("touchEnd", 196, 480);
  await page.waitForTimeout(1100);
  const next = await page.evaluate(windowBoxes);
  const dy = movedTogether(scrolled, next, "two fingers up");
  expect(dy, "two fingers moved the canvas by a row").toBeLessThan(-clh * 0.8);
  near(topOf(next, "s-you-profile"), topOf(scrolled, "s-terminal-typing"), "the next row (You) lands where Terminal was");

  // Two fingers, sideways: the canvas goes to the next window of the row, snapped (the canvas lock's index moves by one).
  const idx = () => page.evaluate(() => (window as unknown as { __tracerClusters: { canvasLock(): { index: number } } }).__tracerClusters.canvasLock().index);
  const i0 = await idx();
  await two("touchStart", 300, 500);
  for (const x of [280, 240, 200, 150, 100]) { await two("touchMove", x, 500); await page.waitForTimeout(30); }
  await two("touchEnd", 100, 500);
  await page.waitForTimeout(1100);
  expect(await idx(), "two fingers moved the canvas one window sideways").toBe(i0 + 1);
  if (SHOTS) { mkdirSync(SHOTS, { recursive: true }); await page.screenshot({ path: `${SHOTS}/rows-p3-next-row.png` }); }
  await context.close();
});

/** The layout's size comes from Settings -> Window Sizes, the same for a Settings window as for a terminal (TASTE: every window starts at the layout's size). */
for (const [label, size, store, expected] of [
  ["desktop, Wide", SIZES.desktop, ["tracer.window-size.desktop", "wide"], 650],
  ["desktop, Full width", SIZES.desktop, ["tracer.window-size.desktop", "full"], 1300],
  ["phone, Full width", SIZES.phone, ["tracer.window-size.phone", "full"], undefined],
] as const) {
  test(`Settings windows follow Window Sizes like a terminal does (${label})`, async ({ browser }) => {
    test.setTimeout(120_000);
    const context = await browser.newContext({ ...size, baseURL: baseURL() });
    await context.addInitScript(([k, v]) => { try { localStorage.setItem(k, v); } catch { /* none */ } }, store);
    const page = await context.newPage();
    await open(page, "&at=appearance.themes");
    const widths = await page.evaluate(() => ({ settings: [...document.querySelectorAll<HTMLElement>('.cl[data-view="settings"] .ui-window')].map((w) => w.offsetWidth), terminal: [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')].map((w) => w.offsetWidth) }));
    for (const w of widths.settings) near(w, widths.terminal[0]!, "a Settings window is as wide as a terminal window");
    // The setting is what makes it wide: the default is a third of the screen, Wide is half of it, Full width nearly all of it (times the UI size).
    if (expected) expect(widths.terminal[0]!, "and that is the width the setting says").toBeGreaterThan(expected);
    await context.close();
  });
}

/** Every pair of windows on the canvas, on every animation frame of a drag: none intersects (TASTE: windows never overlap). Self-contained (runs in the page). */
function watchOverlaps(views: string[]): void {
  const w = window as unknown as { __hits: string[]; __watch: boolean };
  w.__hits = []; w.__watch = true;
  const tick = (): void => {
    const wins = [...document.querySelectorAll<HTMLElement>(views.map((v) => `.cl[data-view="${v}"] .ui-window`).join(", "))].map((n) => {
      // What of the window is drawn: a window scrolled out of its column (below the view's frame) has a box but shows nothing there.
      const r = n.getBoundingClientRect(), col = (n.closest(".cl-group") ?? n.closest(".cl-col"))?.getBoundingClientRect();
      const left = Math.max(r.left, col?.left ?? r.left), right = Math.min(r.right, col?.right ?? r.right), top = Math.max(r.top, col?.top ?? r.top), bottom = Math.min(r.bottom, col?.bottom ?? r.bottom);
      return { id: n.dataset.windowId ?? "?", r: { left, right, top, bottom, width: right - left } };
    }).filter((x) => x.r.width > 0 && x.r.bottom > x.r.top);
    for (let i = 0; i < wins.length; i++) for (let j = i + 1; j < wins.length; j++) {
      const a = wins[i]!.r, b = wins[j]!.r;
      if (a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1) w.__hits.push(`${wins[i]!.id} / ${wins[j]!.id}`);
    }
    if (w.__watch) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

/**
 * Drags each edge of the given windows inward and outward, and returns the overlaps seen on any frame. On a phone there are no edge handles: a press and hold on a
 * window's header shows the four corner handles, and a finger drags those (window-resize.ts), so a phone drags the corners, with touch events.
 */
async function dragEdges(page: Page, ids: string[], views: string[], amount = 110, touch = false): Promise<{ hits: string[]; skipped: string[]; widths: Record<string, number[]>; changed: string[] }> {
  const viewport = page.viewportSize()!;
  const skipped: string[] = [];
  /** Windows OTHER than the dragged one whose size changed during a drag (D323: a drag changes only its own window). */
  const changed: string[] = [];
  const sizes = (): Promise<Record<string, string>> => page.evaluate(() => Object.fromEntries([...document.querySelectorAll<HTMLElement>('.cl[data-view="settings"] .ui-window')].map((n) => [n.dataset.windowId!, `${n.offsetWidth}x${n.offsetHeight}`])));
  const widths: Record<string, number[]> = {};
  const cdp = touch ? await page.context().newCDPSession(page) : undefined;
  const finger = (type: "touchStart" | "touchMove" | "touchEnd", x: number, y: number) => cdp!.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x, y, id: 1 }] });
  await page.evaluate(watchOverlaps, views);
  for (const id of ids) {
    await page.evaluate((i) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: `canvas:win:${i}`, source: "keyboard" } })), id);
    await page.waitForTimeout(1100);
    widths[id] = [];
    const before = await sizes();
    const handles = touch ? ["ne", "nw", "se", "sw"] as const : ["e", "w", "n", "s"] as const;
    for (const edge of handles) // Outward first on a desktop; inward first on a phone, where a window grown past the screen has no handle left to reach back with.
    for (const sign of (touch ? [-1, 1] : [1, -1]) as Array<1 | -1>) {
      if (touch) {
        // The blank part of the header, between the title pill and the action group: a press and hold there starts the resize mode.
        const mode = await page.evaluate((i) => document.querySelector(`[data-window-id="${i}"]`)!.getAttribute("data-resize"), id);
        if (mode !== "touch") {
          const gap = await page.evaluate((i) => { const w = document.querySelector(`[data-window-id="${i}"]`)!; const pill = w.querySelector(".ui-window-pill")!.getBoundingClientRect(), acts = w.querySelector(".ui-window-actions")!.getBoundingClientRect(), edge = acts.width > 0 ? acts.left : w.getBoundingClientRect().right - 8; return { x: (pill.right + edge) / 2, y: (pill.top + pill.bottom) / 2, room: edge - pill.right }; }, id);
          await finger("touchStart", gap.x, gap.y);
          await page.waitForTimeout(700);
          await finger("touchEnd", gap.x, gap.y);
          await page.waitForTimeout(250);
        }
      }
      const box = await page.locator(`[data-window-id="${id}"] .ui-window-resize[data-edge="${edge}"]`).boundingBox();
      // The part of the handle that is on screen: a handle at the bottom of a window as tall as the screen is half outside it.
      const x0 = Math.max(0, box?.x ?? 0), x1 = Math.min(viewport.width, (box?.x ?? 0) + (box?.width ?? 0)), y0 = Math.max(0, box?.y ?? 0), y1 = Math.min(viewport.height, (box?.y ?? 0) + (box?.height ?? 0));
      if (!box || x1 - x0 < 1 || y1 - y0 < 1) { skipped.push(`${id} ${edge} ${JSON.stringify(box)}`); continue; }
      const x = (x0 + x1) / 2, y = (y0 + y1) / 2;
      const east = edge.includes("e") ? 1 : edge.includes("w") ? -1 : 0, south = edge.includes("s") ? 1 : edge.includes("n") ? -1 : 0;
      const dx = east * sign * amount, dy = south * sign * amount;
      if (touch) {
        await finger("touchStart", x, y);
        for (let k = 1; k <= 10; k++) { await finger("touchMove", x + (dx * k) / 10, y + (dy * k) / 10); await page.waitForTimeout(25); }
        await finger("touchEnd", x, y);
      } else {
        await page.mouse.move(x, y);
        await page.mouse.down();
        for (let k = 1; k <= 10; k++) { await page.mouse.move(x + (dx * k) / 10, y + (dy * k) / 10); await page.waitForTimeout(25); }
        await page.mouse.up();
      }
      await page.waitForTimeout(450);
      widths[id]!.push(await page.evaluate((i) => document.querySelector<HTMLElement>(`[data-window-id="${i}"]`)!.offsetWidth, id));
      const after = await sizes();
      for (const [other, size] of Object.entries(after)) if (other !== id && before[other] !== size) changed.push(`${id} ${edge} ${sign}: ${other} ${before[other]} -> ${size}`);
    }
  }
  const hits = await page.evaluate(() => { const w = window as unknown as { __hits: string[]; __watch: boolean }; w.__watch = false; return [...new Set(w.__hits)]; });
  return { hits, skipped, widths, changed };
}

/** Resizing pushes or reflows the neighbours and never draws one window over another: each edge of three windows is dragged in and out, and on every frame no two
 *  window boxes intersect. The same drags on three terminal windows of the Console are the product's own check (they share the resize code). */
for (const [label, size] of [["1440x900", SIZES.desktop], ["393x852", SIZES.phone]] as const) {
  test(`dragging any edge of a window never puts it over another, at ${label}`, async ({ browser }) => {
    test.setTimeout(300_000);
    const context = await browser.newContext({ ...size, baseURL: baseURL() });
    const page = await context.newPage();
    await open(page, "&at=appearance.themes");
    // Each window is dragged on a fresh canvas, so the sizes the last one left do not hide what the next one does.
    const settings = { hits: [] as string[], skipped: [] as string[], widths: {} as Record<string, number[]>, changed: [] as string[] };
    for (const [k, id] of ["s-appearance-themes", "s-mesh-keys", "s-sharing-certificates"].entries()) {
      if (k > 0) await open(page, `&at=${id.slice(2).replace("-", ".")}`);
      const one = await dragEdges(page, [id], ["settings", "docs", "console"], size.isMobile ? 40 : 110, size.isMobile);
      settings.hits.push(...one.hits); settings.skipped.push(...one.skipped); settings.changed.push(...one.changed); Object.assign(settings.widths, one.widths);
    }
    expect(settings.skipped.length, `most handles are reachable (${settings.skipped.join(", ")})`).toBeLessThanOrEqual(6);
    expect(settings.hits.join(" | "), "Settings windows never intersect").toBe("");
    // The owner's answer (D323): a drag changes only its own window, never the rest of its column or its row.
    expect(settings.changed.join(" | "), "no other window changed its size").toBe("");
    expect(new Set(settings.widths["s-appearance-themes"]).size, "the drags did change the window").toBeGreaterThan(1);
    if (SHOTS && !size.isMobile) {
      // After a narrowing drag, the way the owner met it: Theme's right edge pulled in.
      mkdirSync(SHOTS, { recursive: true });
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:settings:appearance.themes", source: "keyboard" } })));
      await page.waitForTimeout(1100);
      const box = (await page.locator('[data-window-id="s-appearance-themes"] .ui-window-resize[data-edge="e"]').boundingBox())!;
      const x = Math.min(size.viewport.width - 2, box.x + box.width / 2), y = box.y + box.height / 2 + 100;
      await page.mouse.move(x, y); await page.mouse.down();
      for (let k = 1; k <= 10; k++) { await page.mouse.move(x - (k * 15), y); await page.waitForTimeout(25); }
      await page.mouse.up();
      await page.waitForTimeout(700);
      await page.screenshot({ path: `${SHOTS}/narrowed-${size.deviceScaleFactor}x-${label}.png` });
    }
    await flyConsole(page);
    await page.waitForTimeout(900);
    const terminals = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window[data-kind="terminal"]')].slice(0, 3).map((w) => w.dataset.windowId!));
    expect(terminals.length).toBe(3);
    const product = await dragEdges(page, terminals, ["console", "settings"], size.isMobile ? 40 : 110, size.isMobile);
    expect(product.hits.join(" | "), "terminal windows never intersect either").toBe("");
    await context.close();
  });
}

/** The breadcrumb names the row in view (D323): a step of the canvas to the next row, with nothing clicked, changes it, and a step back changes it back. */
for (const [label, size] of [["1440x900", SIZES.desktop], ["393x852", SIZES.phone]] as const) {
  test(`the breadcrumb follows the row in view, at ${label}`, async ({ browser }) => {
    test.setTimeout(240_000);
    const context = await browser.newContext({ ...size, baseURL: baseURL() });
    const page = await context.newPage();
    await open(page, "&at=appearance.themes");
    expect((await crumbs(page)).slice(1), "starts on Themes").toEqual(["Appearance", "Themes"]);
    const focused = await active(page);
    const pill = (await page.locator('[data-window-id="s-appearance-themes"] .ui-window-pill').boundingBox())!;
    if (size.isMobile) {
      // Two fingers up: the canvas steps one row, as in the rows test above.
      const cdp = await page.context().newCDPSession(page);
      const two = (type: "touchStart" | "touchMove" | "touchEnd", dy: number) => cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x: 150, y: 500 + dy, id: 1 }, { x: 250, y: 500 + dy, id: 2 }] });
      await two("touchStart", 0);
      for (let k = 1; k <= 10; k++) { await two("touchMove", -k * 20); await page.waitForTimeout(25); }
      await two("touchEnd", -200);
    } else {
      await page.mouse.move(pill.x + pill.width / 2, pill.y + pill.height / 2);
      await page.mouse.wheel(0, 200);
    }
    await page.waitForTimeout(1500);
    // Nothing was clicked, and the window that was focused has left the screen: the focus went to the window now in view (D323).
    expect(focused).toBe("s-appearance-themes");
    expect(await active(page), "the focused window is the one in view").toBe("s-terminal-typing");
    expect((await crumbs(page)).slice(1), "the breadcrumb names the next row, Terminal").toEqual(["Terminal", "Typing"]);
    if (!size.isMobile) {
      await page.mouse.wheel(0, -200);
      await page.waitForTimeout(1500);
      expect((await crumbs(page)).slice(1), "and back").toEqual(["Appearance", "Themes"]);
      // Sideways, to the next window of the row: the group changes with the window in view.
      // The Appearance row (Themes, Layout) fits a desktop screen, so it has no sideways step; the Terminal row has four windows and does.
      await goTo(page, "canvas:settings:terminal.typing");
      await page.waitForTimeout(1200);
      await page.mouse.wheel(300, 0);
      await page.waitForTimeout(1200);
      expect((await crumbs(page)).slice(1), "the next window of the row").toEqual(["Terminal", "Hosts"]);
    }
    await context.close();
  });
}

/** A resize drag changes only its own window (D323): the windows above, below and beside it keep their size, whichever edge is dragged. */
test("desktop: narrowing one window leaves the rest of its column and its row as they were", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ ...SIZES.desktop, baseURL: baseURL() });
  const page = await context.newPage();
  await open(page, "&at=appearance.themes");
  const sizes = (): Promise<Record<string, string>> => page.evaluate(() => Object.fromEntries([...document.querySelectorAll<HTMLElement>('.cl[data-view="settings"] .ui-window')].map((n) => [n.dataset.windowId!, `${n.offsetWidth}x${n.offsetHeight}`])));
  const before = await sizes();
  const east = (await page.locator('[data-window-id="s-appearance-themes"] .ui-window-resize[data-edge="e"]').boundingBox())!;
  const x = east.x + east.width / 2, y = east.y + east.height / 2 + 100;
  await page.mouse.move(x, y); await page.mouse.down();
  for (let k = 1; k <= 10; k++) { await page.mouse.move(x - k * 15, y); await page.waitForTimeout(25); }
  await page.mouse.up();
  await page.waitForTimeout(700);
  const after = await sizes();
  expect(Number(after["s-appearance-themes"]!.split("x")[0]), "Themes is narrower").toBeLessThan(Number(before["s-appearance-themes"]!.split("x")[0]) - 100);
  expect(after["s-appearance-themes"]!.split("x")[1], "and as tall as it was").toBe(before["s-appearance-themes"]!.split("x")[1]);
  for (const [id, size] of Object.entries(before)) if (id !== "s-appearance-themes") expect(after[id], `${id} kept its size`).toBe(size);
  // Layout, in the same row, did not follow Themes' edge: the column's other windows still fill the track.
  const fontLeft = await page.evaluate(() => document.querySelector('[data-window-id="s-appearance-layout"]')!.getBoundingClientRect().left);
  const typingRight = await page.evaluate(() => document.querySelector('[data-window-id="s-terminal-typing"]')!.getBoundingClientRect().right);
  expect(fontLeft - typingRight, "the track is as wide as its widest window").toBeGreaterThan(0);
  await context.close();
});

/** One step sideways: a wheel over a window's header on a desktop, two fingers on a phone (`dir` 1 = to the next window on the right). */
async function stepSideways(page: Page, dir: 1 | -1, touch: boolean, at?: { x: number; y: number }): Promise<void> {
  if (touch) {
    const cdp = await page.context().newCDPSession(page);
    const two = (type: "touchStart" | "touchMove" | "touchEnd", dx: number) => cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x: 200 + dx, y: 500, id: 1 }, { x: 260 + dx, y: 500, id: 2 }] });
    await two("touchStart", 0);
    for (let k = 1; k <= 10; k++) { await two("touchMove", -dir * k * 20); await page.waitForTimeout(25); }
    await two("touchEnd", -dir * 200);
  } else {
    // The pointer stays where it is while the windows slide under it: a point on the header band, over a window's pill or its blank part.
    const where = at ?? { x: 200, y: 93 };
    await page.mouse.move(where.x, where.y);
    await page.mouse.wheel(dir * 300, 0);
  }
  await page.waitForTimeout(1100);
}
/** The share of a window that is on the screen, 0 to 1. */
const shareOnScreen = (page: Page, id: string): Promise<number> => page.evaluate((i) => {
  const r = document.querySelector(`[data-window-id="${i}"]`)!.getBoundingClientRect();
  const w = Math.min(r.right, innerWidth) - Math.max(r.left, 0), h = Math.min(r.bottom, innerHeight) - Math.max(r.top, 0);
  return w > 0 && h > 0 ? (w * h) / (r.width * r.height) : 0;
}, id);

/** Owner, 2026-11-04: the canvas scrolled right past the last window of Appearance into empty space. A row ends where its last window ends. */
for (const [label, size] of [["1440x900", SIZES.desktop], ["393x852", SIZES.phone]] as const) {
  test(`sideways scrolling stops at the end of the row, at ${label}`, async ({ browser }) => {
    test.setTimeout(180_000);
    const context = await browser.newContext({ ...size, baseURL: baseURL() });
    const page = await context.newPage();
    await open(page, "&at=terminal.typing");
    // Terminal has four windows and the longest row (You) has five tracks: more steps than there are windows must not reach the fifth track.
    for (let k = 0; k < 7; k++) await stepSideways(page, 1, size.isMobile);
    const right = await page.evaluate(() => document.querySelector('[data-window-id="s-terminal-multiplexer"]')!.getBoundingClientRect().right);
    expect(right, "the last window of the row is whole on screen (sideways)").toBeLessThanOrEqual(size.viewport.width + 0.5);
    const gap = size.viewport.width - right;
    expect(gap).toBeGreaterThanOrEqual(-0.5);
    // Nothing but the group's inset is to its right: the same distance the longest row (You, five windows) ends at.
    await goTo(page, "canvas:settings:you.devices");
    for (let k = 0; k < 7; k++) await stepSideways(page, 1, size.isMobile);
    const natural = size.viewport.width - (await page.evaluate(() => document.querySelector('[data-window-id="s-you-devices"]')!.getBoundingClientRect().right));
    near(gap, natural, "the short row ends where the longest row ends");
    await goTo(page, "canvas:settings:terminal.multiplexer");
    if (SHOTS) { mkdirSync(SHOTS, { recursive: true }); await page.screenshot({ path: `${SHOTS}/row-end-${size.isMobile ? "p3" : "d2"}.png` }); }
    await context.close();
  });
}

/** Owner, 2026-11-04: after a wider layout the person could scroll to another window while the old one stayed active and named in the breadcrumb. */
for (const [label, size, key, value] of [["1440x900", SIZES.desktop, "tracer.window-size.desktop", "wide"], ["393x852", SIZES.phone, "tracer.window-size.phone", "full"]] as const) {
  test(`a layout change keeps the active window in view, and scrolling hands the focus on, at ${label}`, async ({ browser }) => {
    test.setTimeout(180_000);
    const context = await browser.newContext({ ...size, baseURL: baseURL() });
    const page = await context.newPage();
    await open(page, "&at=terminal.multiplexer");
    expect(await active(page)).toBe("s-terminal-multiplexer");
    await page.evaluate(([k, v]) => { localStorage.setItem(k, v); window.dispatchEvent(new CustomEvent("tracer:window-size")); }, [key, value] as const);
    await page.waitForTimeout(1800);
    expect(await shareOnScreen(page, "s-terminal-multiplexer"), "the active window is still in view after the layout change").toBeGreaterThan(0.5);
    expect(await active(page)).toBe("s-terminal-multiplexer");
    if (SHOTS) { mkdirSync(SHOTS, { recursive: true }); await page.screenshot({ path: `${SHOTS}/layout-kept-${size.isMobile ? "p3" : "d2"}.png` }); }
    // Scroll back along the row until the Layout window has left: the window in front is active, and the breadcrumb names the same one.
    for (let k = 0; k < 5 && (await shareOnScreen(page, "s-terminal-multiplexer")) >= 0.5; k++) await stepSideways(page, -1, size.isMobile);
    await page.waitForTimeout(500);
    expect(await shareOnScreen(page, "s-terminal-multiplexer"), "the last window of Terminal has scrolled away").toBeLessThan(0.5);
    const now = await active(page);
    expect(now, "another window is active").not.toBe("s-terminal-multiplexer");
    expect(await shareOnScreen(page, now!), "and it is the one in front of the person").toBeGreaterThan(0.5);
    const names = await crumbs(page);
    expect(names.slice(1), "the breadcrumb says the same").toEqual(["Terminal", now!.replace("s-terminal-", "").replace(/^./, (c) => c.toUpperCase())]);
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/active-follows-${size.isMobile ? "p3" : "d2"}.png` });
    await context.close();
  });
}
