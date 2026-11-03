/**
 * The session UI on the canvas (`?mock=1&proto=clusters`, scenes via `&sessions=N`; D121, D127, D178, D183): the
 * manager (grouping, order, marks, attach, rename, end), the sidebar inventory, close with Undo, exited sessions,
 * splits through the droplet, the "Sized for" badge, ⌘K, the empty, loading and error states, and what TASTE asks
 * to be measured (motion durations, no rings from the mouse, 44 px on touch, desktop actions in one pill and touch Close).
 */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Browser, type BrowserContext, type Page } from "playwright/test";

type Viewport = { width: number; height: number; touch?: boolean };
const DESKTOP: Viewport = { width: 1440, height: 900 };
const PHONE: Viewport = { width: 393, height: 852, touch: true };

/** `signIns` seeds the account's sign-in count (hints.ts) before the page loads; 1 is a first sign-in. */
async function open(browser: Browser, viewport: Viewport, scene = 0, theme = "ink", signIns = 1, blockStorage = false): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height }, hasTouch: !!viewport.touch, isMobile: !!viewport.touch });
  await context.addInitScript(([n, block]) => {
    if (block) { Storage.prototype.getItem = () => { throw new Error("blocked"); }; Storage.prototype.setItem = () => { throw new Error("blocked"); }; return; }
    if (!localStorage.getItem("tracer.hints.mock")) localStorage.setItem("tracer.hints.mock", JSON.stringify({ signIns: n, shown: {} }));
  }, [signIns, blockStorage] as const);
  const page = await context.newPage();
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&bg=none${scene ? `&sessions=${scene}` : ""}`);
  await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
  await expect.poll(() => page.evaluate(() => typeof (window as unknown as { __tracerClusters?: { sessions?: unknown } }).__tracerClusters?.sessions)).toBe("function");
  await page.waitForTimeout(600);
  return { context, page };
}

type Store = { status: string; hosts: Array<{ host: string; sessions: Array<{ id: string; name: string; state: string; activity: string | null; pinned: boolean }> }> };
const store = (page: Page): Promise<Store> => page.evaluate(() => (window as unknown as { __tracerClusters: { sessions(): Store } }).__tracerClusters.sessions());
const stateOf = async (page: Page, host: string, id: string): Promise<string | undefined> => (await store(page)).hosts.find((h) => h.host === host)?.sessions.find((s) => s.id === id)?.state;
const consoleWindows = (page: Page) => page.locator("[data-view='console'] .ui-window");
const windowOf = (page: Page, host: string) => consoleWindows(page).filter({ has: page.locator(".ui-window-host", { hasText: host }) }).first();
const runScene = (page: Page, n: number): Promise<void> => page.evaluate((k) => (window as unknown as { __tracerClusters: { runSessionScene(n: number): Promise<void> } }).__tracerClusters.runSessionScene(k), n);
const press = async (page: Page, viewport: Viewport, target: ReturnType<Page["locator"]>): Promise<void> => { if (viewport.touch) await target.tap(); else await target.click(); };

test("the manager groups sessions by state, orders them by frecency and marks activity", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP, 1);
  try {
    const pop = page.locator(".cl-sx-pop");
    await expect(pop).toBeVisible();
    await expect(pop.locator(".cl-sx-eyebrow")).toHaveText(["Open", "Detached", "Exited"]);
    await expect(pop.locator(".cl-sx-group[aria-label='Detached'] .cl-sx-name")).toHaveText(["release", "journal", "cargo test"]);
    await expect(pop.locator(".cl-sx-row[data-id='release'] .ui-mark")).toHaveAttribute("data-mark", "ok");
    await expect(pop.locator(".cl-sx-row[data-id='journal'] .ui-mark")).toHaveAttribute("data-mark", "output");
    await expect(pop.locator(".cl-sx-row[data-id='tests'] .ui-mark")).toHaveAttribute("data-mark", "fail");
    await expect(pop.locator(".cl-sx-row[data-id='migrate'] .cl-sx-meta-top")).toContainText("exit 1");
    const own = await pop.locator(".cl-sx-row[data-id='deploy'] .cl-sx-main").evaluate((n) => { const s = getComputedStyle(n); return { border: s.borderTopWidth, outline: s.outlineStyle, fill: s.backgroundColor }; });
    expect(own.border).toBe("0px");
    expect(own.outline).toBe("none");
    expect(own.fill).not.toBe("rgba(0, 0, 0, 0)");
    const box = (await pop.boundingBox())!;
    const win = (await windowOf(page, "build-01").boundingBox())!;
    expect(box.x).toBeGreaterThanOrEqual(win.x + 8 - 1);
    expect(box.x + box.width).toBeLessThanOrEqual(win.x + win.width - 8 + 1);
    expect(box.y + box.height).toBeLessThanOrEqual(win.y + win.height - 8 + 1);
  } finally { await context.close(); }
});

test("a window's actions are one pill as tall as its title pill", async ({ browser }) => {
  for (const viewport of [DESKTOP, PHONE]) {
    const { context, page } = await open(browser, viewport);
    try {
      const win = windowOf(page, "build-01");
      const geometry = await win.evaluate((root) => {
        const pill = root.querySelector(".ui-window-pill")!.getBoundingClientRect();
        const actions = root.querySelector(".ui-window-actions")!;
        const box = actions.getBoundingClientRect();
        const style = getComputedStyle(actions);
        return { pillH: Math.round(pill.height), actionsH: Math.round(box.height), border: style.borderTopWidth, radius: style.borderTopLeftRadius, labels: [...actions.querySelectorAll("button")].filter((b) => b.getBoundingClientRect().height > 0).map((b) => b.getAttribute("aria-label")), buttonH: Math.min(...[...actions.querySelectorAll("button")].map((b) => Math.round(b.getBoundingClientRect().height))), inside: box.right <= root.getBoundingClientRect().right, titleClipped: pill.right <= box.left };
      });
      expect(geometry.actionsH).toBe(geometry.pillH);
      expect(geometry.border).toBe("1px");
      expect(geometry.labels).toEqual(viewport.touch ? ["Close"] : ["Split right", "Split down", "Sessions", "Close"]);
      expect(geometry.inside).toBe(true);
      expect(geometry.titleClipped).toBe(true);
    } finally { await context.close(); }
  }
});

test("choosing a session attaches the window to it; the old one keeps running", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP, 1);
  try {
    await page.locator(".cl-sx-row[data-id='journal'] .cl-sx-main").click();
    await expect(page.locator(".cl-sx-pop")).toHaveCount(0);
    const win = windowOf(page, "build-01");
    await expect(win.locator(".ui-window-session")).toHaveText("journal");
    await expect(win.locator(".cl-preview")).toContainText("Session shim ready");
    expect(await stateOf(page, "build-01", "journal")).toBe("open");
    expect(await stateOf(page, "build-01", "deploy")).toBe("detached");
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator("#tree .bm-leaf[data-id='s:build-01/deploy'] .ui-state-dot")).toHaveAttribute("data-state", "detached");
    await expect(page.locator("#tree .bm-leaf[data-id='s:build-01/journal'][aria-current]")).toHaveCount(1);
  } finally { await context.close(); }
});

test("attaching moves only opacity and transform, and leaves nothing animating at rest", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP, 1);
  try {
    await page.evaluate(() => {
      const seen: string[] = [];
      (window as unknown as { __props: string[] }).__props = seen;
      const watch = (): void => {
        for (const animation of document.getAnimations()) {
          if (animation instanceof CSSTransition) continue;
          const target = (animation.effect as KeyframeEffect | null)?.target as Element | null;
          if (!target?.closest(".cl-sx-pop, .cl-sx-flash, .ui-window-session")) continue;
          for (const frame of (animation.effect as KeyframeEffect).getKeyframes()) for (const key of Object.keys(frame)) if (!["offset", "easing", "composite", "computedOffset"].includes(key)) seen.push(key);
        }
        requestAnimationFrame(watch);
      };
      watch();
    });
    await page.locator(".cl-sx-row[data-id='release'] .cl-sx-main").click();
    await page.waitForTimeout(900);
    const props = new Set(await page.evaluate(() => (window as unknown as { __props: string[] }).__props));
    for (const prop of props) expect(["opacity", "transform"]).toContain(prop);
    expect(props.has("opacity")).toBe(true);
    expect(await page.evaluate(() => document.querySelectorAll(".cl-sx-pop, .cl-sx-flash").length)).toBe(0);
    expect(await page.evaluate(() => [...document.querySelectorAll(".ui-window-session")].filter((n) => getComputedStyle(n).transform !== "none").length)).toBe(0);
  } finally { await context.close(); }
});

test("the popover opens within 200 ms and closes within 130 ms; the keyboard is instant", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    // The first open fetches the manager's code (on demand); measure the second.
    await page.locator("[data-action='sessions']").nth(1).click();
    await expect(page.locator(".cl-sx-pop")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.locator(".cl-sx-pop")).toHaveCount(0);
    const durations = await page.evaluate(async () => {
      const button = document.querySelectorAll<HTMLButtonElement>("[data-action='sessions']")[1]!;
      button.dispatchEvent(new MouseEvent("click", { bubbles: true, detail: 1 }));
      await new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)));
      const open = document.querySelector(".cl-sx-pop")!.getAnimations().map((a) => (a.effect as KeyframeEffect).getTiming().duration);
      button.dispatchEvent(new MouseEvent("click", { bubbles: true, detail: 1 }));
      await new Promise((done) => requestAnimationFrame(done));
      const close = document.querySelector(".cl-sx-pop")?.getAnimations().map((a) => (a.effect as KeyframeEffect).getTiming().duration) ?? [];
      return { open, close };
    });
    expect(durations.open).toEqual([200]);
    expect(durations.close.at(-1)).toBe(130);
    await page.waitForTimeout(250);
    await page.locator("[data-action='sessions']").nth(1).focus();
    await page.keyboard.press("Enter");
    expect(await page.evaluate(() => document.querySelector(".cl-sx-pop")?.getAnimations().length)).toBe(0);
    await page.keyboard.press("Escape");
    await expect(page.locator(".cl-sx-pop")).toHaveCount(0);
  } finally { await context.close(); }
});

test("closing a window never ends its session: a gentle toast, and Reopen brings it back", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await windowOf(page, "build-01").locator("[data-action='close']").click();
    await expect(consoleWindows(page)).toHaveCount(3);
    const toast = page.locator(".ui-toast");
    await expect(toast.locator(".ui-toast-message")).toHaveText("Session keeps running");
    await expect(toast.getByRole("button", { name: "Reopen", exact: true })).toHaveText("Reopen");
    expect(await stateOf(page, "build-01", "deploy")).toBe("detached");
    await page.screenshot({ path: process.env.TOAST_SHOT ?? tracerEvidencePath("close-toast.png") });
    await toast.getByRole("button", { name: "Reopen", exact: true }).click();
    await expect(consoleWindows(page)).toHaveCount(4);
    expect(await stateOf(page, "build-01", "deploy")).toBe("open");
    await expect(consoleWindows(page).first().locator(".ui-window-host")).toHaveText("build-01");
  } finally { await context.close(); }
});

test("the close toast teaches once per sign-in, in the first five sign-ins only", async ({ browser }) => {
  test.setTimeout(120_000);
  for (const signIns of [1, 2, 5, 6]) {
    const { context, page } = await open(browser, DESKTOP, 0, "ink", signIns);
    try {
      // Counts every toast message that appears, so a still-visible first toast cannot hide a second one.
      await page.evaluate(() => {
        const w = window as unknown as { __toasts: string[] };
        w.__toasts = [];
        // The toast host is one element that is revealed and re-filled, so a show is "revealed" or "text changed while shown".
        const host = document.querySelector(".ui-toast") as HTMLElement;
        let was = !host.hidden, last = "";
        new MutationObserver(() => {
          const now = !host.hidden, text = host.querySelector(".ui-toast-message")?.textContent ?? "";
          if (now && text && (!was || text !== last)) w.__toasts.push(text);
          was = now; last = text;
        }).observe(host, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["hidden"] });
      });
      const seen = (): Promise<string[]> => page.evaluate(() => (window as unknown as { __toasts: string[] }).__toasts);
      await windowOf(page, "build-01").locator("[data-action='close']").click();
      await expect(consoleWindows(page)).toHaveCount(3);
      await page.waitForTimeout(500);
      expect(await seen()).toEqual(signIns <= 5 ? ["Session keeps running"] : []);
      // The second close in the same sign-in is silent, whatever the count.
      await consoleWindows(page).first().locator("[data-action='close']").click();
      await expect(consoleWindows(page)).toHaveCount(2);
      await page.waitForTimeout(500);
      expect(await seen()).toEqual(signIns <= 5 ? ["Session keeps running"] : []);
    } finally { await context.close(); }
  }
});

test("storage that throws shows no close toast", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP, 0, "ink", 1, true);
  try {
    await windowOf(page, "build-01").locator("[data-action='close']").click();
    await expect(consoleWindows(page)).toHaveCount(3);
    await page.waitForTimeout(500);
    await expect(page.locator(".ui-toast")).toBeHidden();
  } finally { await context.close(); }
});

test("ending a session names what is running and asks with the compact confirm", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP, 5);
  try {
    const tip = page.locator(".ui-confirm-tip[data-open='true']");
    await expect(tip).toBeVisible();
    await expect(tip.locator(".ui-confirm-tip-message")).toHaveText("End 'apt upgrade'?");
    await expect(tip.locator(".ui-confirm-tip-detail")).toContainText("apt upgrade is still running");
    await expect(tip.locator("button")).toHaveCount(2);
    await expect(tip.locator("button").nth(1)).toHaveAttribute("aria-label", "End session");
    await expect(page.locator(".cl-sx-pop")).toBeVisible();
    await tip.locator("button").nth(0).click();
    expect(await stateOf(page, "edge-arm", "apt-watch")).toBe("open");
    await page.locator(".cl-sx-row[data-id='apt-watch'] .cl-sx-act.is-end").dispatchEvent("click");
    await page.locator(".ui-confirm-tip[data-open='true'] button[aria-label='End session']").click();
    await expect.poll(() => stateOf(page, "edge-arm", "apt-watch")).toBeUndefined();
    await expect(consoleWindows(page)).toHaveCount(3);
  } finally { await context.close(); }
});

test("a rename pins the name and is the window's name", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP, 1);
  try {
    const row = page.locator(".cl-sx-row[data-id='journal']");
    await row.hover();
    await row.locator(".cl-sx-act[data-act='rename']").click();
    const input = row.locator(".cl-sx-name-input");
    await expect(input).toBeFocused();
    await input.fill("agent log");
    await input.press("Enter");
    await expect(row.locator(".cl-sx-name")).toHaveText("agent log");
    await expect(row.locator(".cl-sx-pin")).toHaveCount(1);
    expect((await store(page)).hosts.find((h) => h.host === "build-01")!.sessions.find((s) => s.id === "journal")).toMatchObject({ name: "agent log", pinned: true });
    await row.locator(".cl-sx-main").click();
    await expect(windowOf(page, "build-01").locator(".ui-window-session")).toHaveText("agent log");
  } finally { await context.close(); }
});

test("the sidebar is the inventory: markers, detached notes and exit codes, in frecency order", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP, 2);
  try {
    const leaf = (id: string) => page.locator(`#tree .bm-leaf[data-id='s:${id}']`);
    await expect(leaf("build-01/deploy").locator(".ui-state-dot")).toHaveAttribute("data-state", "open");
    await expect(leaf("build-01/journal").locator(".ui-state-dot")).toHaveAttribute("data-state", "detached");
    // A detached session shows an icon, never the word; its name is the icon's accessible label, its tooltip, and part of the row's own name.
    const note = leaf("build-01/journal").locator(".bm-meta");
    await expect(note).toHaveText("");
    await expect(note.locator("svg")).toHaveCount(1);
    await expect(note).toHaveAttribute("role", "img");
    await expect(note).toHaveAttribute("aria-label", "Detached");
    await expect(leaf("build-01/journal")).toHaveAttribute("aria-label", /build-01.*detached|journal, detached/);
    await expect(leaf("build-01/deploy").locator(".bm-meta svg")).toHaveCount(0);
    await expect(leaf("build-01/bench").locator(".bm-meta svg")).toHaveCount(0);
    await note.hover();
    await expect(page.locator(".tip")).toHaveText("Detached");
    await page.mouse.move(700, 450);
    await expect(leaf("build-01/journal").locator(".ui-mark")).toHaveAttribute("data-mark", "output");
    await expect(leaf("build-01/release").locator(".ui-mark")).toHaveAttribute("data-mark", "ok");
    await expect(leaf("build-01/bench").locator(".bm-meta")).toHaveText("0");
    await expect(leaf("build-01/migrate").locator(".bm-meta")).toHaveText("1");
    await expect(leaf("build-01/migrate").locator(".ui-mark")).toHaveAttribute("data-mark", "fail");
    const order = (await page.locator("#tree .bm-sec[data-id='view:console'] .bm-leaf").evaluateAll((n) => n.map((x) => (x as HTMLElement).dataset.id ?? ""))).filter((id) => id.startsWith("s:build-01/"));
    await expect(page.locator("#tree .bm-sec[data-id='view:console'] .bm-subhead")).toHaveText(["build-01", "edge-arm", "nix-cache", "studio-mac"]);
    expect(order).toEqual(["s:build-01/deploy", "s:build-01/release", "s:build-01/journal", "s:build-01/tests", "s:build-01/bench", "s:build-01/migrate"]);
    await expect(leaf("studio-mac/local-api").locator(".ui-mark")).toHaveAttribute("data-mark", "output", { timeout: 6000 });
    await expect(leaf("edge-arm/edge-shell").locator(".ui-mark")).toHaveAttribute("data-mark", "ok", { timeout: 9000 });
  } finally { await context.close(); }
});

test("the tick, the cross and the dot beside a session say what they mean in a tooltip", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP, 2);
  try {
    const leaf = (id: string) => page.locator(`#tree .bm-leaf[data-id='s:${id}']`);
    const tipOf = async (id: string): Promise<string> => {
      await leaf(id).locator(".ui-mark").hover();
      await expect(page.locator(".tip")).toBeVisible();
      const text = (await page.locator(".tip").textContent()) ?? "";
      await page.mouse.move(700, 450);
      await expect(page.locator(".tip")).toBeHidden();
      return text;
    };
    expect(await tipOf("build-01/release")).toBe("Finished successfully"); // detached, a command finished well
    expect(await tipOf("build-01/journal")).toBe("New output");
    expect(await tipOf("build-01/bench")).toBe("Finished successfully, exit code 0"); // exited: the tick is the exit code in a picture
    expect(await tipOf("build-01/migrate")).toBe("Failed, exit code 1");
  } finally { await context.close(); }
});

test("review flag ?marks=words: exited rows say finished or failed in words", async ({ browser }) => {
  const context = await browser.newContext({ viewport: DESKTOP });
  const page = await context.newPage();
  try {
    await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none&sessions=2&marks=words");
    await expect(page.locator("#tree .bm-leaf[data-id='s:build-01/bench'] .bm-meta")).toHaveText("finished", { timeout: 20_000 });
    await expect(page.locator("#tree .bm-leaf[data-id='s:build-01/migrate'] .bm-meta")).toHaveText("failed · 1");
  } finally { await context.close(); }
});

test("tapping a detached session opens it in a new window and flies the canvas there", async ({ browser }) => {
  for (const viewport of [DESKTOP, PHONE]) {
    const { context, page } = await open(browser, viewport, 2);
    try {
      await expect(page.locator("#sidebar")).toBeVisible();
      await press(page, viewport, page.locator("#tree .bm-leaf[data-id='s:build-01/journal']"));
      await expect(consoleWindows(page)).toHaveCount(5);
      expect(await stateOf(page, "build-01", "journal")).toBe("open");
      if (viewport.touch) await expect(page.locator("#sidebar")).toBeHidden();
      await expect(page.locator(".ui-window[data-active] .ui-window-session")).toHaveText("journal");
      // The canvas frames the new window whole, on a phone and on a desktop (the sidebar is a layer over the canvas, not a dock).
      await expect.poll(async () => { const b = await page.locator(".ui-window[data-active]").boundingBox(); return b ? b.x >= -1 && b.x + b.width <= viewport.width + 1 : false; }, { timeout: 5000 }).toBe(true);
    } finally { await context.close(); }
  }
});

test("an exited session opens its final screen read-only, with Run again and Dismiss", async ({ browser }) => {
  for (const viewport of [DESKTOP, PHONE]) {
    const { context, page } = await open(browser, viewport, 3);
    try {
      const strip = page.locator(".cl-sx-strip");
      await expect(strip).toBeVisible();
      await expect(strip).toContainText("Exited 1");
      await expect(strip.locator(".cl-sx-again")).toHaveText("Run again");
      await expect(strip.locator(".cl-sx-dismiss")).toHaveAttribute("aria-label", "Dismiss");
      await expect(page.locator(".ui-window[data-active] .cl-preview")).toContainText("already exists");
      await expect(page.locator(".ui-window[data-active]")).toHaveAttribute("data-status", "offline");
      await press(page, viewport, strip.locator(".cl-sx-again"));
      await expect(page.locator(".cl-sx-strip")).toHaveCount(0);
      expect(await stateOf(page, "build-01", "migrate")).toBe("open");
    } finally { await context.close(); }
  }
  const { context, page } = await open(browser, DESKTOP, 3);
  try {
    await page.locator(".cl-sx-dismiss").click();
    await expect(consoleWindows(page)).toHaveCount(4);
    expect(await stateOf(page, "build-01", "migrate")).toBeUndefined();
  } finally { await context.close(); }
});

test("both splits open a new shell through the header actions and stack down in the column", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    const win = windowOf(page, "build-01");
    await win.locator("[data-action='split-right']").click();
    await expect(consoleWindows(page)).toHaveCount(5);
    await expect(page.locator(".ui-confirm-tip[data-open='true'], .cl-sx-pop")).toHaveCount(0);
    const created = page.locator(".ui-window[data-window-id*='-s1']");
    await expect(created.locator(".ui-window-session")).toHaveText("shell");
    await page.waitForTimeout(1500);
    // A split narrows its header, so its shared overflow menu carries the actions.
    await created.getByRole("button", { name: "More window actions" }).click();
    await page.locator(".ui-window-menu-item[data-action='split-down']").click();
    await expect(consoleWindows(page)).toHaveCount(6);
    await page.waitForTimeout(1500);
    const columns = await page.locator("[data-view='console'] .cl-col").evaluateAll((cols) => cols.map((c) => c.querySelectorAll(":scope > .ui-window").length));
    expect(columns).toContain(2);
    await expect(page.locator(".ui-window .ui-window-session", { hasText: "infraternal" })).toHaveCount(2, { timeout: 5000 });
  } finally { await context.close(); }
});

test("another device typed last: scaled to fit, a badge says so, typing takes the size over", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP, 7);
  try {
    const badge = page.locator(".cl-sx-badge");
    await expect(badge).toHaveText("Sized for MacBook Pro");
    const preview = windowOf(page, "nix-cache").locator(".cl-preview");
    await expect(preview).toHaveAttribute("data-scaled", "");
    const scale = await preview.evaluate((n) => new DOMMatrix(getComputedStyle(n).transform).a);
    expect(scale).toBeGreaterThan(0.5);
    expect(scale).toBeLessThan(1);
    // The key goes to the active window when the page has the focus. After the load the DOM focus can instead sit in the textarea of
    // the first terminal that attached (build-01) while nix-cache is the active window, and the key then goes to the wrong terminal
    // (on dev this check passed only the runs where the focus was on the page: 4 of 9). The check puts the focus back on the page.
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    await page.keyboard.press("l");
    await expect(badge).toHaveCount(0);
    await expect(preview).not.toHaveAttribute("data-scaled", "");
    await page.waitForTimeout(1000);
    expect(await preview.evaluate((n) => getComputedStyle(n).transform)).toBe("none");
  } finally { await context.close(); }
});

test("⌘K lists every session on every host, the actions and the sessions scenes", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    await page.keyboard.press("Control+Shift+K");
    await page.keyboard.type("detached");
    const rows = page.locator(".result");
    await expect(rows.filter({ hasText: "local-api" })).toHaveCount(1);
    await expect(rows.filter({ hasText: "journal" })).toHaveCount(1);
    await page.keyboard.press("Escape");
    await page.keyboard.press("Control+Shift+K");
    await page.keyboard.type("sessions scene 3");
    await expect(page.locator(".result").first()).toContainText("Mockup: sessions scene 3");
    await page.keyboard.press("Enter");
    await expect(page.locator(".cl-sx-strip")).toBeVisible();
  } finally { await context.close(); }
});

test("the empty, loading and error states keep the product's rhythm", async ({ browser }) => {
  const empty = await open(browser, DESKTOP, 8);
  try { await expect(empty.page.locator(".cl-sx-empty")).toHaveText("No other sessions on nix-cache"); } finally { await empty.context.close(); }
  const loading = await open(browser, DESKTOP, 9);
  try {
    await expect(loading.page.locator(".cl-sx-state[data-kind='loading'] .ui-spinner")).toBeVisible();
    await expect(loading.page.locator(".cl-sx-row")).toHaveCount(6, { timeout: 12_000 });
  } finally { await loading.context.close(); }
  const failed = await open(browser, DESKTOP, 10);
  try {
    const state = failed.page.locator(".cl-sx-state[data-kind='error']");
    await expect(state).toContainText("Could not load sessions");
    const retry = state.locator(".cl-sx-retry");
    await expect(retry).toHaveAttribute("aria-label", "Try again");
    const gap = await state.evaluate((n) => Math.round(n.querySelector(".cl-sx-retry")!.getBoundingClientRect().top - n.querySelector(".cl-sx-state-note")!.getBoundingClientRect().bottom));
    expect(gap).toBeGreaterThanOrEqual(20);
    await retry.click();
    await expect(failed.page.locator(".cl-sx-state[data-kind='loading']")).toBeVisible();
    await expect(failed.page.locator(".cl-sx-row")).toHaveCount(6, { timeout: 6000 });
  } finally { await failed.context.close(); }
});

test("mouse and shortcuts draw no focus ring; Tab does", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  try {
    const button = windowOf(page, "build-01").locator("[data-action='sessions']");
    await button.click();
    await page.locator(".cl-sx-row[data-id='journal'] .cl-sx-main").hover();
    expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).toBeUndefined();
    expect(await button.evaluate((n) => getComputedStyle(n).outlineStyle)).toBe("none");
    await page.keyboard.press("Escape");
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).toBe("on");
  } finally { await context.close(); }
});

test("on touch every control is 44 px and a row swipes open 1:1 with the finger", async ({ browser }) => {
  const { context, page } = await open(browser, PHONE, 1);
  try {
    const sizes = await page.evaluate(() => [...document.querySelectorAll(".cl-sx-row .cl-sx-main")].map((n) => Math.round(n.getBoundingClientRect().height)));
    for (const h of sizes) expect(h).toBeGreaterThanOrEqual(44);
    const row = page.locator(".cl-sx-row[data-id='journal']");
    const box = (await row.boundingBox())!;
    const client = await context.newCDPSession(page);
    const startX = box.x + box.width - 30, y = box.y + box.height / 2;
    await client.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: startX, y, id: 1 }] });
    for (const dx of [-8, -20, -40, -60]) { await client.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: startX + dx, y, id: 1 }] }); await page.waitForTimeout(40); }
    await expect.poll(() => row.locator(".cl-sx-main").evaluate((n) => new DOMMatrix(getComputedStyle(n).transform).e)).toBeCloseTo(-60, 0);
    await client.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    await page.waitForTimeout(700);
    await expect(row.locator(".cl-sx-act")).toHaveCount(2);
    await row.locator(".cl-sx-main").tap({ position: { x: 200, y: 20 } });
    await page.waitForTimeout(600);
    await expect(page.locator(".cl-sx-pop")).toBeVisible();
    expect(await stateOf(page, "build-01", "journal")).toBe("detached");
  } finally { await context.close(); }
});

test("scenes run one after another and each starts from the same four windows", async ({ browser }) => {
  const { context, page } = await open(browser, DESKTOP);
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  try {
    for (const scene of [3, 6, 4, 7, 5, 8]) { await runScene(page, scene); await page.waitForTimeout(scene === 6 ? 3600 : 1700); }
    await runScene(page, 1);
    await expect(page.locator(".cl-sx-pop")).toBeVisible();
    await expect(consoleWindows(page)).toHaveCount(4);
    await expect(page.locator(".cl-sx-strip")).toHaveCount(0);
    expect(await stateOf(page, "build-01", "deploy")).toBe("open");
    expect(await stateOf(page, "build-01", "migrate")).toBe("exited");
    expect(errors).toEqual([]);
  } finally { await context.close(); }
});

test("the manager's code is on demand, fetched at idle so the first open never waits for a download (#128)", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const scripts: string[] = [];
  page.on("request", (r) => { if (r.url().endsWith(".js")) scripts.push(r.url()); });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
  await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
  // Not part of the first screen: it arrives after the page has gone idle, and before anyone asks for it.
  const atFirstScreen = scripts.length;
  await expect.poll(() => scripts.length, { timeout: 10_000 }).toBeGreaterThan(atFirstScreen);
  await page.waitForTimeout(500);
  const settled = scripts.length;
  await windowOf(page, "build-01").locator("[data-action='sessions']").click();
  await expect(page.locator(".cl-sx-pop")).toBeVisible();
  expect(scripts.length, "opening the manager fetches nothing").toBe(settled);
  await context.close();
});

test("on a phone the canvas row has a Sessions action that opens the manager of the active window", async ({ browser }, testInfo) => {
  const { context, page } = await open(browser, PHONE);
  try {
    const item = page.locator("#keyrow-canvas button[aria-label='Sessions']");
    await expect(item).toBeVisible();
    await windowOf(page, "build-01").locator(".ui-window-pill").tap();
    await expect(item).toBeEnabled();
    await item.tap();
    await expect(page.locator(".cl-sx-pop")).toBeVisible({ timeout: 8000 });
    await expect(page.locator(".cl-sx-title")).toHaveText("build-01");
    const capture = tracerEvidencePath("release-prod-3", "mobile-manager.png");
    await page.screenshot({ path: capture });
    await testInfo.attach("mobile session manager", { path: capture, contentType: "image/png" });
  } finally { await context.close(); }
});
