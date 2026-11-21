// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Accessibility audit (#558, J1032): a WCAG 2.2 AA sweep of the main screens, taken from a production build.
 *
 * What it is for. axe-core finds what a machine can find (names, roles, contrast, ARIA validity); the other probes measure what
 * axe cannot: where Tab goes, whether the ring is drawn, how big a touch target is, what `prefers-reduced-motion` really stops,
 * and whether 200 % zoom still fits. Each screen at each size and theme writes `<screen>-<size>-<theme>.json` with the axe
 * violations (rule, impact, up to five nodes) and the probe numbers; the findings in the issue are read from those files.
 *
 * How to run it. It is off unless `A11Y_AUDIT=1`. `A11Y_BROWSER=firefox` runs the same sweep in Firefox (default Chromium).
 * Output goes to the external evidence directory (evidence-path.ts), never into the checkout. axe-core is a dev-only test
 * dependency (MPL-2.0, which lists the AGPL as a permitted secondary licence); it is never bundled into the product.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { startRemovalFromPalette } from "./removal-fixture";

test.skip(!process.env.A11Y_AUDIT, "the accessibility audit is run on request");

/** Which engine this run uses; `firefox` or the default `chromium`. */
const BROWSER = process.env.A11Y_BROWSER === "firefox" ? "firefox" : "chromium";
test.use({ browserName: BROWSER });

/** Where this run writes its files. */
const OUT = tracerEvidencePath("a11y", BROWSER);
/** The path of the axe-core script that is injected into each page. */
const AXE_PATH = createRequire(import.meta.url).resolve("axe-core/axe.min.js");
/** A desktop window and a phone (touch). */
const SIZES = [
  { name: "1440x900", width: 1440, height: 900, touch: false },
  { name: "393x852", width: 393, height: 852, touch: true },
] as const;
/** Both colour modes. */
const THEMES = ["ink", "paper"] as const;

/** What the page's interactive elements look like to a keyboard and to a pointer. */
interface Probe {
  /** Interactive elements without any accessible name (aria-label, aria-labelledby, text, alt, title, value). */
  unnamed: string[];
  /** Interactive elements smaller than 24 x 24 CSS px (WCAG 2.5.8 floor) and, on touch, smaller than 44 x 44. */
  small: Array<{ el: string; w: number; h: number }>;
  /** Count of elements with a positive tabindex (they break the natural focus order). */
  positiveTabindex: number;
  /** Landmarks present: role or tag, with label. */
  landmarks: string[];
  /** Whether the document has a main landmark, a lang, a title. */
  doc: { lang: string; title: string; hasMain: boolean; viewport: string };
  /** Animations running right now (CSS and Web Animations), by animation name. */
  animations: string[];
}

/** Short selector-ish description of an element for the report. */
const DESCRIBE = `(el) => { const t = el.tagName.toLowerCase(); const id = el.id ? "#" + el.id : ""; const c = typeof el.className === "string" && el.className.trim() ? "." + el.className.trim().split(/\\s+/).slice(0, 2).join(".") : ""; return t + id + c; }`;

/** Measures the page for the probe above. */
async function probe(page: Page, touch: boolean): Promise<Probe> {
  return page.evaluate(({ describeSrc, touchTarget, touch }) => {
    const describe = eval(describeSrc) as (el: Element) => string;
    const interactive = Array.from(document.querySelectorAll<HTMLElement>("a[href], button, input:not([type=hidden]), select, textarea, summary, [role=button], [role=link], [role=menuitem], [role=tab], [role=switch], [role=checkbox], [role=option], [role=radio], [tabindex]:not([tabindex='-1'])"));
    const visible = (el: HTMLElement): boolean => {
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      return r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && cs.display !== "none" && !el.closest("[inert], [hidden], [aria-hidden='true']");
    };
    const nameOf = (el: HTMLElement): string => {
      const labelled = el.getAttribute("aria-labelledby");
      if (labelled) return labelled.split(/\s+/).map((id) => document.getElementById(id)?.textContent ?? "").join(" ").trim();
      return (el.getAttribute("aria-label") ?? el.textContent ?? (el as HTMLInputElement).value ?? el.getAttribute("title") ?? el.querySelector("img")?.getAttribute("alt") ?? "").trim()
        || (el.getAttribute("title") ?? "") || ((el as HTMLInputElement).labels?.[0]?.textContent ?? "") || (el.getAttribute("placeholder") ?? "");
    };
    const unnamed: string[] = [];
    const small: Array<{ el: string; w: number; h: number }> = [];
    for (const el of interactive) {
      if (!visible(el)) continue;
      if (!nameOf(el)) unnamed.push(describe(el));
      const r = el.getBoundingClientRect();
      if (r.width < (touch ? touchTarget : 24) || r.height < (touch ? touchTarget : 24)) small.push({ el: describe(el), w: Math.round(r.width * 10) / 10, h: Math.round(r.height * 10) / 10 });
    }
    const landmarks = Array.from(document.querySelectorAll("main, nav, header, footer, aside, [role=main], [role=navigation], [role=banner], [role=complementary], [role=region], [role=dialog], [role=search], [role=toolbar], [role=tree], [role=application]"))
      .map((el) => `${el.getAttribute("role") ?? el.tagName.toLowerCase()}${el.id ? "#" + el.id : ""}[${el.getAttribute("aria-label") ?? el.getAttribute("aria-labelledby") ?? ""}]`);
    return {
      unnamed, small,
      positiveTabindex: document.querySelectorAll("[tabindex]:not([tabindex='0']):not([tabindex^='-'])").length,
      landmarks,
      doc: { lang: document.documentElement.lang, title: document.title, hasMain: !!document.querySelector("main, [role=main]"), viewport: document.querySelector("meta[name=viewport]")?.getAttribute("content") ?? "" },
      animations: document.getAnimations().map((a) => (a as CSSAnimation).animationName ?? (a as CSSTransition).transitionProperty ?? a.constructor.name),
    };
  }, { describeSrc: DESCRIBE, touchTarget: 44, touch });
}

/** One axe violation, trimmed. */
interface Violation { rule: string; impact: string | null; help: string; nodes: Array<{ target: string; html: string; summary: string }> }

/** Runs axe on the whole page against WCAG 2.0/2.1/2.2 A and AA plus best practices; returns the violations trimmed. */
async function axe(page: Page): Promise<Violation[]> {
  if (!(await page.evaluate(() => "axe" in window))) await page.addScriptTag({ path: AXE_PATH });
  return page.evaluate(async () => {
    const results = await (window as unknown as { axe: { run(ctx: unknown, opts: unknown): Promise<{ violations: Array<{ id: string; impact: string | null; help: string; nodes: Array<{ target: unknown[]; html: string; failureSummary?: string }> }> }> } }).axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] },
    });
    return results.violations.map((v) => ({
      rule: v.id, impact: v.impact, help: v.help,
      nodes: v.nodes.slice(0, 5).map((n) => ({ target: n.target.join(" "), html: n.html.slice(0, 160), summary: (n.failureSummary ?? "").slice(0, 240) })),
      count: v.nodes.length,
    }));
  });
}

/** Opens the clusters canvas at `scene` in `theme`, without a background picture. */
async function openCanvas(page: Page, theme: string, scene = 1): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=${theme}&bg=none`);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  // sleep: the canvas finishes its first layout; no event marks it
  await page.waitForTimeout(800);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  // sleep: the camera flight to the console view
  await page.waitForTimeout(900);
}

/** Opens the palette with the keyboard. */
async function openPalette(page: Page): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  // sleep: the palette's open animation
  await page.waitForTimeout(400);
}

for (const size of SIZES) {
  for (const theme of THEMES) {
    test.describe(`${BROWSER} ${size.name} ${theme}`, () => {
      test.use({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, ...(size.touch ? { hasTouch: true, isMobile: BROWSER === "chromium" } : {}) });

      /** Runs one screen: `body` reaches it; then axe and the probe run, and the files are written. */
      const screen = (name: string, body: (page: Page) => Promise<void>): void => {
        test(name, async ({ page }) => {
          const record: Record<string, unknown> = { screen: name, size: size.name, theme, browser: BROWSER };
          try {
            await body(page);
            // sleep: let the screen settle before it is measured
            await page.waitForTimeout(600);
            record.axe = await axe(page);
            record.probe = await probe(page, size.touch);
            mkdirSync(OUT, { recursive: true });
            await page.screenshot({ path: resolve(OUT, `${name}-${size.name}-${theme}.png`) });
          } catch (error) {
            record.error = String(error).slice(0, 300);
          }
          mkdirSync(OUT, { recursive: true });
          writeFileSync(resolve(OUT, `${name}-${size.name}-${theme}.json`), JSON.stringify(record, null, 1));
        });
      };

      screen("sign-in", async (page) => {
        await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
        await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
        await page.emulateMedia({ colorScheme: theme === "ink" ? "dark" : "light" });
        await page.goto("/");
        await expect(page.locator("#login-passkey")).toBeVisible();
      });
      screen("canvas", async (page) => { await openCanvas(page, theme); });
      screen("sidebar", async (page) => {
        await openCanvas(page, theme);
        await page.locator("#sidebar-toggle").click();
        await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
      });
      screen("palette", async (page) => { await openCanvas(page, theme); await openPalette(page); });
      screen("settings", async (page) => {
        await openCanvas(page, theme, 3);
        await openPalette(page);
        await page.keyboard.type("Settings: Appearance");
        await page.keyboard.press("Enter");
        await expect(page.locator(".ui-sp, .ui-settings").first()).toBeVisible({ timeout: 8000 });
      });
      screen("popover", async (page) => {
        await openCanvas(page, theme);
        await page.locator(".ui-window-pill").first().click();
        await expect(page.locator(".canvas-popover")).toBeVisible();
      });
      screen("addhost", async (page) => {
        await openCanvas(page, theme, 3);
        await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
        await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
      });
      screen("remove-host", async (page) => {
        await page.goto(`/?mock=1&proto=clusters&scene=1&bg=none&removal=1&theme=${theme}`);
        await expect(page.locator(".ui-window").nth(1)).toBeVisible({ timeout: 30_000 });
        await startRemovalFromPalette(page);
        await expect(page.locator(".ui-confirm-tip")).toBeVisible();
      });
      screen("terminal", async (page) => {
        await page.context().request.post("/__mock/reset");
        await page.context().request.post("/__mock/open-terminal");
        await page.goto(`/?mock=1&bg=none&theme=${theme}`);
        await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
      });
    });
  }
}

test.describe(`${BROWSER} keyboard walk`, () => {
  test.use({ viewport: { width: 1440, height: 900 } });
  /** Presses Tab up to 80 times on `page`, and writes who got focus, whether a ring showed, and where it was on screen. */
  async function walk(page: Page, label: string): Promise<void> {
    const stops: Array<{ el: string; name: string; ring: boolean; onScreen: boolean; role: string | null }> = [];
    for (let i = 0; i < 80; i++) {
      await page.keyboard.press("Tab");
      await page.mouse.move(1, 1);
      const stop = await page.evaluate((describeSrc) => {
        const describe = eval(describeSrc) as (el: Element) => string;
        const el = document.activeElement as HTMLElement;
        if (!el || el === document.body) return null;
        const cs = getComputedStyle(el);
        const r = el.getBoundingClientRect();
        const ring = (cs.outlineStyle !== "none" && cs.outlineWidth !== "0px") || cs.boxShadow !== "none" || el.getAttribute("data-focus-ring") === "on";
        return { el: describe(el), name: (el.getAttribute("aria-label") ?? el.textContent ?? "").trim().slice(0, 40), ring, onScreen: r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth, role: el.getAttribute("role") };
      }, DESCRIBE);
      if (stop === null) { stops.push({ el: "(body)", name: "", ring: false, onScreen: false, role: null }); break; }
      stops.push(stop);
      if (stops.length > 2 && stops[0]!.el === stop.el && i > 0) break;
    }
    mkdirSync(OUT, { recursive: true });
    writeFileSync(resolve(OUT, `tabwalk-${label}.json`), JSON.stringify(stops, null, 1));
  }
  test("Tab order of the canvas, sign-in and palette", async ({ page }) => {
    await openCanvas(page, "ink");
    await walk(page, "canvas");
    await openPalette(page);
    const trapped = await page.evaluate(async () => {
      const inside = (): boolean => !!document.activeElement?.closest("#palette");
      return { startedInside: inside() };
    });
    for (let i = 0; i < 6; i++) await page.keyboard.press("Tab");
    const focusAfterTabs = await page.evaluate(() => ({ el: document.activeElement?.id || document.activeElement?.className || "", inPalette: !!document.activeElement?.closest("#palette") }));
    await page.keyboard.press("Escape");
    const afterEscape = await page.evaluate(() => ({ el: (document.activeElement as HTMLElement | null)?.id || document.activeElement?.tagName, paletteHidden: getComputedStyle(document.querySelector("#palette")!).display === "none" || !document.querySelector("#palette")!.checkVisibility() }));
    mkdirSync(OUT, { recursive: true });
    writeFileSync(resolve(OUT, "palette-focus.json"), JSON.stringify({ trapped, focusAfterTabs, afterEscape }, null, 1));
  });
  test("Tab order of sign-in", async ({ page }) => {
    await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
    await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
    await page.goto("/");
    await expect(page.locator("#login-passkey")).toBeVisible();
    await walk(page, "sign-in");
  });
});

test.describe(`${BROWSER} reduced motion and zoom`, () => {
  test("prefers-reduced-motion: what still animates", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
    const page = await context.newPage();
    const result: Record<string, unknown> = {};
    for (const [name, open] of [
      ["sign-in", async () => { await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } })); await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} })); await page.goto("/"); await expect(page.locator("#login-passkey")).toBeVisible(); }],
      ["canvas", async () => { await page.unroute("**/auth/status"); await page.unroute("**/auth/session"); await openCanvas(page, "ink"); }],
    ] as const) {
      await open();
      // sleep: let any entrance animation start so it is visible to getAnimations
      await page.waitForTimeout(1200);
      const snapshot = await page.evaluate(() => ({
        running: document.getAnimations().filter((a) => a.playState === "running").map((a) => ({ name: (a as CSSAnimation).animationName ?? (a as CSSTransition).transitionProperty ?? "waapi", target: (a.effect as KeyframeEffect | null)?.target ? ((a.effect as KeyframeEffect).target as Element).tagName + "." + String(((a.effect as KeyframeEffect).target as Element).className).slice(0, 40) : "", iterations: (a.effect?.getComputedTiming().iterations ?? 0) })).slice(0, 40),
        canvases: Array.from(document.querySelectorAll("canvas")).map((c) => ({ cls: c.className, w: c.width, h: c.height, visible: c.checkVisibility() })),
      }));
      // Two frames of the first canvas, to see whether pixels move while the user asked for no motion.
      const moved = await page.evaluate(async () => {
        const c = Array.from(document.querySelectorAll("canvas")).find((x) => x.checkVisibility() && x.width > 0);
        if (!c) return null;
        const hash = (): number => { try { const t = document.createElement("canvas"); t.width = 64; t.height = 64; t.getContext("2d")!.drawImage(c, 0, 0, 64, 64); const d = t.getContext("2d")!.getImageData(0, 0, 64, 64).data; let h = 0; for (let i = 0; i < d.length; i++) h = (h * 31 + d[i]!) | 0; return h; } catch { return -1; } };
        const a = hash(); await new Promise((r) => setTimeout(r, 700)); const b = hash();
        return { a, b, changed: a !== b };
      });
      result[name] = { ...snapshot, canvasMoved: moved };
    }
    mkdirSync(OUT, { recursive: true });
    writeFileSync(resolve(OUT, "reduced-motion.json"), JSON.stringify(result, null, 1));
    await context.close();
  });

  test("200% zoom (720 x 450 CSS px at 1440 x 900) and 200% text", async ({ browser }) => {
    const out: Record<string, unknown> = {};
    for (const mode of ["page-zoom", "text-zoom"] as const) {
      const context = await browser.newContext({ viewport: mode === "page-zoom" ? { width: 720, height: 450 } : { width: 1440, height: 900 }, deviceScaleFactor: 2 });
      const page = await context.newPage();
      await openCanvas(page, "ink");
      if (mode === "text-zoom") await page.addStyleTag({ content: "html { font-size: 220% !important; }" });
      // sleep: layout after the zoom change
      await page.waitForTimeout(800);
      out[mode] = await page.evaluate(() => {
        const bad: Array<{ el: string; clipped: string }> = [];
        for (const el of Array.from(document.querySelectorAll<HTMLElement>("button, a, [role=button], input, label, .row, .result"))) {
          const r = el.getBoundingClientRect();
          if (r.width === 0 || r.height === 0) continue;
          const cs = getComputedStyle(el);
          if (el.scrollWidth > el.clientWidth + 2 && (cs.overflowX === "hidden" || cs.textOverflow === "ellipsis") && (el.textContent ?? "").trim().length > 2) bad.push({ el: el.tagName.toLowerCase() + "." + String(el.className).slice(0, 30), clipped: `${el.scrollWidth}>${el.clientWidth}: ${(el.textContent ?? "").trim().slice(0, 30)}` });
        }
        return { docScrollW: document.documentElement.scrollWidth, innerW: innerWidth, clippedText: bad.slice(0, 15), clippedCount: bad.length };
      });
      mkdirSync(OUT, { recursive: true });
      await page.screenshot({ path: resolve(OUT, `zoom-${mode}.png`) });
      await context.close();
    }
    writeFileSync(resolve(OUT, "zoom.json"), JSON.stringify(out, null, 1));
  });

  test("terminal: roles, names, live regions", async ({ page }) => {
    await page.context().request.post("/__mock/reset");
    await page.context().request.post("/__mock/open-terminal");
    await page.goto("/?mock=1&bg=none");
    await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
    const info = await page.evaluate(() => {
      const t = document.querySelector("#terminal-screen")!;
      const attrs = (el: Element) => Object.fromEntries(Array.from(el.attributes).filter((a) => /^(role|aria-|tabindex|contenteditable|data-connected|inputmode|autocapitalize|spellcheck)/.test(a.name)).map((a) => [a.name, a.value]));
      return {
        screen: attrs(t),
        textareas: Array.from(document.querySelectorAll("textarea, [contenteditable], input")).map((e) => ({ tag: e.tagName, ...attrs(e) })),
        liveRegions: Array.from(document.querySelectorAll("[aria-live], [role=status], [role=alert], [role=log]")).map((e) => ({ tag: e.tagName, id: e.id, cls: String(e.className).slice(0, 30), ...attrs(e) })),
        canvases: Array.from(document.querySelectorAll("#terminal-screen canvas")).map((e) => attrs(e)),
        hasTextRender: !!Array.from(document.querySelectorAll("#terminal-screen *")).find((e) => (e.textContent ?? "").trim().length > 20),
        focusedAfterLoad: document.activeElement?.tagName + "#" + (document.activeElement?.id ?? ""),
      };
    });
    mkdirSync(OUT, { recursive: true });
    writeFileSync(resolve(OUT, "terminal-a11y.json"), JSON.stringify(info, null, 1));
  });
});
