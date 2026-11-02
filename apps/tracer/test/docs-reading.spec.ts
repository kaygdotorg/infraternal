// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The reading aids of the docs (#302) in a production build: callout panels, the folded reasoning block, numbered citations with links
 * both ways, quotes, tables, code that copies, quick facts, a type scale that steps, and the contents that follow the reader.
 *
 * Measured, not eyeballed (TASTE): a callout's box starts on the text's left edge and its icon and title share a centre line (±0.5 px);
 * the icon reaches 3:1 against its panel and the title 4.5:1, over the real background, in ink and paper; a citation can be hit from
 * outside its glyph on touch; the section being read is marked in the contents, and every entry keeps its left edge when the mark moves;
 * the code's "Copied" sits on the code's own first line. Desktop is 1440×900 at 2×, the phone 393×852 at 3×. Captures go to the
 * external evidence directory. The canvas reader is checked at the end (the same module, in a window).
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("docs-reading");
const SIZES = [
  { name: "desktop", width: 1440, height: 900, scale: 2, touch: false },
  { name: "phone", width: 393, height: 852, scale: 3, touch: true },
] as const;

/** Headless Chromium reports a fine pointer even with touch emulation, so the page's own `pointer: coarse` rule is applied as a phone would. */
async function asPhone(page: Page): Promise<void> {
  const source = await (await page.request.get("/docs/docs.css")).text();
  const css = /@media \(pointer: coarse\)\s*\{\s*(:root\s*\{[^}]*\})\s*\}/.exec(source)?.[1] ?? "";
  expect(css, "docs.css has a pointer: coarse rule").toContain("--text-body: 16px");
  const reading = await (await page.request.get("/docs/doc.css")).text();
  // Every `@media (pointer: coarse)` block of doc.css, so the 44 px rows and larger hit areas are the real rules.
  const coarse = [...reading.matchAll(/@media \(pointer: coarse\)\s*\{((?:[^{}]|\{[^{}]*\})*)\}/g)].map((m) => m[1]).join("\n");
  await page.addStyleTag({ content: `${css}\n${coarse}` });
}

/** Contrast between two CSS colours, read as the browser paints them (a canvas resolves `color-mix`, `rgb(from …)` and the rest). */
async function contrast(page: Page, foreground: string, background: string): Promise<number> {
  return page.evaluate(([fg, bg]) => {
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 1;
    const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
    const pixel = (color: string): number[] => { ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = "#000"; ctx.fillRect(0, 0, 1, 1); ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = color; ctx.fillRect(0, 0, 1, 1); return [...ctx.getImageData(0, 0, 1, 1).data]; };
    const luminance = (rgb: number[]): number => { const [r, g, b] = rgb.slice(0, 3).map((v) => { const c = v! / 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!; };
    const a = luminance(pixel(fg!)), b = luminance(pixel(bg!));
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  }, [foreground, background]);
}

for (const size of SIZES) for (const scheme of ["dark", "light"] as const) {
  test(`${size.name} ${scheme}: callouts, reasoning, citations, tables, code and the contents read well and line up`, async ({ browser }) => {
    mkdirSync(OUT, { recursive: true });
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: scheme });
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    const page = await context.newPage();
    const failures: string[] = [];
    page.on("pageerror", (error) => failures.push(error.message));
    page.on("response", (response) => { if (response.status() >= 400) failures.push(`${response.status()} ${response.url()}`); });
    const shot = (name: string, full = false) => page.screenshot({ path: `${OUT}/${size.name}-${scheme}-${name}.png`, fullPage: full });
    const scrollToHeading = async (id: string) => {
      await page.evaluate((target) => { const h = document.getElementById(target)!; window.scrollTo(0, h.getBoundingClientRect().top + window.scrollY - 24); }, id);
      await page.waitForTimeout(220);
    };
    try {
      await page.goto("/docs/reference/keys/");
      if (size.touch) await asPhone(page);
      await page.evaluate(() => document.fonts.ready);
      await shot("keys-top");

      // ---- the type steps: title > section > sub-section > body, each a fixed ratio of the body -----------------------------------
      const scale = await page.evaluate(() => { const px = (selector: string) => parseFloat(getComputedStyle(document.querySelector(selector)!).fontSize); return { body: px(".doc-body > p"), h1: px("h1"), h2: px(".doc-body h2"), h3: px(".doc-body h3") }; });
      expect(scale.h1).toBeGreaterThan(scale.h2);
      expect(scale.h2).toBeGreaterThan(scale.h3);
      expect(scale.h3).toBeGreaterThan(scale.body);
      expect(Math.abs(scale.h2 / scale.body - 1.3), "sections are 1.3 times the body").toBeLessThanOrEqual(0.02);

      // ---- callout panels ------------------------------------------------------------------------------------------------------
      const callouts = await page.evaluate(() => {
        const left = document.querySelector(".doc-body > p")!.getBoundingClientRect().left;
        const width = document.querySelector(".doc-body")!.getBoundingClientRect().width;
        return [...document.querySelectorAll<HTMLElement>(".callout")].map((c) => {
          const box = c.getBoundingClientRect();
          const icon = c.querySelector(".callout-title svg")!.getBoundingClientRect();
          const label = c.querySelector(".callout-title span")!.getBoundingClientRect();
          const style = getComputedStyle(c);
          return {
            kind: c.className.replace("callout callout-", ""), left: box.left - left, over: box.width - width,
            iconMid: icon.top + icon.height / 2, labelMid: label.top + label.height / 2, iconSize: icon.width, iconToLabel: label.left - icon.right,
            padLeft: parseFloat(style.paddingLeft), titleLeft: label.left - box.left,
            stroke: getComputedStyle(c.querySelector(".callout-title svg")!).stroke, ink: getComputedStyle(c.querySelector(".callout-title span")!).color, fill: style.backgroundColor,
            titleText: c.querySelector(".callout-title span")!.textContent,
          };
        });
      });
      expect(callouts.map((c) => c.kind).sort()).toEqual(["caution", "facts", "facts", "important", "note", "tip", "warning", "warning", "warning", "warning", "warning", "warning", "warning"]);
      const bodyBg = scheme === "dark" ? "rgb(16, 17, 19)" : "rgb(246, 246, 244)";
      for (const c of callouts) {
        expect(Math.abs(c.left), `${c.kind}: the panel starts on the text's left edge`).toBeLessThanOrEqual(0.5);
        expect(c.over, `${c.kind}: the panel is no wider than the text`).toBeLessThanOrEqual(0.5);
        expect(Math.abs(c.iconMid - c.labelMid), `${c.kind}: icon and title share a centre line`).toBeLessThanOrEqual(0.5);
        expect(c.iconSize, `${c.kind}: icon size`).toBeCloseTo(size.touch ? 20 : 17, 0);
        expect(Math.abs(c.titleLeft - c.padLeft - c.iconSize - 8), `${c.kind}: title starts one gap after the icon`).toBeLessThanOrEqual(1.5);
        // Over the real background: the fill is the tone at 9% on the page colour.
        const panel = await page.evaluate(([fill, page]) => { const c = document.createElement("canvas").getContext("2d")!; c.fillStyle = page!; c.fillRect(0, 0, 1, 1); c.fillStyle = fill!; c.fillRect(0, 0, 1, 1); const d = c.getImageData(0, 0, 1, 1).data; return `rgb(${d[0]}, ${d[1]}, ${d[2]})`; }, [c.fill, bodyBg]);
        expect(await contrast(page, c.stroke, panel), `${c.kind}: icon against its panel`).toBeGreaterThanOrEqual(3);
        expect(await contrast(page, c.ink, panel), `${c.kind}: title against its panel`).toBeGreaterThanOrEqual(4.5);
      }
      await page.locator(".callout-warning").first().scrollIntoViewIfNeeded();
      await shot("keys-callout");

      // ---- quick facts: the panel on the page says what index.json says (the "?" preview reads the index) ----------------------
      const index = await (await page.request.get("/docs/index.json")).json() as { pages: { slug: string; headings: { id: string; facts?: string }[] }[] };
      const fromIndex = index.pages.find((p) => p.slug === "reference/keys")!.headings.filter((h) => h.facts);
      expect(fromIndex.map((h) => h.id)).toEqual(["browser-sign-in", "host-certificate"]);
      for (const h of fromIndex) {
        const shown = await page.evaluate((id) => { let n = document.getElementById(id)!.nextElementSibling; while (n && !n.matches(".callout-facts")) n = n.nextElementSibling; return n!.textContent!.replace(/^\s*Quick facts\s*/, "").replace(/\s+/g, " ").trim(); }, h.id);
        expect(shown).toBe(h.facts!);
      }

      // ---- the reasoning block: folded, a 44 px row on touch, opens and closes ---------------------------------------------------
      const why = page.locator("details.why").first();
      await why.scrollIntoViewIfNeeded();
      expect(await why.getAttribute("open")).toBeNull();
      const row = await why.locator("summary").boundingBox();
      expect(row!.height).toBeGreaterThanOrEqual(size.touch ? 44 : 28);
      await why.locator("summary").click();
      await page.waitForTimeout(350);
      expect(await why.getAttribute("open")).not.toBeNull();
      await expect(why.locator(".why-body p").first()).toBeVisible();
      const whyEdges = await page.evaluate(() => { const w = document.querySelector("details.why")!; return { box: w.getBoundingClientRect().left, text: document.querySelector(".doc-body > p")!.getBoundingClientRect().left, body: w.querySelector(".why-body p")!.getBoundingClientRect().left, title: w.querySelector("summary")!.getBoundingClientRect().left }; });
      expect(Math.abs(whyEdges.box - whyEdges.text), "the reasoning panel starts on the text's left edge").toBeLessThanOrEqual(0.5);
      expect(Math.abs(whyEdges.body - whyEdges.title - 16), "its text is inset like its title").toBeLessThanOrEqual(0.5);
      await shot("keys-why-open");
      await why.locator("summary").click();
      await page.waitForTimeout(350);
      expect(await why.getAttribute("open")).toBeNull();

      // ---- citations: a number in the text, the source under References, a way back --------------------------------------------
      const cites = await page.locator("sup.cite a").evaluateAll((links) => links.map((a) => [a.textContent, a.getAttribute("href")]));
      expect(cites).toEqual([["1", "#source-1"], ["2", "#source-2"], ["3", "#source-3"], ["4", "#source-4"]]);
      const first = page.locator("#ref-1");
      await first.scrollIntoViewIfNeeded();
      if (size.touch) {
        // A finger is bigger than a number: a point 10 px outside the glyph still lands on the link.
        const box = (await first.boundingBox())!;
        const hit = await page.evaluate(([x, y]) => document.elementFromPoint(x!, y!)?.closest("a")?.id ?? "", [box.x - 10, box.y + box.height / 2]);
        expect(hit, "a tap just beside the number still lands on it").toBe("ref-1");
      }
      await first.click();
      await page.waitForTimeout(300);
      expect(new URL(page.url()).hash).toBe("#source-1");
      // References end the page, so the page cannot always scroll far enough to put the source at the very top: it must be in view and marked.
      expect(await page.evaluate(() => { const r = document.getElementById("source-1")!.getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight; }), "the source is in view").toBe(true);
      expect(await page.evaluate(() => document.getElementById("source-1")!.matches(":target")), "and marked as the target").toBe(true);
      await shot("keys-references");
      await page.locator("#source-1 a.back").click();
      await page.waitForTimeout(300);
      expect(new URL(page.url()).hash).toBe("#ref-1");
      expect(await page.evaluate(() => { const r = document.getElementById("ref-1")!.getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight; }), "the back link returns to the citation").toBe(true);
      // The references are a list with its numbers on the text's left edge, and listed in the contents.
      await expect(page.locator("h2#references")).toHaveText("References");
      expect(await page.evaluate(() => [...document.querySelectorAll(".toc-fold a")].some((a) => a.getAttribute("href") === "#references"))).toBe(true);

      // ---- the contents follow the reader ---------------------------------------------------------------------------------------
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.waitForTimeout(220);
      expect(await page.locator('.toc a[aria-current="location"]').count(), "nothing is current above the first section").toBe(0);
      const list = size.touch ? ".toc-fold" : ".toc-side";
      for (const id of ["signing-in", "host-certificate", "wireguard-static-key", "references"]) {
        await scrollToHeading(id);
        expect(await page.locator(`${list} a[aria-current="location"]`).evaluateAll((links) => links.map((a) => a.getAttribute("href"))), `reading ${id}`).toEqual([`#${id}`]);
      }
      // The mark moves without moving anything: every entry of a level keeps its left edge, current or not.
      if (size.touch) await page.evaluate(() => { document.querySelector<HTMLDetailsElement>(".toc-fold")!.open = true; });
      const edges = await page.evaluate((root) => {
        const lefts = (selector: string) => [...document.querySelectorAll<HTMLAnchorElement>(selector)].filter((a) => a.getBoundingClientRect().width > 0).map((a) => a.getBoundingClientRect().left);
        return { top: lefts(`${root} > ol > li > a`), sub: lefts(`${root} ol ol a`) };
      }, list);
      expect(Math.max(...edges.top) - Math.min(...edges.top), "top-level entries share one left edge").toBeLessThanOrEqual(0.5);
      expect(Math.max(...edges.sub) - Math.min(...edges.sub), "sub-entries share one left edge").toBeLessThanOrEqual(0.5);
      if (!size.touch) {
        await scrollToHeading("host-certificate");
        await shot("keys-contents-rail");
        const bar = await page.evaluate(() => getComputedStyle(document.querySelector('.toc-side a[aria-current="location"]')!).boxShadow);
        expect(bar, "the current entry has its bar").not.toBe("none");
      }

      // ---- a quote, a table and code on the multiplexer page -------------------------------------------------------------------
      await page.goto("/docs/terminal/multiplexer/");
      if (size.touch) await asPhone(page);
      await page.evaluate(() => document.fonts.ready);
      const quote = await page.evaluate(() => { const q = document.querySelector<HTMLElement>(".doc-body > blockquote")!; const s = getComputedStyle(q); return { left: q.getBoundingClientRect().left - document.querySelector(".doc-body > p")!.getBoundingClientRect().left, rule: s.borderLeftWidth, pad: s.paddingLeft }; });
      expect(Math.abs(quote.left), "the quote starts on the text's left edge").toBeLessThanOrEqual(0.5);
      expect(quote.rule).toBe("2px");
      const table = page.locator(".doc-body .table").first();
      await table.scrollIntoViewIfNeeded();
      const tableLook = await table.evaluate((box) => { const th = box.querySelector("th")!; return { left: box.getBoundingClientRect().left - document.querySelector(".doc-body > p")!.getBoundingClientRect().left, band: getComputedStyle(th).backgroundColor, radius: getComputedStyle(box).borderTopLeftRadius }; });
      expect(Math.abs(tableLook.left), "the table box starts on the text's left edge").toBeLessThanOrEqual(0.5);
      expect(tableLook.band, "the header row has its own band").not.toBe("rgba(0, 0, 0, 0)");
      expect(tableLook.radius).not.toBe("0px");
      await shot("multiplexer-table");

      const block = page.locator(".doc-code").first();
      await block.scrollIntoViewIfNeeded();
      const code = (await block.locator("pre").textContent())!.replace(/\n$/, "");
      expect(await block.locator("pre").evaluate((pre) => getComputedStyle(pre).cursor), "the pointer says a block copies").toBe("pointer");
      if (size.touch) {
        // One tap is how a finger starts a scroll: it copies nothing. A double tap copies.
        const at = (await block.boundingBox())!;
        await page.touchscreen.tap(at.x + 40, at.y + 20);
        await page.waitForTimeout(500);
        expect(await block.getAttribute("data-copied"), "one tap does not copy").toBeNull();
        await page.touchscreen.tap(at.x + 40, at.y + 20);
        await page.touchscreen.tap(at.x + 40, at.y + 20);
      } else {
        await block.locator("pre").click();
      }
      await expect(block).toHaveAttribute("data-copied", "");
      await expect(block.locator(".ui-copied")).toHaveText("Copied");
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(code);
      await page.waitForTimeout(260);
      // The first line of the block: the block's top, its padding, and half the block's own line height (the code inside is a little smaller).
      const copied = await block.evaluate((b) => { const o = b.querySelector(".ui-copied")!.getBoundingClientRect(); const pre = b.querySelector("pre")!; const c = b.querySelector("pre code")!; const style = getComputedStyle(pre); const line = parseFloat(style.lineHeight); const r = c.getBoundingClientRect(); return { left: o.left - r.left, mid: o.top + o.height / 2 - (pre.getBoundingClientRect().top + parseFloat(style.paddingTop) + line / 2), codeOpacity: getComputedStyle(c).opacity }; });
      expect(Math.abs(copied.left), "Copied starts where the code starts").toBeLessThanOrEqual(0.5);
      expect(Math.abs(copied.mid), "Copied sits on the code's first line").toBeLessThanOrEqual(0.5);
      expect(copied.codeOpacity, "the code gives way to the confirmation").toBe("0");
      await shot("multiplexer-copied");
      await expect(block).not.toHaveAttribute("data-copied", "", { timeout: 3000 });
      await shot("multiplexer-top");
      await shot("multiplexer-full", true);

      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), "nothing scrolls sideways").toBe(0);
      expect(failures).toEqual([]);
    } finally {
      await context.close();
    }
  });
}

test("the canvas reader: the contents follow the reader inside a window, and a code block copies there too", async ({ browser }) => {
  mkdirSync(OUT, { recursive: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: "dark" });
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const page = await context.newPage();
  try {
    await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=plain&docs=1");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('section.cl[data-view="docs"]')).toBeAttached({ timeout: 15_000 });
    await page.keyboard.press("Control+Shift+K");
    await page.keyboard.type("infraternal multiplexer");
    await page.keyboard.press("Enter");
    const window = '.ui-window[data-window-id="d-terminal/multiplexer"]';
    await expect(page.locator(`${window} .dr-page h1`)).toHaveText("The Infraternal Multiplexer", { timeout: 10_000 });
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(900);
    const camera = await page.evaluate(() => document.querySelector<HTMLElement>(".cl-world")?.style.transform ?? "");
    // A figure in a window picks its picture by the window's width and the app's theme (ink here), not by the browser's own settings.
    // (Only where the figures have been captured: no picture is committed, and otherwise the figure is a placeholder.)
    if (await page.locator(`${window} .figure:not(.figure-pending)`).count() > 0) {
      const figureOf = () => page.evaluate((selector) => { const a = document.querySelector<HTMLElement>(`${selector} .dr-page`)!; const img = a.querySelector<HTMLImageElement>(".figure img")!; return { src: img.currentSrc, narrow: a.clientWidth < 520 }; }, window);
      // (Scroll the window itself, never scrollIntoView, so the lazy picture is near and the canvas stays where it is.)
      await page.evaluate((selector) => { const s = document.querySelector<HTMLElement>(`${selector} .dr-scroll`)!; s.scrollTop = document.querySelector<HTMLElement>(`${selector} .figure`)!.offsetTop - 80; }, window);
      await expect.poll(async () => (await figureOf()).src, { timeout: 8000 }).not.toBe("");
      const figure = await figureOf();
      expect(figure.src, "the window's width chooses the size").toContain(figure.narrow ? ".phone." : ".desktop.");
      expect(figure.src, "the theme chooses ink or paper").toContain(".ink.");
    }
    // Scroll the window to a section: the folded contents mark it.
    await page.evaluate((selector) => { const s = document.querySelector<HTMLElement>(`${selector} .dr-scroll`)!; const h = document.querySelector<HTMLElement>(`${selector} #undoing-a-switch`)!; s.scrollTop = h.offsetTop - 12; }, window);
    await page.waitForTimeout(300);
    expect(await page.locator(`${window} .toc-fold a[aria-current="location"]`).evaluateAll((links) => links.map((a) => a.getAttribute("href")))).toEqual(["#undoing-a-switch"]);
    await page.locator(`${window} .dr-scroll`).evaluate((s) => { s.scrollTop = s.scrollHeight; });
    await page.waitForTimeout(300);
    expect(await page.locator(`${window} .toc-fold a[aria-current="location"]`).evaluateAll((links) => links.map((a) => a.getAttribute("href"))), "the end of the page is the last section").toEqual(["#references"]);
    // A code block copies with a click.
    const block = page.locator(`${window} .doc-code`).first();
    // Scroll the window itself (never scrollIntoView, which could move the canvas) so the block is in view.
    await page.evaluate((selector) => { const s = document.querySelector<HTMLElement>(`${selector} .dr-scroll`)!; const b = document.querySelector<HTMLElement>(`${selector} .doc-code`)!; s.scrollTop = b.offsetTop - 120; }, window);
    await page.waitForTimeout(200);
    await block.locator("pre").click();
    await expect(block).toHaveAttribute("data-copied", "");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain("exec tmux new-session -s main");
    await page.waitForTimeout(260);
    await page.screenshot({ path: `${OUT}/reader-multiplexer-copied.png` });
    expect(await page.evaluate(() => document.querySelector<HTMLElement>(".cl-world")?.style.transform ?? ""), "the canvas did not move").toBe(camera);
  } finally {
    await context.close();
  }
});
