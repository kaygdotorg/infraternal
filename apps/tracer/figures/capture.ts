// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Captures the figures of the user docs (#302): `bun run docs:figures` from apps/tracer.
 *
 * What it does. Builds the app's preview build with the demo dataset (playwright.figures.config.ts: TRACER_DATASET=docs), serves it with
 * the test double running the same dataset, and for every entry of figures.ts, at each size (desktop 2x, phone 3x) and in each scheme
 * (ink, paper): opens the product, reaches the state through its own UI, checks that no internal name is on the page, and writes
 * the picture. A figure with a clip is then played again from the same state and recorded. Everything lands in `docs/user/figures/`
 * with `manifest.json`, which the docs build reads (docs-figure.ts). That folder is git-ignored: nothing it writes is committed (where the docs' media lives is undecided), and a page whose pictures are not there shows "Figure pending" under the caption. Run it again after the UI changes and the pictures follow.
 *
 * Deterministic. The clock is fixed (March 14, 09:41, UTC) and the locale is en-US; the cursor never blinks (its animation is held at
 * one opacity); stills are taken under reduced motion so every state is at rest; the demo dataset is the same every run. Clips are
 * recorded with motion on, because the motion is what they show.
 *
 * Small. Stills are WebP encoded by the browser itself (a canvas), clips are WebM from the browser's screencast: no encoder is added to
 * the toolchain. A picture over MAX_STILL bytes or a clip over MAX_CLIP fails the run, so the pages stay light.
 *
 * Safe. Before any picture the page's text, labels and tooltips are searched for the internal names, private addresses and key shapes
 * of docs-dataset.ts (`findLeaks`). A single hit fails the capture: a name the dataset missed never reaches a screenshot.
 *
 * `FIGURES_ONLY=a,b` limits the run to those figures, `FIGURES_SIZES=desktop` to a size, `FIGURES_PREVIEW=<dir>` also writes PNG copies
 * to look at, and `FIGURES_OUT=<dir>` writes somewhere other than docs/user/figures (the manifest then holds only what was captured).
 */
import { mkdirSync, readFileSync, existsSync, statSync, writeFileSync, renameSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Browser, type BrowserContext, type Page } from "playwright/test";
import { findLeaks } from "../docs-dataset";
import { FIGURE_SCHEMES, FIGURE_SIZES, figureFile, type FigureManifest } from "../docs-figure";
import { FIGURES, SIZES, type Crop, type Figure, type Scheme, type SizeName } from "./figures";

const OUT = resolve(process.env.FIGURES_OUT ?? resolve(import.meta.dirname, "../../../docs/user/figures"));
const PREVIEW = process.env.FIGURES_PREVIEW ? resolve(process.env.FIGURES_PREVIEW) : undefined;
const ONLY = process.env.FIGURES_ONLY?.split(",").map((name) => name.trim()).filter(Boolean);
const ONLY_SIZES = process.env.FIGURES_SIZES?.split(",").map((name) => name.trim()) as SizeName[] | undefined;
const FIXED_TIME = "2026-03-14T09:41:00Z";
/** WebP quality of a still, 0..1. Flat interface colours stay clean at this level and the files stay small. */
const STILL_QUALITY = 0.9;
const MAX_STILL = 160_000;
const MAX_CLIP = 1_000_000;

test.describe.configure({ mode: "serial" });
test.setTimeout(5 * 60_000);

const manifest: FigureManifest = {};
mkdirSync(OUT, { recursive: true });
const manifestPath = resolve(OUT, "manifest.json");
// A partial run keeps what earlier runs captured.
const existing: FigureManifest = existsSync(manifestPath) && !process.env.FIGURES_OUT ? JSON.parse(readFileSync(manifestPath, "utf8")) : {};

/** Holds the cursor at one opacity: its blink is an animation the page starts, and a still must not depend on its phase. */
const STEADY_CURSOR = `(() => {
  const animate = Element.prototype.animate;
  Element.prototype.animate = function (keyframes, options) {
    return this.classList?.contains("terminal-cursor-layer") ? animate.call(this, [{ opacity: 1 }, { opacity: 1 }], options) : animate.call(this, keyframes, options);
  };
})();`;

async function openContext(browser: Browser, size: SizeName, scheme: Scheme, viewport: { width: number; height: number }, still: boolean): Promise<BrowserContext> {
  const spec = SIZES[size];
  return browser.newContext({
    viewport, deviceScaleFactor: still ? spec.scale : 1, hasTouch: spec.touch, isMobile: spec.touch,
    colorScheme: scheme === "ink" ? "dark" : "light", reducedMotion: still ? "reduce" : "no-preference",
    locale: "en-US", timezoneId: "UTC",
  });
}

async function openPage(context: BrowserContext, address: string): Promise<Page> {
  const page = await context.newPage();
  await page.addInitScript(STEADY_CURSOR);
  await page.clock.setFixedTime(new Date(FIXED_TIME));
  await page.goto(address);
  return page;
}

/**
 * The mockups' own scaffolding (the "mockup" tag, the test-double badge, the frame counter) is not the product and is not in a
 * picture. It is hidden, not removed, so the page a figure is taken from is the page the specs know. Applied after the figure has
 * reached its state, because a figure's steps may wait for these elements.
 */
async function hideScaffolding(page: Page): Promise<void> {
  await page.addStyleTag({ content: ".cl-mockup, .test-double-badge, [data-mockup-chrome], .perf-hud { display: none !important; }" });
}

/** Everything a reader (or a screen reader) could see: text, labels, tooltips, placeholders, the title. */
async function visibleWords(page: Page): Promise<string> {
  return page.evaluate(() => {
    const parts = [document.title, document.body.innerText];
    for (const element of document.querySelectorAll("[aria-label],[title],[data-tip],[placeholder],[alt]")) {
      for (const name of ["aria-label", "title", "data-tip", "placeholder", "alt"]) parts.push(element.getAttribute(name) ?? "");
    }
    return parts.join("\n");
  });
}

async function assertClean(page: Page, label: string): Promise<void> {
  const leaks = findLeaks(await visibleWords(page));
  expect(leaks, `${label}: internal names on the page (add them to docs-dataset.ts)`).toEqual([]);
}

/** The region of the window a picture shows, in CSS px, kept inside the window. */
async function regionOf(page: Page, crop: Crop, viewport: { width: number; height: number }): Promise<{ x: number; y: number; width: number; height: number }> {
  if ("whole" in crop) return { x: 0, y: 0, width: viewport.width, height: viewport.height };
  const box = await crop.around(page).boundingBox();
  if (!box) throw new Error("the element a figure is cropped around is not on the page");
  const x = Math.max(0, Math.floor(box.x - crop.air)), y = Math.max(0, Math.floor(box.y - crop.air));
  const right = Math.min(viewport.width, Math.ceil(box.x + box.width + crop.air)), bottom = Math.min(viewport.height, Math.ceil(box.y + box.height + crop.air));
  return { x, y, width: right - x, height: bottom - y };
}

/** PNG to WebP with the browser's own encoder, so no tool has to be installed. */
async function toWebp(page: Page, png: Buffer): Promise<Buffer> {
  const base64 = await page.evaluate(async ({ data, quality }) => {
    const image = new Image();
    image.src = `data:image/png;base64,${data}`;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth; canvas.height = image.naturalHeight;
    canvas.getContext("2d")!.drawImage(image, 0, 0);
    const blob = await new Promise<Blob>((done, fail) => canvas.toBlob((b) => (b ? done(b) : fail(new Error("webp encoding is not available"))), "image/webp", quality));
    return await new Promise<string>((done) => { const reader = new FileReader(); reader.onload = () => done(String(reader.result).split(",")[1]!); reader.readAsDataURL(blob); });
  }, { data: png.toString("base64"), quality: STILL_QUALITY });
  return Buffer.from(base64, "base64");
}

const viewportOf = (figure: Figure, size: SizeName): { width: number; height: number } => ({ ...SIZES[size], ...(figure.viewport?.[size] ?? {}) });
const cropOf = (figure: Figure, size: SizeName): Crop => ("whole" in figure.crop || "around" in figure.crop ? figure.crop as Crop : (figure.crop as Partial<Record<SizeName, Crop>>)[size] ?? { whole: true });

for (const figure of FIGURES) {
  if (ONLY && !ONLY.includes(figure.name)) continue;
  for (const size of FIGURE_SIZES) {
    if (ONLY_SIZES && !ONLY_SIZES.includes(size)) continue;
    for (const scheme of FIGURE_SCHEMES) {
      test(`${figure.name} · ${size} · ${scheme}`, async ({ browser }) => {
        const viewport = viewportOf(figure, size);
        const box = { width: 0, height: 0 };
        // ---- the still ----
        const stillContext = await openContext(browser, size, scheme, viewport, true);
        try {
          const page = await openPage(stillContext, figure.address(scheme, size));
          await figure.prepare(page, size);
          await hideScaffolding(page);
          await assertClean(page, `${figure.name} ${size} ${scheme}`);
          const region = await regionOf(page, cropOf(figure, size), viewport);
          box.width = region.width; box.height = region.height;
          const png = await page.screenshot({ clip: region, animations: "disabled", caret: "initial" });
          const encoder = await stillContext.newPage();
          const webp = await toWebp(encoder, png);
          await encoder.close();
          expect(webp.length, `${figure.name} ${size} ${scheme}: the picture stays light`).toBeLessThan(MAX_STILL);
          writeFileSync(resolve(OUT, figureFile(figure.name, size, scheme, "webp")), webp);
          if (PREVIEW) { mkdirSync(PREVIEW, { recursive: true }); writeFileSync(resolve(PREVIEW, `${figure.name}.${size}.${scheme}.png`), png); }
        } finally {
          await stillContext.close();
        }
        // ---- the clip: the same window, played ----
        if (figure.clip) {
          const clipContext = await openContext(browser, size, scheme, viewport, false);
          try {
            const page = await openPage(clipContext, figure.address(scheme, size));
            await figure.prepare(page, size);
            await hideScaffolding(page);
            const temporary = resolve(OUT, `.${figureFile(figure.name, size, scheme, "webm")}`);
            await page.screencast.start({ path: temporary, size: { width: viewport.width, height: viewport.height } });
            await figure.clip(page, (ms) => page.waitForTimeout(ms));
            await page.screencast.stop();
            await assertClean(page, `${figure.name} ${size} ${scheme} (clip)`);
            expect(statSync(temporary).size, `${figure.name} ${size} ${scheme}: the clip stays under about 1 MB`).toBeLessThan(MAX_CLIP);
            renameSync(temporary, resolve(OUT, figureFile(figure.name, size, scheme, "webm")));
          } finally {
            rmSync(resolve(OUT, `.${figureFile(figure.name, size, scheme, "webm")}`), { force: true });
            await clipContext.close();
          }
        }
        const entry = (manifest[figure.name] ??= structuredClone(existing[figure.name]) ?? { desktop: { width: 0, height: 0 }, phone: { width: 0, height: 0 } });
        entry[size] = { width: box.width, height: box.height };
        if (figure.clip) entry.clip = true;
      });
    }
  }
}

test.afterAll(() => {
  const merged: FigureManifest = { ...existing, ...manifest };
  writeFileSync(manifestPath, `${JSON.stringify(merged, null, 2)}\n`);
});
