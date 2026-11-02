// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The figures of the docs (docs-figure.ts, #302) on a production build. No picture is committed (docs/user/figures is git-ignored), so
 * what the suite finds depends on whether `bun run docs:figures` has been run where it runs: without the pictures every figure is its
 * caption under a "Figure pending" placeholder, and that is what is measured; with them, the pictures and clips are. Each half runs
 * only where its state exists.
 *
 * With the pictures: a picture of the product with a caption, and a clip that plays
 * only while it is on screen. Measured (TASTE: ±0.5 px): a figure's box starts on the text's left edge and is no wider than the text;
 * its picture is exactly as sharp as it was captured (the file is 2x on desktop, 3x on a phone, of the size the page gives it); its
 * caption sits under it. The browser picks the ink or paper picture by its colour scheme and the phone or desktop picture by width.
 * A clip is laid exactly over its still, plays muted and looping while the figure is on screen, pauses when it leaves, and never
 * starts under reduced motion. Every picture is under 160 KB and every clip under 1 MB.
 */
import { existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("docs-figures");
/** The figures have been captured into the folder this build reads. */
const CAPTURED = existsSync(resolve(import.meta.dirname, "../../../docs/user/figures/manifest.json"));
const PAGES = ["terminal/multiplexer", "reference/keys"] as const;
const SIZES = [
  { name: "desktop", width: 1440, height: 900, scale: 2, touch: false },
  { name: "phone", width: 393, height: 852, scale: 3, touch: true },
] as const;

/** The picture file the browser chose for a figure, and how big it is when drawn. */
const chosen = (page: Page, name: string) => page.evaluate((figure) => {
  const img = document.querySelector<HTMLImageElement>(`.figure[data-figure="${figure}"] img`)!;
  const src = img.currentSrc ? new URL(img.currentSrc).pathname : "";
  // The size the page declared for the picture the browser chose: its <source>, or the plain <img> when that one was chosen.
  const source = [...img.parentElement!.querySelectorAll("source")].find((s) => s.getAttribute("srcset") === src);
  const declared = source ?? img;
  return { src, natural: img.naturalWidth, shown: img.getBoundingClientRect().width, attribute: Number(declared.getAttribute("width")), declaredHeight: Number(declared.getAttribute("height")) };
}, name);

for (const size of SIZES) for (const scheme of ["dark", "light"] as const) {
  test(`${size.name} ${scheme}: figures line up, are sharp, and the browser picks the picture for its scheme and width`, async ({ browser }) => {
    test.skip(!CAPTURED, "the figures have not been captured here (bun run docs:figures)");
    mkdirSync(OUT, { recursive: true });
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: scheme });
    const page = await context.newPage();
    const failures: string[] = [];
    page.on("pageerror", (error) => failures.push(error.message));
    page.on("response", (response) => { if (response.status() >= 400) failures.push(`${response.status()} ${response.url()}`); });
    try {
      for (const slug of PAGES) {
        await page.goto(`/docs/${slug}/`);
        await page.evaluate(() => document.fonts.ready);
        const names = await page.locator(".figure").evaluateAll((figures) => figures.map((f) => (f as HTMLElement).dataset.figure!));
        expect(names.length, `${slug} has figures`).toBeGreaterThan(0);
        for (const name of names) {
          const figure = page.locator(`.figure[data-figure="${name}"]`);
          await figure.scrollIntoViewIfNeeded();
          await expect.poll(async () => (await chosen(page, name)).natural, { message: `${name} loads` }).toBeGreaterThan(0);
          const looks = await page.evaluate((id) => {
            const f = document.querySelector<HTMLElement>(`.figure[data-figure="${id}"]`)!;
            const box = f.querySelector(".figure-media")!.getBoundingClientRect();
            const text = document.querySelector(".doc-body > p")!.getBoundingClientRect();
            const body = document.querySelector(".doc-body")!.getBoundingClientRect();
            const caption = f.querySelector("figcaption")!.getBoundingClientRect();
            const img = f.querySelector("img")!;
            return { left: box.left - text.left, over: box.right - body.right, captionGap: caption.top - box.bottom, loading: img.getAttribute("loading"), decoding: img.getAttribute("decoding"), alt: img.alt, captionText: f.querySelector("figcaption")!.textContent!, ratio: box.width / box.height };
          }, name);
          expect(Math.abs(looks.left), `${name}: starts on the text's left edge`).toBeLessThanOrEqual(0.5);
          expect(looks.over, `${name}: no wider than the text`).toBeLessThanOrEqual(0.5);
          expect(looks.captionGap, `${name}: the caption sits under the picture`).toBeGreaterThanOrEqual(0);
          expect(looks.captionGap, `${name}: and close to it`).toBeLessThanOrEqual(12);
          expect(looks.loading).toBe("lazy");
          expect(looks.decoding).toBe("async");
          expect(looks.alt.length, `${name}: alt text`).toBeGreaterThan(10);
          expect(looks.captionText.length, `${name}: caption`).toBeGreaterThan(10);
          // The shape never changes (no layout shift): the box has the captured picture's proportions.
          const pick = await chosen(page, name);
          expect(Math.abs(looks.ratio - pick.attribute / pick.declaredHeight), `${name}: proportions`).toBeLessThan(0.01);
          expect(Math.abs(pick.natural / (pick.attribute * size.scale) - 1), `${name}: the file is the size declared`).toBeLessThan(0.01);

          // The browser's choice: the picture for the phone below 36rem, for the colour scheme of the reader.
          expect(pick.src, `${name}: size`).toContain(size.touch ? ".phone." : ".desktop.");
          expect(pick.src, `${name}: scheme`).toContain(scheme === "dark" ? ".ink." : ".paper.");
          // Sharp: the file holds the captured scale times the size the page shows (never upscaled).
          if (pick.shown >= pick.attribute - 0.5) expect(pick.natural, `${name}: as sharp as it was captured`).toBe(pick.attribute * size.scale);
          // Light: the file is small.
          const bytes = (await (await page.request.get(pick.src)).body()).length;
          expect(bytes, `${name}: picture under 160 KB`).toBeLessThan(160_000);
          await figure.screenshot({ path: `${OUT}/${size.name}-${scheme}-${slug}-${name}.png` });
        }
      }
      expect(failures).toEqual([]);
    } finally {
      await context.close();
    }
  });
}

test("a clip lies exactly over its still, plays while on screen, pauses when it leaves, and is under 1 MB", async ({ browser }) => {
  test.skip(!CAPTURED, "the figures have not been captured here (bun run docs:figures)");
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: "dark" });
  const page = await context.newPage();
  try {
    await page.goto("/docs/terminal/multiplexer/");
    await page.evaluate(() => document.fonts.ready);
    const clip = page.locator(".figure[data-clip]").first();
    const name = await clip.getAttribute("data-figure");
    expect(name).toBeTruthy();
    // Before it is on screen there is no video at all: the still is all that was loaded.
    expect(await page.locator(".figure-clip").count()).toBe(0);
    await clip.scrollIntoViewIfNeeded();
    await expect(clip.locator("video.figure-clip")).toHaveCount(1, { timeout: 5000 });
    const video = clip.locator("video.figure-clip");
    await expect.poll(() => video.evaluate((v: HTMLVideoElement) => !v.paused && v.currentTime > 0), { timeout: 8000 }).toBe(true);
    const facts = await video.evaluate((v: HTMLVideoElement) => {
      const still = v.parentElement!.querySelector("img")!.getBoundingClientRect();
      const box = v.getBoundingClientRect();
      return { muted: v.muted, loop: v.loop, inline: v.playsInline, src: new URL(v.src).pathname, poster: new URL(v.poster).pathname, dx: box.left - still.left, dy: box.top - still.top, dw: box.width - still.width, dh: box.height - still.height, width: v.videoWidth, height: v.videoHeight };
    });
    expect(facts.muted && facts.loop && facts.inline).toBe(true);
    expect(facts.src).toContain(".desktop.ink.webm");
    expect(facts.poster, "the still is the poster").toContain(".desktop.ink.webp");
    for (const [what, value] of Object.entries({ x: facts.dx, y: facts.dy, width: facts.dw, height: facts.dh })) expect(Math.abs(value), `the clip lies over its still: ${what}`).toBeLessThanOrEqual(0.5);
    // The clip has the proportions of the still, so nothing is cropped or stretched.
    const attr = await clip.locator("img").evaluate((i: HTMLImageElement) => i.width / i.height);
    expect(Math.abs(facts.width / facts.height - attr)).toBeLessThan(0.01);
    expect((await (await page.request.get(facts.src)).body()).length, "the clip is under about 1 MB").toBeLessThan(1_000_000);
    await page.screenshot({ path: `${OUT}/clip-playing.png` });
    // Off screen it pauses.
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect.poll(() => video.evaluate((v: HTMLVideoElement) => v.paused), { timeout: 5000 }).toBe(true);
  } finally {
    await context.close();
  }
});

test("under reduced motion a clip never starts: the still is the figure", async ({ browser }) => {
  test.skip(!CAPTURED, "the figures have not been captured here (bun run docs:figures)");
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark", reducedMotion: "reduce" });
  const page = await context.newPage();
  try {
    await page.goto("/docs/terminal/multiplexer/");
    const clip = page.locator(".figure[data-clip]").first();
    await clip.scrollIntoViewIfNeeded();
    await page.waitForTimeout(1500);
    expect(await page.locator("video").count()).toBe(0);
    await expect(clip.locator("img")).toBeVisible();
  } finally {
    await context.close();
  }
});

for (const size of SIZES) for (const scheme of ["dark", "light"] as const) {
  test(`${size.name} ${scheme}: a figure that has not been captured is its caption under a placeholder, and lines up`, async ({ browser }) => {
    test.skip(CAPTURED, "the figures are captured here: the pictures are measured instead");
    const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale, hasTouch: size.touch, isMobile: size.touch, colorScheme: scheme });
    const page = await context.newPage();
    const requests: string[] = [];
    page.on("request", (request) => requests.push(new URL(request.url()).pathname));
    try {
      for (const [slug, expected] of [["terminal/multiplexer", ["sessions-windows", "multiplexer-switch"]], ["reference/keys", ["account-card", "add-machine"]]] as const) {
        await page.goto(`/docs/${slug}/`);
        await page.evaluate(() => document.fonts.ready);
        const names = await page.locator(".figure").evaluateAll((figures) => figures.map((f) => (f as HTMLElement).dataset.figure!));
        expect(names.sort(), `${slug}: its figures`).toEqual([...expected].sort());
        for (const name of names) {
          const figure = page.locator(`.figure[data-figure="${name}"]`);
          await figure.scrollIntoViewIfNeeded();
          const looks = await page.evaluate((id) => {
            const f = document.querySelector<HTMLElement>(`.figure[data-figure="${id}"]`)!;
            const box = f.querySelector(".figure-media")!.getBoundingClientRect();
            const text = document.querySelector(".doc-body > p")!.getBoundingClientRect();
            const body = document.querySelector(".doc-body")!.getBoundingClientRect();
            const caption = f.querySelector("figcaption")!.getBoundingClientRect();
            const holder = f.querySelector(".figure-placeholder")!;
            return { pending: f.classList.contains("figure-pending"), left: box.left - text.left, over: box.right - body.right, captionGap: caption.top - box.bottom, label: holder.getAttribute("aria-label") ?? "", role: holder.getAttribute("role"), words: holder.textContent, captionText: f.querySelector("figcaption")!.textContent ?? "", pictures: f.querySelectorAll("picture, img, video").length };
          }, name);
          expect(looks.pending, `${name}: pending`).toBe(true);
          expect(looks.words).toBe("Figure pending");
          expect(looks.role).toBe("img");
          expect(looks.label.length, `${name}: the placeholder says what the picture shows`).toBeGreaterThan(20);
          expect(looks.captionText.length, `${name}: the caption is there`).toBeGreaterThan(20);
          expect(looks.pictures, `${name}: no picture or clip`).toBe(0);
          expect(Math.abs(looks.left), `${name}: starts on the text's left edge`).toBeLessThanOrEqual(0.5);
          expect(looks.over, `${name}: no wider than the text`).toBeLessThanOrEqual(0.5);
          expect(looks.captionGap, `${name}: the caption sits under the placeholder`).toBeGreaterThanOrEqual(0);
          expect(looks.captionGap).toBeLessThanOrEqual(12);
          await figure.screenshot({ path: `${OUT}/${size.name}-${scheme}-${slug}-${name}-pending.png` });
        }
      }
      expect(requests.filter((path) => path.startsWith("/docs/figures/")), "nothing is fetched for a figure that is not there").toEqual([]);
    } finally {
      await context.close();
    }
  });
}
