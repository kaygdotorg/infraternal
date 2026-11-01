/**
 * Frosted means really frosted (TASTE, #256): a Frosted window shows a real blur of the canvas behind it, at rest and
 * while the canvas pans. This is the stripe test.
 *
 * How: the screen's backdrop (the mesh behind the canvas) is replaced by hard black and white vertical stripes (20 px
 * each, fixed to the screen), the dots and the grain are hidden and the windows' own content is made invisible, so what shows inside a window is its material:
 * its tint and whatever of the stripes the blur lets through. The metric is the sharpest horizontal step between two
 * neighbouring pixels in a band inside a window, as a fraction of the same step with the windows' `backdrop-filter`
 * switched off (stripes under the tint only). 1 means the stripe edges pass untouched (no blur sees the canvas, the
 * "fake frost" this test exists for); a real 24 px blur leaves about 0.02.
 *
 * The failure it catches: a `clip-path`, filter, mask, opacity or blend mode on an element between the window and the
 * canvas backdrop makes that element a backdrop root, and the window's blur then sees only what is inside it. On the
 * viewport's old `clip-path` this scored 1.00 in Chromium. The other half: nothing may switch the blur off while the
 * canvas pans, so the same band is measured in the middle of a pan and every window must still compute a blur.
 *
 * Headless Chromium paints the backdrop blur in software, which is enough to see where the blur reaches.
 */
import { expect, test, type Page } from "playwright/test";
import { openCanvas } from "./frosted-scroll-harness";

interface Box { x: number; y: number; width: number; height: number }

/**
 * The sharpest step along the band's rows, in luminance (0 to 255), over a crop of a full-viewport PNG. The crop is made
 * here and not by `screenshot({ clip })`: at DPR 2 a clipped capture takes another render path and showed the backdrop
 * unblurred on a tree that blurs it (the full capture, and the eye, say otherwise).
 */
async function sharpestStep(page: Page, png: Buffer, band: Box): Promise<number> {
  return page.evaluate(async ([b64, box]) => {
    const img = new Image();
    img.src = `data:image/png;base64,${b64}`;
    await img.decode();
    const k = img.width / innerWidth;
    const c = document.createElement("canvas");
    c.width = Math.round(box.width * k); c.height = Math.round(box.height * k);
    const g = c.getContext("2d", { willReadFrequently: true })!;
    g.drawImage(img, box.x * k, box.y * k, box.width * k, box.height * k, 0, 0, c.width, c.height);
    const { data, width, height } = g.getImageData(0, 0, c.width, c.height);
    const lum = (i: number): number => 0.2126 * data[i * 4]! + 0.7152 * data[i * 4 + 1]! + 0.0722 * data[i * 4 + 2]!;
    let best = 0;
    for (let y = 0; y < height; y++) for (let x = 1; x < width; x++) best = Math.max(best, Math.abs(lum(y * width + x) - lum(y * width + x - 1)));
    return best;
  }, [png.toString("base64"), band] as const);
}

/** The biggest on-screen window's rectangle. */
const windowBox = (page: Page): Promise<Box> => page.evaluate(() => {
  let best: Box = { x: 0, y: 0, width: 0, height: 0 };
  for (const w of document.querySelectorAll(".ui-window[data-onscreen]")) {
    const r = w.getBoundingClientRect();
    if (r.width * r.height > best.width * best.height) best = { x: r.x, y: r.y, width: r.width, height: r.height };
  }
  return best;
});

/** The band of a window to measure: its middle, 30 px tall, 120 px in from both sides (a pan swings it by about 70 px). */
const bandOf = (b: Box): Box => ({ x: Math.round(b.x + 120), y: Math.round(b.y + b.height / 2 - 15), width: Math.round(b.width - 240), height: 30 });

for (const dpr of [1, 2] as const) {
  test(`a Frosted window blurs black and white stripes on the canvas behind it, at rest and mid-pan (DPR ${dpr})`, async ({ browser }) => {
    test.setTimeout(120_000);
    const open = await openCanvas(browser, { windows: 4, count: 4, dpr });
    const { page, context } = open;
    try {
      await page.addStyleTag({ content: `
        .terminal-screen .backdrop { background: repeating-linear-gradient(90deg, #000 0 20px, #fff 20px 40px) !important; }
        .terminal-screen .backdrop::before, .ui-canvas-backdrop { display: none !important; }
        .ui-window * { visibility: hidden !important; }` });
      await page.waitForTimeout(500);
      const box = await windowBox(page);
      expect(box.width, "a window wide enough for the band").toBeGreaterThan(400);
      const band = bandOf(box);
      const measure = async (): Promise<number> => sharpestStep(page, await page.screenshot(), band);

      // The reference: the same band with the windows' blur off. The stripes show sharp under the tint alone.
      const unblurred = await page.addStyleTag({ content: ".ui-window { backdrop-filter: none !important; -webkit-backdrop-filter: none !important; }" });
      await page.waitForTimeout(300);
      const sharp = await measure();
      expect(sharp, "the reference has visible stripe edges").toBeGreaterThan(20);
      await unblurred.evaluate((style) => { (style as Element).remove(); });
      await page.waitForTimeout(300);

      // At rest, with the blur on.
      const rest = (await measure()) / sharp;

      // Mid-pan: a wheel event per animation frame on a small sine, and the capture taken while it runs. The page keeps the
      // world's x at every frame, so the test can say the world moved during the capture and the band stayed inside the window.
      await page.evaluate(() => {
        const w = window as unknown as { __stop?: boolean; __xs: number[] };
        w.__stop = false;
        w.__xs = [];
        const viewport = document.querySelector(".cl-viewport")!;
        const world = document.querySelector(".cl-world")!;
        const t0 = performance.now();
        const tick = (t: number): void => {
          viewport.dispatchEvent(new WheelEvent("wheel", { deltaX: Math.round(5 * Math.sin((2 * Math.PI * (t - t0)) / 1500)), deltaY: 0, bubbles: true, cancelable: true, clientX: 720, clientY: 450 }));
          w.__xs.push(world.getBoundingClientRect().x);
          if (!w.__stop) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
      });
      await page.waitForTimeout(400);
      const frames = (): Promise<number> => page.evaluate(() => (window as unknown as { __xs: number[] }).__xs.length);
      const first = await frames();
      const during = await measure();
      const last = await frames();
      const blurs = await page.evaluate(() => [...document.querySelectorAll(".ui-window[data-onscreen]")].map((w) => getComputedStyle(w).backdropFilter));
      const xs = await page.evaluate(() => { const w = window as unknown as { __stop: boolean; __xs: number[] }; w.__stop = true; return w.__xs; });
      const captured = xs.slice(first, last + 1);
      expect(last - first, "frames ran during the capture").toBeGreaterThan(2);
      expect(Math.max(...captured) - Math.min(...captured), "the canvas was panning while the capture was taken").toBeGreaterThan(1);
      expect(Math.max(...xs.map((x) => Math.abs(x - xs[0]!))), "the pan stays inside the band's margin").toBeLessThan(110);
      const mid = during / sharp;

      console.log(`FROSTED-REAL DPR ${dpr}: stripe edge as a fraction of the unblurred one: at rest ${rest.toFixed(3)}, mid-pan ${mid.toFixed(3)} (sharp step ${sharp.toFixed(0)}); backdrop-filter mid-pan: ${[...new Set(blurs)].join(" | ")}`);
      expect(rest, "at rest the stripes behind a Frosted window are soft").toBeLessThan(0.2);
      expect(mid, "mid-pan the stripes behind a Frosted window are soft").toBeLessThan(0.2);
      expect(blurs.length, "windows on screen").toBeGreaterThan(0);
      for (const b of blurs) expect(b, "every window keeps its blur while the canvas pans").toMatch(/blur\(/);
    } finally {
      await context.close();
    }
  });
}
