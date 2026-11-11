/**
 * The X of a window's close button sits exactly in the middle of its round button (#141). The shared button class had no
 * padding reset, so the browser's default horizontal padding (6 px) squeezed the content box to 12 px and a 16 px icon
 * overflowed to the right by 2 px. The check reads both the boxes and the painted pixels (a 2x screenshot of the button,
 * the bounding box of everything that is not the button's own background), for every window type that closes.
 */
import { expect, test, type Page } from "playwright/test";

async function ink(page: Page, selector: string, dpr: number): Promise<{ dx: number; dy: number; box: [number, number] }> {
  const el = page.locator(selector).first();
  const rect = (await el.boundingBox())!;
  // The default UI size scales every header by 1.1, so a button sits on fractional pixels (28.59 px wide at x 483.61). A screenshot clip is
  // snapped to whole pixels, so the middle of the image is not the middle of the button. The clip is taken on whole CSS pixels and the
  // button's true centre and half-sizes are passed in device pixels, measured against the clip's origin.
  const x0 = Math.floor(rect.x), y0 = Math.floor(rect.y);
  const clip = { x: x0, y: y0, width: Math.ceil(rect.x + rect.width) - x0, height: Math.ceil(rect.y + rect.height) - y0 };
  const png = await page.screenshot({ clip });
  const button = { cx: (rect.x + rect.width / 2 - x0) * dpr, cy: (rect.y + rect.height / 2 - y0) * dpr, rx: (rect.width * dpr) / 2, ry: (rect.height * dpr) / 2 };
  return page.evaluate(async ([b64, dpr, button]) => {
    const img = new Image(); img.src = `data:image/png;base64,${b64}`; await img.decode();
    const c = document.createElement("canvas"); c.width = img.width; c.height = img.height;
    const g = c.getContext("2d")!; g.drawImage(img, 0, 0);
    const d = g.getImageData(0, 0, c.width, c.height).data;
    // Look only well inside the button's ellipse so the antialiased rim and what is behind it never count.
    const inside = (x: number, y: number): boolean => ((x + 0.5 - button.cx) / button.rx) ** 2 + ((y + 0.5 - button.cy) / button.ry) ** 2 < 0.45;
    const lo = 0, hi = Math.max(c.width, c.height);
    const at = (x: number, y: number): number[] => x >= c.width || y >= c.height ? [0, 0, 0] : [d[(y * c.width + x) * 4]!, d[(y * c.width + x) * 4 + 1]!, d[(y * c.width + x) * 4 + 2]!];
    const bg = at(Math.round(button.cx), Math.round(button.cy - button.ry * 0.76));
    let x0 = 1e9, x1 = -1, y0 = 1e9, y1 = -1;
    for (let y = lo; y < hi; y++) for (let x = lo; x < hi; x++) { if (x >= c.width || y >= c.height || !inside(x, y)) continue; const p = at(x, y); if (Math.abs(p[0]! - bg[0]!) + Math.abs(p[1]! - bg[1]!) + Math.abs(p[2]! - bg[2]!) > 40) { x0 = Math.min(x0, x); x1 = Math.max(x1, x); y0 = Math.min(y0, y); y1 = Math.max(y1, y); } }
    return { dx: ((x0 + x1 + 1) / 2 - button.cx) / (dpr as number), dy: ((y0 + y1 + 1) / 2 - button.cy) / (dpr as number), box: [(x1 - x0 + 1) / (dpr as number), (y1 - y0 + 1) / (dpr as number)] as [number, number] };
  }, [png.toString("base64"), dpr, button] as const);
}

for (const [name, viewport, dpr, touch] of [["desktop", { width: 1440, height: 900 }, 2, false], ["phone", { width: 393, height: 852 }, 3, true]] as const) {
  test(`the X is centred in its close button on every window type (${name})`, async ({ browser }) => {
    test.setTimeout(60_000);
    const ctx = await browser.newContext({ viewport, deviceScaleFactor: dpr, hasTouch: touch, isMobile: touch });
    const page = await ctx.newPage();
    await page.goto("/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1500);
    for (const view of ["console", "containers"]) {
      await page.evaluate((v) => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView(v), view);
      await page.waitForTimeout(1500);
      const ids = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".ui-window")].filter((w) => { const r = w.getBoundingClientRect(); return r.width > 0 && r.left >= 0 && r.right <= innerWidth && r.top >= 0 && r.bottom <= innerHeight && w.querySelector('[data-action="close"]'); }).map((w) => w.dataset.windowId!));
      expect(ids.length).toBeGreaterThan(0);
      for (const id of ids) {
        const sel = `.ui-window[data-window-id="${id}"] [data-action="close"]`;
        const boxes = await page.locator(sel).evaluate((a) => { const b = a.getBoundingClientRect(), s = a.querySelector("svg")!.getBoundingClientRect(); return { dx: s.left + s.width / 2 - (b.left + b.width / 2), dy: s.top + s.height / 2 - (b.top + b.height / 2) }; });
        expect(Math.abs(boxes.dx), `${id} icon box dx`).toBeLessThanOrEqual(0.5);
        expect(Math.abs(boxes.dy), `${id} icon box dy`).toBeLessThanOrEqual(0.5);
        const painted = await ink(page, sel, dpr);
        console.log("close X", name, id, JSON.stringify(painted));
        expect(Math.abs(painted.dx), `${id} painted dx`).toBeLessThanOrEqual(0.5);
        expect(Math.abs(painted.dy), `${id} painted dy`).toBeLessThanOrEqual(0.5);
      }
    }
    await ctx.close();
  });
}
