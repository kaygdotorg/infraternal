/**
 * The Mesh view never overlaps another view, and its cluster labels read in full when the chip has room.
 * The Mesh's size arrives late (its code loads on demand and lays the graph out then), so the views around it must
 * be settled apart at that moment, at every width and for both pointer kinds.
 */
import { devices, expect, test, type Browser, type Page } from "playwright/test";

const base = `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`;
const URL = "/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft&mesh=128&meshgrants=40";
type Box = { id: string; x: number; y: number; w: number; h: number };

async function open(browser: Browser, w: number, h: number, touch: boolean): Promise<{ page: Page; close(): Promise<void> }> {
  const context = await browser.newContext({ ...(touch ? devices["iPhone 15"] : {}), baseURL: base, viewport: { width: w, height: h }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  await page.goto(URL);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(900);
  return { page, close: () => context.close() };
}
const boxes = (page: Page): Promise<Box[]> => page.evaluate("window.__tracerClusters.views()") as Promise<Box[]>;
const overlaps = (a: Box, b: Box): boolean => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

for (const [w, h, touch] of [[1440, 900, false], [600, 900, false], [390, 844, true], [393, 852, true], [375, 667, true]] as const) {
  test(`mesh ${w}x${h}${touch ? " touch" : ""}: no two views overlap once the Mesh has laid out, and labels are whole`, async ({ browser }) => {
    test.setTimeout(90_000);
    const { page, close } = await open(browser, w, h, touch);
    try {
      await page.evaluate("window.__tracerClusters.flyView('mesh')");
      await expect.poll(async () => ((await page.evaluate("window.__tracerClusters.mesh.stats()")) as { chips: number } | undefined)?.chips ?? -1, { timeout: 20_000 }).toBeGreaterThanOrEqual(0);
      await page.waitForTimeout(1200);
      const all = await boxes(page);
      for (let i = 0; i < all.length; i++) for (let j = i + 1; j < all.length; j++) {
        expect(overlaps(all[i]!, all[j]!), `${all[i]!.id} ${JSON.stringify(all[i])} overlaps ${all[j]!.id} ${JSON.stringify(all[j])}`).toBe(false);
      }
      // Chip labels: the count is never cut ("15 on…"): it has no ellipsis, and each of its parts sits inside its chip.
      const cut = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".cl-chip")].flatMap((chip) => {
        const r = chip.getBoundingClientRect();
        const meta = chip.querySelector<HTMLElement>(".cl-chip-meta")!;
        const bad = getComputedStyle(meta).textOverflow === "ellipsis" ? ["ellipsis"] : [];
        for (const part of meta.querySelectorAll<HTMLElement>(".cl-chip-part")) if (part.getBoundingClientRect().right > r.right + 1) bad.push(`${part.textContent} leaves the chip`);
        // No line of the count starts with the separator: the part's own text has none, and when it wraps to a new line it
        // starts at the row's left edge, where its hung ::before is outside the row and clipped.
        const parts = [...meta.querySelectorAll<HTMLElement>(".cl-chip-part")];
        for (const part of parts) if (part.textContent!.trim().startsWith("·")) bad.push("a part starts with the dot");
        const [first, second] = parts;
        if (first && second) {
          const mr = meta.getBoundingClientRect(), wrapped = second.getBoundingClientRect().top > first.getBoundingClientRect().top + 1;
          const dot = getComputedStyle(second, "::before").content;
          if (wrapped && !(Math.abs(second.getBoundingClientRect().left - mr.left) < 1 && getComputedStyle(meta).overflowX === "clip")) bad.push("wrapped count shows a dot");
          if (!wrapped && !dot.includes("·")) bad.push("one-line count lost its dot");
        }
        return bad.map((b) => `${chip.dataset.cluster}: ${b}`);
      }));
      expect(cut).toEqual([]);
      expect(await page.locator(".cl-chip-meta").count()).toBeGreaterThan(0);
    } finally { await close(); }
  });
}
