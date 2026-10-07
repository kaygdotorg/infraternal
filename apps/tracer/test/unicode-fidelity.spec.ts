/** Verifies Ghostty retains Unicode graphemes across raw PTY frame boundaries. */
import { expect, test } from "playwright/test";

const SAMPLE = "👩🏽‍💻 👨‍👩‍👧‍👦 🧑🏾‍🚀 🇩🇪 🇺🇳";
const MODES = ["single", "utf8-split", "grapheme-split", "snapshot"] as const;

test("raw frames retain behemoth emoji clusters across UTF-8 and grapheme boundaries", async ({ page }) => {
  test.setTimeout(60_000);
  const context = page.context();
  for (const mode of MODES) {
    await page.goto("about:blank");
    await context.request.post("/__mock/reset");
    await context.request.post("/__mock/open-terminal");
    await page.goto("/?mock=1&theme=ink&bg=none");
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
    let probe: { mode: string; bytes: number; output_sequence: string } | undefined;
    for (let attempt = 0; attempt < 40 && !probe; attempt += 1) {
      const response = await context.request.post("/__mock/unicode-case", { data: { mode } });
      if (response.status() === 200) probe = await response.json() as typeof probe;
      else expect(response.status()).toBe(409);
      if (!probe) await page.waitForTimeout(25);
    }
    expect(probe?.mode).toBe(mode);
    await expect.poll(async () => {
      const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
      return metrics !== undefined && BigInt(metrics.outputSequence) >= BigInt(probe!.output_sequence);
    }).toBe(true);
    const text = await page.evaluate(() => window.__tracerTestDouble?.graphemeText() ?? "");
    expect(text, `${mode} write path`).toContain(SAMPLE);
    for (const cluster of ["👩🏽‍💻", "👨‍👩‍👧‍👦", "🧑🏾‍🚀", "🇩🇪", "🇺🇳"]) {
      expect(text, `${mode} retains ${cluster}`).toContain(cluster);
    }
    console.log(`Unicode ${mode}: output=${probe!.output_sequence} B; all five clusters retained`);
  }
});
