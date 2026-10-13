/**
 * No frame of a split, before, during or after its animation, flashes (#141). A CDP screencast records the composited
 * frames; a frame is a flash when it differs clearly from the frame before and the one after while those two agree with
 * each other (a normal animation changes a little every frame, a flash is one wrong frame in between). The strip is
 * saved under the external job evidence directory for a person to review.
 */
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync, writeFileSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";

async function record(page: Page, run: () => Promise<void>, settleMs: number): Promise<Array<{ t: number; data: string }>> {
  const cdp = await page.context().newCDPSession(page);
  const frames: Array<{ t: number; data: string }> = [];
  cdp.on("Page.screencastFrame", (f) => { frames.push({ t: f.metadata.timestamp ?? 0, data: f.data }); void cdp.send("Page.screencastFrameAck", { sessionId: f.sessionId }).catch(() => {}); });
  await cdp.send("Page.startScreencast", { format: "jpeg", quality: 70, everyNthFrame: 1, maxWidth: 480, maxHeight: 300 });
  await run();
  await page.waitForTimeout(settleMs);
  await cdp.send("Page.stopScreencast");
  return frames;
}

/** Per frame: how far it is out of line with its neighbours (share of the frame that differs, minus the neighbours' own difference). */
async function spikes(page: Page, frames: Array<{ data: string }>): Promise<number[]> {
  const probe = await page.context().newPage();
  const out = await probe.evaluate(async (list) => {
    const pix: Uint8ClampedArray[] = [];
    for (const d of list) {
      const img = new Image();
      await new Promise((r) => { img.onload = r; img.src = `data:image/jpeg;base64,${d}`; });
      const c = document.createElement("canvas"); c.width = img.width; c.height = img.height;
      const g = c.getContext("2d")!; g.drawImage(img, 0, 0);
      pix.push(g.getImageData(0, 0, c.width, c.height).data);
    }
    const diff = (x: Uint8ClampedArray, y: Uint8ClampedArray): number => { let n = 0; for (let i = 0; i < x.length; i += 4) if (Math.abs(x[i]! - y[i]!) + Math.abs(x[i + 1]! - y[i + 1]!) + Math.abs(x[i + 2]! - y[i + 2]!) > 120) n++; return n / (x.length / 4); };
    return pix.map((px, k) => (k === 0 || k === pix.length - 1) ? 0 : Math.min(diff(px, pix[k - 1]!), diff(px, pix[k + 1]!)) - diff(pix[k - 1]!, pix[k + 1]!));
  }, frames.map((f) => f.data));
  await probe.close();
  return out;
}

export async function flashStrip(page: Page, name: string, act: () => Promise<void>): Promise<{ frames: number; worst: number }> {
  const frames = await record(page, act, 2500);
  const sp = await spikes(page, frames);
  const dir = tracerEvidencePath("split-flash", name);
  mkdirSync(dir, { recursive: true });
  frames.forEach((f, i) => writeFileSync(`${dir}/f${String(i).padStart(3, "0")}.jpg`, Buffer.from(f.data, "base64")));
  writeFileSync(`${dir}/spikes.json`, JSON.stringify(sp.map((v, i) => [i, Math.round((frames[i]!.t - frames[0]!.t) * 1000), +v.toFixed(4)])));
  return { frames: frames.length, worst: Math.max(0, ...sp) };
}

for (const theme of ["mocha", "latte"]) for (const direction of ["down", "right"]) {
  test(`no flash when splitting ${direction} on ${theme}`, async ({ page }) => {
    test.setTimeout(90_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`/?mock=1&proto=clusters&scene=1&theme=${theme}&bg=none`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1200);
    await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
    await page.waitForTimeout(1500);
    await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').first().click({ position: { x: 20, y: 40 } });
    await page.waitForTimeout(500);
    const r = await flashStrip(page, `${theme}-${direction}`, async () => { await page.evaluate((d) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: `canvas:split:${d}`, source: "pointer" } })), direction); });
    console.log(theme, direction, "frames", r.frames, "worst spike", r.worst.toFixed(4));
    expect(r.worst, "no frame is a flash between two agreeing neighbours").toBeLessThan(0.02);
  });
}
