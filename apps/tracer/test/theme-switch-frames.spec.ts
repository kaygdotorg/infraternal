/**
 * Every frame of an open glass notice across a theme switch, from the computed styles (D365, #567).
 *
 * A theme switch rewrites the glass contrast rules (`installGlassRules`). This spec proves the rules are in force on the FIRST
 * frame painted after the click, so no frame shows the new page colours with the old theme's glass: it keeps an error notice
 * open over a flat picture, switches Ink to Paper and back through the palette, records every animation frame from the click,
 * and asserts that in every frame, the first included, each text run of the notice reaches 4.5:1 on the notice's own tint over
 * the picture. The first and last text colour are in the trace so a deferred rewrite would show. The trace goes to `frames.jsonl` next to the glass frames.
 */
import { appendFileSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { LINE, openScene, putPicture, removePicture } from "./glass-scenes";
import { settled } from "./glass-settled";

const OUT = tracerEvidencePath("glass-frames", "theme-switch-frames.jsonl");
const NOTICE = '.ui-toast[data-hidden="false"]';

interface Trace { frames: number; lowest: number; at: number; text: string; fgFirst: string; fgLast: string }

for (const [from, to, picture] of [["ink", "paper", "black"], ["ink", "paper", "white"], ["paper", "ink", "black"], ["paper", "ink", "white"]] as const) {
  test(`switching ${from} to ${to} over a ${picture} picture: no frame of the error notice dips under ${LINE}:1`, async ({ browser }) => {
    test.setTimeout(120_000);
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: from === "ink" ? "dark" : "light" });
    const page = await context.newPage();
    await openScene(page, from, 3);
    await putPicture(page, picture, "fill", "screen");
    await page.evaluate(() => { window.__toast!.show({ message: "Could not open a shell on this host.", tone: "error", duration: 0, action: { label: "Try again" } }); });
    await expect(page.locator(NOTICE)).toBeVisible();
    await settled(page, NOTICE);
    // Open the palette first, so the click below is the only thing between the recorder and the switch.
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill(to === "ink" ? "Ink" : "Paper");
    const option = page.locator(`[role="option"][data-action="theme:${to}"]`);
    await expect(option).toBeVisible();
    const rgb = picture === "white" ? 255 : 0;
    const trace = await option.evaluate((element, { sel, rgb }) => new Promise<Trace>((resolve) => {
      const lum = (r: number, g: number, b: number): number => { const f = (v: number): number => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
      const nums = (s: string): number[] => (/\(([^)]+)\)/.exec(s)?.[1] ?? "").split(/[ ,/]+/).filter(Boolean).map(Number);
      const out: Trace = { frames: 0, lowest: 99, at: -1, text: "", fgFirst: "", fgLast: "" };
      const start = performance.now();
      const measure = (): void => {
        const el = document.querySelector<HTMLElement>(sel);
        if (!el) return;
        const [or = 0, og = 0, ob = 0, oa = 1] = nums(getComputedStyle(el).getPropertyValue("--overlay"));
        const bg: [number, number, number] = [or * oa + rgb * (1 - oa), og * oa + rgb * (1 - oa), ob * oa + rgb * (1 - oa)];
        const w = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
        let worst = 99, worstText = "";
        for (let t = w.nextNode(); t; t = w.nextNode()) {
          const p = t.parentElement;
          if (!p || !(t.textContent ?? "").trim()) continue;
          const ps = getComputedStyle(p);
          const [tr = 0, tg = 0, tb = 0, ta = 1] = nums(ps.color);
          const under: [number, number, number] = [...bg];
          const chain: HTMLElement[] = [];
          for (let a: HTMLElement | null = p; a && a !== el; a = a.parentElement) chain.unshift(a);
          for (const a of chain) {
            const [fr = 0, fg2 = 0, fb = 0, fa = 1] = nums(getComputedStyle(a).backgroundColor);
            if (fa > 0) { under[0] = fr * fa + under[0] * (1 - fa); under[1] = fg2 * fa + under[1] * (1 - fa); under[2] = fb * fa + under[2] * (1 - fa); }
          }
          const fg = lum(tr * ta + under[0] * (1 - ta), tg * ta + under[1] * (1 - ta), tb * ta + under[2] * (1 - ta)), b = lum(...under);
          const ratio = (Math.max(fg, b) + 0.05) / (Math.min(fg, b) + 0.05);
          if (ratio < worst) { worst = ratio; worstText = (t.textContent ?? "").trim().slice(0, 30); }
        }
        const fgNow = getComputedStyle(el).getPropertyValue("--fg");
        if (worst < 99) {
          out.frames += 1;
          if (!out.fgFirst) out.fgFirst = fgNow;
          out.fgLast = fgNow;
          if (worst < out.lowest) { out.lowest = worst; out.at = out.frames; out.text = worstText; }
        }
      };
      const tick = (): void => {
        measure();
        if (performance.now() - start > 1200) resolve(out); else requestAnimationFrame(tick);
      };
      // The switch, then the frame in which the browser first paints it: the first measurement is of that frame.
      (element as HTMLElement).click();
      requestAnimationFrame(tick);
    }), { sel: NOTICE, rgb });
    appendFileSync(OUT, `${JSON.stringify({ from, to, picture, ...trace, lowest: Number(trace.lowest.toFixed(2)) })}\n`);
    expect.soft(trace.frames, "frames recorded").toBeGreaterThanOrEqual(4);
    expect.soft(trace.lowest, `lowest "${trace.text}" ${trace.lowest.toFixed(2)}:1 at frame ${trace.at} of ${trace.frames}`).toBeGreaterThanOrEqual(LINE);
    await removePicture(page);
    await context.close();
  });
}
