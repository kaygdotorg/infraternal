/**
 * Every frame of a glass surface's first second over a flat picture, from the computed styles (D365, #448).
 *
 * The pixel specs measure a settled surface. A person also sees the frames before it settles: the surface opens (it is already
 * marked and on the static floor in its first frame), then the glass samples the picture and writes a lighter tint and new text
 * colours, and buttons and rows ease their text colour (`transition: color`) toward the new value while the tint changes at once.
 * This logs, on every animation frame from the moment the surface is first visible, the contrast of every text run against the
 * flat picture with the surface's tint composited over it (a flat picture has one backdrop colour, so no screenshot is needed),
 * and asserts the lowest over all frames is at least 4.5:1. The tint is read as the surface paints it (`--overlay`) and each run's
 * colour is its computed colour of that frame, so a colour that lags the tint shows up here. The trace goes to `frames.jsonl`.
 */
import { appendFileSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { LINE, openScene, putPicture, removePicture, SIZES, surfacesFor } from "./glass-scenes";

/** The trace file. */
const OUT = tracerEvidencePath("glass-frames", "frames.jsonl");

/** What the in-page recorder returns for one case. */
interface Trace { frames: number; lowest: number; at: number; text: string; shownAt: number; first: number; settled: number }

for (const size of SIZES) {
  for (const scheme of ["ink", "paper"] as const) {
    for (const surface of surfacesFor(size)) {
      for (const card of [2, 3, 4]) {
        test(`${size.id} ${scheme === "ink" ? "Ink" : "Paper"} card ${card}: no frame of the ${surface.id} dips under ${LINE}:1 over flat pictures`, async ({ browser }) => {
          // Three pictures, each opened, watched for 1.5 s and closed: more than the default 90 s on a loaded host.
          test.setTimeout(240_000);
          const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
          const page = await context.newPage();
          await openScene(page, scheme, card);
          for (const picture of ["white", "black", "grey"] as const) {
            await putPicture(page, picture, "fill", surface.host);
            const rgb = picture === "white" ? 255 : picture === "black" ? 0 : 0x77;
            // The recorder starts before the surface opens and stops after 90 frames or 1.5 s past the first visible one.
            const recording = page.evaluate(({ sel, rgb }) => new Promise<Trace>((resolve) => {
              const lum = (r: number, g: number, b: number): number => { const f = (v: number): number => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
              const nums = (s: string): number[] => (/\(([^)]+)\)/.exec(s)?.[1] ?? "").split(/[ ,/]+/).filter(Boolean).map(Number);
              const out: Trace = { frames: 0, lowest: 99, at: -1, text: "", shownAt: -1, first: 99, settled: 99 };
              const start = performance.now();
              let n = 0, visibleSince = 0;
              const tick = (): void => {
                const el = document.querySelector<HTMLElement>(sel);
                const now = performance.now();
                if (el) {
                  const cs = getComputedStyle(el);
                  const shown = !el.hidden && cs.visibility !== "hidden" && Number(cs.opacity) > 0;
                  if (shown) {
                    if (!visibleSince) { visibleSince = now; out.shownAt = n; }
                    const o = nums(cs.getPropertyValue("--overlay"));
                    const [or = 0, og = 0, ob = 0, oa = 1] = o;
                    const bg: [number, number, number] = [or * oa + rgb * (1 - oa), og * oa + rgb * (1 - oa), ob * oa + rgb * (1 - oa)];
                    const w = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
                    let worst = 99, worstText = "";
                    for (let t = w.nextNode(); t; t = w.nextNode()) {
                      const p = t.parentElement;
                      if (!p || !(t.textContent ?? "").trim() || p.closest(".swatch")) continue;
                      const ps = getComputedStyle(p);
                      if (ps.visibility === "hidden" || Number(ps.opacity) === 0) continue;
                      const [tr = 0, tg = 0, tb = 0, ta = 1] = nums(ps.color);
                      // A control's own fill (a button, a hovered row) sits between the tint and its label: composite the fills from the surface down.
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
                    if (worst < 99) {
                      out.frames += 1;
                      if (out.first === 99) out.first = worst;
                      out.settled = worst;
                      if (worst < out.lowest) { out.lowest = worst; out.at = out.frames; out.text = worstText; }
                    }
                  }
                }
                n += 1;
                if ((visibleSince && now - visibleSince > 1500) || now - start > 12_000) resolve(out); else requestAnimationFrame(tick);
              };
              requestAnimationFrame(tick);
            }), { sel: surface.selector, rgb });
            await surface.open(page);
            const trace = await recording;
            appendFileSync(OUT, `${JSON.stringify({ size: size.id, scheme, surface: surface.id, picture, card, ...trace, lowest: Number(trace.lowest.toFixed(2)), first: Number(trace.first.toFixed(2)), settled: Number(trace.settled.toFixed(2)) })}\n`);
            // A loaded host paints few frames in 1.5 s (8 to 10 were seen); what is needed is the first, some in between and the settled one.
            expect.soft(trace.frames, `${picture}: frames recorded`).toBeGreaterThanOrEqual(4);
            expect.soft(trace.lowest, `${picture}: lowest "${trace.text}" ${trace.lowest.toFixed(2)}:1 at frame ${trace.at} of ${trace.frames} (first ${trace.first.toFixed(2)}, settled ${trace.settled.toFixed(2)})`).toBeGreaterThanOrEqual(LINE);
            await surface.close(page);
            await expect(page.locator(surface.selector).first()).toBeHidden({ timeout: 8000 });
            await removePicture(page);
          }
          await context.close();
        });
      }
    }
  }
}
