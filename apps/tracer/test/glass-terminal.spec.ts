/**
 * Glass over a real terminal screen with bright rows under it (D365, #448).
 *
 * The earlier check assumed a terminal never shows more than a fifth of a card in one bright colour. Two adjacent inverse
 * rows (a status line and a prompt, nano, vim, tmux) are 7% of a card by area and still took Ink to 3.6:1, because the card's
 * own blur leaves a thin band almost as bright as it is. The glass now reads the terminal's real cells under the card, so this
 * spec writes exactly those screens into the real terminal of the mock page (`/?mock=1`, no mockup needed), opens the palette
 * over it, and measures its text on the rendered pixels (`glass-pixels.ts`).
 *
 * Cases: Ink and Paper (named with `&theme=`, never left to the colour scheme), Tinted, Clear and Frosted, at 1440 x 900 and
 * 393 x 852, with two inverse rows under the card's top edge, its bottom edge, its middle, and none, plus the heavier screens of the
 * review: editor bars (four rows, about 30% of the card), a light pane over half the screen, and a fully inverse screen. Each also
 * checks the first painted frame: the palette must already carry `data-glass-under` when it first becomes visible. Each asserts that the
 * palette was found to be over the terminal (`data-glass-under="terminal"`), that every text run reaches 4.5:1, and that the
 * adaptive update ran (`data-glass-stats` makes the glass count its updates). The lowest ratio, the update count and their
 * cost go to `ratios.jsonl` and `stats.jsonl` in the evidence directory.
 */
import { appendFileSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { measure } from "./glass-pixels";
import { glassReady } from "./glass-settled";

/** Where the captures and the tables land. */
const OUT = tracerEvidencePath("glass-terminal");
/** The line every text run must reach (D365). */
const LINE = 4.5;
/** The two sizes of the review. */
const SIZES = [{ id: "1440x900", width: 1440, height: 900, phone: false }, { id: "393x852", width: 393, height: 852, phone: true }] as const;
/** Where the two bright rows go, relative to the card. */
const LAYOUTS = ["plain", "top", "middle", "bottom", "bars", "pane", "full"] as const;

/** A screenful of dense text, as `ls -la` would leave it. */
const DENSE = Array.from({ length: 80 }, (_, i) => `drwxr-xr-x  12 kayg kayg  ${String(4096 + i * 37).padStart(6)} Nov  9 12:${String(i % 60).padStart(2, "0")} infraternal-${i.toString(16)}-build-output`).join("\r\n");

for (const size of SIZES) {
  for (const scheme of ["ink", "paper"] as const) {
    for (const card of [2, 3, 4]) {
      for (const layout of LAYOUTS) {
        test(`${size.id} ${scheme === "ink" ? "Ink" : "Paper"} card ${card}, bright rows ${layout}: palette text reaches ${LINE}:1`, async ({ browser }) => {
          const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
          const page = await context.newPage();
          await page.context().request.post("/__mock/reset");
          await page.context().request.post("/__mock/open-terminal");
          await page.goto(`/?mock=1&theme=${scheme}&card=${card}&fps=0`);
          await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
          await glassReady(page);
          await page.evaluate(() => document.documentElement.setAttribute("data-glass-stats", ""));
          await page.evaluate((text) => window.__tracerTestDouble!.writeText(`\x1b[2J\x1b[H${text}`), DENSE);
          // First open: only to learn where the card lands; it is closed again before the bright rows are written.
          await page.keyboard.press("Control+Shift+K");
          const palette = page.locator("#palette");
          await expect(palette).toBeVisible();
          // sleep: the palette grows in over 200 ms, and the screen must have painted before its rows are read
          await page.waitForTimeout(500);
          const box = (await palette.boundingBox())!;
          const geometry = await page.evaluate(() => {
            const m = window.__tracerTestDouble!.rendererMetrics()!;
            const canvas = document.querySelector<HTMLCanvasElement>("#terminal-screen canvas")!;
            const r = canvas.getBoundingClientRect();
            return { cols: m.cols, rows: m.rows, top: r.top, cellH: r.height / m.rows };
          });
          const first = Math.max(0, Math.floor((box.y - geometry.top) / geometry.cellH)), last = Math.min(geometry.rows - 1, Math.floor((box.y + box.height - geometry.top) / geometry.cellH) - 1);
          const at = layout === "top" ? first : layout === "bottom" ? last - 1 : Math.round((first + last) / 2);
          if (layout === "bars" || layout === "pane" || layout === "full") {
            // bars: an editor's title and status line at the card's top and bottom edge plus a bright prompt row under each
            // (4 rows, about 30% of the card); pane: a light pane over the left half of every row; full: every cell inverse.
            const inverse = (row: number, from: number, to: number): string => `\x1b[${row + 1};${from + 1}H\x1b[7m${" ".repeat(to - from)}\x1b[0m`;
            const lines: string[] = [];
            if (layout === "bars") for (const row of [first, first + 1, last - 1, last]) lines.push(inverse(row, 0, geometry.cols));
            else for (let row = 0; row < geometry.rows; row++) lines.push(inverse(row, 0, layout === "full" ? geometry.cols : Math.floor(geometry.cols / 2)));
            await page.evaluate((text) => window.__tracerTestDouble!.writeText(text), lines.join(""));
          } else if (layout !== "plain") {
            const rows = [at, at + 1].map((row) => `\x1b[${row + 1};1H\x1b[7m${" ".repeat(geometry.cols)}\x1b[0m`).join("");
            await page.evaluate((text) => window.__tracerTestDouble!.writeText(text), rows);
          }
          // Reopen over the finished screen, so the card opens over bright rows that were already there (the open-time case).
          await page.keyboard.press("Escape");
          await expect(palette).toBeHidden();
          // sleep: one render pass for the written rows to paint before the card opens over them
          await page.waitForTimeout(300);
          // Logs every frame from now on: whether the palette is shown, whether it is marked, and its tint alpha.
          await page.evaluate(() => {
            const frames: Array<{ shown: boolean; under: string | null; overlay: string }> = [];
            (globalThis as { __frames?: typeof frames }).__frames = frames;
            const tick = (): void => {
              const p = document.querySelector<HTMLElement>("#palette");
              if (p) frames.push({ shown: !p.hidden && getComputedStyle(p).visibility !== "hidden", under: p.dataset.glassUnder ?? null, overlay: getComputedStyle(p).getPropertyValue("--overlay") });
              if (frames.length < 120) requestAnimationFrame(tick);
            };
            requestAnimationFrame(tick);
          });
          await page.keyboard.press("Control+Shift+K");
          await expect(palette).toBeVisible();
          // sleep: one render pass and one frame for the glass to read the new cells and write its answer
          await page.waitForTimeout(500);
          await page.screenshot({ path: `${OUT}/${size.id}-${scheme}-card${card}-${layout}.png` });
          await expect(palette).toHaveAttribute("data-glass-under", "terminal");
          const frames = await page.evaluate(() => (globalThis as { __frames?: Array<{ shown: boolean; under: string | null; overlay: string }> }).__frames!);
          const firstShown = frames.find((f) => f.shown);
          // How many frames the card stays on the floor before the glass lightens it to what the screen needs (the open animation is ~12 frames).
          const shownAt = frames.findIndex((f) => f.shown), settledAt = frames.findIndex((f, i) => i >= shownAt && f.shown && f.overlay === frames[frames.length - 1]!.overlay);
          appendFileSync(`${OUT}/first-frame.jsonl`, `${JSON.stringify({ size: size.id, scheme, card, layout, first: firstShown ?? null, settled: frames[frames.length - 1], framesOnFloor: settledAt - shownAt })}\n`);
          expect(firstShown, "the palette was painted").toBeDefined();
          expect(firstShown!.under, "the palette is on the static floor in the first frame it is visible").toBe("terminal");
          const results = await measure(page, "#palette");
          const stats = await page.evaluate(() => (globalThis as { __glassStats?: unknown }).__glassStats ?? null);
          appendFileSync(`${OUT}/ratios.jsonl`, `${JSON.stringify({ size: size.id, scheme, card, layout, lowest: Number(results[0]!.ratio.toFixed(2)), text: results[0]!.text })}\n`);
          appendFileSync(`${OUT}/stats.jsonl`, `${JSON.stringify({ size: size.id, scheme, card, layout, stats })}\n`);
          expect(stats, "the adaptive update ran").not.toBeNull();
          expect(results[0]!.ratio, `lowest: "${results[0]!.text}" ${results[0]!.ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(LINE);
          await context.close();
        });
      }
    }
  }
}
