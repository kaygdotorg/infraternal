// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Frame-time bench for glass over a terminal (D365, #448; priority 3: it must feel native on an iPhone).
 *
 * One page, bundled by `glass-frame-bench.spec.ts` and also served as a static page to Safari in the iPhone Simulator, so the same
 * code produces the desktop and the phone numbers. It uses the real glass code (`applyTheme`, the watcher in `glass-under.on-demand.ts` and the
 * grid tracker in `glass-adapt.on-demand.ts`) over a stand-in terminal: 40 rows of text, bright rows under the card, and a screen that
 * repaints and notifies the glass on EVERY frame, which is the worst case of a busy terminal. Three phases of {@link PHASE_MS} each:
 *  - `idle`: the screen streams and no card is open (the baseline);
 *  - `card-untracked`: the card is open over the screen but the screen is not registered, so the card has its blur and nothing more;
 *  - `card-tracked`: the screen is registered, so the glass reads its cells and re-solves each frame it changes.
 * Each reports the rAF frame intervals (p50, p95, p99, max, and the number over 1.5 frame times) and, for the tracked phase, the glass's
 * own update count and time (`globalThis.__glassStats`). The glass's cost is `card-tracked` minus `card-untracked`.
 */
import { applyTheme, THEMES } from "../../../packages/ui/src/themes";
import { registerGlassGrid, type GlassGrid, type GlassGridRead } from "../../../packages/ui/src/glass-under.on-demand";

/** How long each phase runs, in milliseconds. */
const PHASE_MS = 4000;
/** The stand-in screen: columns and rows. */
const COLS = 80, ROWS = 40;

/** Frame-interval summary of one phase. */
export interface PhaseReport { phase: string; frames: number; p50: number; p95: number; p99: number; max: number; over1_5: number; glass?: { updates: number; meanMs: number; maxMs: number; readMeanMs: number } }
/** Everything the bench measured and where. */
export interface BenchReport { userAgent: string; dpr: number; viewport: string; phases: PhaseReport[] }

/** Builds the screen, the card and the grid the glass reads. Returns the way to register the grid and the per-frame repaint. */
function build(): { register(): () => void; repaint(n: number): void; card: HTMLElement } {
  const root = document.documentElement;
  const screen = document.createElement("div");
  screen.id = "screen";
  screen.style.cssText = `position:fixed;inset:0;overflow:hidden;font:12px/16px ui-monospace,monospace;white-space:pre;background:${THEMES.ink!.bg};color:${THEMES.ink!.fg}`;
  const lines: HTMLElement[] = [];
  const inverse = new Set([14, 15, 24, 25]);
  for (let r = 0; r < ROWS; r++) {
    const line = document.createElement("div");
    if (inverse.has(r)) line.style.cssText = `background:${THEMES.ink!.fg};color:${THEMES.ink!.bg}`;
    screen.append(line);
    lines.push(line);
  }
  document.body.append(screen);
  const card = document.createElement("section");
  card.className = "ui-overlay-surface";
  card.hidden = true;
  card.style.cssText = "position:fixed;left:50%;top:22%;width:min(360px,90vw);transform:translateX(-50%);padding:16px;z-index:5;border-radius:16px;font:14px/20px system-ui,sans-serif";
  card.innerHTML = Array.from({ length: 10 }, (_, i) => `<div style="color:var(--fg);padding:6px 0">Row ${i + 1} of the card</div>`).join("");
  document.body.append(card);
  applyTheme(THEMES.ink!, root, 4);
  const paint = (n: number): void => { lines.forEach((line, r) => { line.textContent = `${String((n + r) % 1000).padStart(4)} drwxr-xr-x kayg kayg infraternal-${(n * 7 + r).toString(16)}-build-output`; }); };
  paint(0);
  const grid: GlassGrid = {
    element: screen,
    read(rect: DOMRect, base: readonly [number, number, number]): GlassGridRead | null {
      const b = screen.getBoundingClientRect();
      const cellW = b.width / COLS, cellH = b.height / ROWS;
      const c0 = Math.max(0, Math.floor((rect.left - b.left) / cellW)), c1 = Math.min(COLS - 1, Math.ceil((rect.right - b.left) / cellW) - 1);
      const r0 = Math.max(0, Math.floor((rect.top - b.top) / cellH)), r1 = Math.min(ROWS - 1, Math.ceil((rect.bottom - b.top) / cellH) - 1);
      const out = new Uint8Array((r1 - r0 + 1) * (c1 - c0 + 1) * 3);
      let at = 0;
      for (let r = r0; r <= r1; r++) for (let c = c0; c <= c1; c++) {
        const v = inverse.has(r) ? [236, 236, 238] : [base[0], base[1], base[2]];
        out[at++] = v[0]!; out[at++] = v[1]!; out[at++] = v[2]!;
      }
      return { x: b.left + c0 * cellW, y: b.top + r0 * cellH, cellW, cellH, cols: c1 - c0 + 1, rows: r1 - r0 + 1, rgb: out };
    },
    subscribe(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
  };
  const listeners = new Set<() => void>();
  return { register: () => registerGlassGrid(grid), repaint: (n) => { paint(n); listeners.forEach((l) => l()); }, card };
}

/** Runs one phase and returns its frame intervals. `n` is the running frame number the repaint uses. */
function phase(name: string, repaint: (n: number) => void): Promise<PhaseReport> {
  return new Promise((done) => {
    const deltas: number[] = [];
    let last = 0, n = 0;
    const start = performance.now();
    const tick = (t: number): void => {
      if (last) deltas.push(t - last);
      last = t;
      repaint(n++);
      if (t - 0 < start + PHASE_MS) requestAnimationFrame(tick); else finish();
    };
    const finish = (): void => {
      const sorted = [...deltas].sort((a, b) => a - b);
      const q = (p: number): number => Number((sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))] ?? 0).toFixed(2));
      const med = q(0.5);
      done({ phase: name, frames: deltas.length, p50: med, p95: q(0.95), p99: q(0.99), max: q(1), over1_5: deltas.filter((d) => d > med * 1.5).length });
    };
    requestAnimationFrame(tick);
  });
}

/** Runs the three phases and returns the report; also left on `globalThis.__benchReport`. */
export async function runBench(): Promise<BenchReport> {
  document.documentElement.setAttribute("data-glass-stats", "");
  const { register, repaint, card } = build();
  const phases: PhaseReport[] = [];
  phases.push(await phase("idle", repaint));
  card.hidden = false;
  // sleep: let the card paint and its blur settle before timing
  await new Promise((r) => setTimeout(r, 600));
  phases.push(await phase("card-untracked", repaint));
  const unregister = register();
  // sleep: the adaptive chunk loads on first use and the watcher notices the grid on its next look
  await new Promise((r) => setTimeout(r, 1200));
  const stats0 = { ...((globalThis as { __glassStats?: { updates: number; totalMs: number; maxMs: number; readMs: number } }).__glassStats ?? { updates: 0, totalMs: 0, maxMs: 0, readMs: 0 }) };
  const tracked = await phase("card-tracked", repaint);
  const stats1 = (globalThis as { __glassStats?: { updates: number; totalMs: number; maxMs: number; readMs: number } }).__glassStats;
  if (stats1) { const u = stats1.updates - stats0.updates; tracked.glass = { updates: u, meanMs: Number(((stats1.totalMs - stats0.totalMs) / Math.max(1, u)).toFixed(3)), maxMs: Number(stats1.maxMs.toFixed(3)), readMeanMs: Number(((stats1.readMs - stats0.readMs) / Math.max(1, u)).toFixed(3)) }; }
  phases.push(tracked);
  unregister();
  const report: BenchReport = { userAgent: navigator.userAgent, dpr: devicePixelRatio, viewport: `${innerWidth}x${innerHeight}`, phases };
  (globalThis as { __benchReport?: BenchReport }).__benchReport = report;
  return report;
}
