// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Frame captures and timelines of two pointer animations, for the owner's review (#484, #471): the top pill morphing into
 * the view list and back, and a window split down. Run on demand against a production build:
 * `J475_CAPTURE=1 J475_LABEL=before bun x playwright test test/motion-capture.spec.ts`.
 *
 * It is a capture, not a gate: it asserts nothing about time (functional specs never do; speed budgets live in
 * `perf/` and `motion-speed.test.ts` checks the declared durations). Each case writes, under the evidence directory
 * `j475-<label>/<case>/`, a JPEG per compositor frame (`NNN-<ms>.jpg`, `ms` since the click) from a CDP screencast and
 * `timeline.json`, a per-animation-frame record of the state the case cares about, plus `summary.json` with the durations
 * read from it. Montage the JPEGs into a strip with ImageMagick `montage`.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { expect, test, type CDPSession, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** Whether the capture runs; it is skipped in the normal suite. */
const enabled = process.env.J475_CAPTURE === "1";
/** `before` or `after`: the directory the files land in. */
const label = process.env.J475_LABEL ?? "run";
/** The view the mock opens on. */
const VIEW = '.cl[data-view="console"]';

/** Opens the clusters mock on the Console view, with one window active. */
async function boot(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  // sleep: the mock's scene needs a moment to settle before the camera flight
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  // sleep: the camera flight to the view lasts under 300 ms; this leaves margin for a loaded VM
  await page.waitForTimeout(1500);
}

/** One screencast frame on disk: its index and the milliseconds since recording began. */
interface Shot { index: number; at: number }

/**
 * Starts a CDP screencast writing JPEGs into `dir`; `stop()` ends it. File names carry the frame's timestamp relative to the
 * first frame, so a strip can be labelled with real times.
 */
async function screencast(page: Page, dir: string): Promise<{ stop(): Promise<Shot[]> }> {
  mkdirSync(dir, { recursive: true });
  const cdp: CDPSession = await page.context().newCDPSession(page);
  const shots: Shot[] = [];
  let origin = -1;
  cdp.on("Page.screencastFrame", (frame) => {
    const stamp = (frame.metadata.timestamp ?? 0) * 1000;
    if (origin < 0) origin = stamp;
    const at = Math.round(stamp - origin);
    const index = shots.length;
    shots.push({ index, at });
    writeFileSync(`${dir}/${String(index).padStart(3, "0")}-${at}.jpg`, Buffer.from(frame.data, "base64"));
    void cdp.send("Page.screencastFrameAck", { sessionId: frame.sessionId }).catch(() => undefined);
  });
  await cdp.send("Page.startScreencast", { format: "jpeg", quality: 80, everyNthFrame: 1 });
  return { async stop() { await cdp.send("Page.stopScreencast").catch(() => undefined); await cdp.detach().catch(() => undefined); return shots; } };
}

test.describe("J475 motion captures", () => {
  test.skip(!enabled, "set J475_CAPTURE=1 to capture");
  test.setTimeout(120_000);

  test("the top pill opens into the view list and closes back", async ({ page }) => {
    const out = tracerEvidencePath(`j475-${label}`, "pill-menu");
    await boot(page);
    // One sample per animation frame: the panel, how far the content has faded in, the clip and the pill's own fade.
    await page.evaluate(() => {
      const w = window as unknown as { __pillLog: unknown[]; __pillStart: number };
      w.__pillLog = [];
      const tick = (now: number): void => {
        const panel = document.querySelector<HTMLElement>(".cl-viewlist");
        const rows = panel?.querySelector<HTMLElement>(".cl-viewlist-rows");
        const pill = document.querySelector<HTMLElement>("#capsule");
        w.__pillLog.push({
          t: now,
          panel: Boolean(panel),
          clip: panel?.style.clipPath ?? "",
          rows: rows ? Number(getComputedStyle(rows).opacity) : null,
          pill: pill ? Number(getComputedStyle(pill).opacity) : null,
        });
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
    const cap = await screencast(page, `${out}/frames`);
    const box = (await page.locator("#capsule").boundingBox())!;
    const mark = async (name: string): Promise<void> => { await page.evaluate((n) => (window as unknown as { __pillLog: unknown[] }).__pillLog.push({ mark: n, t: performance.now() }), name); };
    // sleep: lets the screencast start delivering frames so the first one is the resting pill
    await page.waitForTimeout(300);
    await mark("click-open");
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    // sleep: the open animation plus margin for a loaded VM
    await page.waitForTimeout(900);
    await mark("click-close");
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    // sleep: the close animation plus margin
    await page.waitForTimeout(900);
    const shots = await cap.stop();
    const log = await page.evaluate(() => (window as unknown as { __pillLog: Array<Record<string, unknown>> }).__pillLog);
    writeFileSync(`${out}/timeline.json`, JSON.stringify(log, null, 1));
    writeFileSync(`${out}/summary.json`, JSON.stringify({ frames: shots.length, ...summarisePill(log) }, null, 1));
  });

  test("a pointer split down", async ({ page }) => {
    const out = tracerEvidencePath(`j475-${label}`, "split-down");
    await boot(page);
    await page.locator(`${VIEW} .ui-window .ui-window-body`).first().click({ position: { x: 20, y: 40 } });
    // sleep: the click makes the window active and focuses its terminal
    await page.waitForTimeout(500);
    // One sample per animation frame: every window's box and opacity, and whether the liquid layer is drawn.
    await page.evaluate((view) => {
      const w = window as unknown as { __splitLog: unknown[] };
      w.__splitLog = [];
      const tick = (now: number): void => {
        w.__splitLog.push({
          t: now,
          goo: document.querySelectorAll("canvas.cl-goo").length,
          wins: [...document.querySelectorAll<HTMLElement>(`${view} .ui-window`)].map((el) => {
            const r = el.getBoundingClientRect();
            const body = el.querySelector<HTMLElement>(".ui-window-body");
            return { id: el.dataset.windowId, x: Math.round(r.x * 10) / 10, y: Math.round(r.y * 10) / 10, w: Math.round(r.width * 10) / 10, h: Math.round(r.height * 10) / 10, o: Number(getComputedStyle(el).opacity), bo: body ? Number(getComputedStyle(body).opacity) : null };
          }),
        });
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }, VIEW);
    const cap = await screencast(page, `${out}/frames`);
    const button = (await page.locator(`${VIEW} .ui-window[data-active] [data-action="split-down"]`).boundingBox())!;
    // sleep: lets the screencast deliver the resting frame first
    await page.waitForTimeout(300);
    await page.evaluate(() => (window as unknown as { __splitLog: unknown[] }).__splitLog.push({ mark: "click", t: performance.now() }));
    await page.mouse.click(button.x + button.width / 2, button.y + button.height / 2);
    // sleep: the split's motion plus margin for a loaded VM
    await page.waitForTimeout(1600);
    const shots = await cap.stop();
    const log = await page.evaluate(() => (window as unknown as { __splitLog: Array<Record<string, unknown>> }).__splitLog);
    writeFileSync(`${out}/timeline.json`, JSON.stringify(log, null, 1));
    writeFileSync(`${out}/summary.json`, JSON.stringify({ frames: shots.length, ...summariseSplit(log) }, null, 1));
  });
});

/** A sample from the pill's frame log. */
type PillSample = Record<string, unknown>;

/**
 * Reads the pill timeline: for the open and the close (each starting at its `click-*` mark), the time to the first frame the
 * panel is in the document, to the first frame its rows are at least half visible, and to the last frame anything is still
 * moving; plus the frames that showed the panel with its rows below 10 % (a blank card).
 */
function summarisePill(log: PillSample[]): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const phase of ["open", "close"]) {
    const start = log.find((s) => s.mark === `click-${phase}`);
    if (!start) continue;
    const t0 = start.t as number;
    const next = log.find((s) => typeof s.mark === "string" && s.t as number > t0 && s.mark !== `click-${phase}`);
    const frames = log.filter((s) => s.mark === undefined && (s.t as number) >= t0 && (!next || (s.t as number) < (next.t as number)));
    const first = (pred: (s: PillSample) => boolean): number | null => { const s = frames.find(pred); return s ? Math.round((s.t as number) - t0) : null; };
    const shown = frames.filter((s) => s.panel);
    result[phase] = {
      panelFirstFrameMs: first((s) => Boolean(s.panel)),
      rowsHalfVisibleMs: first((s) => Boolean(s.panel) && (s.rows as number) >= 0.5),
      settledMs: first((s) => phase === "open" ? Boolean(s.panel) && s.clip === "" && (s.rows as number) >= 0.999 : !s.panel),
      panelFramesWithRowsBelow10pct: shown.filter((s) => (s.rows as number) < 0.1).length,
      panelFrames: shown.length,
    };
  }
  return result;
}

/** A sample from the split's frame log. */
type SplitSample = { t?: number; mark?: string; goo?: number; wins?: Array<{ id: string; x: number; y: number; w: number; h: number; o: number; bo: number | null }> };

/**
 * Reads the split timeline from the click: the number of windows after it, when the new window's box first appears, when
 * every box stops changing (the last frame any box moved), the longest the liquid layer is drawn, and the frames in which
 * the new window shows at less than full opacity (the fade).
 */
function summariseSplit(log: SplitSample[]): Record<string, unknown> {
  const start = log.find((s) => s.mark === "click");
  if (!start) return { error: "no click mark" };
  const t0 = start.t!;
  const frames = log.filter((s) => s.mark === undefined && s.t! >= t0);
  const before = new Set(frames[0]?.wins?.map((w) => w.id));
  let lastMove = 0, appeared: number | null = null, gooFrames = 0, gooLast = 0;
  let prev = frames[0];
  const fade: number[] = [];
  for (const f of frames) {
    const fresh = f.wins?.find((w) => !before.has(w.id));
    if (fresh && appeared === null) appeared = Math.round(f.t! - t0);
    if (fresh) fade.push(Math.min(fresh.o, fresh.bo ?? 1));
    if (f.goo) { gooFrames++; gooLast = Math.round(f.t! - t0); }
    const moved = JSON.stringify(f.wins?.map((w) => [w.id, w.x, w.y, w.w, w.h])) !== JSON.stringify(prev?.wins?.map((w) => [w.id, w.x, w.y, w.w, w.h]));
    if (moved) lastMove = Math.round(f.t! - t0);
    prev = f;
  }
  return { newWindowFirstFrameMs: appeared, boxesLastMovedMs: lastMove, liquidLayerFrames: gooFrames, liquidLayerLastMs: gooLast, newWindowOpacitySamples: fade.slice(0, 40) };
}
