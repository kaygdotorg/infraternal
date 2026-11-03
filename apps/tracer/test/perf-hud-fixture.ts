/** Shared production frame-meter fixture for functional incidents and perf-VM budgets (#314). */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { Incident } from "../src/perf-hud.on-demand";
import { tracerEvidencePath } from "./evidence-path";
import { expect, type Page } from "playwright/test";

const URL = "/?mock=1&proto=clusters&scene=7&theme=ink&bg=none";

type Hud = { bench(calls?: number, batch?: number): { meanUs: number; p99Us: number; maxUs: number }; selfTime(): { frames: number; meanMs: number }; pauseRepaint(): void; flush(): void; finish(): void; state(): { sid: string; incidents: number; refresh: number } };
export const hud = (page: Page) => ({
  call: <T,>(fn: (h: Hud) => T): Promise<T> => page.evaluate(`(${fn.toString()})(window.__perfHud)`) as Promise<T>,
});

export async function open(page: Page, query = "&fps=bench"): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(URL + query);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  if (query.includes("bench")) await page.waitForFunction("!!window.__perfHud", undefined, { timeout: 10_000 });
  await page.keyboard.press("Control+Shift+G"); // canvas lock off: free pan
  await page.waitForTimeout(1500);
}

/** Records the same real injected stall for functional attribution and perf-VM timing checks. */
export async function recordPanStall(page: Page) {
  const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
  const file = resolve(process.env.INFRATERNAL_PERF_DIR ?? tracerEvidencePath("perf"), `${port}.jsonl`);
  await open(page);
  // The stall lives in a script of its own, so a long-animation-frame entry can name it.
  await page.addScriptTag({ content: `
    window.__stall = false;
    function perfSpecStall() { const end = performance.now() + 200; while (performance.now() < end) { /* busy */ } }
    document.querySelector(".cl-viewport").addEventListener("wheel", () => { if (window.__stall) { window.__stall = false; requestAnimationFrame(perfSpecStall); } }, { capture: true });
    //# sourceURL=perf-spec-stall.js` });
  await page.evaluate(() => new Promise<void>((done) => {
    const target = document.querySelector(".cl-viewport")!;
    const start = performance.now();
    const step = (t: number): void => {
      if (t - start > 900) { done(); return; }
      if (t - start > 400 && !(window as unknown as { __armed?: boolean }).__armed) { (window as unknown as { __armed: boolean; __stall: boolean }).__armed = true; (window as unknown as { __stall: boolean }).__stall = true; }
      target.dispatchEvent(new WheelEvent("wheel", { deltaX: 24, deltaY: 9, clientX: 720, clientY: 450, bubbles: true, cancelable: true }));
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }));
  await page.waitForTimeout(1200);
  const sid = (await hud(page).call((h) => { h.finish(); h.flush(); return h.state().sid; }));
  await expect.poll(async () => (await readFile(file, "utf8").catch(() => "")).includes(sid), { timeout: 8000 }).toBe(true);
  const lines = (await readFile(file, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.sid === sid);
  const incidents = lines.filter((l) => l.t === "incident" && l.kind === "freeze" && l.activity === "pan") as unknown as Array<Incident & { page: string }>;
  console.log("PERF-INCIDENT", JSON.stringify(incidents[0]));
  return { sessionRecorded: lines.some((line) => line.t === "session"), incidents };
}
