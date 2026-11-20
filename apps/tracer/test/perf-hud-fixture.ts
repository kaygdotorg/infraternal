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
  // The stall lives in a script served from its own URL, so a long-animation-frame entry can name it. It used to be an inline script
  // tagged with `//# sourceURL=perf-spec-stall.js`; Chromium reports a script by its URL, and a bare file name in a source-URL comment is
  // not one, so Chromium 159 listed no script at all for the 211 ms frame (empty `scripts`).
  await page.context().route("**/perf-spec-stall.js", (route) => route.fulfill({ contentType: "text/javascript", body: `
    window.__stall = false;
    function perfSpecStall() { const end = performance.now() + 200; while (performance.now() < end) { /* busy */ } }
    document.querySelector(".cl-viewport").addEventListener("wheel", () => { if (window.__stall) { window.__stall = false; requestAnimationFrame(perfSpecStall); } }, { capture: true });
  ` }));
  await page.addScriptTag({ url: "/perf-spec-stall.js" });
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
  // The session record is written when the page starts, so its sid is in the file long before the flushed incident arrives; waiting for the
  // sid alone read the file before the incident was posted and found none in about one run in four. Wait for the pan freeze itself.
  const read = async (): Promise<Array<Record<string, unknown>>> => (await readFile(file, "utf8").catch(() => "")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.sid === sid);
  const isPanFreeze = (l: Record<string, unknown>): boolean => l.t === "incident" && l.kind === "freeze" && l.activity === "pan";
  await expect.poll(async () => (await read()).some(isPanFreeze), { timeout: 8000 }).toBe(true).catch(() => undefined); // no incident: the spec's own length check reports it
  const lines = await read();
  const incidents = lines.filter(isPanFreeze) as unknown as Array<Incident & { page: string }>;
  console.log("PERF-INCIDENT", JSON.stringify(incidents[0]));
  return { sessionRecorded: lines.some((line) => line.t === "session"), incidents };
}
