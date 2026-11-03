/**
 * The frame meter and frame-drop recorder (issue #116): an incident reaches the mock server's file with its cause,
 * the meter's frame body costs next to nothing, and it causes no layout or style recalculation between repaints.
 * `?fps=bench` mounts the meter with its measuring hooks (`window.__perfHud`).
 */
import { tracerEvidencePath } from "./evidence-path";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const file = resolve(process.env.INFRATERNAL_PERF_DIR ?? tracerEvidencePath("perf"), `${port}.jsonl`);
import { hud, open } from "./perf-hud-fixture";

test("a 200 ms stall during a pan reaches the file as one freeze, with its activity and script", async ({ page }) => {
  test.setTimeout(60_000);
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
  const lines = (await readFile(file, "utf8")).trim().split("\n").map((l) => JSON.parse(l) as Record<string, any>).filter((l) => l.sid === sid);
  const incidents = lines.filter((l) => l.t === "incident" && l.kind === "freeze" && l.activity === "pan");
  console.log("PERF-INCIDENT", JSON.stringify(incidents[0]));
  expect(lines.some((l) => l.t === "session")).toBe(true);
  expect(incidents).toHaveLength(1);
  const [incident] = incidents;
  expect(incident!.activity).toBe("pan");
  expect(incident!.worstMs).toBeGreaterThan(190);
  expect(incident!.page).toContain("proto=clusters");
  expect(incident!.intervals.length).toBeGreaterThan(10);
  expect(incident!.loaf.length).toBeGreaterThan(0);
  const scripts = incident!.loaf.flatMap((f: { scripts: Array<{ src: string; ms: number }> }) => f.scripts);
  expect(scripts.some((s: { src: string; ms: number }) => s.src.includes("perf-spec-stall") && s.ms > 150)).toBe(true);
  // The evidence for a stall at rest: the heartbeat timer was late (the main thread was blocked), the last input is
  // named, the page-state ring and the support flags are there, and the JS heap is read where the browser has it.
  const diag = incident!.diag;
  expect(diag.stalls.some((s: { late: number }) => s.late > 100)).toBe(true);
  expect(diag.action.type).toBe("wheel");
  expect(diag.ws).toEqual({ msgs: expect.any(Number), bytes: expect.any(Number) });
  expect(Array.isArray(diag.events)).toBe(true);
  expect(diag.support).toEqual({ loaf: expect.any(Boolean), longtask: expect.any(Boolean), event: expect.any(Boolean) });
  expect(diag.heap === null || typeof diag.heap.usedMB === "number").toBe(true);
});
