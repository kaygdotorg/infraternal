/** Functional persistence, coalescing and cause attribution for frame-drop incidents (#314). */
import { expect, test } from "playwright/test";
import { recordPanStall } from "./perf-hud-fixture";

test("a 200 ms stall during a pan reaches the file as one freeze, with its activity and script", async ({ page }) => {
  test.setTimeout(60_000);
  const { sessionRecorded, incidents } = await recordPanStall(page);
  expect(sessionRecorded).toBe(true);
  expect(incidents).toHaveLength(1);
  const [incident] = incidents;
  expect(incident!.activity).toBe("pan");
  expect(incident!.page).toContain("proto=clusters");
  expect(incident!.intervals.length).toBeGreaterThan(10);
  expect(incident!.loaf.length).toBeGreaterThan(0);
  const scripts = incident!.loaf.flatMap((f: { scripts: Array<{ src: string; ms: number }> }) => f.scripts);
  expect(scripts.some((s: { src: string; ms: number }) => s.src.includes("perf-spec-stall"))).toBe(true);
  // The evidence for a stall at rest: the heartbeat timer was late (the main thread was blocked), the last input is
  // named, the page-state ring and the support flags are there, and the JS heap is read where the browser has it.
  const diag = incident!.diag;
  expect(diag.stalls.length).toBeGreaterThan(0);
  expect(diag.action?.type).toBe("wheel");
  expect(diag.ws).toEqual({ msgs: expect.any(Number), bytes: expect.any(Number) });
  expect(Array.isArray(diag.events)).toBe(true);
  expect(diag.support).toEqual({ loaf: expect.any(Boolean), longtask: expect.any(Boolean), event: expect.any(Boolean) });
  expect(diag.heap === null || typeof diag.heap.usedMB === "number").toBe(true);
});
