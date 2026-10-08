import { describe, expect, test } from "bun:test";
import { DROP, FREEZE, FrameDetector, OK } from "./perf-detector";

/** Feeds `count` frames at `hz`, starting after `t0`; returns the last timestamp. */
function feed(d: FrameDetector, t0: number, hz: number, count: number): number {
  let t = t0;
  for (let i = 0; i < count; i++) { t += 1000 / hz; d.frame(t); }
  return t;
}

describe("FrameDetector", () => {
  test("estimates the refresh from the median and snaps it", () => {
    for (const hz of [60, 90, 120, 144]) {
      const d = new FrameDetector();
      feed(d, 1000, hz + 0.7, 100);
      d.estimate();
      expect(d.refresh).toBe(hz);
    }
  });

  test("nothing is a drop before the rate is known", () => {
    const d = new FrameDetector();
    d.frame(1000);
    expect(d.frame(1090)).toBe(OK);
  });

  test("a drop is over 1.5 refresh intervals, a freeze over 100 ms", () => {
    const d = new FrameDetector();
    let t = feed(d, 1000, 120, 100);
    d.estimate();
    expect(d.frame((t += 8.3))).toBe(OK);
    expect(d.frame((t += 12.6))).toBe(DROP); // 12.6 > 1.5 * 8.33
    expect(d.frame((t += 12.0))).toBe(OK);
    expect(d.frame((t += 101))).toBe(FREEZE);
  });

  test("the refresh only goes up: a slow page is not a slower display", () => {
    const d = new FrameDetector();
    let t = feed(d, 1000, 120, 100);
    d.estimate();
    t = feed(d, t, 30, 300);
    d.estimate();
    expect(d.refresh).toBe(120);
  });

  test("the first frame after a pause is not an interval", () => {
    const d = new FrameDetector();
    const t = feed(d, 1000, 60, 100);
    d.estimate();
    d.resume();
    expect(d.frame(t + 60_000)).toBe(OK);
  });

  test("fps, p95 and window read the ring", () => {
    const d = new FrameDetector();
    feed(d, 1000, 100, 200);
    expect(Math.round(d.fps())).toBe(100);
    expect(d.p95()).toBeCloseTo(10, 1);
    expect(d.window(150, 5, 5)).toHaveLength(11);
  });
});
