/** Checks physical motion against elapsed time when the browser misses frames. */
import { expect, test } from "bun:test";
import { Spring, type SpringConfig } from "./spring";

test("a missed frame does not stretch a settled spring", () => {
  const originalRequest = globalThis.requestAnimationFrame;
  const originalCancel = globalThis.cancelAnimationFrame;
  const originalMedia = globalThis.matchMedia;
  let callback: FrameRequestCallback | undefined;
  let pending = false;
  globalThis.requestAnimationFrame = (next) => { callback = next; pending = true; return 1; };
  globalThis.cancelAnimationFrame = () => { pending = false; };
  globalThis.matchMedia = (() => ({ matches: false })) as typeof matchMedia;
  try {
    const spring = new Spring(0, () => {}, { visualDuration: 0.15, bounce: 0 });
    spring.set(1);
    pending = false;
    callback!(performance.now() + 1200);
    expect(spring.value).toBe(1);
    expect(pending).toBe(false);
  } finally {
    globalThis.requestAnimationFrame = originalRequest;
    globalThis.cancelAnimationFrame = originalCancel;
    globalThis.matchMedia = originalMedia;
  }
});

test("motion follows elapsed time across frame rates and damping regimes", () => {
  const originalRequest = globalThis.requestAnimationFrame;
  const originalCancel = globalThis.cancelAnimationFrame;
  const originalMedia = globalThis.matchMedia;
  let callback: FrameRequestCallback | undefined;
  globalThis.requestAnimationFrame = (next) => { callback = next; return 1; };
  globalThis.cancelAnimationFrame = () => {};
  globalThis.matchMedia = (() => ({ matches: false })) as typeof matchMedia;
  const sample = (cfg: SpringConfig, frames: number): number => {
    const spring = new Spring(0, () => {}, cfg);
    spring.restDelta = spring.restVelocity = 0;
    spring.set(1);
    const start = (spring as unknown as { last: number }).last;
    for (let i = 1; i <= frames; i++) callback!(start + i * 250 / frames);
    return spring.value;
  };
  try {
    for (const [stiffness, damping] of [[100, 8], [100, 20], [100, 40], [0, 0]]) {
      const cfg = { stiffness: stiffness!, damping: damping! };
      const slow = sample(cfg, 1), fast = sample(cfg, 60);
      expect(Number.isFinite(slow)).toBe(true);
      expect(slow).toBeCloseTo(fast, 10);
    }
  } finally {
    globalThis.requestAnimationFrame = originalRequest;
    globalThis.cancelAnimationFrame = originalCancel;
    globalThis.matchMedia = originalMedia;
  }
});

test("a flung spring carries the release velocity before it turns back", () => {
  const originalRequest = globalThis.requestAnimationFrame;
  const originalCancel = globalThis.cancelAnimationFrame;
  const originalMedia = globalThis.matchMedia;
  let callback: FrameRequestCallback | undefined;
  globalThis.requestAnimationFrame = (next) => { callback = next; return 1; };
  globalThis.cancelAnimationFrame = () => {};
  globalThis.matchMedia = (() => ({ matches: false })) as typeof matchMedia;
  try {
    // A row released at 100 px, still moving right at 2000 px/s, settling back to 0: it first keeps going right.
    const spring = new Spring(0, () => {}, { visualDuration: 0.3, bounce: 0 });
    spring.value = 100;
    spring.fling(0, 2000);
    const start = (spring as unknown as { last: number }).last;
    callback!(start + 16);
    expect(spring.value).toBeGreaterThan(100);
    for (let i = 2; i < 120; i += 1) callback!(start + 16 * i);
    expect(spring.value).toBe(0);
  } finally {
    globalThis.requestAnimationFrame = originalRequest;
    globalThis.cancelAnimationFrame = originalCancel;
    globalThis.matchMedia = originalMedia;
  }
});
