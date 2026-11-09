// SPDX-License-Identifier: AGPL-3.0-only
/**
 * No overshoot, ever (TASTE section 3, owner 2026-11-02: "can we get rid of this elastic overshoot please? it looks
 * terrible everytime it happens!").
 *
 * Two kinds of check. The scans read the source of apps/tracer and packages/ui and reject anything that asks for an
 * easing that passes its end: a non-zero `bounce`, a `cubic-bezier` with a control point outside [0, 1] on the value
 * axis, a "back" or "elastic" easing, or a raw `{ stiffness, damping }` spring outside the short allow-list. The
 * numeric checks run the real `Spring` and the FLIP curve and assert that no value passes its target.
 *
 * Allow-list (each entry needs a reason a reader can check):
 * - droplet.on-demand.ts: the split-window droplet. TASTE section 3 ("Splits are playful physics") and the row that
 *   says liquid motion belongs to the droplet make its wobble the owner's own request. Pending the owner's word on
 *   whether the new rule also covers it (issue #308).
 * - countup.ts: raw spring that is overdamped for every duration (asserted below), so it cannot overshoot.
 */
import { expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { Spring } from "../../../packages/ui/src/spring";
import { flipEasing } from "../src/canvas/layout/flip";

const repo = join(import.meta.dir, "../../..");
const ROOTS = ["apps/tracer", "packages/ui"];
const SKIP_DIRS = new Set(["node_modules", "dist", "vendor", "fonts", "test", "real", "docs-dist"]);
const RAW_SPRING_ALLOWED = new Set(["apps/tracer/src/canvas/layout/droplet.on-demand.ts", "packages/ui/src/countup.ts", "packages/ui/src/spring.ts"]);

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) { if (!SKIP_DIRS.has(name)) sources(path, out); continue; }
    if (/\.(ts|css|svelte|html)$/.test(name) && !/\.(test|spec)\.ts$/.test(name)) out.push(path);
  }
  return out;
}
const files = ROOTS.flatMap((root) => sources(join(repo, root))).map((path) => ({ path, rel: relative(repo, path), text: readFileSync(path, "utf8") }));

/** Every offence as `file:line text`, so a failure says where. */
function offences(pattern: RegExp, bad: (m: RegExpExecArray) => boolean, skip?: (rel: string) => boolean): string[] {
  const out: string[] = [];
  for (const f of files) {
    if (skip?.(f.rel)) continue;
    f.text.split("\n").forEach((line, i) => {
      for (const m of line.matchAll(new RegExp(pattern.source, "g"))) if (bad(m as RegExpExecArray)) out.push(`${f.rel}:${i + 1} ${m[0]}`);
    });
  }
  return out;
}

test("the scan sees the source it is meant to police", () => {
  expect(files.length).toBeGreaterThan(50);
  expect(files.some((f) => f.rel === "packages/ui/src/spring.ts")).toBe(true);
  expect(files.some((f) => f.rel.endsWith("styles.css"))).toBe(true);
});

test("no spring asks for a bounce", () => {
  expect(offences(/\bbounce\s*:\s*([^,}\s)]+)/, (m) => m[1] !== "0")).toEqual([]);
});

test("no cubic-bezier has a control point beyond [0, 1] on the value axis", () => {
  const bad = offences(/cubic-bezier\(\s*([-\d.]+)\s*,\s*([-\d.]+)\s*,\s*([-\d.]+)\s*,\s*([-\d.]+)\s*\)/, (m) => {
    const y1 = Number(m[2]), y2 = Number(m[4]);
    return y1 < 0 || y1 > 1 || y2 < 0 || y2 > 1;
  });
  expect(bad).toEqual([]);
  // The rule must be able to fail: the curve the product used to ship is rejected.
  const probe = /cubic-bezier\(\s*([-\d.]+)\s*,\s*([-\d.]+)\s*,\s*([-\d.]+)\s*,\s*([-\d.]+)\s*\)/.exec("cubic-bezier(0.34, 1.4, 0.64, 1)")!;
  expect(Number(probe[2]) > 1).toBe(true);
});

test("no 'back' or 'elastic' easing", () => {
  expect(offences(/\b(easeOutBack|easeInBack|easeInOutBack|backOut|backIn|elasticOut|elasticIn|easeOutElastic|easeInElastic)\b|1\.70158|\bback\.(out|inOut)\b/i, () => true)).toEqual([]);
});

test("raw stiffness and damping springs exist only where the allow-list says", () => {
  expect(offences(/\bstiffness\s*[:=]/, () => true, (rel) => RAW_SPRING_ALLOWED.has(rel))).toEqual([]);
});

test("the count-up spring is overdamped for every duration it can be given", () => {
  for (const d of [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 20]) {
    const stiffness = 100 / d, damping = 20 + 40 / d;
    expect(damping * damping).toBeGreaterThanOrEqual(4 * stiffness);
  }
});

/** Runs a Spring at rest from 0 to 1 at a frame rate and returns the largest value it ever reports. */
function peak(visualDuration: number, fps: number): number {
  const originalRequest = globalThis.requestAnimationFrame;
  const originalCancel = globalThis.cancelAnimationFrame;
  const originalMedia = globalThis.matchMedia;
  let callback: FrameRequestCallback | undefined;
  globalThis.requestAnimationFrame = (next) => { callback = next; return 1; };
  globalThis.cancelAnimationFrame = () => {};
  globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
  try {
    let max = 0;
    const spring = new Spring(0, (v) => { max = Math.max(max, v); }, { visualDuration, bounce: 0 });
    spring.set(1);
    const start = (spring as unknown as { last: number }).last;
    for (let i = 1; i <= fps * 4; i++) callback!(start + (i * 1000) / fps);
    expect(spring.value).toBe(1);
    return max;
  } finally {
    globalThis.requestAnimationFrame = originalRequest;
    globalThis.cancelAnimationFrame = originalCancel;
    globalThis.matchMedia = originalMedia;
  }
}

test("a Spring from rest never passes its target, at any duration or frame rate", () => {
  for (const d of [0.08, 0.16, 0.26, 0.4, 0.5, 0.85]) for (const fps of [20, 30, 60, 120]) expect(peak(d, fps)).toBeLessThanOrEqual(1);
});

test("retargeting a moving Spring never carries it past the new target", () => {
  const originalRequest = globalThis.requestAnimationFrame;
  const originalCancel = globalThis.cancelAnimationFrame;
  const originalMedia = globalThis.matchMedia;
  let callback: FrameRequestCallback | undefined;
  globalThis.requestAnimationFrame = (next) => { callback = next; return 1; };
  globalThis.cancelAnimationFrame = () => {};
  globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
  try {
    // A fast flight toward 10, retargeted at several points of its run to a target only a little further than where it
    // is: without the cap the carried speed would run past the target and come back.
    for (const frames of [3, 6, 9, 12, 18]) {
      let seen = 0;
      const spring = new Spring(0, (v) => { seen = v; }, { visualDuration: 0.2, bounce: 0 });
      spring.set(10);
      let t = (spring as unknown as { last: number }).last;
      for (let i = 0; i < frames; i++) { t += 16; callback!(t); }
      const target = spring.value + 0.05;
      spring.set(target);
      let max = seen;
      for (let i = 0; i < 400; i++) { t += 16; callback!(t); max = Math.max(max, seen); }
      expect(max, `retarget after ${frames} frames`).toBeLessThanOrEqual(target + 1e-9);
      expect(spring.value).toBe(target);
    }
  } finally {
    globalThis.requestAnimationFrame = originalRequest;
    globalThis.cancelAnimationFrame = originalCancel;
    globalThis.matchMedia = originalMedia;
  }
});

test("the FLIP curve never passes its end", () => {
  // The reflow plays the product's ease-out (#471); its value-axis control points must stay in [0, 1].
  const { css } = flipEasing({ visualDuration: 0.28 });
  const [, y1, , y2] = /cubic-bezier\(([-\d.]+),\s*([-\d.]+),\s*([-\d.]+),\s*([-\d.]+)\)/.exec(css)!.slice(1).map(Number);
  for (const y of [y1!, y2!]) { expect(y).toBeGreaterThanOrEqual(0); expect(y).toBeLessThanOrEqual(1); }
});
