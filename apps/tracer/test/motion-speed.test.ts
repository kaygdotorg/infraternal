// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Fast, ease-out motion (TASTE section 3, "Fast, ease-out, under 300 ms"). Owner, 2026-11-09: "when did animations
 * become so slow in the mockup and production? did you forget emil's rulue?", quoting "Use ease-out for anything
 * entering or leaving the screen. Keep UI animations under 300ms." (#471).
 *
 * What fails this test:
 * - a `Spring` duration (`visualDuration`) over 0.3 s;
 * - a CSS transition or animation, or a Web Animation (`element.animate`), whose duration plus delay is over 300 ms;
 * - a curve that starts slowly: `ease-in`, `ease-in-out`, or a `cubic-bezier` whose first control point leaves the
 *   start flatter than a straight line (y1 < x1);
 * - `ease`, `linear` or no easing at all (CSS and the Web Animations API then use `ease` and `linear`) on anything that
 *   moves, resizes or fades. Both start slowly or crawl. `ease` stays fine for a colour change in place (a hover tint),
 *   which neither enters nor leaves;
 * - a `Spring` released from rest that does not cover most of its distance in the first frames.
 *
 * Durations written as `var(--t-press|pop|panel)` are read from packages/ui/styles.css, so a token that grows past
 * 300 ms fails here too. Toast and notice dwell times (`duration:` on a toast) are not motion and are not scanned.
 *
 * The allow-list holds continuous indicators and ambient loops, which run for as long as their state lasts, plus the
 * one deliberate stagger. Each entry is `file` + a fragment of the offending text, with the reason.
 */
import { expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { Spring } from "../../../packages/ui/src/spring";
import { flipEasing } from "../src/canvas/layout/flip";

/** The longest a UI motion may take, in milliseconds (owner: "Keep UI animations under 300ms"). */
const LIMIT_MS = 300;

/**
 * Motion that may break the rules, and why. A loop is not an enter or exit: it runs while a state lasts.
 * Matching is `file` plus a text fragment that must appear in the offending declaration or call.
 */
const ALLOWED: Array<{ file: string; has: string; why: string }> = [
  { file: "packages/ui/styles.css", has: "ui-spinner-turn", why: "spinner: a constant-speed turn, linear by nature" },
  { file: "packages/ui/styles.css", has: "ui-mark-spin", why: "busy mark spinner: constant-speed turn" },
  { file: "packages/ui/styles.css", has: "ui-conn-turn", why: "reconnecting spinner: constant-speed turn" },
  { file: "packages/ui/styles.css", has: "ui-glitch-bands", why: "ambient glitch loop on the sign-in wordmark" },
  { file: "packages/ui/styles.css", has: "ui-setup-pulse", why: "breathing fill while a setup stage runs (a progress indicator)" },
  { file: "apps/tracer/mesh.css", has: "cl-note-breathe", why: "breathing icon while the mesh note is open (ambient)" },
  { file: "apps/tracer/clusters.css", has: "cl-blink", why: "terminal caret blink: a stepped loop, not a transition" },
  { file: "apps/tracer/style.css", has: "keywiggle", why: "edit-mode wiggle of the key toolbar: an ambient loop while editing" },
  { file: "packages/ui/styles.css", has: "ui-conn-pulse", why: "connection status pulse: the status icon's own motion (TASTE 'Status is an icon with motion'), not an enter or exit" },
  { file: "packages/ui/styles.css", has: "ui-setting-found", why: "the tint on a setting ⌘K jumped to fades slowly so the eye finds the row; a colour in place, nothing moves" },
  { file: "packages/ui/src/terminal-cursor-layer.ts", has: "CURSOR_BLINK_PERIOD_MS", why: "terminal caret blink: a stepped loop, not a transition" },
];
const allowed = (rel: string, text: string): boolean => ALLOWED.some((a) => a.file === rel && text.includes(a.has));

const repo = join(import.meta.dir, "../../..");
const ROOTS = ["apps/tracer", "packages/ui"];
const SKIP_DIRS = new Set(["node_modules", "dist", "vendor", "fonts", "test", "real", "docs-dist"]);
function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) { if (!SKIP_DIRS.has(name)) sources(path, out); continue; }
    if (/\.(ts|css|svelte|html)$/.test(name) && !/\.(test|spec)\.ts$/.test(name)) out.push(path);
  }
  return out;
}
const files = ROOTS.flatMap((root) => sources(join(repo, root))).map((path) => ({ path, rel: relative(repo, path), text: readFileSync(path, "utf8") }));
/** The line number of offset `at` in `text`, for `file:line` messages. */
const lineOf = (text: string, at: number): number => text.slice(0, at).split("\n").length;

/** The duration tokens of packages/ui/styles.css, in milliseconds. */
const tokens = new Map<string, number>();
for (const m of readFileSync(join(repo, "packages/ui/styles.css"), "utf8").matchAll(/--(t-[a-z]+)\s*:\s*([\d.]+)(ms|s)\s*;/g)) {
  tokens.set(m[1]!, Number(m[2]) * (m[3] === "s" ? 1000 : 1));
}

/** A time in milliseconds from `120ms`, `0.3s` or `var(--t-pop)`; undefined when it is not a time. */
function ms(token: string): number | undefined {
  const lit = /^(-?[\d.]+)(ms|s)$/.exec(token);
  if (lit) return Number(lit[1]) * (lit[2] === "s" ? 1000 : 1);
  const v = /^var\(--(t-[a-z]+)/.exec(token);
  return v ? tokens.get(v[1]!) : undefined;
}

/** Properties whose change moves, resizes or fades something: these need an ease-out curve. Colours may use `ease`. */
const MOVING = /^(all|opacity|transform|translate|scale|rotate|top|left|right|bottom|inset|width|height|min-height|max-height|block-size|inline-size|margin|padding|grid-template-rows|grid-template-columns|clip-path|filter|backdrop-filter|stroke-dashoffset|flex|flex-basis|offset)/;

/**
 * Whether an easing starts slowly. `ease-in`, `ease-in-out` and `ease`, and a cubic-bezier whose first handle leaves
 * flatter than the straight line (y1 < x1), all spend the first frames barely moving.
 */
function slowStart(easing: string): boolean {
  if (/^ease-in(-out)?$/.test(easing) || easing === "ease") return true;
  const b = /cubic-bezier\(\s*([-\d.]+)\s*,\s*([-\d.]+)/.exec(easing);
  return b ? Number(b[2]) < Number(b[1]) : false;
}

/** Splits a CSS value on commas that are not inside parentheses. */
function splitTop(value: string): string[] {
  const out: string[] = []; let depth = 0, cur = "";
  for (const ch of value) {
    if (ch === "(") depth++; else if (ch === ")") depth--;
    if (ch === "," && depth === 0) { out.push(cur.trim()); cur = ""; } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}
/** Splits one shorthand item on spaces that are not inside parentheses. */
function words(item: string): string[] {
  const out: string[] = []; let depth = 0, cur = "";
  for (const ch of item) {
    if (ch === "(") depth++; else if (ch === ")") depth--;
    if (/\s/.test(ch) && depth === 0) { if (cur) out.push(cur); cur = ""; } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}
const EASING = /^(ease|ease-in|ease-out|ease-in-out|linear|step-start|step-end|steps\(|cubic-bezier\(|linear\(|var\(--ease)/;

/** One CSS transition or animation item, read from its shorthand. */
interface Motion { property: string; duration: number; delay: number; easing: string; loop: boolean }
/** Reads one `transition:` or `animation:` shorthand item. An omitted easing is `ease`, as in CSS. */
function parseItem(item: string, kind: "transition" | "animation"): Motion {
  const ws = words(item);
  const times = ws.map(ms).filter((t): t is number => t !== undefined);
  // `var(--ease-out, ...)` and `var(--ease-drawer, ...)` are the product's ease-out curves; a fallback inside does not count.
  const easingWord = ws.find((w) => EASING.test(w) && ms(w) === undefined);
  const easing = easingWord === undefined ? "ease" : /^var\(--ease-(out|drawer)/.test(easingWord) ? "ease-out" : easingWord;
  const property = kind === "transition" ? (ws.find((w) => /^[a-z-]+$/.test(w) && !EASING.test(w) && w !== "allow-discrete") ?? "all") : "animation";
  return { property, duration: times[0] ?? 0, delay: times[1] ?? 0, easing, loop: ws.includes("infinite") };
}

/** Every CSS transition and animation in the scanned stylesheets, with where it is. */
function cssMotions(): Array<Motion & { at: string; text: string; rel: string }> {
  const out: Array<Motion & { at: string; text: string; rel: string }> = [];
  for (const f of files) {
    if (!f.rel.endsWith(".css")) continue;
    for (const m of f.text.matchAll(/(?<![-\w])(transition|animation)\s*:\s*([^;}]+)/g)) {
      const kind = m[1] as "transition" | "animation";
      const value = m[2]!.trim();
      if (value === "none" || value.startsWith("var(")) continue;
      for (const item of splitTop(value)) out.push({ ...parseItem(item, kind), at: `${f.rel}:${lineOf(f.text, m.index!)}`, text: `${kind}: ${item}`, rel: f.rel });
    }
    // A custom property that holds a transition (`--ui-button-transition: ...`) is a transition too.
    for (const m of f.text.matchAll(/--[\w-]*transition\s*:\s*([^;}]+)/g)) {
      for (const item of splitTop(m[1]!.trim())) out.push({ ...parseItem(item, "transition"), at: `${f.rel}:${lineOf(f.text, m.index!)}`, text: `transition: ${item}`, rel: f.rel });
    }
  }
  return out;
}

/** The argument text of every `.animate(` call in script, found by matching parentheses. */
function animateCalls(): Array<{ at: string; text: string; rel: string }> {
  const out: Array<{ at: string; text: string; rel: string }> = [];
  for (const f of files) {
    if (!f.rel.endsWith(".ts")) continue;
    for (const m of f.text.matchAll(/\.animate\(/g)) {
      let depth = 1, i = m.index! + m[0].length;
      for (; i < f.text.length && depth; i++) { const ch = f.text[i]; if (ch === "(") depth++; else if (ch === ")") depth--; }
      out.push({ at: `${f.rel}:${lineOf(f.text, m.index!)}`, text: f.text.slice(m.index!, i), rel: f.rel });
    }
  }
  return out;
}

test("the scan sees the motion it is meant to police", () => {
  expect(files.some((f) => f.rel === "packages/ui/src/spring.ts")).toBe(true);
  expect(tokens.get("t-panel")).toBeGreaterThan(0);
  expect(cssMotions().length).toBeGreaterThan(100);
  expect(animateCalls().length).toBeGreaterThan(30);
  // The rules must be able to fail: the shapes the product shipped before #471 are caught.
  expect(parseItem("grid-template-rows 340ms var(--ease-drawer)", "transition").duration).toBe(340);
  expect(parseItem("opacity var(--t-pop)", "transition").easing).toBe("ease");
  expect(slowStart("ease-in-out")).toBe(true);
  expect(slowStart("cubic-bezier(0.42, 0, 1, 1)")).toBe(true);
  expect(slowStart("cubic-bezier(0.23, 1, 0.32, 1)")).toBe(false);
});

test("no spring lasts more than 300 ms", () => {
  const bad: string[] = [];
  for (const f of files) {
    if (!f.rel.endsWith(".ts")) continue;
    for (const m of f.text.matchAll(/visualDuration\s*:\s*([\d.]+)/g)) {
      if (Number(m[1]) * 1000 > LIMIT_MS) bad.push(`${f.rel}:${lineOf(f.text, m.index!)} ${m[0]}`);
    }
  }
  expect(bad).toEqual([]);
});

test("no CSS transition or animation lasts more than 300 ms, delay included", () => {
  const bad = cssMotions().filter((m) => !m.loop && m.duration + m.delay > LIMIT_MS && !allowed(m.rel, m.text)).map((m) => `${m.at} ${m.text}`);
  expect(bad).toEqual([]);
});

test("every looping CSS animation is on the allow-list", () => {
  expect(cssMotions().filter((m) => m.loop && !allowed(m.rel, m.text)).map((m) => `${m.at} ${m.text}`)).toEqual([]);
});

test("nothing that moves or fades in CSS starts slowly", () => {
  const bad = cssMotions().filter((m) => m.duration > 0 && !allowed(m.rel, m.text) && (
    /^ease-in/.test(m.easing) || (/cubic-bezier/.test(m.easing) && slowStart(m.easing))
    || (MOVING.test(m.property) || m.property === "animation") && (m.easing === "ease" || m.easing === "linear")
  )).map((m) => `${m.at} ${m.text}`);
  expect(bad).toEqual([]);
});

test("no Web Animation lasts more than 300 ms or starts slowly", () => {
  const bad: string[] = [];
  for (const call of animateCalls()) {
    if (allowed(call.rel, call.text)) continue;
    const duration = Number(/\bduration\s*:\s*(\d+)/.exec(call.text)?.[1] ?? 0);
    const delay = Number(/\bdelay\s*:\s*(\d+)/.exec(call.text)?.[1] ?? 0);
    const easing = /\beasing\s*:\s*("[^"]*"|[\w.()]+)/.exec(call.text)?.[1];
    const literal = easing?.startsWith("\"") ? easing.slice(1, -1) : undefined;
    // No easing means linear in the Web Animations API; a literal must be ease-out shaped. A named constant
    // (EASE_OUT, css from flipEasing) is checked where it is defined.
    const slow = easing === undefined || (literal !== undefined && (literal === "linear" || slowStart(literal)));
    if (duration + delay > LIMIT_MS || slow) bad.push(`${call.at} ${call.text.replace(/\s+/g, " ").slice(0, 140)}`);
  }
  expect(bad).toEqual([]);
});

test("the FLIP reflow curve is the product's ease-out and lasts its duration", () => {
  for (const d of [0.2, 0.28]) {
    const { css, duration } = flipEasing({ visualDuration: d });
    expect(css).toBe("cubic-bezier(0.23, 1, 0.32, 1)");
    expect(duration).toBe(Math.round(d * 1000));
  }
});

/** Runs a Spring from rest from 0 to 1 at 60 fps and returns its value after each frame. */
function frames(visualDuration: number): number[] {
  const originalRequest = globalThis.requestAnimationFrame;
  const originalCancel = globalThis.cancelAnimationFrame;
  const originalMedia = globalThis.matchMedia;
  let callback: FrameRequestCallback | undefined;
  globalThis.requestAnimationFrame = (next) => { callback = next; return 1; };
  globalThis.cancelAnimationFrame = () => {};
  globalThis.matchMedia = (() => ({ matches: false })) as unknown as typeof matchMedia;
  try {
    const spring = new Spring(0, () => {}, { visualDuration });
    spring.set(1);
    const start = (spring as unknown as { last: number }).last;
    const out: number[] = [];
    for (let i = 1; i <= 120; i++) { callback!(start + (i * 1000) / 60); out.push(spring.value); }
    return out;
  } finally {
    globalThis.requestAnimationFrame = originalRequest;
    globalThis.cancelAnimationFrame = originalCancel;
    globalThis.matchMedia = originalMedia;
  }
}

test("a Spring from rest is ease-out: a fifth of the way in the first frame, half by a third of its time, done at its time", () => {
  for (const d of [0.12, 0.2, 0.26, 0.3]) {
    const v = frames(d);
    expect(v[0], `${d}s: first frame`).toBeGreaterThan(0.2);
    // Frame i ends at (i + 1) / 60 s.
    expect(v[Math.floor((d / 3) * 60)]!, `${d}s: half the distance by a third of the duration`).toBeGreaterThanOrEqual(0.5);
    expect(v[Math.ceil(d * 60)]!, `${d}s: on its target at its duration`).toBe(1);
    expect(Math.max(...v)).toBeLessThanOrEqual(1);
  }
});
