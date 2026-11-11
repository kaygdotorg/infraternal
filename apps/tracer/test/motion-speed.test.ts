// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Fast, ease-out motion (TASTE section 3, "Fast, ease-out, under 300 ms"). Owner, 2026-11-09: "when did animations
 * become so slow in the mockup and production? did you forget emil's rulue?", quoting "Use ease-out for anything
 * entering or leaving the screen. Keep UI animations under 300ms." (#471).
 *
 * What fails this test:
 * - a `Spring` duration (`visualDuration`) over 0.3 s, written as a literal, an expression or a constant; one given by a
 *   name the scan cannot resolve (a parameter) is refused;
 * - a CSS transition or animation (shorthand or `-duration`/`-delay` longhand), a Web Animation (`element.animate`), or a
 *   transition set from script (`el.style.transition = ...`, template strings with constants included), whose duration
 *   plus delay is over 300 ms. Named constants and conditionals are read through (both branches count); an unresolvable
 *   duration is refused;
 * - a curve that starts slowly: `ease-in`, `ease-in-out`, or a `cubic-bezier` whose first control point leaves the
 *   start flatter than a straight line (y1 < x1);
 * - `ease`, `linear` or no easing at all (CSS and the Web Animations API then use `ease` and `linear`) on anything that
 *   moves, resizes or fades. Both start slowly or crawl. `ease` stays fine for a colour change in place (a hover tint),
 *   which neither enters nor leaves. A `transition-timing-function` longhand names no property, so there `ease` and
 *   `linear` are refused outright;
 * - a `Spring` released from rest that does not cover most of its distance in the first frames.
 *
 * Durations written as `var(--t-press|pop|panel)` are read from packages/ui/styles.css, so a token that grows past
 * 300 ms fails here too; a `calc()` scaled by #427's `--ui-motion-scale` is read at scale 1, the pointer case. Toast and notice dwell times (`duration:` on a toast) are not motion and are not scanned.
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
  // Press-and-hold progress cue (J455's question on #471): the window leans in only while a finger rests on the header,
  // for exactly the hold time (`HOLD_MS`, 450 ms, after 120 ms so a tap shows nothing). The hold timer cancels it at
  // 450 ms, so it never plays its nominal 570 ms, and the release reverses in 220 ms. It follows a gesture's progress
  // like a spinner follows work; shortening it would make the cue finish before the hold counts.
  { file: "packages/ui/src/window-resize.ts", has: "duration: HOLD_MS", why: "press-and-hold progress cue, as long as the hold itself; cancelled at the hold time" },
  // The reflow's duration comes from `flipEasing(cfg)` (visualDuration x 1000); its own test below checks that, and every
  // `flip.play` visualDuration is scanned by the spring rule.
  { file: "apps/tracer/src/canvas/layout/flip.ts", has: "{ duration, easing: css }", why: "duration from flipEasing, checked by its own test and the spring scan" },
  // The windows prototype mock staggers its sections and windows (`delay = index * 45`, `enter(entry, delay)`); each item's
  // own motion is 160-280 ms on EASE_OUT. A stagger offsets items against each other; it is not a slower motion.
  { file: "apps/tracer/src/canvas/mock/windows-proto/canvas.ts", has: "delay, easing: EASE_OUT", why: "stagger offsets in a prototype mock; each item's motion is <= 280 ms" },
];
/** Whether the declaration or call `text` in file `rel` is on the allow-list. */
const allowed = (rel: string, text: string): boolean => ALLOWED.some((a) => a.file === rel && text.includes(a.has));

/** The repository root. */
const repo = join(import.meta.dir, "../../..");
/** The trees the scan reads: the web app and the shared UI package. */
const ROOTS = ["apps/tracer", "packages/ui"];
/** Directories never scanned: dependencies, build output, vendored code, fonts and tests. */
const SKIP_DIRS = new Set(["node_modules", "dist", "vendor", "fonts", "test", "real", "docs-dist"]);
/** Every TypeScript, CSS, Svelte and HTML source under `dir`, tests excluded. */
function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) { if (!SKIP_DIRS.has(name)) sources(path, out); continue; }
    if (/\.(ts|css|svelte|html)$/.test(name) && !/\.(test|spec)\.ts$/.test(name)) out.push(path);
  }
  return out;
}
/** The scanned files with their repo-relative path and text. */
const files = ROOTS.flatMap((root) => sources(join(repo, root))).map((path) => ({ path, rel: relative(repo, path), text: readFileSync(path, "utf8") }));
/** The line number of offset `at` in `text`, for `file:line` messages. */
const lineOf = (text: string, at: number): number => text.slice(0, at).split("\n").length;

/** The duration tokens of packages/ui/styles.css, in milliseconds. */
const tokens = new Map<string, number>();
for (const m of readFileSync(join(repo, "packages/ui/styles.css"), "utf8").matchAll(/--(t-[a-z]+)\s*:\s*([\d.]+)(ms|s)\s*;/g)) {
  tokens.set(m[1]!, Number(m[2]) * (m[3] === "s" ? 1000 : 1));
}

/**
 * A time in milliseconds from `120ms`, `0.3s`, `var(--t-pop)` or a `calc()` of them, such as #427's
 * `calc(var(--t-pop) * var(--ui-motion-scale, 1))` (read at scale 1); undefined when it is not a time.
 */
function ms(token: string): number | undefined {
  const lit = /^(-?[\d.]+)(ms|s)$/.exec(token);
  if (lit) return Number(lit[1]) * (lit[2] === "s" ? 1000 : 1);
  if (!/^(var|calc)\(/.test(token)) return undefined;
  // Resolve each innermost `var()`: a duration token to its milliseconds, #427's `--ui-motion-scale` to 1 (a pointer
  // change; a key sets it to 0, which is instant and needs no check), and anything else to its numeric fallback.
  let expr = token, guard = 0;
  for (let m = /var\(\s*--([\w-]+)\s*(?:,\s*([^()]*?))?\s*\)/.exec(expr); m && guard++ < 20; m = /var\(\s*--([\w-]+)\s*(?:,\s*([^()]*?))?\s*\)/.exec(expr)) {
    const name = m[1]!, fallback = m[2];
    const value = tokens.has(name) ? `${tokens.get(name)}ms` : name === "ui-motion-scale" ? "1" : fallback?.trim();
    if (value === undefined || value === "") return undefined;
    expr = expr.slice(0, m.index) + value + expr.slice(m.index + m[0].length);
  }
  // What is left is plain arithmetic on numbers and times; a time becomes its milliseconds.
  const arithmetic = expr.replace(/^calc/, "").replace(/(-?[\d.]+)(ms|s)\b/g, (_, n: string, unit: string) => String(Number(n) * (unit === "s" ? 1000 : 1)));
  if (!/^[\d.\s()+\-*/]+$/.test(arithmetic)) return undefined;
  const value = Function(`"use strict"; return (${arithmetic});`)() as unknown;
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
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
/** A shorthand word that names an easing (keyword, function or product curve variable). */
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

/** A source to scan: its repo-relative path and its text. The fixture tests below feed sources in the same shape. */
type Src = { rel: string; text: string };

/** Every CSS transition and animation shorthand in the stylesheets of `list`, with where it is. */
function cssMotions(list: Src[] = files): Array<Motion & { at: string; text: string; rel: string }> {
  const out: Array<Motion & { at: string; text: string; rel: string }> = [];
  for (const f of list) {
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

/** The argument text of every `.animate(` call in the scripts of `list`, found by matching parentheses. */
function animateCalls(list: Src[] = files): Array<{ at: string; text: string; rel: string }> {
  const out: Array<{ at: string; text: string; rel: string }> = [];
  for (const f of list) {
    if (!f.rel.endsWith(".ts")) continue;
    for (const m of f.text.matchAll(/\.animate\(/g)) {
      let depth = 1, i = m.index! + m[0].length;
      for (; i < f.text.length && depth; i++) { const ch = f.text[i]; if (ch === "(") depth++; else if (ch === ")") depth--; }
      out.push({ at: `${f.rel}:${lineOf(f.text, m.index!)}`, text: f.text.slice(m.index!, i), rel: f.rel });
    }
  }
  return out;
}

/**
 * `text` with its comments blanked out (newlines kept, so line numbers stay right). Comments describe motion, they
 * are not motion: `{ visualDuration }` in a doc comment must not count. Strings and template strings are kept.
 */
function stripComments(text: string): string {
  let out = "", quote = "", i = 0;
  while (i < text.length) {
    const ch = text[i]!, next = text[i + 1];
    if (quote) {
      out += ch;
      if (ch === "\\") { out += next ?? ""; i += 2; continue; }
      if (ch === quote) quote = "";
      i++; continue;
    }
    if (ch === "/" && next === "/") { while (i < text.length && text[i] !== "\n") { out += " "; i++; } continue; }
    if (ch === "/" && next === "*") {
      const end = text.indexOf("*/", i + 2), stop = end < 0 ? text.length : end + 2;
      out += text.slice(i, stop).replace(/[^\n]/g, " "); i = stop; continue;
    }
    if (ch === "\"" || ch === "'" || ch === "`") quote = ch;
    out += ch; i++;
  }
  return out;
}

/** The scanned scripts of `list` with comments removed. */
const scripts = (list: Src[]): Src[] => list.filter((f) => f.rel.endsWith(".ts")).map((f) => ({ rel: f.rel, text: stripComments(f.text) }));

/**
 * The expression a `const NAME = ...` gives, looked up in `src`, then in `list`, then exported from any scanned file
 * (an imported constant such as `EASE_OUT`). Undefined when the name is not a constant anywhere.
 */
function constExpr(name: string, src: Src, list: Src[]): { expr: string; src: Src } | undefined {
  // `const A = 1;`, or one of several in one statement (`const POP = 160, SWAP = 140;`); the value stops at `,` or `;`.
  const own = new RegExp(`(?:^|[^\\w.$])const\\s+(?:[^;=]*=[^;]*?,\\s*)?${name}\\s*(?::[^=,;\\n]+)?=\\s*([^,;\\n]+)`);
  const exported = new RegExp(`export\\s+const\\s+${name}\\s*(?::[^=\\n]+)?=\\s*([^;\\n]+)`);
  const hit = own.exec(src.text);
  if (hit) return { expr: hit[1]!.trim(), src };
  // Otherwise only a constant another file exports (an import such as `EASE_OUT`), never another file's local.
  for (const f of [...list, ...files]) {
    const m = exported.exec(f.text);
    if (m) return { expr: m[1]!.trim(), src: f };
  }
  return undefined;
}

/** Splits `cond ? yes : no` at its top level; undefined when `expr` is not a conditional. */
function splitTernary(expr: string): { yes: string; no: string } | undefined {
  let depth = 0, q = -1;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i]!;
    if ("([{".includes(ch)) depth++; else if (")]}".includes(ch)) depth--;
    else if (depth === 0 && ch === "?" && expr[i + 1] !== "?" && expr[i + 1] !== "." && expr[i - 1] !== "?") { q = i; break; }
  }
  if (q < 0) return undefined;
  depth = 0;
  let nested = 0;
  for (let i = q + 1; i < expr.length; i++) {
    const ch = expr[i]!;
    if ("([{".includes(ch)) depth++; else if (")]}".includes(ch)) depth--;
    else if (depth === 0 && ch === "?" && expr[i + 1] !== "?" && expr[i + 1] !== ".") nested++;
    else if (depth === 0 && ch === ":") { if (nested) nested--; else return { yes: expr.slice(q + 1, i).trim(), no: expr.slice(i + 1).trim() }; }
  }
  return undefined;
}

/**
 * Every number a duration expression can come out as (both branches of a conditional; the condition is not judged),
 * with the names it could not resolve. Constants are followed through `const` declarations, also across files, so
 * `duration: SWAP` or `visualDuration: D` is read as the number behind it. An unresolved name makes the caller refuse
 * the motion: a duration the scan cannot read is a duration the scan cannot vouch for.
 */
function valuesOf(expr: string, src: Src, list: Src[], depth = 0): { values: number[]; unresolved: string[] } {
  const e = expr.replace(/\bas\s+const\b/g, "").trim();
  const t = splitTernary(e);
  if (t) {
    const yes = valuesOf(t.yes, src, list, depth), no = valuesOf(t.no, src, list, depth);
    return { values: [...yes.values, ...no.values], unresolved: [...yes.unresolved, ...no.unresolved] };
  }
  const unresolved: string[] = [];
  const substituted = e.replace(/(?<![\w.$])([A-Za-z_$][\w$]*)(?![\w$]*\s*\()/g, (name) => {
    const c = depth < 5 ? constExpr(name, src, list) : undefined;
    if (!c) { unresolved.push(name); return "NaN"; }
    const v = valuesOf(c.expr, c.src, list, depth + 1);
    unresolved.push(...v.unresolved);
    return v.values.length ? String(Math.max(...v.values)) : "NaN";
  });
  if (unresolved.length) return { values: [], unresolved };
  if (!/^[\d.\s()+\-*/]+$/.test(substituted)) return { values: [], unresolved: [e] };
  const value = Function(`"use strict"; return (${substituted});`)() as unknown;
  return typeof value === "number" && Number.isFinite(value) ? { values: [value], unresolved: [] } : { values: [], unresolved: [e] };
}

/** The text a string or template literal holds, with `${...}` resolved to the constant behind it; undefined if one is unknown. */
function literalText(raw: string, src: Src, list: Src[]): string | undefined {
  const body = raw.slice(1, -1);
  if (!raw.startsWith("`")) return body;
  let unknown = false;
  const text = body.replace(/\$\{([^}]*)\}/g, (_, inner: string) => {
    const name = inner.trim();
    const c = /^[A-Za-z_$][\w$]*$/.test(name) ? constExpr(name, src, list) : undefined;
    if (c && /^["'`]/.test(c.expr)) return c.expr.slice(1, -1);
    const v = valuesOf(name, src, list);
    if (v.unresolved.length || !v.values.length) { unknown = true; return "?"; }
    return String(Math.max(...v.values));
  });
  return unknown ? undefined : text;
}

/** Whether a single easing (CSS or WAAPI) starts slowly or crawls when its property is unknown: `ease`, `linear`, `ease-in*`, a slow cubic-bezier. */
function slowEasing(easing: string): boolean {
  const e = /^var\(--ease-(out|drawer)/.test(easing) ? "ease-out" : easing.trim();
  return e === "ease" || e === "linear" || /^ease-in/.test(e) || (/cubic-bezier/.test(e) && slowStart(e));
}

/** CSS longhands (`transition-duration`, `-delay`, `-timing-function` and the `animation-` ones) in `list`, item by item. */
function cssLonghands(list: Src[]): Array<{ at: string; rel: string; text: string; kind: string; item: string }> {
  const out: Array<{ at: string; rel: string; text: string; kind: string; item: string }> = [];
  for (const f of list) {
    if (!f.rel.endsWith(".css")) continue;
    for (const m of f.text.matchAll(/(?<![-\w])(transition|animation)-(duration|delay|timing-function)\s*:\s*([^;}]+)/g)) {
      const value = m[3]!.replace(/!important/, "").trim();
      for (const item of splitTop(value)) out.push({ at: `${f.rel}:${lineOf(f.text, m.index!)}`, rel: f.rel, text: `${m[1]}-${m[2]}: ${value}`, kind: m[2]!, item });
    }
  }
  return out;
}

/**
 * Spring durations over the limit in the scripts of `list`, as `file:line text`. A literal, an expression or a
 * constant is read through to its number; a name that resolves to nothing (a parameter) is refused, because the scan
 * cannot vouch for it. A type annotation (`visualDuration: number`) is not a duration.
 */
function springOffences(list: Src[]): string[] {
  const bad: string[] = [];
  for (const f of scripts(list)) {
    for (const m of f.text.matchAll(/visualDuration\s*:\s*([^,;}\n]+)/g)) {
      const expr = m[1]!.trim();
      if (/^number\b/.test(expr)) continue;
      const v = valuesOf(expr, f, list);
      const at = `${f.rel}:${lineOf(f.text, m.index!)} ${m[0].trim()}`;
      if (v.unresolved.length) bad.push(`${at} (unresolved: ${v.unresolved.join(", ")})`);
      else if (Math.max(...v.values) * 1000 > LIMIT_MS) bad.push(at);
    }
    // `{ visualDuration }` shorthand takes a variable of that name.
    for (const m of f.text.matchAll(/[{,]\s*visualDuration\s*(?=[,}])/g)) {
      const v = valuesOf("visualDuration", f, list);
      const at = `${f.rel}:${lineOf(f.text, m.index!)} { visualDuration }`;
      if (v.unresolved.length) bad.push(`${at} (unresolved)`);
      else if (Math.max(...v.values) * 1000 > LIMIT_MS) bad.push(at);
    }
  }
  return bad;
}

/** CSS transitions and animations of `list` that last too long, delay included (loops are judged separately), longhands too. */
function cssDurationOffences(list: Src[]): string[] {
  const shorthand = cssMotions(list).filter((m) => !m.loop && m.duration + m.delay > LIMIT_MS && !allowed(m.rel, m.text)).map((m) => `${m.at} ${m.text}`);
  const longhand = cssLonghands(list).filter((l) => (l.kind === "duration" || l.kind === "delay") && (ms(l.item) ?? 0) > LIMIT_MS && !allowed(l.rel, l.text)).map((l) => `${l.at} ${l.text}`);
  return [...shorthand, ...new Set(longhand)];
}

/**
 * CSS motions of `list` that start slowly: a slow curve anywhere, or `ease`/`linear` on a move or fade. A
 * `transition-timing-function` longhand names no property, so there `ease` and `linear` are refused outright.
 */
function cssSlowOffences(list: Src[]): string[] {
  const shorthand = cssMotions(list).filter((m) => m.duration > 0 && !allowed(m.rel, m.text) && (
    /^ease-in/.test(m.easing) || (/cubic-bezier/.test(m.easing) && slowStart(m.easing))
    || (MOVING.test(m.property) || m.property === "animation") && (m.easing === "ease" || m.easing === "linear")
  )).map((m) => `${m.at} ${m.text}`);
  const longhand = cssLonghands(list).filter((l) => l.kind === "timing-function" && slowEasing(l.item) && !allowed(l.rel, l.text)).map((l) => `${l.at} ${l.text}`);
  return [...shorthand, ...new Set(longhand)];
}

/**
 * Web Animations in `list` that last too long or start slowly. `duration` and `delay` may be literals, expressions
 * or constants (read through to their numbers, both branches of a conditional); one the scan cannot resolve is refused.
 */
function waapiOffences(list: Src[]): string[] {
  const bad: string[] = [];
  const stripped = new Map(scripts(list).map((f) => [f.rel, f]));
  for (const call of animateCalls(list)) {
    if (allowed(call.rel, call.text)) continue;
    const src = stripped.get(call.rel)!;
    const read = (key: string): { ms: number; unresolved: string[] } => {
      const m = new RegExp(`[{,]\\s*${key}\\b\\s*(?::\\s*([^,}]+))?(?=\\s*[,}])`).exec(call.text);
      if (!m) return { ms: 0, unresolved: [] };
      const v = valuesOf((m[1] ?? key).trim(), src, list);
      return { ms: v.values.length ? Math.max(...v.values) : 0, unresolved: v.unresolved };
    };
    const duration = read("duration"), delay = read("delay");
    const easing = /\beasing\s*:\s*("[^"]*"|[\w.()]+)/.exec(call.text)?.[1];
    const literal = easing?.startsWith("\"") ? easing.slice(1, -1) : undefined;
    // No easing means linear in the Web Animations API; a literal must be ease-out shaped. A named constant
    // (EASE_OUT, css from flipEasing) is checked where it is defined.
    const slow = easing === undefined || (literal !== undefined && (literal === "linear" || slowStart(literal)));
    const unresolved = [...duration.unresolved, ...delay.unresolved];
    if (duration.ms + delay.ms > LIMIT_MS || slow || unresolved.length) {
      bad.push(`${call.at} ${call.text.replace(/\s+/g, " ").slice(0, 140)}${unresolved.length ? ` (unresolved: ${unresolved.join(", ")})` : ""}`);
    }
  }
  return bad;
}

/**
 * Transitions set from script in `list` (`el.style.transition = ...`, its duration, delay and timing-function
 * longhands, and `style.setProperty("transition", ...)`). Each string or template literal on the right is read like CSS,
 * with `${CONSTANT}` resolved; one the scan cannot resolve is refused. `""` and `"none"` hand back to the stylesheet.
 */
function inlineOffences(list: Src[]): string[] {
  const bad: string[] = [];
  const PROPS: Record<string, string> = { transition: "transition", transitionDuration: "duration", transitionDelay: "delay", transitionTimingFunction: "timing-function",
    "transition-duration": "duration", "transition-delay": "delay", "transition-timing-function": "timing-function" };
  for (const f of scripts(list)) {
    const sites = [
      ...[...f.text.matchAll(/\.style\.(transition(?:Duration|Delay|TimingFunction)?)\s*=(?!=)\s*([^;\n]+)/g)].map((m) => ({ at: m.index!, prop: m[1]!, rhs: m[2]! })),
      ...[...f.text.matchAll(/\.style\.setProperty\(\s*["'](transition(?:-duration|-delay|-timing-function)?)["']\s*,\s*([^)\n]+)\)/g)].map((m) => ({ at: m.index!, prop: m[1]!, rhs: m[2]! })),
    ];
    for (const site of sites.sort((a, b) => a.at - b.at)) {
      const kind = PROPS[site.prop]!;
      const where = `${f.rel}:${lineOf(f.text, site.at)}`;
      if (allowed(f.rel, site.rhs)) continue;
      for (const lit of site.rhs.match(/"[^"]*"|'[^']*'|`[^`]*`/g) ?? []) {
        const text = literalText(lit, f, list);
        if (text === undefined) { bad.push(`${where} ${lit} (unresolved)`); continue; }
        if (text.trim() === "" || text.trim() === "none") continue;
        const offending = splitTop(text).some((item) => {
          if (kind === "duration" || kind === "delay") return (ms(item) ?? 0) > LIMIT_MS;
          if (kind === "timing-function") return slowEasing(item);
          const m = parseItem(item, "transition");
          return m.duration + m.delay > LIMIT_MS || (m.duration > 0 && (/^ease-in/.test(m.easing) || (/cubic-bezier/.test(m.easing) && slowStart(m.easing))
            || (MOVING.test(m.property) && (m.easing === "ease" || m.easing === "linear"))));
        });
        if (offending) bad.push(`${where} ${site.prop} = ${text}`);
      }
    }
  }
  return bad;
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
  // The resolvers read the real tree: a constant from a comma declaration, and a template with an imported constant.
  const tooltip = scripts(files).find((f) => f.rel === "packages/ui/src/tooltip.ts")!;
  expect(valuesOf("SWAP", tooltip, files).values.length).toBe(1);
  expect(valuesOf("SWAP", tooltip, files).values[0]).toBeGreaterThan(0);
  expect(literalText("`width ${TRAVEL}ms ${EASE_OUT}`", tooltip, files)).toMatch(/^width \d+ms cubic-bezier\(0\.23, 1, 0\.32, 1\)$/);
});

test("durations scaled by #427's --ui-motion-scale are read at scale 1, not as 0", () => {
  // A key-caused change sets the scale to 0 (instant); a pointer leaves it at 1, which is the duration the rule judges.
  expect(ms("calc(var(--t-pop) * var(--ui-motion-scale, 1))")).toBe(tokens.get("t-pop")!);
  expect(ms("calc(var(--t-panel) * var(--ui-motion-scale, 1))")).toBe(tokens.get("t-panel")!);
  expect(ms("calc(340ms * var(--ui-motion-scale, 1))")).toBe(340);
  expect(ms("calc(var(--i, 0) * 50ms)")).toBe(0);
  const item = parseItem("opacity calc(var(--t-pop) * var(--ui-motion-scale, 1)) ease", "transition");
  expect(item.duration).toBe(tokens.get("t-pop")!);
  expect(item.easing).toBe("ease");
  expect(parseItem("transform calc(420ms * var(--ui-motion-scale, 1)) var(--ease-out)", "transition").duration).toBe(420);
  // The scan really reads them: the stylesheets' scaled transitions come out with their durations, none as 0.
  // A discrete flip written `visibility 0s calc(...)` really lasts 0 s (only its delay is scaled), so it is left out.
  const scaled = cssMotions().filter((m) => m.text.includes("--ui-motion-scale") && !/\s0m?s\b/.test(m.text) && !m.text.startsWith("transition: display"));
  expect(scaled.length).toBeGreaterThan(5);
  expect(scaled.filter((m) => m.duration === 0).map((m) => `${m.at} ${m.text}`)).toEqual([]);
});

// J455's review of #471 (comment 89290) found four ways motion slipped past the scan. Each fixture below must be caught,
// and the safe neighbours beside it must not be.
test("CSS longhands are read: transition-duration, -delay and -timing-function (and the animation ones)", () => {
  const css: Src = { rel: "fixture.css", text: [
    ".a { transition-duration: 420ms; }",
    ".b { transition-timing-function: ease-in-out; }",
    ".c { animation-duration: 0.5s; }",
    ".d { transition-delay: 360ms; }",
    ".e { transition-duration: var(--t-pop), var(--t-press); transition-timing-function: ease-out, var(--ease-out); }",
    ".f { transition-duration: 0ms !important; transition-delay: 0s; }",
  ].join("\n") };
  expect(cssDurationOffences([css]).map((o) => o.split(" ")[0])).toEqual(["fixture.css:1", "fixture.css:3", "fixture.css:4"]);
  expect(cssSlowOffences([css]).map((o) => o.split(" ")[0])).toEqual(["fixture.css:2"]);
});

test("Web Animation durations given by a named constant or an expression are resolved", () => {
  const ts: Src = { rel: "fixture.ts", text: [
    "const SLOW = 480;",
    "const POP = 180;",
    "el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: SLOW, easing: EASE_OUT });",
    "el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: reduced() ? 160 : 420, easing: EASE_OUT });",
    "el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: NOT_DEFINED_ANYWHERE, easing: EASE_OUT });",
    "el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: POP, delay: POP, easing: EASE_OUT });",
    "el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: POP, easing: EASE_OUT });",
    "el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: reduced() ? 120 : 200, easing: EASE_OUT });",
  ].join("\n") };
  expect(waapiOffences([ts]).map((o) => o.split(" ")[0])).toEqual(["fixture.ts:3", "fixture.ts:4", "fixture.ts:5", "fixture.ts:6"]);
});

test("transitions set inline from script are read, constants in template strings included", () => {
  const ts: Src = { rel: "fixture.ts", text: [
    "const TRAVEL = 400;",
    "const SHORT = 150;",
    "el.style.transition = \"opacity 360ms var(--ease-out)\";",
    "el.style.transition = `transform ${TRAVEL}ms ${EASE_OUT}`;",
    "el.style.transition = \"opacity 120ms ease\";",
    "el.style.setProperty(\"transition\", \"transform 200ms ease-in-out\");",
    "el.style.transitionDuration = \"500ms\";",
    "el.style.transition = animate ? `opacity ${SHORT}ms ${EASE_OUT}` : \"none\";",
    "el.style.transition = \"\";",
    "el.style.transition = other.style.transition;",
  ].join("\n") };
  expect(inlineOffences([ts]).map((o) => o.split(" ")[0])).toEqual(["fixture.ts:3", "fixture.ts:4", "fixture.ts:5", "fixture.ts:6", "fixture.ts:7"]);
});

test("a spring duration given through a variable is resolved, and an unknown one is refused", () => {
  const ts: Src = { rel: "fixture.ts", text: [
    "const D = 0.45;",
    "new Spring(0, f, { visualDuration: D });",
    "const twice = { visualDuration: 0.2 * 2 };",
    "const make = (d: number) => new Spring(0, g, { visualDuration: d });",
    "const ok = { visualDuration: QUICK };",
    "const QUICK = 0.2;",
    "type Cfg = { visualDuration: number; bounce?: 0 };",
    "// a comment that says { visualDuration: 0.9 } is not motion",
  ].join("\n") };
  expect(springOffences([ts]).map((o) => o.split(" ")[0])).toEqual(["fixture.ts:2", "fixture.ts:3", "fixture.ts:4"]);
});

test("no spring lasts more than 300 ms", () => {
  expect(springOffences(files)).toEqual([]);
});

test("no CSS transition or animation lasts more than 300 ms, delay included", () => {
  expect(cssDurationOffences(files)).toEqual([]);
});

test("every looping CSS animation is on the allow-list", () => {
  expect(cssMotions().filter((m) => m.loop && !allowed(m.rel, m.text)).map((m) => `${m.at} ${m.text}`)).toEqual([]);
});

test("nothing that moves or fades in CSS starts slowly", () => {
  expect(cssSlowOffences(files)).toEqual([]);
});

test("no Web Animation lasts more than 300 ms or starts slowly", () => {
  expect(waapiOffences(files)).toEqual([]);
});

test("no transition set from script lasts more than 300 ms or starts slowly", () => {
  expect(inlineOffences(files)).toEqual([]);
});

test("the FLIP reflow curve is the product's ease-out and lasts its duration", () => {
  for (const d of [0.2, 0.28]) {
    const { css, duration } = flipEasing({ visualDuration: d });
    expect(css).toBe("cubic-bezier(0.23, 1, 0.32, 1)");
    expect(duration).toBe(Math.round(d * 1000));
  }
});

test("a pointer split fades the new window in within 150 ms on the product ease-out and glides the others within 150 ms (#484)", () => {
  const text = files.find((f) => f.rel === "apps/tracer/src/canvas/windows/split.on-demand.ts")!.text;
  expect(Number(/const SPLIT_FADE_MS = (\d+);/.exec(text)?.[1])).toBeLessThanOrEqual(150);
  expect(text).toMatch(/\{ duration: SPLIT_FADE_MS, easing: EASE_OUT \}/);
  const glide = Number(/const SPLIT_GLIDE = \{ visualDuration: ([\d.]+) \}/.exec(text)?.[1]);
  expect(glide).toBeGreaterThan(0);
  expect(flipEasing({ visualDuration: glide }).duration).toBeLessThanOrEqual(150);
  // Both reflow calls of a split use that glide, never the 280 ms default.
  expect(text.match(/flip\.play\(before(?!, false, SPLIT_GLIDE)/g) ?? []).toEqual([]);
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
