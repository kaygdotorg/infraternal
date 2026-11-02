/**
 * Gates the production JavaScript transfer in two budgets (D188), and the font transfer (D175).
 *
 * - **Critical path**: everything needed before the first paint of sign-in and of the first screen (the entries,
 *   their static imports, the core screen, the terminal and its renderer with the WASM). Strict, and unchanged.
 * - **On demand**: code that loads only when the person takes an action (the add-host wizard, the share studio,
 *   a Settings window): modules named `*.on-demand.ts` and what only they reach. Its own budget.
 * - **Deferred**: code that loads after the first screen is up (the canvas: views, Mesh, the droplet, the toolbar's
 *   edit mode, the settings windows). Its own budget: the size at the time of the decision plus a stated margin.
 *
 * Which chunk is which comes from the build graph (`chunks.json`, written by build.ts from the bundler's own
 * metafile), never from a list of chunk names. A chunk the graph did not classify fails the gate.
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { brotliCompressSync, gzipSync } from "node:zlib";

const dist = process.env.TRACER_DIST ?? "dist";
const KIB = 1024;
const limits = {
  critical: { gzip: 320 * KIB, brotli: 267 * KIB },
  // Release-6 shared layout and offline drawing measured 56,712 B gzip / 50,322 B brotli. D188 sets each cap to
  // the measured size rounded up to a whole KiB plus a 4 KiB margin: 60 KiB gzip / 54 KiB brotli.
  deferred: { gzip: 60 * KIB, brotli: 54 * KIB },
  // On demand (D188): the limit is per chunk, not for the class. A module named `*.on-demand.ts` costs nothing until the
  // person asks for it (the Mesh view, the session manager, a Settings window, the add-host wizard), so adding another
  // such feature must not take budget from the others; what the gate guards is that no single one grows without
  // thought. 20 KiB gzip / 18 KiB brotli each (the largest, Mesh, is about 8.5 KB gzip today). The class total is
  // reported, not limited.
  onDemand: { gzip: 20 * KIB, brotli: 18 * KIB },
};
const classes = JSON.parse(await readFile(`${dist}/chunks.json`, "utf8")) as { critical: string[]; deferred: string[]; onDemand: string[] };
const onDemandChunks = new Map<string, { gzip: number; brotli: number }>();
const totals = { critical: { identity: 0, gzip: 0, brotli: 0 }, deferred: { identity: 0, gzip: 0, brotli: 0 }, onDemand: { identity: 0, gzip: 0, brotli: 0 } };
for (const name of await readdir(dist, { recursive: true })) {
  // The docs pages' own script (docs/doc.js, docs-build.ts) is a file of its own, loaded only by a standalone docs page: it is not
  // part of the app's bundle and has no chunk class. (The canvas reader runs the same code from an on-demand chunk, which is counted.)
  if (!name.endsWith(".js") || name.startsWith("docs/")) continue;
  const klass = classes.critical.includes(name) ? "critical" : classes.deferred.includes(name) ? "deferred" : classes.onDemand.includes(name) ? "onDemand" : undefined;
  if (!klass) throw new Error(`${name} is in no chunk class: chunks.json is stale, rebuild`);
  // The server gives a year-long immutable cache only to `chunk-<8 alphanumerics>.js` (web_assets.rs). Every split
  // chunk must have such a content-hashed name, or a returning visit would revalidate (or miss) it. The entries
  // (the app and the two workers) are named for their role and revalidate with a conditional request.
  const entry = name === "main.js" || name.endsWith(".worker.js");
  if (!entry && !/^chunk-[0-9a-z]{8}\.js$/.test(name)) throw new Error(`${name} has no content-hashed chunk name`);
  const identity = (await stat(`${dist}/${name}`)).size;
  const gzip = await stat(`${dist}/${name}.gz`).then((file) => file.size).catch(() => identity);
  const brotli = await stat(`${dist}/${name}.br`).then((file) => file.size).catch(() => identity);
  if (klass === "onDemand") onDemandChunks.set(name, { gzip, brotli });
  totals[klass].identity += identity;
  totals[klass].gzip += gzip;
  totals[klass].brotli += brotli;
  console.log(`${klass} ${name}: identity=${identity} gzip=${gzip} brotli=${brotli} bytes`);
}
if (totals.critical.identity === 0) throw new Error("no production JavaScript found");
for (const klass of ["critical", "deferred", "onDemand"] as const) {
  const t = totals[klass], l = limits[klass];
  console.log(`JavaScript transfer, ${klass}: identity=${t.identity} gzip=${t.gzip}/${l.gzip} brotli=${t.brotli}/${l.brotli} bytes`);
}
if (totals.critical.gzip > limits.critical.gzip || totals.critical.brotli > limits.critical.brotli) {
  throw new Error("production critical-path JavaScript exceeds the compressed transfer budget");
}
const biggest = { name: "", gzip: 0, brotli: 0 };
for (const [name, size] of onDemandChunks) if (size.gzip > biggest.gzip) Object.assign(biggest, { name, ...size });
console.log(`JavaScript transfer, onDemand largest chunk ${biggest.name}: gzip=${biggest.gzip}/${limits.onDemand.gzip} brotli=${biggest.brotli}/${limits.onDemand.brotli} bytes (class total gzip=${totals.onDemand.gzip} brotli=${totals.onDemand.brotli}, not limited)`);
for (const [name, size] of onDemandChunks) {
  if (size.gzip > limits.onDemand.gzip || size.brotli > limits.onDemand.brotli) throw new Error(`on-demand chunk ${name} exceeds its compressed transfer budget`);
}
if (totals.deferred.gzip > limits.deferred.gzip || totals.deferred.brotli > limits.deferred.brotli) {
  throw new Error("production deferred JavaScript exceeds its compressed transfer budget");
}

/**
 * Gates the self-hosted font transfer (D87, D175). Fonts are woff2, which is already
 * compressed, so the figures are wire sizes with gzip and brotli measured as a check that no
 * encoding would add or save bytes. Every directory under dist/fonts is one family and must
 * have a budget below; a family nobody budgeted fails the build. Limits per family:
 *  - critical: the upright face of the default family is preloaded and gates the sign-in card
 *    and the first terminal paint, so it must stay small (one variable face replaced the
 *    regular, medium and semibold statics that the sign-in card pulled in, 101 KB, and the
 *    Geist Mono file before them, 71 KB);
 *  - total: every face of the family, upright and italic. Other families are fetched only when
 *    previewed or picked, so their size is paid on first use, never on first paint.
 * Nerd Font symbols are budgeted apart: they are fetched only when output holds a prompt icon.
 */
const KB = 1024;
const familyBudgets: Record<string, { critical?: number; total: number }> = {
  "maple-mono-nf": { critical: 50 * KB, total: 104 * KB },
  // Sizes measured at subset time (identity bytes): roman + italic, rounded up to the next KB
  // plus a small allowance. Commit Mono has four static faces, so its total covers all four.
  "geist-mono": { total: 44 * KB },
  "jetbrains-mono": { total: 74 * KB },
  "commit-mono": { total: 74 * KB },
  "monaspace-neon": { total: 86 * KB },
  "ibm-plex-mono": { total: 44 * KB },
  "cascadia-code": { total: 86 * KB },
  "fira-code": { total: 40 * KB },
  "source-code-pro": { total: 48 * KB },
};
const symbolsLimit = 230 * KB;
const fontRoot = `${dist}/fonts`;
const fontEntries = await readdir(fontRoot, { withFileTypes: true });
let fontFailure = "";
const summary: string[] = [];
const sized = async (path: string): Promise<number> => {
  const bytes = await readFile(path);
  const gzip = Math.min(bytes.length, gzipSync(bytes, { level: 9 }).length);
  const brotli = Math.min(bytes.length, brotliCompressSync(bytes).length);
  console.log(`${path.replace(`${dist}/`, "")}: identity=${bytes.length} gzip=${gzip} brotli=${brotli} bytes`);
  return bytes.length;
};
for (const entry of fontEntries) {
  if (!entry.isDirectory()) {
    if (entry.name === "nerd-symbols.woff2") {
      const size = await sized(`${fontRoot}/${entry.name}`);
      summary.push(`symbols=${size}/${symbolsLimit}`);
      if (size > symbolsLimit) fontFailure ||= "the Nerd Font symbols exceed the transfer budget";
    }
    continue;
  }
  const budget = familyBudgets[entry.name];
  if (!budget) { fontFailure ||= `font family ${entry.name} has no transfer budget`; continue; }
  let total = 0;
  let critical = 0;
  for (const name of (await readdir(`${fontRoot}/${entry.name}`)).filter((file) => file.endsWith(".woff2")).sort()) {
    const size = await sized(`${fontRoot}/${entry.name}/${name}`);
    total += size;
    if (name === "roman.latin.woff2") critical = size;
  }
  summary.push(`${entry.name}=${total}/${budget.total}${budget.critical ? ` (critical ${critical}/${budget.critical})` : ""}`);
  if (total === 0 || total > budget.total) fontFailure ||= `font family ${entry.name} exceeds its transfer budget`;
  if (budget.critical && (critical === 0 || critical > budget.critical)) fontFailure ||= `the upright face of ${entry.name} exceeds its critical budget`;
}
console.log(`Font transfer: ${summary.join(" ")} bytes`);
if (fontFailure) throw new Error(fontFailure);
for (const name of Object.keys(familyBudgets)) {
  if (!fontEntries.some((entry) => entry.isDirectory() && entry.name === name)) throw new Error(`font family ${name} has a budget but no files in dist/fonts`);
}
