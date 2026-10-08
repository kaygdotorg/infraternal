/** Gates the whole production JavaScript transfer, including deferred terminal/WASM bytes [5][41], and the font transfer (D175). */
import { readdir, readFile, stat } from "node:fs/promises";
import { brotliCompressSync, gzipSync } from "node:zlib";

const limits = { gzip: 300 * 1024, brotli: 250 * 1024 };
const totals = { identity: 0, gzip: 0, brotli: 0 };
for (const name of await readdir("dist", { recursive: true })) {
  if (!name.endsWith(".js")) continue;
  const identity = (await stat(`dist/${name}`)).size;
  const gzip = await stat(`dist/${name}.gz`).then((file) => file.size).catch(() => identity);
  const brotli = await stat(`dist/${name}.br`).then((file) => file.size).catch(() => identity);
  totals.identity += identity;
  totals.gzip += gzip;
  totals.brotli += brotli;
  console.log(`${name}: identity=${identity} gzip=${gzip} brotli=${brotli} bytes`);
}
if (totals.identity === 0) throw new Error("no production JavaScript found");
console.log(`JavaScript transfer: identity=${totals.identity} gzip=${totals.gzip}/${limits.gzip} brotli=${totals.brotli}/${limits.brotli} bytes`);
if (totals.gzip > limits.gzip || totals.brotli > limits.brotli) {
  throw new Error("production JavaScript exceeds the compressed transfer budget");
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
const fontRoot = "dist/fonts";
const fontEntries = await readdir(fontRoot, { withFileTypes: true });
let fontFailure = "";
const summary: string[] = [];
const sized = async (path: string): Promise<number> => {
  const bytes = await readFile(path);
  const gzip = Math.min(bytes.length, gzipSync(bytes, { level: 9 }).length);
  const brotli = Math.min(bytes.length, brotliCompressSync(bytes).length);
  console.log(`${path.replace("dist/", "")}: identity=${bytes.length} gzip=${gzip} brotli=${brotli} bytes`);
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
