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
 * Gates the self-hosted Maple Mono NF font transfer (D175). Fonts are woff2, which is
 * already compressed, so the figures are wire sizes with gzip and brotli measured as
 * a check that no encoding would add or save bytes. Three limits:
 *  - critical: the regular face is preloaded and gates the sign-in card and the first
 *    terminal paint, so it must stay small (the Geist Mono file it replaced was 71 KB);
 *  - latin: all faces the UI and terminal can draw text with;
 *  - symbols: the Nerd Font face, fetched only when output holds a prompt icon.
 */
const fontLimits = { critical: 36 * 1024, latin: 180 * 1024, symbols: 230 * 1024 };
const fontNames = (await readdir("dist/fonts")).filter((name) => name.startsWith("MapleMonoNF-") && name.endsWith(".woff2"));
if (fontNames.length === 0) throw new Error("no Maple Mono NF fonts found in dist/fonts");
const fontSizes = { critical: 0, latin: 0, symbols: 0 };
for (const name of fontNames.sort()) {
  const bytes = await readFile(`dist/fonts/${name}`);
  const gzip = Math.min(bytes.length, gzipSync(bytes, { level: 9 }).length);
  const brotli = Math.min(bytes.length, brotliCompressSync(bytes).length);
  console.log(`fonts/${name}: identity=${bytes.length} gzip=${gzip} brotli=${brotli} bytes`);
  if (name.includes("symbols")) fontSizes.symbols += bytes.length;
  else fontSizes.latin += bytes.length;
  if (name === "MapleMonoNF-Regular.latin.woff2") fontSizes.critical = bytes.length;
}
console.log(`Font transfer: critical=${fontSizes.critical}/${fontLimits.critical} latin=${fontSizes.latin}/${fontLimits.latin} symbols=${fontSizes.symbols}/${fontLimits.symbols} bytes`);
if (fontSizes.critical === 0 || fontSizes.critical > fontLimits.critical || fontSizes.latin > fontLimits.latin || fontSizes.symbols > fontLimits.symbols) {
  throw new Error("Maple Mono NF fonts exceed the transfer budget");
}
