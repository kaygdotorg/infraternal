/** Gates the whole production JavaScript transfer, including deferred terminal/WASM bytes [5][41]. */
import { readdir, stat } from "node:fs/promises";

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
