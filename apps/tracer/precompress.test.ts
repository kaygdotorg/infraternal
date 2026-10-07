/** Verifies build compression against the real codecs and excludes compressed binary formats. */
import { test, expect } from "bun:test";
import { mkdir, readFile, rm, writeFile, access } from "node:fs/promises";
import { gunzipSync, brotliDecompressSync } from "node:zlib";
import { precompress } from "./precompress";

test("text sidecars round-trip deterministically; compressed formats remain identity", async () => {
  const root = `../../target/precompress-test-${process.pid}`;
  await mkdir(`${root}/fonts`, { recursive: true });
  try {
    const source = Buffer.from("const repeated = 'transfer budget';\n".repeat(1000));
    await writeFile(`${root}/chunk-12345678.js`, source);
    await writeFile(`${root}/index.html`, source);
    await writeFile(`${root}/fonts/font.woff2`, source);
    await writeFile(`${root}/image.png`, source);
    await writeFile(`${root}/archive.gz`, source);
    await precompress(root);
    const gzip = await readFile(`${root}/chunk-12345678.js.gz`);
    const brotli = await readFile(`${root}/chunk-12345678.js.br`);
    expect(gunzipSync(gzip)).toEqual(source);
    expect(brotliDecompressSync(brotli)).toEqual(source);
    expect(gzip.length).toBeLessThan(source.length);
    expect(brotli.length).toBeLessThan(gzip.length);
    expect(await readFile(`${root}/index.html.br`)).toEqual(brotli);
    for (const path of ["fonts/font.woff2", "image.png", "archive.gz"]) {
      for (const encoding of ["gz", "br"]) {
        await expect(access(`${root}/${path}.${encoding}`)).rejects.toThrow();
      }
    }
    await precompress(root);
    expect(await readFile(`${root}/chunk-12345678.js.gz`)).toEqual(gzip);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
