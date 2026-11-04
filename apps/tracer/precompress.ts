/** Writes deterministic best-level encodings for text assets; binary formats retain identity. */
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join, extname } from "node:path";
import { brotliCompressSync, gzipSync, constants } from "node:zlib";

/** File types worth compressing; images, fonts and other binary formats are already compressed. */
const TEXT_EXTENSIONS = new Set([".html", ".js", ".css", ".json", ".svg", ".txt", ".wasm"]);

/**
 * Walks `directory` and writes a gzip (`.gz`) and a Brotli (`.br`) copy next to every text asset, each only when it is
 * smaller than the original. The output is the same on every run, so builds stay reproducible.
 */
export async function precompress(directory: string): Promise<void> {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      await precompress(path);
    } else if (TEXT_EXTENSIONS.has(extname(entry.name))) {
      const source = await readFile(path);
      const gzip = gzipSync(source, { level: 9 });
      const brotli = brotliCompressSync(source, {
        params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
      });
      // A sidecar must save bytes. Missing encodings safely fall back to identity.
      if (gzip.length < source.length) await writeFile(`${path}.gz`, gzip);
      if (brotli.length < source.length) await writeFile(`${path}.br`, brotli);
    }
  }
}
