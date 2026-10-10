/** Independent #158 review: the production canvas still fits the existing deferred JavaScript transfer budget. */
import { expect, test } from "bun:test";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

test("dead-session production canvas fits the deferred Brotli budget", async () => {
  // Run `bun run build` in apps/tracer first; the manifest uses the real production build graph.
  const dist = resolve(import.meta.dirname, "..", process.env.TRACER_DIST ?? "dist");
  const classes = JSON.parse(await readFile(resolve(dist, "chunks.json"), "utf8")) as { deferred: string[] };
  let bytes = 0;
  for (const name of classes.deferred) bytes += (await stat(resolve(dist, `${name}.br`))).size;
  console.log(`deferred_brotli_bytes=${bytes} budget_bytes=${44 * 1024}`);
  expect(bytes).toBeLessThanOrEqual(44 * 1024);
});
