/** Checks checkout-independent compiler metadata in shipping static artifacts (D243, #229). */
import { expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const repository = resolve(import.meta.dir, "../..");
const source = process.env.INFRATERNAL_STATIC_SOURCE_ROOT ?? repository;
const targetRoot = process.env.CARGO_TARGET_DIR ?? resolve(repository, "target");

for (const [target, compiler] of [
  ["x86_64-unknown-linux-musl", "musl-cc-avx512.sh"],
  ["aarch64-unknown-linux-musl", "musl-cc.sh"],
] as const) {
  const binary = resolve(targetRoot, target, "release/infraternal");
  const name = `${target} compiler metadata is independent of the checkout location`;
  if (!existsSync(binary)) { test.skip(name, () => {}); continue; }
  test(name, () => {
    const compilerPath = Buffer.from(resolve(source, ".cargo", compiler));
    expect(readFileSync(binary).includes(compilerPath)).toBe(false);
  });
}
