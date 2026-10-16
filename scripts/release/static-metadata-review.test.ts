/** Checks checkout-independent compiler metadata in shipping static artifacts (D243, #229). */
import { expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const repository = resolve(import.meta.dir, "../..");
const source = process.env.INFRATERNAL_STATIC_SOURCE_ROOT ?? repository;
const targetRoot = process.env.CARGO_TARGET_DIR ?? resolve(repository, "target");
const registryRoot = resolve(process.env.CARGO_HOME ?? resolve(process.env.HOME!, ".cargo"), "registry/src");

for (const [target, compiler] of [
  ["x86_64-unknown-linux-musl", "musl-cc-avx512.sh"],
  ["aarch64-unknown-linux-musl", "musl-cc.sh"],
] as const) {
  const binary = resolve(targetRoot, target, "release/infraternal");
  const name = `${target} compiler metadata is independent of the checkout location`;
  if (!existsSync(binary)) { test.skip(name, () => {}); continue; }
  test(name, () => {
    const compilerPath = Buffer.from(resolve(source, ".cargo", compiler));
    const bytes = readFileSync(binary);
    expect(bytes.includes(compilerPath)).toBe(false);
    expect(bytes.includes(Buffer.from(`/.cargo/${compiler}`))).toBe(false);
    expect(bytes.includes(Buffer.from(`${source}/`))).toBe(false);
    expect(bytes.includes(Buffer.from(`${resolve(targetRoot)}/`))).toBe(false);
    expect(bytes.includes(Buffer.from(`${registryRoot}/`))).toBe(false);
  });
}
