/** Checks fresh #201 static artifacts against the exact published shipping caps [D243]. */
import { expect, test } from "bun:test";
import { readFileSync, statSync } from "node:fs";

const gate = readFileSync(new URL("./verify.d/rust.sh", import.meta.url), "utf8");
const artifacts = [
  ["x86_64-unknown-linux-musl", process.env.INFRATERNAL_REVIEW_STATIC_X86],
  ["aarch64-unknown-linux-musl", process.env.INFRATERNAL_REVIEW_STATIC_ARM],
] as const;

for (const [target, artifact] of artifacts) {
  test.skipIf(!artifact)(`fresh full-feature ${target} artifact matches its recorded cap`, () => {
    const ceiling = gate.match(new RegExp(`${target}\\) max_size_bytes=(\\d+)`));
    expect(ceiling).not.toBeNull();
    // Use the real rebuilt file. Synthetic +1-byte controls alone cannot
    // establish that the ordinary build reproduces a previously measured cap.
    expect(statSync(artifact!).size).toBe(Number(ceiling![1]));
  });
}
