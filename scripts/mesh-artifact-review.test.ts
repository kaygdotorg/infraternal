/** Reports fresh #201 static artifact deltas against recorded baselines [D243 amended 2026-11-01]. */
import { expect, test } from "bun:test";
import { readFileSync, statSync } from "node:fs";

const gate = readFileSync(new URL("./verify.d/rust.sh", import.meta.url), "utf8");
const artifacts = [
  ["x86_64-unknown-linux-musl", process.env.INFRATERNAL_REVIEW_STATIC_X86],
  ["aarch64-unknown-linux-musl", process.env.INFRATERNAL_REVIEW_STATIC_ARM],
] as const;

for (const [target, artifact] of artifacts) {
  test.skipIf(!artifact)(`fresh full-feature ${target} artifact reports its recorded baseline delta`, () => {
    const baseline = gate.match(new RegExp(`${target}\\)\\s+baseline_bytes=(\\d+)`));
    expect(baseline).not.toBeNull();
    const image = statSync(artifact!);
    expect(image.isFile()).toBe(true);
    expect(image.size).toBeGreaterThan(0);
    const delta = image.size - Number(baseline![1]);
    console.log(`${target}: size: ${image.size} bytes; baseline ${baseline![1]}; delta ${delta >= 0 ? "+" : ""}${delta} bytes (report only, D243 amended 2026-11-01)`);
  });
}
