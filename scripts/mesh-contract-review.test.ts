/** Checks that the published encrypted-copy contract describes the shipping delay (#201). */
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

test("encrypted path copy deadline agrees with the wire contract", () => {
  const source = readFileSync(new URL("../crates/plugins/remote/src/remote_path_copies.rs", import.meta.url), "utf8");
  const contract = readFileSync(new URL("../contracts/wire.md", import.meta.url), "utf8");
  const implementation = source.match(/COPY_DELAY: Duration = Duration::from_millis\((\d+)\)/);
  const declaration = contract.match(/Ordinary mesh-to-enrolled copies each become eligible\s+(\d+) ms after/);
  expect(implementation).not.toBeNull();
  expect(declaration).not.toBeNull();
  expect(Number(declaration![1])).toBe(Number(implementation![1]));
});
