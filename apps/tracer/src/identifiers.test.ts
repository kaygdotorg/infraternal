/** Checks canonical random window identifiers on origins without the secure-context UUID helper. */
import { expect, test } from "bun:test";
import { isCanonicalUuid, randomUuid } from "./identifiers";

test("randomUuid mints canonical, distinct version-4 UUIDs", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 1000; i++) {
    const id = randomUuid();
    expect(isCanonicalUuid(id)).toBe(true);
    expect(id[14]).toBe("4");
    expect("89ab").toContain(id[19]!);
    seen.add(id);
  }
  expect(seen.size).toBe(1000);
});
