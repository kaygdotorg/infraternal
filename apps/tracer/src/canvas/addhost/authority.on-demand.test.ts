/** CA wrapping is scoped to one membership generation; the account key never leaves the browser. */
import { expect, test } from "bun:test";
import { hkdfSync } from "node:crypto";
import { deriveCaKey } from "./authority.on-demand";

test("CA wrapping matches the contract's HKDF domain and separates generations", async () => {
  const user = "11111111-2222-3333-4444-555555555555";
  const dek = new Uint8Array(32).fill(3);
  const salt = new Uint8Array(32).fill(5);
  const key = await deriveCaKey(dek, salt, user, 1);
  const expected = hkdfSync("sha256", dek, salt, `infraternal/ca-wrap/v1|${user}|1`, 32);
  expect(Buffer.from(key).equals(Buffer.from(expected))).toBe(true);
  expect(Buffer.from(key).equals(Buffer.from(await deriveCaKey(dek, salt, user, 2)))).toBe(false);
  await expect(deriveCaKey(dek, salt, "foreign-shaped-invalid-id", 1)).rejects.toThrow();
});
