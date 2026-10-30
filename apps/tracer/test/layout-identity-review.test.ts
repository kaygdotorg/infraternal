/** Account identifiers must leave browser storage on sign-out under the zero-identity-write review requirement (#250). */
import { expect, test } from "bun:test";
import { clearAccountStorage } from "../src/account-storage";
import { recordSignIn, teachOnce } from "../src/hints";

test("sign-in and layout-close hints cannot retain the account identifier after sign-out", () => {
  const originals = ["localStorage", "sessionStorage"].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)] as const);
  const values = new Map<string, string>();
  const storage = { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key), key: (index: number) => [...values.keys()][index] ?? null, get length() { return values.size; } };
  for (const [key] of originals) Object.defineProperty(globalThis, key, { configurable: true, value: storage });
  try {
    const account = "11111111-1111-4111-8111-111111111111";
    recordSignIn(account); teachOnce(account, "close-keeps-running");
    expect(clearAccountStorage(account)).toBe(true);
    expect([...values].filter(([key, value]) => key.includes(account) || value.includes(account)), "sign-out removes every persisted reference to the account").toEqual([]);
  } finally {
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  }
});
